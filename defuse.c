#pragma comment(lib, "CldApi")

#define _CRT_SECURE_NO_WARNINGS

#define _WIN32_WINNT    0x0A00

#define DEBUG

#define DIRECTORY_POPULATE_TIMEOUT_MS   4000

#include "defuse.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <WinBase.h>
#include <Unknwn.h>
#include <cfapi.h>
#include <sddl.h>

#ifdef DEBUG
    #define DEBUG_INFO_DUMP                 fprintf(stderr, "::%s:%i> ", __func__, (int)__LINE__);
    #define DEBUG_DUMP(message, ...)        { DEBUG_INFO_DUMP fprintf(stderr, message "\n", __VA_ARGS__); }
    #define DEBUG_NOTE(message)             DEBUG_DUMP("%s", message);

    #define DEBUG_ERRNO(key, err)           DEBUG_DUMP("%s returned %i (%s)", key, (int)err, strerror(err < 0 ? -err : err));
    #define DEBUG_ERRNO2(key, err)          DEBUG_DUMP("%s returned %i (%s)", key, (int)err, err < 0 ? strerror(-err) : "ACK");

    static void __DEBUG_HANDLE(const char *key, HRESULT hr, const char *func, int line) {
        if (hr != S_OK) {
            LPTSTR szBuffer = NULL;
            FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER  | FORMAT_MESSAGE_FROM_SYSTEM, NULL, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&szBuffer, 0, NULL);
            fprintf(stderr, "::%s:%i> %s error 0x%x: %s", func, line, key, (int)hr, szBuffer);
            if (szBuffer)
                LocalFree(szBuffer);
        } else {
            fprintf(stderr, "::%s:%i> %s returned 0x%x\n", func, line, key, (int)hr);
        }
    }
    #define DEBUG_HANDLE(key, err)          __DEBUG_HANDLE(key, err, __func__, (int)__LINE__);

#else
    #define DEBUG_DUMP(message, ...)
    #define DEBUG_NOTE(message)

    #define DEBUG_ERRNO(key, err)
    #define DEBUG_ERRNO2(key, err)
    #define DEBUG_HANDLE(key, err)
#endif

#ifndef S_ISDIR
    #define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
#endif
#define LARGE_TIME(src) ((unsigned __int64)src)*10000000 + 116444736000000000LL;

#define FIELD_SIZE( type, field ) ( sizeof( ( (type*)0 )->field ) )
#define CF_SIZE_OF_OP_PARAM( field )                                           \
    ( FIELD_OFFSET( CF_OPERATION_PARAMETERS, field ) +                         \
      FIELD_SIZE( CF_OPERATION_PARAMETERS, field ) )

struct fuse_chan {
    wchar_t path[MAX_PATH + 1];
    struct fuse *fs;
};

struct fuse {
    struct fuse_operations op;
    struct fuse_conn_info connection;
    struct fuse_chan* ch;
    void *user_data;
    char *path_utf8;
    CF_CONNECTION_KEY s_transferCallbackConnectionKey;
    HANDLE sem;

    unsigned int fetch_op_count;
    DWORD populate_root;
    char running;

    char **refresh_paths;
    int len_refresh_paths;
};

int fuse_populate_directory(struct fuse *f, const char *path, int recursive);

static int DeleteDirectory(const wchar_t *sPath) {
    HANDLE hFind;
    WIN32_FIND_DATAW FindFileData;

    wchar_t DirPath[4096];
    wchar_t FileName[4096];

    wcscpy(DirPath, sPath);
    wcscat(DirPath, L"\\*");
    wcscpy(FileName, sPath);
    wcscat(FileName, L"\\");

    hFind = FindFirstFileW(DirPath, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
        return 0;

    wcscpy(DirPath, FileName);

    int bSearch = 1;
    while (bSearch) {
        if (FindNextFileW(hFind, &FindFileData)) {
            if ((!wcscmp(FindFileData.cFileName, L".")) || (!wcscmp(FindFileData.cFileName, L"..")))
                continue;

            wcscat(FileName, FindFileData.cFileName);

            HANDLE h;
            HRESULT hr = CfOpenFileWithOplock(FileName, CF_OPEN_FILE_FLAG_NONE, &h);
            DEBUG_HANDLE("CfOpenFileWithOplock", hr);
            if (!FAILED(hr)) {
                HRESULT hr2 = CfRevertPlaceholder(h, CF_REVERT_FLAG_NONE, NULL);
                DEBUG_HANDLE("CfRevertPlaceholder", hr2);
                CfCloseHandle(h);
            }

            if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                DeleteDirectory(FileName);
                RemoveDirectoryW(FileName);
                wcscpy(FileName, DirPath);
            } else {
                if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
                    _wchmod(FileName, _S_IWRITE);

                // overwrite files before deleting
                FILE *file = NULL;
                if (!_wfopen_s(&file, FileName, L"w"))
                    fclose(file);

                DeleteFileW(FileName);
                wcscpy(FileName, DirPath);
            }
        } else {
            if (GetLastError() == ERROR_NO_MORE_FILES) {
                bSearch = 0;
            } else {
                FindClose(hFind);
                return 0;
            }

        }
    }
    FindClose(hFind);

    return RemoveDirectoryW(sPath);
}

void fuse_lock(struct fuse *f) {
    WaitForSingleObject(f->sem, INFINITE);
}

void fuse_unlock(struct fuse *f) {
    ReleaseSemaphore(f->sem, 1, NULL);
}

/*
static void update_placeholder_flags(const wchar_t *NormalizedPath, CF_UPDATE_FLAGS flags) {
    HANDLE h;
    DEBUG_DUMP("update_placeholder_flags %S", NormalizedPath);

    // no update for root
    if ((NormalizedPath) && (NormalizedPath[0] == '/') && (!NormalizedPath[1]))
        return;

    HRESULT hr2 = CfOpenFileWithOplock(NormalizedPath, CF_OPEN_FILE_FLAG_NONE, &h);
    DEBUG_HANDLE("CfOpenFileWithOplock", hr2);
    if (!FAILED(hr2)) {
        hr2 = CfUpdatePlaceholder(h, NULL, NULL, 0, NULL, 0, flags, NULL, NULL);
        DEBUG_HANDLE("CfUpdatePlaceholder", hr2);
        CfCloseHandle(h);
    }
}
*/

static char *get_full_path(const char *path, const char *name) {
    int len_name = name ? (int)strlen(name) : 0;
    int len_path = path ? (int)strlen(path) : 0;

    int add_slash = 0;
    if ((len_path > 0) && (len_name > 0) && (path[len_path - 1] != '/') && (path[len_path - 1] != '\\') && (name[0] != '/') && (name[0] != '\\'))
        add_slash = 1;

    char *full_path = (char *)malloc(len_path + len_name + add_slash + 1);

    if (full_path) {
        memcpy(full_path, path, len_path);
        if (add_slash)
            full_path[len_path] = '/';
        memcpy(full_path + len_path + add_slash, name, len_name);
        full_path[len_path + len_name + add_slash] = 0;
    }
    return full_path;
}

static char *toUTF8(const wchar_t *src) {
    if (!src)
        return NULL;

    int len = (int)wcslen(src);
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, src, len, 0, 0, NULL, NULL);
    char *buf = (char *)malloc((utf8_len + 1) * sizeof(char));
    if (buf) {
        WideCharToMultiByte(CP_UTF8, 0, src, len, buf, utf8_len, NULL, NULL);
        buf[utf8_len] = 0;
    }
    return buf;
}

static char *toUTF8_path(const wchar_t *src, int bytes_len) {
    if ((!src) || (!src[0]) || (bytes_len <= 0))
        return _strdup("/");

    int add_path = 0;
    if (src[0] != '/')
        add_path = 1;
    int len = bytes_len / 2;
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, src, len, 0, 0, NULL, NULL);
    char *buf = (char *)malloc((utf8_len + add_path + 1) * sizeof(char));
    if (buf) {
        WideCharToMultiByte(CP_UTF8, 0, src, len, buf + add_path, utf8_len, NULL, NULL);
        if (add_path)
            buf[0] = '/';
        buf[utf8_len + add_path] = 0;
    }
    return buf;
}

static wchar_t *fromUTF8(const char *src) {
    if (!src)
        src = "";

    int len = (int)strlen(src);
    int length = MultiByteToWideChar(CP_UTF8, 0, src, len, 0, 0);
    wchar_t *buf = (wchar_t *)malloc((length + 1) * sizeof(wchar_t));
    if (buf) {
        MultiByteToWideChar(CP_UTF8, 0, src, len, buf, length);
        buf[length] = 0;
    }
    return buf;
}

int fuse_is_read_only(struct fuse *f, const char *path) {
    int read_only = 0;

    if ((f) && (f->op.statfs)) {
        struct statvfs stbuf;

        if (!f->op.statfs(path, &stbuf)) {
            if ((!stbuf.f_bfree) || (!stbuf.f_bavail ) || (!stbuf.f_ffree) || (!stbuf.f_favail))
                read_only = 1;
        }
    }
    return read_only;
}

void CALLBACK OnFetchData(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    struct fuse *f = (struct fuse *)callbackInfo->CallbackContext;
    fuse_lock(f);
    f->fetch_op_count ++;
    fuse_unlock(f);

    CF_OPERATION_INFO opInfo = { 0 };
    CF_OPERATION_PARAMETERS opParams = { 0 };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
    opInfo.ConnectionKey = callbackInfo->ConnectionKey;
    opInfo.TransferKey = callbackInfo->TransferKey;
    opInfo.RequestKey = callbackInfo->RequestKey;
    opInfo.CorrelationVector = callbackInfo->CorrelationVector;

    opParams.ParamSize = CF_SIZE_OF_OP_PARAM(TransferData);
    opParams.TransferData.CompletionStatus = STATUS_SUCCESS;
    opParams.TransferData.Offset.QuadPart = 0;
    opParams.TransferData.Length.QuadPart = 0;

    int open_err = 0;
    struct fuse_file_info finfo = { 0 };
    char *path = toUTF8_path((wchar_t *)callbackInfo->FileIdentity, callbackInfo->FileIdentityLength);

    DEBUG_DUMP("FetchData %s", path);

    if (f->op.open) {
        fuse_lock(f);
        open_err = f->op.open(path, &finfo);
        fuse_unlock(f);
    }

    DEBUG_ERRNO("op.open", open_err);

    char buf[0x10000];
    HRESULT hr;
    if (open_err) {
        opParams.TransferData.Buffer = buf;
        opParams.TransferData.Offset.QuadPart = callbackParameters->FetchData.RequiredFileOffset.QuadPart;
        opParams.TransferData.Length.QuadPart = callbackParameters->FetchData.RequiredLength.QuadPart;
        opParams.TransferData.CompletionStatus = STATUS_UNSUCCESSFUL;

        hr = CfExecute(&opInfo, &opParams);
        DEBUG_HANDLE("CfExecute", hr);
    } else {
        if (f->op.read) {
            __int64 size = (__int64)callbackParameters->FetchData.RequiredLength.QuadPart;
            __int64 offset = (__int64)callbackParameters->FetchData.RequiredFileOffset.QuadPart;

            LARGE_INTEGER ProviderProgressCompleted = { 0 };

            __int64 read_size = size;
            if (read_size > sizeof(buf))
                read_size = sizeof(buf);

            do {
                int err = f->op.read(path, buf, read_size, offset, &finfo);
                DEBUG_ERRNO2("op.read", err);
                if (err < 0) {
                    DEBUG_ERRNO("op.read", err);
                    opParams.TransferData.CompletionStatus = NTSTATUS_FROM_WIN32(EIO);
                    opParams.TransferData.Buffer = buf;
                    opParams.TransferData.Offset.QuadPart = callbackParameters->FetchData.RequiredFileOffset.QuadPart;//offset;
                    opParams.TransferData.Length.QuadPart = callbackParameters->FetchData.RequiredLength.QuadPart;//size;
                    hr = CfExecute(&opInfo, &opParams);

                    DEBUG_HANDLE("CfExecute", hr);
                    break;
                } else {
                    opParams.TransferData.Buffer = buf;
                    opParams.TransferData.Offset.QuadPart = offset;
                    opParams.TransferData.Length.QuadPart = err;
                    opParams.TransferData.CompletionStatus = STATUS_SUCCESS;
                    
                    hr = CfExecute(&opInfo, &opParams);
                    DEBUG_HANDLE("CfExecute", hr);
                    if (FAILED(hr)) {
                        // 0x8007018e: The cloud operation was canceled by user.
                        if (hr != 0x8007018e) {
                            DEBUG_DUMP("Error in CfExecute => offset %" PRId64 ", len %i", offset, err);
                            opParams.TransferData.CompletionStatus = NTSTATUS_FROM_WIN32(EIO);
                            opParams.TransferData.Buffer = buf;
                            opParams.TransferData.Offset.QuadPart = callbackParameters->FetchData.RequiredFileOffset.QuadPart;
                            opParams.TransferData.Length.QuadPart = callbackParameters->FetchData.RequiredLength.QuadPart;
                            hr = CfExecute(&opInfo, &opParams);
                        }
                        break;
                    }

                    ProviderProgressCompleted.QuadPart += err;
                    hr = CfReportProviderProgress(callbackInfo->ConnectionKey, callbackInfo->TransferKey, callbackParameters->FetchData.RequiredLength, ProviderProgressCompleted);
                    DEBUG_HANDLE("CfReportProviderProgress", hr);
                    DEBUG_DUMP("  [ %3.2f%% ]", (double)ProviderProgressCompleted.QuadPart / (double)callbackParameters->FetchData.RequiredLength.QuadPart * 100);

                    size -= err;
                    offset += err;

                    if (size < read_size)
                        read_size = size;
                }
            } while (size > 0);
        }

        if (f->op.release) {
            fuse_lock(f);
            f->op.release(path, &finfo);
            fuse_unlock(f);
        }
    }
    free(path);
    fuse_lock(f);
    f->fetch_op_count --;
    fuse_unlock(f);
}

static int is_modified(struct fuse *f, char *path, char *full_path) {
    struct stat st_buf = { 0 };
    struct stat st_buf2 = { 0 };

    if ((f->op.getattr) && (!f->op.getattr(path, &st_buf))) {
        if (!stat(full_path, &st_buf2)) {
            if ((st_buf.st_mtime >= st_buf2.st_mtime) && (st_buf.st_size == st_buf2.st_size)) {
                return 0;
            }
        }
    }

    return 1;
}

static int is_newer_in_cloud(struct fuse *f, char *path, char *full_path) {
    struct stat st_buf = { 0 };
    struct stat st_buf2 = { 0 };

    if ((f->op.getattr) && (!f->op.getattr(path, &st_buf))) {
        if (!stat(full_path, &st_buf2)) {
            if (st_buf.st_mtime <= st_buf2.st_mtime) {
                return 0;
            }
        }
    }

    return 1;
}

void CALLBACK OnFileOpen(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
#ifdef DEBUG
    char *path = toUTF8_path((wchar_t *)callbackInfo->FileIdentity, callbackInfo->FileIdentityLength);
    DEBUG_DUMP("File opened %s", path);
    free(path);
#endif
}

static int fuse_sync_full_sync(struct fuse *f, char *path, char *full_path, int try_create) {
    struct fuse_file_info finfo = { 0 };
    DEBUG_DUMP("Sync file %s", path);

    if (!f->op.write) {
        DEBUG_NOTE("op.write is not set");
        return -EACCES;
    }

    int err = 0;
    struct stat st_buf = { 0 };

    FILE* local_file = NULL;
    
    err = fopen_s(&local_file, full_path, "rb");
    if (!local_file) {
        DEBUG_DUMP("Error opening %s", full_path);
        return -EACCES;
    }

    int created = 0;
    if (try_create) {
        if (f->op.create) {
            err = f->op.create(path, 0666, &finfo);
            DEBUG_ERRNO("op.create", err);
            if (!err)
                created = 1;
        }
    }
    if (!created) {
        if (f->op.truncate) {
            __int64 fuse_file_size = 0;
            if ((f->op.getattr) && (!f->op.getattr(path, &st_buf)))
                fuse_file_size = st_buf.st_size;

            _fseeki64(local_file, 0, SEEK_END);
            __int64 fsize = _ftelli64(local_file);
            _fseeki64(local_file, 0, SEEK_SET);

            if (fsize < fuse_file_size)
                f->op.truncate(path, fsize);

            DEBUG_DUMP("Truncate %s at %i", path, (int)fsize);
        }

        if (f->op.open) {
            err = f->op.open(path, &finfo);
            if (err) {
                fclose(local_file);
                DEBUG_ERRNO("op.open", err);
                return err;
            }
        }
    }

    char buffer[8192];
    off_t offset = 0;
    while (!feof(local_file)) {
        size_t bytes = fread(buffer, 1, sizeof(buffer), local_file);
        DEBUG_ERRNO2("fread", bytes);
        if (bytes <= 0) {
            if (bytes < 0)
                err = -EIO;
            break;
        }
        buffer[bytes] = 0;

        off_t written = 0;
        do {
            fuse_lock(f);
            err = f->op.write(path, buffer + written, bytes - written, offset + written, &finfo);
            fuse_unlock(f);
            DEBUG_ERRNO2("op.write", err);
            if (err <= 0)
                break;

            written += err;
        } while (written < bytes);

        if (written != bytes)
            break;

        offset += written;
    }
    if (err > 0)
        err = 0;
    fclose(local_file);

    if (f->op.utimens) {
        if (!stat(full_path, &st_buf)) {
            struct timespec tv[2];
            tv[0].tv_sec = st_buf.st_atime;
            tv[0].tv_nsec = 0;
            tv[1].tv_sec = st_buf.st_mtime;
            tv[1].tv_nsec = 0;
            fuse_lock(f);
            f->op.utimens(path, tv);
            fuse_unlock(f);
        }
    }

    if (f->op.release) {
        fuse_lock(f);
        f->op.release(path, &finfo);
        fuse_unlock(f);
    }

    return err;
}

void CALLBACK OnFileClose(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    struct fuse *f = (struct fuse *)callbackInfo->CallbackContext;
    DEBUG_NOTE("File close");

    HANDLE h;
    HRESULT hr = CfOpenFileWithOplock(callbackInfo->NormalizedPath, CF_OPEN_FILE_FLAG_EXCLUSIVE, &h);
    DEBUG_HANDLE("CfOpenFileWithOplock", hr);
    if (hr == S_OK) {
        HRESULT hr2;

        char *path = toUTF8_path((wchar_t *)callbackInfo->FileIdentity, callbackInfo->FileIdentityLength);
        char *full_path = toUTF8(callbackInfo->NormalizedPath);

        hr2 = CfSetInSyncState(h, CF_IN_SYNC_STATE_IN_SYNC, CF_SET_IN_SYNC_FLAG_NONE, NULL);
        DEBUG_HANDLE("CfSetInSyncState", hr2);

        if (is_newer_in_cloud(f, path, full_path)) {
            LARGE_INTEGER start;
            LARGE_INTEGER len;
            start.QuadPart = 0;
            len.QuadPart = -1;

            hr = CfDehydratePlaceholder(h, start, len, CF_DEHYDRATE_FLAG_NONE, NULL);
            DEBUG_HANDLE("CfDehydratePlaceholder", hr);
        }

        free(path);
        free(full_path);

        CfCloseHandle(h);
    }
}

void CALLBACK OnFileDelete(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    struct fuse *f = (struct fuse *)callbackInfo->CallbackContext;
    int err = -1;

    char *path = toUTF8_path((wchar_t *)callbackInfo->FileIdentity, callbackInfo->FileIdentityLength);
    DEBUG_DUMP("Delete %s", path);

    fuse_lock(f);
    if (!fuse_is_read_only(f, path)) {
        if (callbackParameters->Delete.Flags & CF_CALLBACK_DELETE_FLAG_IS_DIRECTORY) {
            if (f->op.rmdir)
                err = f->op.rmdir(path);
        } else {
            if (f->op.unlink)
                err = f->op.unlink(path);
        }
    }
    fuse_unlock(f);

    free(path);

    DEBUG_ERRNO("op.rmdir/unlink", err);
    
    CF_OPERATION_INFO opInfo = { 0 };
    CF_OPERATION_PARAMETERS opParams = { 0 };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_ACK_DELETE;
    opInfo.ConnectionKey = callbackInfo->ConnectionKey;
    opInfo.TransferKey = callbackInfo->TransferKey;
    opInfo.CorrelationVector = callbackInfo->CorrelationVector;
    opInfo.RequestKey = callbackInfo->RequestKey;

    opParams.ParamSize = CF_SIZE_OF_OP_PARAM(AckDelete);
    opParams.AckDelete.CompletionStatus = err ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
    opParams.AckDelete.Flags = CF_OPERATION_ACK_DELETE_FLAG_NONE;

    HRESULT hr = CfExecute(&opInfo, &opParams);
    DEBUG_HANDLE("CfExecute", hr);
}

void CALLBACK OnFileRename(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    struct fuse *f = (struct fuse *)callbackInfo->CallbackContext;
    int err = -1;
    char *path = toUTF8_path((wchar_t *)callbackInfo->FileIdentity, callbackInfo->FileIdentityLength);
    char *path2;

    DEBUG_DUMP("Rename %s", path);

    if ((f->op.rename) && (!fuse_is_read_only(f, path))) {
        path = toUTF8_path((wchar_t *)callbackInfo->FileIdentity, callbackInfo->FileIdentityLength);
        path2 = toUTF8_path(callbackParameters->Rename.TargetPath, callbackParameters->Rename.TargetPath ? wcslen(callbackParameters->Rename.TargetPath) : 0);
        fuse_lock(f);
        err = f->op.rename(path, path2, 0);
        fuse_unlock(f);
        DEBUG_DUMP("Rename %s to %s, errno: %i", path, path2, err);
        free(path);
        free(path2);
    }

    CF_OPERATION_INFO opInfo = { 0 };
    CF_OPERATION_PARAMETERS opParams = { 0 };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_ACK_RENAME;
    opInfo.ConnectionKey = callbackInfo->ConnectionKey;
    opInfo.TransferKey = callbackInfo->TransferKey;
    opInfo.CorrelationVector = callbackInfo->CorrelationVector;
    opInfo.RequestKey = callbackInfo->RequestKey;

    opParams.ParamSize = CF_SIZE_OF_OP_PARAM(AckRename);
    opParams.AckRename.CompletionStatus = err ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
    opParams.AckRename.Flags = CF_OPERATION_ACK_RENAME_FLAG_NONE;

    HRESULT hr = CfExecute(&opInfo, &opParams);
    DEBUG_HANDLE("CfExecute", hr);
}

/* *******************************************************************************************
// OnFetchPlacehodlers - disabled because of buggy behaviour (unaccessible files/folders)

static int fuse_fill_dir(void *buf, const char *name, const struct stat *stbuf, off_t off) {
    struct fuse *f = (struct fuse *)((void**)buf)[0];
    CF_PLACEHOLDER_CREATE_INFO **placeholders = (CF_PLACEHOLDER_CREATE_INFO **)((void **)buf)[1];
    unsigned int *placeholders_count = (unsigned int *)((void**)buf)[2];
    struct fuse_file_info* finfo = (struct fuse_file_info*)((void**)buf)[3];
    struct stat stbuf2;
    char *path = (char *)((void**)buf)[4];

    if ((!finfo) || (!f)) {
        DEBUG_NOTE("I/O error");
        return -EIO;
    }

    if (off < finfo->offset) {
        DEBUG_NOTE("offset error");
        return 0;
    }

    if ((!name) || (!strcmp(name, ".")) || (!strcmp(name, "..")))
        return 0;

    int len_name = name ? (int)strlen(name) : 0;
    int len_path = path ? (int)strlen(path) : 0;
    char *full_path = (char *)malloc(len_path + len_name + 2);

    if (full_path) {
        memcpy(full_path, path, len_path);
        if (path[len_path - 1] == '/') {
            memcpy(full_path + len_path, name, len_name);
            full_path[len_path + len_name] = 0;
        } else {
            full_path[len_path] = '/';
            memcpy(full_path + len_path + 1, name, len_name);
            full_path[len_path + len_name + 1] = 0;
        }
    }
    DEBUG_DUMP("    %s", full_path);

    if ((!stbuf) && (f->op.getattr) && (name) && (path) && (path[0])) {
        memset(&stbuf2, 0, sizeof(stbuf2));
        if ((!strcmp(name, ".")) || (!strcmp(name, ".."))) {
            if (!f->op.getattr(path, &stbuf2))
                stbuf = &stbuf2;
        } else {
            if (!f->op.getattr(full_path, &stbuf2))
                stbuf = &stbuf2;
        }
    }
    CF_PLACEHOLDER_CREATE_INFO *placeholders2 = (CF_PLACEHOLDER_CREATE_INFO *)realloc(*placeholders, sizeof(CF_PLACEHOLDER_CREATE_INFO) * ((*placeholders_count) + 1));
    if (!placeholders2) {
        DEBUG_NOTE("realloc error");
        return -ENOMEM;
    }

    *placeholders = placeholders2;

    CF_PLACEHOLDER_CREATE_INFO *placeholder = &placeholders2[*placeholders_count];
    (*placeholders_count) ++;

    memset(placeholder, 0, sizeof(CF_PLACEHOLDER_CREATE_INFO));

    wchar_t *wname = fromUTF8(full_path);
    placeholder->FileIdentity = wname;
    placeholder->FileIdentityLength = (DWORD)(wcslen(wname) * sizeof(wchar_t));
    placeholder->RelativeFileName = fromUTF8(name);

    // do not free wname nor placeholder->RelativeFileName here (it will be freed by OnFetchPlaceholders)
    placeholder->Flags = CF_PLACEHOLDER_CREATE_FLAG_NONE;
    if (stbuf) {
        placeholder->Flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;

        if (S_ISDIR(stbuf->st_mode)) {
            placeholder->FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
            placeholder->FsMetadata.FileSize.QuadPart = 0;
        } else {
            placeholder->FsMetadata.FileSize.QuadPart = stbuf->st_size;
        }

        placeholder->FsMetadata.BasicInfo.CreationTime.QuadPart = LARGE_TIME(stbuf->st_ctime);
        placeholder->FsMetadata.BasicInfo.ChangeTime.QuadPart = LARGE_TIME(stbuf->st_mtime);
        placeholder->FsMetadata.BasicInfo.LastAccessTime.QuadPart = LARGE_TIME(stbuf->st_atime);
        placeholder->FsMetadata.BasicInfo.LastWriteTime.QuadPart = LARGE_TIME(stbuf->st_mtime);

        if ((name) && (name[0] == '.') && (name[1]) && (name[1] != '.'))
            placeholder->FsMetadata.BasicInfo.FileAttributes |= FILE_ATTRIBUTE_HIDDEN;
        else
            placeholder->FsMetadata.BasicInfo.FileAttributes |= FILE_ATTRIBUTE_NORMAL;

        placeholder->FsMetadata.BasicInfo.FileAttributes |= FILE_ATTRIBUTE_ARCHIVE | 0x2000 | 0x20000;
    } else {
        DEBUG_NOTE("No file attributtes received");
    }

    finfo->session_offset++;

    free(full_path);

    return 0;
}

void CALLBACK OnFetchPlaceholders(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    CF_OPERATION_INFO opInfo = { 0 };
    CF_OPERATION_PARAMETERS opParams = { 0 };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
    opInfo.ConnectionKey = callbackInfo->ConnectionKey;
    opInfo.TransferKey = callbackInfo->TransferKey;
    opInfo.RequestKey = callbackInfo->RequestKey;
    opInfo.CorrelationVector = callbackInfo->CorrelationVector;

    opParams.ParamSize = CF_SIZE_OF_OP_PARAM(TransferPlaceholders);
    opParams.TransferPlaceholders.CompletionStatus = STATUS_SUCCESS;
    struct fuse *f = (struct fuse *)callbackInfo->CallbackContext;

    CF_PLACEHOLDER_CREATE_INFO *placeholders = NULL;
    unsigned int placeholders_count = 0;

    if (f) {

        struct fuse_file_info fi = { 0 };
        int open_err = 0;
        char *path = toUTF8_path((wchar_t *)callbackInfo->FileIdentity, callbackInfo->FileIdentityLength);
        DEBUG_DUMP("Fetch placeholders: %s (pattern '%S', trigger %S)", path, callbackParameters->FetchPlaceholders.Pattern, callbackInfo->ProcessInfo ? callbackInfo->ProcessInfo->CommandLine : L"n/a");

        if (f->op.opendir) {
            fuse_lock(f);
            open_err = f->op.opendir(path, &fi);
            fuse_unlock(f);
            if (open_err)
                opParams.TransferPlaceholders.CompletionStatus = STATUS_UNSUCCESSFUL;
        }

        DEBUG_ERRNO("op.opendir", open_err);

        if (!open_err) {
            if (f->op.readdir) {
                void* data[5];
                data[0] = (void*)f;
                data[1] = (void*)&placeholders;
                data[2] = (void*)&placeholders_count;
                data[3] = (void*)&fi;
                data[4] = (void*)path;

                fuse_lock(f);
                int err = f->op.readdir(path, data, fuse_fill_dir, fi.offset, &fi);
                fuse_unlock(f);
                if (err)
                    opParams.TransferPlaceholders.CompletionStatus = STATUS_UNSUCCESSFUL;

                opParams.TransferPlaceholders.Flags = CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE;
                opParams.TransferPlaceholders.PlaceholderTotalCount.QuadPart = placeholders_count;
                opParams.TransferPlaceholders.PlaceholderCount = placeholders_count;
                opParams.TransferPlaceholders.PlaceholderArray = placeholders;
            }

            if ((f->op.releasedir) && (!open_err)) {
                fuse_lock(f);
                f->op.releasedir(path, &fi);
                fuse_unlock(f);
            }
        }


        free(path);
    }

    HRESULT hr = CfExecute(&opInfo, &opParams);
    DEBUG_HANDLE("CfExecute", hr);
    DEBUG_DUMP("Processed entities %i/%i", (int)opParams.TransferPlaceholders.EntriesProcessed, (int)placeholders_count);
    unsigned int i;
    for (i = 0; i < placeholders_count; i++) {
        free((void *)placeholders[i].FileIdentity);
        free((void *)placeholders[i].RelativeFileName);
    }
    free(placeholders);

    update_placeholder_flags(callbackInfo->NormalizedPath, CF_UPDATE_FLAG_DISABLE_ON_DEMAND_POPULATION);
}
// ****************************************************************************************** */

static int fuse_fill_dir_no_demand(void *buf, const char *name, const struct stat *stbuf, off_t off) {
    struct fuse *f = (struct fuse *)((void**)buf)[0];
    struct fuse_file_info* finfo = (struct fuse_file_info*)((void**)buf)[1];
    char *path = (char *)((void**)buf)[2];
    int recursive = (int)(uintptr_t)((void**)buf)[3];

    struct stat stbuf2;

    if ((!finfo) || (!f)) {
        DEBUG_NOTE("I/O error");
        return -EIO;
    }

    if (off < finfo->offset) {
        DEBUG_NOTE("offset error");
        return 0;
    }

    if ((!name) || (!strcmp(name, ".")) || (!strcmp(name, "..")))
        return 0;

    int len_name = name ? (int)strlen(name) : 0;
    int len_path = path ? (int)strlen(path) : 0;
    char *full_path = (char *)malloc(len_path + len_name + 2);

    if (full_path) {
        memcpy(full_path, path, len_path);
        if (path[len_path - 1] == '/') {
            memcpy(full_path + len_path, name, len_name);
            full_path[len_path + len_name] = 0;
        } else {
            full_path[len_path] = '/';
            memcpy(full_path + len_path + 1, name, len_name);
            full_path[len_path + len_name + 1] = 0;
        }
    }
    DEBUG_DUMP("    %s", full_path);

    if ((!stbuf) && (f->op.getattr) && (name) && (path) && (path[0])) {
        memset(&stbuf2, 0, sizeof(stbuf2));
        if ((!strcmp(name, ".")) || (!strcmp(name, ".."))) {
            if (!f->op.getattr(path, &stbuf2))
                stbuf = &stbuf2;
        } else {
            if (!f->op.getattr(full_path, &stbuf2))
                stbuf = &stbuf2;
        }
    }

    CF_PLACEHOLDER_CREATE_INFO placeholder;
    memset(&placeholder, 0, sizeof(CF_PLACEHOLDER_CREATE_INFO));

    wchar_t *wname = fromUTF8(full_path);
    placeholder.FileIdentity = wname;
    placeholder.FileIdentityLength = (DWORD)(wcslen(wname) * sizeof(wchar_t));
    placeholder.RelativeFileName = fromUTF8(name);

    int is_dir = 0;
    // do not free wname nor placeholder->RelativeFileName here (it will be freed by OnFetchPlaceholders)
    placeholder.Flags = CF_PLACEHOLDER_CREATE_FLAG_NONE;
    if (stbuf) {
        placeholder.Flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;

        if (S_ISDIR(stbuf->st_mode)) {
            placeholder.FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
            placeholder.FsMetadata.FileSize.QuadPart = 0;
            placeholder.Flags |= CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION;
            is_dir = 1;
        } else {
            placeholder.FsMetadata.FileSize.QuadPart = stbuf->st_size;
        }

        placeholder.FsMetadata.BasicInfo.CreationTime.QuadPart = LARGE_TIME(stbuf->st_ctime);
        placeholder.FsMetadata.BasicInfo.ChangeTime.QuadPart = LARGE_TIME(stbuf->st_mtime);
        placeholder.FsMetadata.BasicInfo.LastAccessTime.QuadPart = LARGE_TIME(stbuf->st_atime);
        placeholder.FsMetadata.BasicInfo.LastWriteTime.QuadPart = LARGE_TIME(stbuf->st_mtime);

        if ((name) && (name[0] == '.') && (name[1]) && (name[1] != '.'))
            placeholder.FsMetadata.BasicInfo.FileAttributes |= FILE_ATTRIBUTE_HIDDEN;
        else
            placeholder.FsMetadata.BasicInfo.FileAttributes |= FILE_ATTRIBUTE_NORMAL;

        placeholder.FsMetadata.BasicInfo.FileAttributes |= FILE_ATTRIBUTE_ARCHIVE  | 0x2000 | 0x20000;
    } else {
        DEBUG_NOTE("No file attributtes received");
    }

    char *full_file_path = get_full_path(f->path_utf8, path);
    wchar_t *full_wname = fromUTF8(full_file_path);
    HRESULT hr = CfCreatePlaceholders(full_wname, &placeholder, 1, CF_CREATE_FLAG_NONE, NULL);
    DEBUG_HANDLE("CfCreatePlaceholders", hr);
    if (hr == 0x800700b7) {
        // Cannot create a file when that file already exists.
        HANDLE h;
        HRESULT hr2 = CfOpenFileWithOplock(full_wname, CF_OPEN_FILE_FLAG_NONE, &h);
        DEBUG_HANDLE("CfOpenFileWithOplock", hr2);
        if (!FAILED(hr2)) {
            hr2 = CfUpdatePlaceholder(h, &placeholder.FsMetadata, placeholder.FileIdentity, placeholder.FileIdentityLength, NULL, 0, placeholder.Flags, NULL, NULL);
            DEBUG_HANDLE("CfUpdatePlaceholder", hr2);
            CfCloseHandle(h);

            if (hr2 == 0x80070178) {
                // The file is not a cloud file.
                hr2 = CfOpenFileWithOplock(full_wname, CF_OPEN_FILE_FLAG_NONE, &h);
                if (!FAILED(hr2)) {
                    hr2 = CfConvertToPlaceholder(h, placeholder.FileIdentity, placeholder.FileIdentityLength * sizeof(wchar_t), CF_CONVERT_FLAG_NONE , NULL, NULL);
                    DEBUG_HANDLE("CfConvertToPlaceholder", hr2);

                    if (!FAILED(hr2)) {
                        hr2 = CfUpdatePlaceholder(h, &placeholder.FsMetadata, placeholder.FileIdentity, placeholder.FileIdentityLength, NULL, 0, placeholder.Flags, NULL, NULL);
                        DEBUG_HANDLE("CfUpdatePlaceholder", hr2);
                    }

                    CfCloseHandle(h);
                }
            }
        }
    }

    free(full_wname);
    free(full_file_path);

    finfo->session_offset++;

    if ((recursive) && (is_dir)) {
        DEBUG_DUMP("Populating %s", full_path);
        fuse_unlock(f);
        fuse_populate_directory(f, full_path, recursive);
        fuse_lock(f);
    }

    free((void *)wname);
    free((void *)placeholder.RelativeFileName);
    free((void *)full_path);

    if (FAILED(hr))
        return -1;

    return 0;
}

int fuse_populate_directory(struct fuse *f, const char *path, int recursive) {
    DEBUG_DUMP("Populating %s", path);
    int populate_err = -1;
    if (f) {
        struct fuse_file_info fi = { 0 };
        int open_err = 0;

        if (f->op.opendir) {
            fuse_lock(f);
            open_err = f->op.opendir(path, &fi);
            fuse_unlock(f);
            populate_err = open_err;
        }

        DEBUG_ERRNO("op.opendir", open_err);

        if (!open_err) {
            if (f->op.readdir) {
                void* data[4];
                data[0] = (void*)f;
                data[1] = (void*)&fi;
                data[2] = (void*)path;
                data[3] = (void*)(intptr_t)recursive;

                fuse_lock(f);
                int err = f->op.readdir(path, data, fuse_fill_dir_no_demand, fi.offset, &fi);
                fuse_unlock(f);

                populate_err = err;
            }

            if ((f->op.releasedir) && (!open_err)) {
                fuse_lock(f);
                f->op.releasedir(path, &fi);
                fuse_unlock(f);
            }
        }
    }
    return populate_err;
}

void CALLBACK OnValidateData(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    // to do
    DEBUG_NOTE("Validate data");
}

void CALLBACK OnCancelFetchData(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    // to do
    DEBUG_NOTE("Cancel fetch data");
}

static void remove_placeholder(struct fuse *f, const char *path) {
    if ((!path) || (!path[0]) || (!strcmp(path, "/")) || (!strcmp(path, ".")))
        return;

    char *full_path = get_full_path(f->path_utf8, path);

    wchar_t *full_path_w = fromUTF8(full_path);
    HANDLE h;
    HRESULT hr = CfOpenFileWithOplock(full_path_w, CF_OPEN_FILE_FLAG_NONE, &h);
    // 0x80070002 = The system cannot find the file specified.
    if (hr != 0x80070002) {

        DEBUG_HANDLE("CfOpenFileWithOplock", hr);

        if (!FAILED(hr)) {
            HRESULT hr2 = CfRevertPlaceholder(h, CF_REVERT_FLAG_NONE, NULL);
            DEBUG_HANDLE("CfRevertPlaceholder", hr2);
            CfCloseHandle(h);

            // op.getattr may return error, so run both rmdir and unlink
            rmdir(full_path);
            _unlink(full_path);

            free(full_path_w);
            free(full_path);
        }
    }
}

static int fuse_update_path(struct fuse *f, const char *path) {
    if ((!f->op.getattr) || (!path))
        return 0;

    const char *name = NULL;
    if (path) {
        int len = strlen(path);
        int i;
        for (i = len - 1; i >= 0; i --) {
            if ((path[i] == '/') || (path[i] == '\\')) {
                name = path + i + 1;
                break;
            }
        }
    }
    if (!name)
        return 0;

    int updated = 0;
    char *full_path = get_full_path(f->path_utf8, path);
    struct stat stbuf = { 0 };
    if (!f->op.getattr(path, &stbuf)) {
        CF_PLACEHOLDER_CREATE_INFO placeholder;
        memset(&placeholder, 0, sizeof(CF_PLACEHOLDER_CREATE_INFO));

        wchar_t *wname = fromUTF8(path);
        placeholder.FileIdentity = wname;
        placeholder.FileIdentityLength = (DWORD)(wcslen(wname) * sizeof(wchar_t));
        placeholder.RelativeFileName = fromUTF8(name);

        placeholder.Flags = CF_PLACEHOLDER_CREATE_FLAG_NONE;
        placeholder.Flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;

        if (S_ISDIR(stbuf.st_mode)) {
            placeholder.FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
            placeholder.FsMetadata.FileSize.QuadPart = 0;
            placeholder.Flags |= CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION;
        } else {
            placeholder.FsMetadata.FileSize.QuadPart = stbuf.st_size;
        }

        placeholder.FsMetadata.BasicInfo.CreationTime.QuadPart = LARGE_TIME(stbuf.st_ctime);
        placeholder.FsMetadata.BasicInfo.ChangeTime.QuadPart = LARGE_TIME(stbuf.st_mtime);
        placeholder.FsMetadata.BasicInfo.LastAccessTime.QuadPart = LARGE_TIME(stbuf.st_atime);
        placeholder.FsMetadata.BasicInfo.LastWriteTime.QuadPart = LARGE_TIME(stbuf.st_mtime);

        if ((name) && (name[0] == '.') && (name[1]) && (name[1] != '.'))
            placeholder.FsMetadata.BasicInfo.FileAttributes |= FILE_ATTRIBUTE_HIDDEN;
        else
            placeholder.FsMetadata.BasicInfo.FileAttributes |= FILE_ATTRIBUTE_NORMAL;

        placeholder.FsMetadata.BasicInfo.FileAttributes |= FILE_ATTRIBUTE_ARCHIVE  | 0x2000 | 0x20000;

        HANDLE h;

        wchar_t *full_wname = fromUTF8(full_path);
        HRESULT hr2 = CfOpenFileWithOplock(full_wname, CF_OPEN_FILE_FLAG_NONE, &h);
        DEBUG_HANDLE("CfOpenFileWithOplock", hr2);
        if (!FAILED(hr2)) {
            hr2 = CfUpdatePlaceholder(h, &placeholder.FsMetadata, placeholder.FileIdentity, placeholder.FileIdentityLength, NULL, 0, placeholder.Flags, NULL, NULL);
            DEBUG_HANDLE("CfUpdatePlaceholder", hr2);
            CfCloseHandle(h);

            if (!FAILED(hr2))
                updated = 1;
        }

        free((void *)placeholder.RelativeFileName);
        free(full_wname);
        free(wname);
    }
    free(full_path);
    return updated;
}

void fuse_notify_refresh(struct fuse *f, const char *path) {
    DEBUG_DUMP("Needs refresh %s", path);
    if ((!f) || (!f->ch))
        return;

    if ((!path) || (!path[0])) {
        f->populate_root = 1;
        return;
    }

    int i;

    fuse_lock(f);
    for (i = 0; i < f->len_refresh_paths; i ++) {
        // already in list
        if (!strcmp(f->refresh_paths[i], path)) {
            fuse_unlock(f);
            return;
        }
    }

    char **paths = (char **)realloc(f->refresh_paths, sizeof(char **) * (f->len_refresh_paths + 1));
    if (!paths) {
        DEBUG_NOTE("Error reallocating");
        fuse_unlock(f);
        return;
    }

    f->refresh_paths = paths;
    f->refresh_paths[f->len_refresh_paths ++ ] = strdup(path ? path : "");
    fuse_unlock(f);
}

void fuse_notify_refresh_sync(struct fuse *f, const char *path) {
    DEBUG_DUMP("Needs refresh %s", path);
    if ((!f) || (!f->ch))
        return;

    struct stat st_buf = { 0 };

    if ((f->op.getattr) && (!f->op.getattr(path, &st_buf))) {
        if (S_ISDIR(st_buf.st_mode)) {
            if ((!path) || (!path[0]) || (((path[0] == '/') || (path[0] == '\\')) && (!path[1]))) {
                f->populate_root = 1;
            } else {
                fuse_populate_directory(f, path, 0);
            }
        } else
        if (fuse_update_path(f, path)) {
            DEBUG_DUMP("Fast refreshed %s", path);
            return;
        } else {
            int i;
            int len = strlen(path);
            for (i = len - 1; i >= 0; i --) {
                if ((path[i] == '/') || (path[i] == '\\')) {
                    if (i) {
                        char *path2 = strdup(path);
                        if (path2) {
                            path2[i] = 0;
                            DEBUG_DUMP("Recursive refresh %s (%s)", path2, path);
                            fuse_notify_refresh(f, path2);
                            free(path2);
                        }
                    } else
                        f->populate_root = 1;
                    break;
                }
            }
        }
    } else
        f->populate_root = 1;
}

void fuse_notify_delete(struct fuse *f, const char *path) {
    DEBUG_DUMP("Deleted %s", path);
    if ((!f) || (!f->ch))
        return;

    remove_placeholder(f, path);
}

void fuse_notify_refresh_tree(struct fuse *f) {
    DEBUG_NOTE("Refresh tree");
    if ((!f) || (!f->ch))
        return;

    f->populate_root = 2;
}

struct fuse_chan *fuse_mount(const char *dir, void* args) {
    const char *def_mnt = "defuse";
    if (!dir)
        dir = def_mnt;

    struct fuse_chan *ch = (struct fuse_chan *)malloc(sizeof(struct fuse_chan));
    if (!ch)
        return NULL;

    memset(ch, 0, sizeof(struct fuse_chan));

    CF_SYNC_REGISTRATION CfSyncRegistration = { 0 };
    CfSyncRegistration.StructSize = sizeof(CF_SYNC_REGISTRATION);
    CfSyncRegistration.ProviderName = L"edwork";
    CfSyncRegistration.ProviderVersion = L"1.0";
    CfSyncRegistration.ProviderId = (GUID){ 0x328cd0f9, 0x9f45, 0x4d22, { 0x90, 0x86, 0x73, 0x8a, 0xe5, 0x83, 0x5c, 0x20 } };

    CF_SYNC_POLICIES CfSyncPolicies = { 0 };
    CfSyncPolicies.StructSize = sizeof(CF_SYNC_POLICIES);
    CfSyncPolicies.HardLink = CF_HARDLINK_POLICY_NONE;
    CfSyncPolicies.Hydration.Primary = CF_HYDRATION_POLICY_PROGRESSIVE;
    CfSyncPolicies.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_STREAMING_ALLOWED | CF_HYDRATION_POLICY_MODIFIER_AUTO_DEHYDRATION_ALLOWED;
    CfSyncPolicies.InSync = CF_INSYNC_POLICY_TRACK_FILE_LAST_WRITE_TIME | CF_INSYNC_POLICY_TRACK_DIRECTORY_LAST_WRITE_TIME;
    CfSyncPolicies.Population.Primary = CF_POPULATION_POLICY_FULL;
    CfSyncPolicies.Population.Modifier = CF_POPULATION_POLICY_MODIFIER_NONE;
    CfSyncPolicies.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY_CREATE_UNRESTRICTED | CF_PLACEHOLDER_MANAGEMENT_POLICY_CONVERT_TO_UNRESTRICTED | CF_PLACEHOLDER_MANAGEMENT_POLICY_UPDATE_UNRESTRICTED;

    MultiByteToWideChar(CP_UTF8, 0, dir, (int)strlen(dir), ch->path, MAX_PATH);

    CreateDirectoryW(ch->path, NULL);

    HRESULT hr = CfRegisterSyncRoot(ch->path, &CfSyncRegistration, &CfSyncPolicies, CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT);
    DEBUG_HANDLE("CfRegisterSyncRoot", hr);
    if (FAILED(hr)) {
        CfUnregisterSyncRoot(ch->path);
        RemoveDirectoryW(ch->path);
        free(ch);
        return NULL;
    }

    return ch;
}

static void recursive_create(struct fuse *f, char *path) {
    char *full_path = get_full_path(f->path_utf8, path);
    DEBUG_DUMP("Created %s", full_path);
    int err = -1;
    int is_dir = 0;
    if (GetFileAttributesA(full_path) & FILE_ATTRIBUTE_DIRECTORY) {
        is_dir = 1;
        if (f->op.mkdir) {
            fuse_lock(f);
            err = f->op.mkdir(path, 0666);
            fuse_unlock(f);
            DEBUG_ERRNO("op.mkdir", err);
        }
    } else {
        if (f->op.create) {
            // try create + sync for drag & drop files
            err = fuse_sync_full_sync(f, path, full_path, 1);
            if (err) {
                // fall back to create
                struct fuse_file_info finfo = { 0 };
                fuse_lock(f);
                err = f->op.create(path, 0666, &finfo);
                fuse_unlock(f);
                DEBUG_ERRNO("op.create", errno);
                if ((f->op.release) && (!err)) {
                    fuse_lock(f);
                    f->op.release(path, &finfo);
                    fuse_unlock(f);
                }
            }
        }
    }
    if (!err) {
        fuse_lock(f);
        HANDLE h;
        wchar_t *full_path_w = fromUTF8(full_path);
        HRESULT hr = CfOpenFileWithOplock(full_path_w, CF_OPEN_FILE_FLAG_NONE, &h);
        DEBUG_HANDLE("CfOpenFileWithOplock", hr);
        free(full_path_w);
        if (!FAILED(hr)) {
            wchar_t *wname = fromUTF8(path);
            HRESULT hr2 = CfConvertToPlaceholder(h, wname, wcslen(wname) * sizeof(wchar_t), /* is_dir ? CF_CONVERT_FLAG_ENABLE_ON_DEMAND_POPULATION : */ CF_CONVERT_FLAG_NONE , NULL, NULL);
            DEBUG_HANDLE("CfConvertToPlaceholder", hr2);
            CfCloseHandle(h);
            free(wname);
        }
        fuse_unlock(f);

        if (is_dir) {
            WIN32_FIND_DATA FindFileData;
            int path_len = strlen(full_path);
            char *full_path2 = malloc(path_len + 3);
            if (full_path2) {
                strcpy(full_path2, full_path);
                strcat(full_path2, "\\*");
                DEBUG_DUMP("Scanning %s", full_path2);
                HANDLE hFind = FindFirstFile(full_path2, &FindFileData);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        if ((strcmp(FindFileData.cFileName, ".")) && (strcmp(FindFileData.cFileName, ".."))) {
                            int len = strlen(FindFileData.cFileName);
                            char *file_path = (char *)malloc(path_len + len + 2);
                            if (file_path) {
                                strcpy(file_path, path);
                                strcat(file_path, "/");
                                strcat(file_path, FindFileData.cFileName);

                                recursive_create(f, file_path);

                                free(file_path);
                            }
                        }
                    } while (FindNextFile(hFind, &FindFileData));
                    FindClose(hFind);
                }
                free(full_path2);
            }
        }
    }
    free(full_path);
}

int fuse_loop(struct fuse *f) {
    CF_CALLBACK_REGISTRATION callbackTable[] = {
        { CF_CALLBACK_TYPE_FETCH_DATA, OnFetchData },
        { CF_CALLBACK_TYPE_NOTIFY_FILE_OPEN_COMPLETION, OnFileOpen },
        { CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION, OnFileClose },
        { CF_CALLBACK_TYPE_NOTIFY_DELETE, OnFileDelete },
        { CF_CALLBACK_TYPE_NOTIFY_RENAME, OnFileRename },
        // { CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS, OnFetchPlaceholders },
        { CF_CALLBACK_TYPE_VALIDATE_DATA, OnValidateData },
        { CF_CALLBACK_TYPE_CANCEL_FETCH_DATA, OnCancelFetchData },
        CF_CALLBACK_REGISTRATION_END
    };

    if ((!f) || (!f->ch))
        return -1;

    // watch for modification
    HANDLE dir_handle = CreateFileA(f->path_utf8, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (dir_handle == INVALID_HANDLE_VALUE) {
        HRESULT dir_err = HRESULT_FROM_WIN32(GetLastError());
        DEBUG_HANDLE("CreateFileA", dir_err);
        return -1;
    }

    OVERLAPPED overlapped;
    overlapped.hEvent = CreateEvent(NULL, FALSE, 0, NULL);

    uint8_t change_buf[1024];
    BOOL success = ReadDirectoryChangesW(dir_handle, change_buf, 1024, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE, NULL, &overlapped, NULL);
    DEBUG_DUMP("ReadDirectoryChangesW returned %s", success ? "TRUE" : "FALSE");

    HRESULT hr = CfConnectSyncRoot(f->ch->path, callbackTable, f, CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, &f->s_transferCallbackConnectionKey);
    DEBUG_HANDLE("CfConnectSyncRoot", hr);
    if (FAILED(hr))
        return -1;
    else
        f->running = 1;

    fuse_populate_directory(f, "/", 1);

    while (f->running == 1) {
        DWORD wait_status = WaitForSingleObject(overlapped.hEvent, 100); 

        if (wait_status == WAIT_OBJECT_0) {
            DWORD bytes_transferred;
            GetOverlappedResult(dir_handle, &overlapped, &bytes_transferred, FALSE);
            FILE_NOTIFY_INFORMATION *ev = (FILE_NOTIFY_INFORMATION *)change_buf;

            if (f->running != 1)
                break;

            for (;;) {
                if (ev->Action == FILE_ACTION_ADDED) {
                    char *path = toUTF8_path(ev->FileName, ev->FileNameLength);

                    recursive_create(f, path);

                    free(path);
                } else
                if (ev->Action == FILE_ACTION_MODIFIED) {
                    char *path = toUTF8_path(ev->FileName, ev->FileNameLength);
                    char *full_path = get_full_path(f->path_utf8, path);
                    if (!(GetFileAttributesA(full_path) & FILE_ATTRIBUTE_DIRECTORY)) {
                        HANDLE h;
                        wchar_t *full_path_w = fromUTF8(full_path);

                        fuse_lock(f);

                        HRESULT hr = CfOpenFileWithOplock(full_path_w, CF_OPEN_FILE_FLAG_NONE, &h);
                        free(full_path_w);
                        DEBUG_HANDLE("CfOpenFileWithOplock", hr);
                        if (!FAILED(hr)) {
                            wchar_t *wname = fromUTF8(path);
                            HRESULT hr2 = CfConvertToPlaceholder(h, wname, wcslen(wname) * sizeof(wchar_t), CF_CONVERT_FLAG_MARK_IN_SYNC, NULL, NULL);
                            DEBUG_HANDLE("CfConvertToPlaceholder", hr2);
                            CfCloseHandle(h);
                            free(wname);
                        }

                        fuse_unlock(f);

                        DEBUG_DUMP("Modified %s", full_path);
                        fuse_sync_full_sync(f, path, full_path, 0);
                    }
                    free(full_path);
                    free(path);
                }

                if (ev->NextEntryOffset)
                    *((uint8_t**)&ev) += ev->NextEntryOffset;
                else
                    break;
            }
            ReadDirectoryChangesW(dir_handle, change_buf, 1024, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME, NULL, &overlapped, NULL);
        }

        if (f->refresh_paths) {
            fuse_lock(f);
            char **refresh_paths = f->refresh_paths;
            int len_refresh_paths = f->len_refresh_paths;

            f->refresh_paths = NULL;
            f->len_refresh_paths = 0;

            fuse_unlock(f);

            int i;
            for (i = 0; i < len_refresh_paths; i ++) {
                char *refresh_path = refresh_paths[i];
                fuse_notify_refresh_sync(f, refresh_path);
                free(refresh_path);
            }

            free(refresh_paths);
        }

        if (f->populate_root) {
            fuse_populate_directory(f, "/", (f->populate_root == 2));
            f->populate_root = 0;
        }
    }
    CloseHandle(dir_handle);

    f->running = -1;
    return 0;
}

int fuse_loop_mt(struct fuse *f) {
    return fuse_loop(f);
}

struct fuse *fuse_new(struct fuse_chan *ch, void *args, const struct fuse_operations *op, size_t op_size, void* private_data) {
    DEBUG_NOTE("fuse_new called");

    if (!ch)
        return NULL;

    struct fuse * this_ref = (struct fuse *)malloc(sizeof(struct fuse));
    if (!this_ref) {
        DEBUG_NOTE("malloc failed");
        return NULL;
    }

    memset(this_ref, 0, sizeof(struct fuse));

    if (op)
        this_ref->op = *op;

    if (this_ref->op.init) {
        struct fuse_config cfg = { 0 };
        this_ref->op.init(&this_ref->connection, &cfg);
    }
    this_ref->user_data = private_data;

    if (ch) {
        ch->fs = this_ref;
        this_ref->path_utf8 = toUTF8(ch->path);
    }
    this_ref->ch = ch;
    this_ref->sem = CreateSemaphore(NULL, 1, 0xFFFF, NULL);

    return this_ref;
}

void fuse_unmount(const char *dir, struct fuse_chan *ch) {
    // not implemented
}

int fuse_set_signal_handlers(struct fuse *se) {
    if (!se)
        return -1;

    // not implemented

    return 0;
}

struct fuse *fuse_get_session(struct fuse *f) {
    return f;
}

void fuse_remove_signal_handlers(struct fuse *se) {
    // not implemented
}

void fuse_exit(struct fuse *f) {
    DEBUG_NOTE("fuse_exit called");
    if ((f) && (f->running == 1)) {
        CfDisconnectSyncRoot(f->s_transferCallbackConnectionKey);
        if (f->ch) {
            CfUnregisterSyncRoot(f->ch->path);
            DeleteDirectory(f->ch->path);
        }
        f->running = -1;
    }
}

int fuse_reload(struct fuse *f) {
    DEBUG_NOTE("fuse_reload called");
    if ((!f) || (!f->ch))
        return -1;

    return 0;
}

void fuse_destroy(struct fuse *f) {
    DEBUG_NOTE("fuse_destroy called");
    if (f) {
        if (f->op.destroy)
            f->op.destroy(f->user_data);

        free(f->path_utf8);

        CloseHandle(f->sem);

        int i;
        if (f->refresh_paths) {
            for (i = 0; i < f->len_refresh_paths; i ++)
                free(f->refresh_paths[i]);

            free(f->refresh_paths);
        }
        free(f);
    }
}
