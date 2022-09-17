#pragma comment(lib, "CldApi")

#define _CRT_SECURE_NO_WARNINGS

#define _WIN32_WINNT    0x0A00

#include "defuse.h"
#include "khash.h"

#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <WinBase.h>
#include <Unknwn.h>
#include <cfapi.h>
#include <sddl.h>

#ifndef S_ISDIR
    #define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
#endif
#define LARGE_TIME(src) ((unsigned __int64)src)*10000000 + 116444736000000000LL;

#define FIELD_SIZE( type, field ) ( sizeof( ( (type*)0 )->field ) )
#define CF_SIZE_OF_OP_PARAM( field )                                           \
    ( FIELD_OFFSET( CF_OPERATION_PARAMETERS, field ) +                         \
      FIELD_SIZE( CF_OPERATION_PARAMETERS, field ) )

KHASH_MAP_INIT_INT64(guid, void*)

struct fuse_chan {
    wchar_t path[MAX_PATH + 1];
    struct fuse* fs;
};

struct fuse {
    struct fuse_operations op;
    struct fuse_conn_info connection;
    struct fuse_chan* ch;
    void* user_data;
    char* path_utf8;
    CF_CONNECTION_KEY s_transferCallbackConnectionKey;

    khash_t(guid)* guids;
    HANDLE sem;

    char running;
};

static uint64_t guid64(const PCORRELATION_VECTOR vector) {
    if (!vector)
        return 0;

    char *key = (char *)vector->Vector;
    int len = RTL_CORRELATION_VECTOR_STRING_LENGTH;

    uint64_t seed = 0;
    const uint64_t m = 0xc6a4a7935bd1e995LLU;
    const int r = 47;

    uint64_t h = seed ^ (len * m);

    const uint64_t* data = (const uint64_t*)key;
    const uint64_t* end = data + (len / 8);

    while (data != end) {
        uint64_t k = *data++;

        k *= m;
        k ^= k >> r;
        k *= m;

        h ^= k;
        h *= m;
    }

    const unsigned char* data2 = (const unsigned char*)data;

    switch (len & 7) {
    case 7: h ^= ((uint64_t)data2[6]) << 48;
    case 6: h ^= ((uint64_t)data2[5]) << 40;
    case 5: h ^= ((uint64_t)data2[4]) << 32;
    case 4: h ^= ((uint64_t)data2[3]) << 24;
    case 3: h ^= ((uint64_t)data2[2]) << 16;
    case 2: h ^= ((uint64_t)data2[1]) << 8;
    case 1: h ^= ((uint64_t)data2[0]);
        h *= m;
    };

    h ^= h >> r;
    h *= m;
    h ^= h >> r;

    return h;
}

static void *guid_data(struct fuse* f, const PCORRELATION_VECTOR vector) {
    if (!vector)
        return NULL;

    uint64_t hash = guid64(vector);

    void* data = NULL;

    WaitForSingleObject(f->sem, INFINITE);

    khint_t k = kh_get(guid, f->guids, hash);
    if ((k != kh_end(f->guids)) && (kh_exist(f->guids, k)))
        data = kh_val(f->guids, k);

    ReleaseSemaphore(f->sem, 1, NULL);

    return data;
}

static int guid_set_data(struct fuse* f, const PCORRELATION_VECTOR vector, void* data) {
    if (!vector)
        return 0;

    uint64_t hash = guid64(vector);

    int absent;

    WaitForSingleObject(f->sem, INFINITE);

    khint_t k = kh_put(guid, f->guids, hash, &absent);
    kh_value(f->guids, k) = data;

    ReleaseSemaphore(f->sem, 1, NULL);

    return absent;
}

static void *guid_remove_key(struct fuse* f, const PCORRELATION_VECTOR vector) {
    if (!vector)
        return NULL;

    uint64_t hash = guid64(vector);
    void* data = NULL;

    WaitForSingleObject(f->sem, INFINITE);

    khint_t k = kh_get(guid, f->guids, hash);
    if ((k != kh_end(f->guids)) && (kh_exist(f->guids, k))) {
        data = kh_val(f->guids, k);
        kh_del(guid, f->guids, k);
    }

    ReleaseSemaphore(f->sem, 1, NULL);

    return data;
}

static struct fuse_file_info* guid_file_info(struct fuse* f, const PCORRELATION_VECTOR vector) {
    if (!vector)
        return NULL;

    struct fuse_file_info* finfo = (struct fuse_file_info*)guid_data(f, vector);
    if (!finfo) {
        finfo = (struct fuse_file_info*)malloc(sizeof(struct fuse_file_info));
        if (!finfo)
            return NULL;
        memset(finfo, 0, sizeof(struct fuse_file_info));
        guid_set_data(f, vector, finfo);
    }
    return finfo;
}

static char *toUTF8(const wchar_t* src) {
    if (!src)
        return NULL;

    int len = (int)wcslen(src);
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, src, len, 0, 0, NULL, NULL);
    char* buf = (char*)malloc((utf8_len + 1) * sizeof(char));
    if (buf) {
        WideCharToMultiByte(CP_UTF8, 0, src, len, buf, utf8_len, NULL, NULL);
        buf[utf8_len] = 0;
    }
    return buf;
}

static char *toUTF8_path(const wchar_t* src) {
    if ((!src) || (!src[0]))
        return _strdup("/");

    int add_path = 0;
    if (src[0] != '/')
        add_path = 1;
    int len = (int)wcslen(src);
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, src, len, 0, 0, NULL, NULL);
    char* buf = (char*)malloc((utf8_len + add_path + 1) * sizeof(char));
    if (buf) {
        WideCharToMultiByte(CP_UTF8, 0, src, len, buf + add_path, utf8_len, NULL, NULL);
        if (add_path)
            buf[0] = '/';
        buf[utf8_len + add_path] = 0;
    }
    return buf;
}

static wchar_t *fromUTF8(const char* src) {
    if (!src)
        src = "";

    int len = (int)strlen(src);
    int length = MultiByteToWideChar(CP_UTF8, 0, src, len, 0, 0);
    wchar_t* buf = (wchar_t*)malloc((length + 1) * sizeof(wchar_t));
    if (buf) {
        MultiByteToWideChar(CP_UTF8, 0, src, len, buf, length);
        buf[length] = 0;
    }
    return buf;
}

void CALLBACK OnFetchData(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    struct fuse* f = (struct fuse*)callbackInfo->CallbackContext;

    CF_OPERATION_INFO opInfo = { 0 };
    CF_OPERATION_PARAMETERS opParams = { 0 };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
    opInfo.ConnectionKey = callbackInfo->ConnectionKey;
    opInfo.TransferKey = callbackInfo->TransferKey;
    opParams.ParamSize = CF_SIZE_OF_OP_PARAM(TransferData);
    opParams.TransferData.CompletionStatus = STATUS_SUCCESS;
    opParams.TransferData.Offset.QuadPart = 0;
    opParams.TransferData.Length.QuadPart = 0;

    char buf[8192];
    if (f->op.read) {
        size_t size = (size_t)callbackParameters->FetchData.RequiredLength.QuadPart;
        off_t offset = (off_t)callbackParameters->FetchData.RequiredFileOffset.QuadPart;

        if (size > sizeof(buf))
            size = sizeof(buf);

        struct fuse_file_info* finfo = guid_file_info(f, callbackInfo->CorrelationVector);
        char *path = toUTF8_path((wchar_t*)callbackInfo->FileIdentity);
        int err = f->op.read(path, buf, size, offset, finfo);
        free(path);

        if (err < 0) {
            opParams.TransferData.CompletionStatus = NTSTATUS_FROM_WIN32(-err);
        } else {
            opParams.TransferData.Buffer = buf;
            opParams.TransferData.Offset.QuadPart = offset;
            opParams.TransferData.Length.QuadPart = err;
        }
    }

    CfExecute(&opInfo, &opParams);
}

void CALLBACK OnFileOpen(CONST CF_CALLBACK_INFO* callbackInfo, CONST CF_CALLBACK_PARAMETERS* callbackParameters) {
    struct fuse *f = (struct fuse *)callbackInfo->CallbackContext;
    if (f->op.open) {
        char* path = toUTF8_path((wchar_t*)callbackInfo->FileIdentity);

        struct fuse_file_info* finfo = guid_file_info(f, callbackInfo->CorrelationVector);
        f->op.open(path, finfo);
        free(path);
    }
}

static int fuse_sync_full_sync(struct fuse* f, char* path, char *full_path, struct fuse_file_info* finfo) {
    if (!f->op.write)
        return -EACCES;

    int err = 0;

    FILE* local_file = NULL;
    
    
    err = fopen_s(&local_file, full_path, "rb");
    if (!local_file)
        return -EACCES;

    char buffer[8192];
    off_t offset = 0;
    while (!feof(local_file)) {
        size_t bytes = fread(buffer, 1, sizeof(buffer), local_file);
        if (bytes <= 0) {
            if (bytes < 0)
                err = -EIO;
            break;
        }
        off_t written = 0;
        do {
            err = f->op.write(path, buffer + written, bytes - written, offset + written, finfo);
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

    if (f->op.flush)
        f->op.flush(path, finfo);

    if (f->op.fsync)
        f->op.fsync(path, 0, finfo);

    if (f->op.truncate)
        f->op.truncate(path, offset);

    if (f->op.utimens) {
        struct stat st_buf;
        if (!stat(full_path, &st_buf)) {
            struct timespec tv[2];
            tv[0].tv_sec = st_buf.st_atime;
            tv[0].tv_nsec = 0;
            tv[1].tv_sec = st_buf.st_mtime;
            tv[1].tv_nsec = 0;
            f->op.utimens(path, tv);
        }
    }

    return err;
}

void CALLBACK OnFileClose(CONST CF_CALLBACK_INFO* callbackInfo, CONST CF_CALLBACK_PARAMETERS* callbackParameters) {
    struct fuse *f = (struct fuse*)callbackInfo->CallbackContext;

    char *path = toUTF8_path((wchar_t*)callbackInfo->FileIdentity);
    struct fuse_file_info *finfo = (struct fuse_file_info *)guid_remove_key(f, callbackInfo->CorrelationVector);
    if (f->op.release)
        f->op.release(path, finfo);

    HANDLE h;
    HRESULT hr = CfOpenFileWithOplock(callbackInfo->NormalizedPath, CF_OPEN_FILE_FLAG_EXCLUSIVE, &h);
    if (hr == S_OK) {
        LARGE_INTEGER start;
        LARGE_INTEGER len;
        start.QuadPart = 0;
        len.QuadPart = -1;
        hr = CfDehydratePlaceholder(h, start, len, CF_DEHYDRATE_FLAG_NONE, NULL);
        // not in sync
        if (hr == 0x80070179) {
            if (!(callbackParameters->CloseCompletion.Flags & CF_CALLBACK_CLOSE_COMPLETION_FLAG_DELETED)) {
                char* full_path = toUTF8(callbackInfo->NormalizedPath);
                fuse_sync_full_sync(f, path, full_path, finfo);
                free(full_path);
            }
        }
        if (FAILED(hr)) {
            CfCloseHandle(h);

            // reopen file!
            CfOpenFileWithOplock(callbackInfo->NormalizedPath, CF_OPEN_FILE_FLAG_EXCLUSIVE, &h);
            CfSetInSyncState(h, CF_IN_SYNC_STATE_IN_SYNC, CF_SET_IN_SYNC_FLAG_NONE, NULL);
            CfDehydratePlaceholder(h, start, len, CF_DEHYDRATE_FLAG_NONE, NULL);
        }

        CfCloseHandle(h);
    }
    if (finfo)
        free(finfo);
    free(path);
}

void CALLBACK OnFileDelete(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    struct fuse *f = (struct fuse *)callbackInfo->CallbackContext;
    int err = -1;
    char *path;
    if (callbackParameters->Delete.Flags == CF_CALLBACK_DELETE_FLAG_NONE) {
        if (f->op.unlink) {
            path = toUTF8_path((wchar_t*)callbackInfo->FileIdentity);
            err = f->op.unlink(path);
            free(path);
        }
    } else
    if (callbackParameters->Delete.Flags == CF_CALLBACK_DELETE_FLAG_IS_DIRECTORY) {
        if (f->op.rmdir) {
            path = toUTF8_path((wchar_t*)callbackInfo->FileIdentity);
            err = f->op.rmdir(path);
            free(path);
        }
    }

    CF_OPERATION_INFO opInfo = { 0 };
    CF_OPERATION_PARAMETERS opParams = { 0 };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_ACK_DELETE;
    opInfo.ConnectionKey = callbackInfo->ConnectionKey;
    opInfo.TransferKey = callbackInfo->TransferKey;
    opParams.ParamSize = CF_SIZE_OF_OP_PARAM(AckDelete);
    opParams.AckDelete.CompletionStatus = err ? NTSTATUS_FROM_WIN32(-err) : STATUS_SUCCESS;
    opParams.AckDelete.Flags = CF_OPERATION_ACK_DELETE_FLAG_NONE;

    CfExecute(&opInfo, &opParams);
}

void CALLBACK OnFileRename(CONST CF_CALLBACK_INFO *callbackInfo, CONST CF_CALLBACK_PARAMETERS *callbackParameters) {
    struct fuse* f = (struct fuse*)callbackInfo->CallbackContext;
    int err = -1;
    char *path;
    char *path2;
    if (f->op.rename) {
        path = toUTF8_path((wchar_t*)callbackInfo->FileIdentity);
        path2 = toUTF8_path(callbackParameters->Rename.TargetPath);
        err = f->op.rename(path, path2, 0);
        free(path);
        free(path2);
    }

    CF_OPERATION_INFO opInfo = { 0 };
    CF_OPERATION_PARAMETERS opParams = { 0 };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_ACK_RENAME;
    opInfo.ConnectionKey = callbackInfo->ConnectionKey;
    opInfo.TransferKey = callbackInfo->TransferKey;
    opParams.ParamSize = CF_SIZE_OF_OP_PARAM(AckRename);
    opParams.AckRename.CompletionStatus = err ? NTSTATUS_FROM_WIN32(-err) : STATUS_SUCCESS;
    opParams.AckRename.Flags = CF_OPERATION_ACK_RENAME_FLAG_NONE;

    CfExecute(&opInfo, &opParams);
}

static int fuse_fill_dir(void* buf, const char* name, const struct stat* stbuf, off_t off) {
    struct fuse* f = (struct fuse*)((void**)buf)[0];
    CF_PLACEHOLDER_CREATE_INFO **placeholders = (CF_PLACEHOLDER_CREATE_INFO **)((void **)buf)[1];
    unsigned int *placeholders_count = (unsigned int *)((void**)buf)[2];
    struct fuse_file_info* finfo = (struct fuse_file_info*)((void**)buf)[3];
    struct stat stbuf2;
    char* path = (char*)((void**)buf)[4];
    PCWSTR SearchExpression = (PCWSTR)((void**)buf)[5];

    if ((!finfo) || (!f))
        return -EIO;

    if (off < finfo->offset)
        return 0;

    if ((!name) || ((name[0] == '.') && (name[1] == 0)) || ((name[0] == '.') && (name[1] == '.') && (name[2] == 0))) {
        finfo->session_offset++;
        return 0;
    }
    if ((!stbuf) && (f->op.getattr) && (name) && (path) && (path[0])) {
        memset(&stbuf2, 0, sizeof(stbuf2));
        int len_name = (int)strlen(name);
        int len_path = (int)strlen(path);
        char* full_path = (char*)malloc(len_path + len_name + 2);
        if (full_path) {
            memcpy(full_path, path, len_path);
            if (path[len_path - 1] == '/') {
                memcpy(full_path + len_path, name, len_name);
                full_path[len_path + len_name] = 0;
            }
            else {
                memcpy(full_path + len_path + 1, name, len_name);
                full_path[len_path] = '/';
                full_path[len_path + len_name + 1] = 0;
            }
            if (!f->op.getattr(full_path, &stbuf2))
                stbuf = &stbuf2;
            free(full_path);
        }
    }
    CF_PLACEHOLDER_CREATE_INFO *placeholders2 = (CF_PLACEHOLDER_CREATE_INFO *)realloc(*placeholders, sizeof(CF_PLACEHOLDER_CREATE_INFO) * ((*placeholders_count) + 1));
    if (!placeholders2)
        return -ENOMEM;

    *placeholders = placeholders2;

    CF_PLACEHOLDER_CREATE_INFO *placeholder = &placeholders2[*placeholders_count];
    (*placeholders_count) ++;

    memset(placeholder, 0, sizeof(CF_PLACEHOLDER_CREATE_INFO));

    wchar_t* wname = fromUTF8(name);
    placeholder->FileIdentity = wname;
    placeholder->FileIdentityLength = (DWORD)(wcslen(wname) * sizeof(wchar_t));
    placeholder->RelativeFileName = wname;

    placeholder->Flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
    if (stbuf) {
        if (S_ISDIR(stbuf->st_mode))
            placeholder->FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;

        placeholder->FsMetadata.BasicInfo.CreationTime.QuadPart = LARGE_TIME(stbuf->st_ctime);
        placeholder->FsMetadata.BasicInfo.ChangeTime.QuadPart = LARGE_TIME(stbuf->st_mtime);
        placeholder->FsMetadata.BasicInfo.LastAccessTime.QuadPart = LARGE_TIME(stbuf->st_atime);
        placeholder->FsMetadata.BasicInfo.LastWriteTime.QuadPart = LARGE_TIME(stbuf->st_mtime);
        placeholder->FsMetadata.FileSize.QuadPart = stbuf->st_size;

        if ((name) && (name[0] == '.'))
            placeholder->FsMetadata.BasicInfo.FileAttributes |= FILE_ATTRIBUTE_HIDDEN;
        else
            placeholder->FsMetadata.BasicInfo.FileAttributes |= FILE_ATTRIBUTE_NORMAL;
    }

    finfo->session_offset++;

    return 0;
}

void CALLBACK OnFetchPlaceholders(CONST CF_CALLBACK_INFO* callbackInfo, CONST CF_CALLBACK_PARAMETERS* callbackParameters) {
    CF_OPERATION_INFO opInfo = { 0 };
    CF_OPERATION_PARAMETERS opParams = { 0 };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
    opInfo.ConnectionKey = callbackInfo->ConnectionKey;
    opInfo.TransferKey = callbackInfo->TransferKey;
    opParams.ParamSize = CF_SIZE_OF_OP_PARAM(TransferPlaceholders);
    opParams.TransferPlaceholders.CompletionStatus = STATUS_SUCCESS;
    struct fuse *f = (struct fuse*)callbackInfo->CallbackContext;

    CF_PLACEHOLDER_CREATE_INFO *placeholders = NULL;
    unsigned int placeholders_count = 0;

    if (f) {

        struct fuse_file_info fi = { 0 };
        int open_err = 0;
        char *path = toUTF8_path((wchar_t *)callbackInfo->FileIdentity);
        if (f->op.opendir) {
            open_err = f->op.opendir(path, &fi);
            if (open_err)
                opParams.TransferPlaceholders.CompletionStatus = NTSTATUS_FROM_WIN32(-open_err);
        }

        if (!open_err) {
            if (f->op.readdir) {

                void* data[6];
                data[0] = (void*)f;
                data[1] = (void*)&placeholders;
                data[2] = (void*)&placeholders_count;
                data[3] = (void*)&fi;
                data[4] = (void*)path;
                data[5] = (void*)callbackParameters->FetchPlaceholders.Pattern;

                int err = f->op.readdir(path, data, fuse_fill_dir, fi.offset, &fi);
                if (err)
                    opParams.TransferPlaceholders.CompletionStatus = NTSTATUS_FROM_WIN32(-err);

                opParams.TransferPlaceholders.Flags = CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE;
                opParams.TransferPlaceholders.PlaceholderTotalCount.QuadPart = placeholders_count;

                opParams.TransferPlaceholders.PlaceholderCount = placeholders_count;
                opParams.TransferPlaceholders.EntriesProcessed = placeholders_count;
                opParams.TransferPlaceholders.PlaceholderArray = placeholders;
            }

            if ((f->op.releasedir) && (!open_err))
                f->op.releasedir(path, &fi);
        }

        free(path);
    }

    CfExecute(&opInfo, &opParams);

    unsigned int i;
    for (i = 0; i < placeholders_count; i++)
        free((void *)placeholders[i].FileIdentity);
    free(placeholders);
}

struct fuse_chan *fuse_mount(const char *dir, void* args) {
    const char* def_mnt = "gyro";
    if (!dir)
        dir = def_mnt;

    struct fuse_chan* ch = (struct fuse_chan *)malloc(sizeof(struct fuse_chan));
    if (!ch)
        return NULL;

    memset(ch, 0, sizeof(struct fuse_chan));

    CF_SYNC_REGISTRATION CfSyncRegistration = { 0 };
    CfSyncRegistration.StructSize = sizeof(CF_SYNC_REGISTRATION);
    CfSyncRegistration.ProviderName = L"edwork";
    CfSyncRegistration.ProviderVersion = L"1.0";

    CF_SYNC_POLICIES CfSyncPolicies = { 0 };
    CfSyncPolicies.StructSize = sizeof(CF_SYNC_POLICIES);
    CfSyncPolicies.HardLink = CF_HARDLINK_POLICY_NONE;
    CfSyncPolicies.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;
    CfSyncPolicies.InSync = CF_INSYNC_POLICY_TRACK_ALL;
    CfSyncPolicies.Population.Primary = CF_POPULATION_POLICY_PARTIAL;

    MultiByteToWideChar(CP_UTF8, 0, dir, (int)strlen(dir), ch->path, MAX_PATH);

    CreateDirectoryW(ch->path, NULL);

    HRESULT hr = CfRegisterSyncRoot(ch->path, &CfSyncRegistration, &CfSyncPolicies, CF_REGISTER_FLAG_NONE);
    if (FAILED(hr)) {
        CfUnregisterSyncRoot(ch->path);
        RemoveDirectoryW(ch->path);
        free(ch);
        return NULL;
    }

    return ch;
}

int fuse_loop(struct fuse* f) {
    CF_CALLBACK_REGISTRATION callbackTable[] = {
        { CF_CALLBACK_TYPE_FETCH_DATA, OnFetchData },
        { CF_CALLBACK_TYPE_NOTIFY_FILE_OPEN_COMPLETION, OnFileOpen },
        { CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION, OnFileClose },
        { CF_CALLBACK_TYPE_NOTIFY_DELETE, OnFileDelete },
        { CF_CALLBACK_TYPE_NOTIFY_RENAME, OnFileRename },
        { CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS, OnFetchPlaceholders },
        CF_CALLBACK_REGISTRATION_END
    };

    if ((!f) || (!f->ch))
        return -1;

    HRESULT hr = CfConnectSyncRoot(f->ch->path, callbackTable, f, CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, &f->s_transferCallbackConnectionKey);

    if (FAILED(hr))
        return -1;
    else
        f->running = 1;

    while (f->running == 1)
        Sleep(100);

    f->running = -1;
    return 0;
}

int fuse_loop_mt(struct fuse* f) {
    return fuse_loop(f);
}

static int DeleteDirectory(const wchar_t *sPath) {
    HANDLE hFind;
    WIN32_FIND_DATAW FindFileData;

    wchar_t DirPath[MAX_PATH];
    wchar_t FileName[MAX_PATH];

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
            if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!DeleteDirectory(FileName)) {
                    FindClose(hFind);
                    return 0;
                }
                RemoveDirectoryW(FileName);
                wcscpy(FileName, DirPath);
            }
            else {
                if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
                    _wchmod(FileName, _S_IWRITE);
                if (!DeleteFileW(FileName)) {
                    FindClose(hFind);
                    return 0;
                }
                wcscpy(FileName, DirPath);
            }
        }
        else {
            if (GetLastError() == ERROR_NO_MORE_FILES) {
                bSearch = 0;
            }
            else {
                FindClose(hFind);
                return 0;
            }

        }
    }
    FindClose(hFind);

    return RemoveDirectoryW(sPath);
}

struct fuse* fuse_new(struct fuse_chan* ch, void* args, const struct fuse_operations* op, size_t op_size, void* private_data) {
    if (!ch)
        return NULL;

    struct fuse* this_ref = (struct fuse*)malloc(sizeof(struct fuse));
    if (!this_ref)
        return NULL;

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
    this_ref->guids = kh_init(guid);
    this_ref->sem = CreateSemaphore(NULL, 1, 0xFFFF, NULL);

    return this_ref;
}

void fuse_unmount(const char* dir, struct fuse_chan* ch) {
    // not implemented
}

int fuse_set_signal_handlers(struct fuse* se) {
    if (!se)
        return -1;

    // not implemented

    return 0;
}

struct fuse* fuse_get_session(struct fuse* f) {
    return f;
}

void fuse_remove_signal_handlers(struct fuse* se) {
    // not implemented
}

void fuse_exit(struct fuse* f) {
    if ((f) && (f->running == 1)) {
        CfDisconnectSyncRoot(f->s_transferCallbackConnectionKey);
        if (f->ch) {
            CfUnregisterSyncRoot(f->ch->path);
            DeleteDirectory(f->ch->path);
        }
        f->running = -1;
    }
}

int fuse_reload(struct fuse* f) {
    if ((!f) || (!f->ch))
        return -1;

    return 0;
}

void fuse_destroy(struct fuse* f) {
    if (f) {
        if (f->op.init)
            f->op.destroy(f->user_data);

        kh_destroy(guid, f->guids);
        free(f->path_utf8);
        CloseHandle(f->sem);
        free(f);
    }
}
