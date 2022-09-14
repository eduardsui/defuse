#include "gyro_fuse.h"
#include <inttypes.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>

#include <wchar.h>
#include <windows.h>
#include <objbase.h>
#include <projectedfslib.h>

#include "khash.h"

#ifndef S_ISDIR
    #define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
#endif

KHASH_MAP_INIT_INT64(guid, void *)

struct fuse_chan {
    wchar_t path[MAX_PATH + 1];
    struct fuse *fs;
};

struct fuse {
    PRJ_STARTVIRTUALIZING_OPTIONS options;
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT instanceHandle;
    PRJ_CALLBACKS callbacks;
    PRJ_NOTIFICATION_MAPPING notificationMappings[1];
    struct fuse_operations op;
    struct fuse_conn_info connection;
    struct fuse_chan *ch;
    void *user_data;
    char *path_utf8;
    char running;

    khash_t(guid)* guids;
};

static uint64_t guid64(const GUID *guid) {
    char key[sizeof(GUID)];

    memset(key, 0, sizeof(key));
    memcpy(key, &guid->Data1, sizeof(guid->Data1));

    // endianess is not important (same machine)
    int len = sizeof(guid->Data1);
    memcpy(key + len, &guid->Data2, sizeof(guid->Data2));
    len += sizeof(guid->Data2);
    memcpy(key + len, &guid->Data3, sizeof(guid->Data3));
    len += sizeof(guid->Data3);
    memcpy(key + len, guid->Data4, sizeof(guid->Data4));
    len += sizeof(guid->Data4);

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

static void* guid_data(struct fuse* f, const GUID * EnumerationId) {
    if (!EnumerationId)
        return NULL;

    uint64_t hash = guid64(EnumerationId);

    void* data = NULL;
    khint_t k = kh_get(guid, f->guids, hash);
    if ((k != kh_end(f->guids)) && (kh_exist(f->guids, k)))
        data = kh_val(f->guids, k);

    return data;
}

static int guid_set_data(struct fuse* f, const GUID* EnumerationId, void *data) {
    if (!EnumerationId)
        return 0;

    uint64_t hash = guid64(EnumerationId);

    int absent;
    khint_t k = kh_put(guid, f->guids, hash, &absent);
    kh_value(f->guids, k) = data;

    return absent;
}

static void *guid_remove_key(struct fuse* f, const GUID* EnumerationId) {
    if (!EnumerationId)
        return NULL;

    uint64_t hash = guid64(EnumerationId);
    void* data = NULL;
    khint_t k = kh_get(guid, f->guids, hash);
    if ((k != kh_end(f->guids)) && (kh_exist(f->guids, k))) {
        data = kh_val(f->guids, k);
        kh_del(guid, f->guids, k);
    }
    return data;
}

static struct fuse_file_info *guid_file_info(struct fuse* f, const GUID* EnumerationId) {
    if (!EnumerationId)
        return NULL;

    struct fuse_file_info *finfo = (struct fuse_file_info *)guid_data(f, EnumerationId);
    if (!finfo) {
        finfo = (struct fuse_file_info*)malloc(sizeof(struct fuse_file_info));
        if (!finfo)
            return NULL;
        memset(finfo, 0, sizeof(struct fuse_file_info));
        guid_set_data(f, EnumerationId, finfo);
    }
    return finfo;
}

static void guid_close(struct fuse* f, const GUID* EnumerationId) {
    if (!EnumerationId)
        return;

    struct fuse_file_info *finfo = (struct fuse_file_info *)guid_remove_key(f, EnumerationId);
    if (finfo)
        free(finfo);
}

static char* toUTF8(const wchar_t* src) {
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

static char* toUTF8_path(const wchar_t* src) {
    if (!src)
        return NULL;

    int add_path = 0;
    if (src[0] != '/')
        add_path = 1;
    int len = (int)wcslen(src);
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, src, len, 0, 0, NULL, NULL);
    char* buf = (char*)malloc((utf8_len + add_path  + 1) * sizeof(char));
    if (buf) {
        WideCharToMultiByte(CP_UTF8, 0, src, len, buf + add_path, utf8_len, NULL, NULL);
        if (add_path)
            buf[0] = '/';
        buf[utf8_len + add_path] = 0;
    }
    return buf;
}

static wchar_t* fromUTF8(const char* src) {
    if (!src)
        return NULL;

    int len = (int)strlen(src);
    int length = MultiByteToWideChar(CP_UTF8, 0, src, len, 0, 0);
    wchar_t* buf = (wchar_t *)malloc((length + 1) * sizeof(wchar_t));
    if (buf) {
        MultiByteToWideChar(CP_UTF8, 0, src, len, buf, length);
        buf[length] = 0;
    }
    return buf;
}

HRESULT StartDirEnumCallback_C(const PRJ_CALLBACK_DATA* CallbackData, const GUID* EnumerationId) {
    struct fuse* f = (struct fuse*)CallbackData->InstanceContext;
    if (!f)
        return S_FALSE;

    int res = 0;
    if (f->op.opendir) {
        struct fuse_file_info* finfo = guid_file_info(f, EnumerationId);

        char *dir_name = toUTF8(CallbackData->FilePathName);
        res = f->op.opendir(((dir_name) && (dir_name[0])) ? dir_name : "/", finfo);
        free(dir_name);

        if (res < 0)
            res *= -1;
    }

    return HRESULT_FROM_WIN32(res);
}

HRESULT EndDirEnumCallback_C(const PRJ_CALLBACK_DATA* CallbackData, const GUID* EnumerationId) {
    struct fuse* f = (struct fuse*)CallbackData->InstanceContext;
    if (!f)
        return S_FALSE;

    struct fuse_file_info *finfo = (struct fuse_file_info *)guid_remove_key(f, EnumerationId);
    if (f->op.releasedir) {
        char *dir_name = toUTF8(CallbackData->FilePathName);
        f->op.releasedir(((dir_name) && (dir_name[0])) ? dir_name : "/", finfo);
        free(dir_name);
    }

    if (finfo)
       free(finfo);

    return S_OK;
}

static int fuse_fill_dir(void* buf, const char* name, const struct stat* stbuf, off_t off) {
    struct fuse* f = (struct fuse*)((void**)buf)[0];
    PRJ_DIR_ENTRY_BUFFER_HANDLE DirEntryBufferHandle = (PRJ_DIR_ENTRY_BUFFER_HANDLE)((void**)buf)[1];
    PCWSTR SearchExpression = (PCWSTR)((void**)buf)[2];
    struct fuse_file_info* finfo = (struct fuse_file_info*)((void**)buf)[3];
    PRJ_FILE_BASIC_INFO info;
    struct stat stbuf2;
    char *path = (char *)((void**)buf)[4];

    if ((!finfo) || (!f) || (!DirEntryBufferHandle))
        return -EIO;

    if (off < finfo->offset)
        return 0;

    if ((!name) || ((name[0] == '.') && (name[1] == 0)) || ((name[0] == '.') && (name[1] == '.') && (name[2] == 0))) {
        finfo->session_offset ++;
        return 0;
    }

    memset(&info, 0, sizeof(PRJ_FILE_BASIC_INFO));

    if ((!stbuf) && (f->op.getattr) && (name) && (path) && (path[0])) {
        memset(&stbuf2, 0, sizeof(stbuf2));
        int len_name = (int)strlen(name);
        int len_path = (int)strlen(path);
        char *full_path = (char* )malloc(len_path + len_name + 2);
        if (full_path) {
            memcpy(full_path, path, len_path);
            if (path[len_path - 1] == '/') {
                memcpy(full_path + len_path, name, len_name);
                full_path[len_path + len_name] = 0;
            } else {
                memcpy(full_path + len_path + 1, name, len_name);
                full_path[len_path] = '/';
                full_path[len_path + len_name + 1] = 0;
            }
            if (!f->op.getattr(full_path, &stbuf2))
                stbuf = &stbuf2;
            free(full_path);
        }
    }
    if (stbuf) {
        if (S_ISDIR(stbuf->st_mode))
            info.IsDirectory = TRUE;
        info.CreationTime.QuadPart = stbuf->st_ctime;
        info.ChangeTime.QuadPart = stbuf->st_mtime;
        info.LastAccessTime.QuadPart = stbuf->st_atime;
        info.LastWriteTime.QuadPart = stbuf->st_mtime;
        info.FileSize = stbuf->st_size;
    }

    wchar_t* dir = fromUTF8(name);

    HRESULT err = 0;
    if (PrjFileNameMatch(dir, SearchExpression)) {
        err = PrjFillDirEntryBuffer(dir, &info, DirEntryBufferHandle);
        if (FAILED(err)) {
            finfo->failed_buffer = 1;
        } else {
            finfo->session_offset ++;
        }
    }

    free(dir);

    return (int)err;
}

HRESULT GetDirEnumCallback_C(const PRJ_CALLBACK_DATA* CallbackData, const GUID* EnumerationId, PCWSTR SearchExpression, PRJ_DIR_ENTRY_BUFFER_HANDLE DirEntryBufferHandle) {
    struct fuse* f = (struct fuse*)CallbackData->InstanceContext;
    if (!f)
        return S_FALSE;

    int res = ENOENT;
    if (f->op.readdir) {
        struct fuse_file_info* finfo = guid_file_info(f, EnumerationId);

        // important to avoid unnecessary calls to readdir function
        if ((finfo->offset) && (!finfo->failed_buffer))
            return S_OK;

        char *dir_name = toUTF8(CallbackData->FilePathName);

        void* data[5];
        data[0] = (void*)f;
        data[1] = (void *)DirEntryBufferHandle;
        data[2] = (void*)SearchExpression;
        data[3] = (void*)finfo;
        data[4] = (void*)(((dir_name) && (dir_name[0])) ? dir_name : "/");

        res = f->op.readdir((char *)data[4], data, fuse_fill_dir, finfo->offset, finfo);
        free(dir_name);

        finfo->offset = finfo->session_offset;

        if (res < 0)
            res *= -1;
    }
    return HRESULT_FROM_WIN32(res);
}

HRESULT GetPlaceholderInfoCallback_C(const PRJ_CALLBACK_DATA* CallbackData) {
    struct fuse* f = (struct fuse*)CallbackData->InstanceContext;
    if (!f)
        return S_FALSE;

    int res = 0;
    if (f->op.getattr) {
        struct stat st_buf;
        memset(&st_buf, 0, sizeof(st_buf));

        char* path = toUTF8_path(CallbackData->FilePathName);
        res = f->op.getattr(path, &st_buf);
        free(path);

        if (!res) {
            PRJ_PLACEHOLDER_INFO info;
            memset(&info, 0, sizeof(PRJ_PLACEHOLDER_INFO));

            info.FileBasicInfo.ChangeTime.QuadPart = st_buf.st_mtime;
            info.FileBasicInfo.CreationTime.QuadPart = st_buf.st_ctime;
            info.FileBasicInfo.LastAccessTime.QuadPart = st_buf.st_atime;
            info.FileBasicInfo.LastWriteTime.QuadPart = st_buf.st_mtime;
            info.FileBasicInfo.FileSize = st_buf.st_size;

            if (S_ISDIR(st_buf.st_mode))
                info.FileBasicInfo.IsDirectory = TRUE;

            HRESULT hr = PrjWritePlaceholderInfo(f->instanceHandle, CallbackData->FilePathName, &info, sizeof(info));
            if (FAILED(hr)) {
                fprintf(stderr, "FAIL!\n");
            }
        }

        if (res < 0)
            res *= -1;
    }
    return HRESULT_FROM_WIN32(res);
}

HRESULT GetFileDataCallback_C(const PRJ_CALLBACK_DATA* CallbackData, UINT64 ByteOffset, UINT32 Length) {
    struct fuse* f = (struct fuse*)CallbackData->InstanceContext;
    if (!f)
        return S_FALSE;

    int res = ENOENT;

    struct stat st_buf;
    memset(&st_buf, 0, sizeof(st_buf));

    char* path = toUTF8_path(CallbackData->FilePathName);

    int err = 0;

    if ((!err) && (f->op.read)) {
        char* buffer = (char* )PrjAllocateAlignedBuffer(f->instanceHandle, Length);
        if (buffer) {
            err = f->op.read(path, buffer, Length, (off_t)ByteOffset, guid_file_info(f, &CallbackData->DataStreamId));
            if (err > 0)
                PrjWriteFileData(f->instanceHandle, &CallbackData->DataStreamId, buffer, ByteOffset, err);

            PrjFreeAlignedBuffer(buffer);
            if (err > 0)
                err = 0;
        }
    }

    free(path);

    res = err;

    if (res < 0)
        res *= -1;

    return HRESULT_FROM_WIN32(res);
}

static int fuse_sync_full_sync(struct fuse* f, char *path, PCWSTR DestinationFileName, struct fuse_file_info* finfo) {
    if ((!f->op.write) || (!finfo->needs_sync))
        return -EACCES;

    char full_path[4096];
    full_path[0] = 0;

    snprintf(full_path, sizeof(full_path), "%s%s", f->path_utf8, path);
    int err = 0;

    FILE* local_file = fopen(full_path, "rb");
    if (!local_file)
        return -EACCES;

    if (f->op.truncate) {
        err = f->op.truncate(path, 0);
        if (err < 0)
            return err;
    }

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
    fclose(local_file);

    PRJ_UPDATE_FAILURE_CAUSES err_cause = PRJ_UPDATE_FAILURE_CAUSE_NONE;
    PrjDeleteFile(f->instanceHandle, DestinationFileName, PRJ_UPDATE_ALLOW_DIRTY_DATA | PRJ_UPDATE_ALLOW_DIRTY_METADATA | PRJ_UPDATE_ALLOW_READ_ONLY, &err_cause);

    return err;
}

HRESULT NotificationCallback_C(const PRJ_CALLBACK_DATA* CallbackData, BOOLEAN IsDirectory, PRJ_NOTIFICATION NotificationType, PCWSTR DestinationFileName, PRJ_NOTIFICATION_PARAMETERS* NotificationParameters) {
    struct fuse* f = (struct fuse*)CallbackData->InstanceContext;
    if (!f)
        return S_FALSE;

    int ret = EACCES;
    struct fuse_file_info *finfo;
    char* path = NULL;
    int err = 0;

    switch (NotificationType) {
        case PRJ_NOTIFICATION_FILE_OPENED:
            ret = 0;
            if (!IsDirectory) {
                if (f->op.open) {
                    finfo = guid_file_info(f, &CallbackData->DataStreamId);
                    path = toUTF8_path(CallbackData->FilePathName);
                    ret = f->op.open(path, finfo);
                }
            }
            break;
        case PRJ_NOTIFICATION_NEW_FILE_CREATED:
            if (IsDirectory) {
                if (f->op.mkdir) {
                    path = toUTF8_path(CallbackData->FilePathName);
                    ret = f->op.mkdir(path, 0755);
                }
            } else {
                if (f->op.create) {
                    finfo = guid_file_info(f, &CallbackData->DataStreamId);
                    path = toUTF8_path(CallbackData->FilePathName);
                    ret = f->op.create(path, 0755, finfo);
                }
            }
            break;
        case PRJ_NOTIFICATION_FILE_OVERWRITTEN:
            break;
        case PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_NO_MODIFICATION:
        case PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED:            
        case PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_DELETED:
            if (!IsDirectory) {
                path = toUTF8_path(CallbackData->FilePathName);
                finfo = guid_file_info(f, &CallbackData->DataStreamId);
                if ((NotificationType == PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED) || (finfo->needs_sync)) {
                    if (f->op.write)
                        err = fuse_sync_full_sync(f, path, CallbackData->FilePathName, finfo);
                    else
                        err = EACCES;

                }
                if (f->op.release)
                    ret = f->op.release(path, finfo);

                if ((!ret) && (err))
                    ret = err;
                guid_close(f, &CallbackData->DataStreamId);
            }
            // no break on delete to trigger the delete events
            if (NotificationType != PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_DELETED)
                break;
        case PRJ_NOTIFICATION_PRE_DELETE:
            if (IsDirectory) {
                if (f->op.rmdir) {
                    path = toUTF8_path(CallbackData->FilePathName);
                    ret = f->op.rmdir(path);
                }
            } else {
                if (f->op.unlink) {
                    path = toUTF8_path(CallbackData->FilePathName);
                    ret = f->op.unlink(path);
                }
            }
            break;
        case PRJ_NOTIFICATION_PRE_RENAME:
            if (f->op.rename) {
                path = toUTF8_path(CallbackData->FilePathName);
                char *path2 = toUTF8_path(DestinationFileName);
                ret = f->op.rename(path, path2, 0);
                free(path2);
            }
            break;
        case PRJ_NOTIFICATION_PRE_SET_HARDLINK:
            break;
        case PRJ_NOTIFICATION_FILE_RENAMED:
            break;
        case PRJ_NOTIFICATION_HARDLINK_CREATED:
            break;
        case PRJ_NOTIFICATION_FILE_PRE_CONVERT_TO_FULL:
            if (!IsDirectory) {
                finfo = guid_file_info(f, &CallbackData->DataStreamId);
                if (finfo)
                    finfo->needs_sync = 1;
                ret = 0;
            }
            break;
    }
    if (ret < 0)
        ret *= -1;
    if (path)
        free(path);
    return HRESULT_FROM_WIN32(ret);
}

static int VirtualFS_stop(struct fuse* this_ref) {
    if (!this_ref)
        return -1;

    this_ref->running = 0;
    PrjStopVirtualizing(this_ref->instanceHandle);

    return 0;
}

int fuse_enable_service() {
    return system("powershell Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart");
}


struct fuse* fuse_new(struct fuse_chan *ch, void *args, const struct fuse_operations *op, size_t op_size, void *private_data) {
    struct fuse* this_ref = (struct fuse*)malloc(sizeof(struct fuse));
    if (!this_ref)
        return NULL;

    memset(this_ref, 0, sizeof(struct fuse));

    this_ref->notificationMappings[0].NotificationRoot = L"";
    this_ref->notificationMappings[0].NotificationBitMask = PRJ_NOTIFY_FILE_OPENED | PRJ_NOTIFY_NEW_FILE_CREATED | PRJ_NOTIFY_FILE_OVERWRITTEN | PRJ_NOTIFY_PRE_DELETE | PRJ_NOTIFY_PRE_RENAME | PRJ_NOTIFY_PRE_SET_HARDLINK | PRJ_NOTIFY_FILE_RENAMED | PRJ_NOTIFY_HARDLINK_CREATED | PRJ_NOTIFY_FILE_HANDLE_CLOSED_NO_MODIFICATION | PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_MODIFIED | PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_DELETED | PRJ_NOTIFY_FILE_PRE_CONVERT_TO_FULL;

    this_ref->options.NotificationMappings = this_ref->notificationMappings;
    this_ref->options.NotificationMappingsCount = 1;

    this_ref->callbacks.StartDirectoryEnumerationCallback = StartDirEnumCallback_C;
    this_ref->callbacks.EndDirectoryEnumerationCallback = EndDirEnumCallback_C;
    this_ref->callbacks.GetDirectoryEnumerationCallback = GetDirEnumCallback_C;
    this_ref->callbacks.GetPlaceholderInfoCallback = GetPlaceholderInfoCallback_C;
    this_ref->callbacks.GetFileDataCallback = GetFileDataCallback_C;
    this_ref->callbacks.NotificationCallback = NotificationCallback_C;

    if (op)
        this_ref->op = *op;

    if (this_ref->op.init) {
        struct fuse_config cfg = {0};
        this_ref->op.init(&this_ref->connection, &cfg);
    }
    this_ref->guids = kh_init(guid);
    this_ref->user_data = private_data;

    if (ch) {
        ch->fs = this_ref;
        this_ref->path_utf8 = toUTF8(ch->path);
    }
    this_ref->ch = ch;
    return this_ref;
}

struct fuse_chan *fuse_mount(const char *mountpoint, void *args) {
    const char *def_mnt = "gyro";
    if (!mountpoint)
        mountpoint = def_mnt;

    struct fuse_chan *ch = (struct fuse_chan*)malloc(sizeof(struct fuse_chan));
    if (!ch)
        return NULL;

    MultiByteToWideChar(CP_UTF8, 0, mountpoint, (int)strlen(mountpoint), ch->path, MAX_PATH);

    GUID instanceId;
    CreateDirectoryA(mountpoint, NULL);
    if (FAILED(CoCreateGuid(&instanceId))) {
        free(ch);
        return NULL;
    }

    if (FAILED(PrjMarkDirectoryAsPlaceholder(ch->path, NULL, NULL, &instanceId))) {
        free(ch);
        return NULL;
    }

    return ch;
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


int fuse_loop(struct fuse* f) {
    if ((!f) || (!f->ch))
        return -1;

    HRESULT hr = PrjStartVirtualizing(f->ch->path, &f->callbacks, f, &f->options, &f->instanceHandle);
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

void fuse_exit(struct fuse* f) {
    if ((f) && (f->running == 1)) {
        VirtualFS_stop(f);
        f->running = -1;
    }
}

void fuse_destroy(struct fuse* f) {
    if (f) {
        if (f->op.init)
            f->op.destroy(f->user_data);

        kh_destroy(guid, f->guids);
        free(f->path_utf8);
        free(f);
    }
}
