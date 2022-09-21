extern "C" {
    #include "defuse.h"
}
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

static struct options {
    const char* filename;
    const char* contents;
    int show_help;
} options;

static int hello_getattr(const char* path, struct stat* stbuf) {
    int res = 0;

    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    }
    else if (strcmp(path + 1, options.filename) == 0) {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = (off_t)strlen(options.contents);
    }
    else
        res = -ENOENT;

    return res;
}

static int hello_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi) {
    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, options.filename, NULL, 0);

    return 0;
}

static int hello_open(const char* path, struct fuse_file_info* fi)
{
    if (strcmp(path + 1, options.filename) != 0)
        return -ENOENT;

    return 0;
}

static int hello_read(const char* path, char* buf, size_t size, off_t offset,
    struct fuse_file_info* fi)
{
    size_t len;
    (void)fi;
    if (strcmp(path + 1, options.filename) != 0)
        return -ENOENT;

    len = strlen(options.contents);
    if (offset < len) {
        if (offset + size > len)
            size = len - offset;
        memcpy(buf, options.contents + offset, size);
    }
    else
        size = 0;

    return (int)size;
}

static int hello_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
    return (int)size;
}

int main() {
    struct fuse_chan *ch = fuse_mount("C:\\Users\\Eduard\\source\\repos\\fuse\\x64\\Debug\\hello3", NULL);
    if (ch) {
        struct fuse_operations hello_oper = { 0 };

        hello_oper.getattr = hello_getattr;
        hello_oper.readdir = hello_readdir;
        hello_oper.open = hello_open;
        hello_oper.read = hello_read;
        hello_oper.write = hello_write;

        options.filename = _strdup("hello");
        options.contents = _strdup("Hello World!\n");

        struct fuse* f = fuse_new(ch, NULL, &hello_oper, sizeof(hello_oper), NULL);
        if (f) {
            fuse_loop(f);
        }
    }
    return 0;
}
