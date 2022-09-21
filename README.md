# defuse
Single C-file library mapping basic fuse APIs(somehow compatible with libfuse) over Cloud Filter API (cfapi).

This library was written for one of my projects(edwork).

The reason for writting this is that unlinke the two implementations of FUSE for Microsoft Windows that I am aware of (Dokan and WinFSP), `defuse` doesn't have any dependencies and doesn't require any driver installation or superuser privileges. In a nutshell defuse is fuse over Win32 APIs. Also, this code has no license restrictions (public domain).


# Usage
Just add `defuse.c` and `defuse.h` to your fuse project and `#include "defuse.h"` instead of `fuse.h`.

# Implemented callbacks
`defuse` implements some (but not all) of the `fuse` callbacks:

`statfs`, `open`, `opendir`, `create`, `mkdir`, `read`, `write`, `truncate`, `readdir`, `unlink`, `rmdir`, `release`, `releasedir`, `rename`, `getattr`, `flush`, `fsync`, `utimens`, `init`, `destroy`

# Notes
I personally prefer `gcc` and `clang` compilers. It also compiles with msvc. For MinGW distribuion, you need a modified to be able to compile. The modified `cfapi.h` is avaiable in `mingw/include`.
