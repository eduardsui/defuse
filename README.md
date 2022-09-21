# defuse
Single C-file library mapping basic fuse APIs over Cloud Filter API (cfapi).

This library was written for one of my projects(edwork).

# Usage
Just add `defuse.c` and `defuse.h` to your fuse project and `#include "defuse.h"` instead of `fuse.h`.

# Implemented callbacks
`defuse` implements some (but not all) of the `fus`e callbacks:

`statfs`, `open`, `opendir`, `create`, `mkdir`, `read`, `write`, `truncate`, `readdir`, `unlink`, `rmdir`, `release`, `releasedir`, `rename`, `getattr`, `flush`, `fsync`, `utimens`, `init`, `destroy`

# Notes
I personally prefer `gcc` and `clang` compilers. It also compiles with msvc. For MinGW distribuion, you need `cfapi.h`.
