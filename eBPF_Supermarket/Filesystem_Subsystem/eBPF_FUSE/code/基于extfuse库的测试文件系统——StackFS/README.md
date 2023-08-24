# Simple StackFS FUSE file system to test ExtFUSE functionality

You need modified [libfuse](https://github.com/extfuse/libfuse/tree/ExtFUSE-1.0) and [extfuse](https://github.com/extfuse/extfuse) library to add ExtFUSE support to StackFS.

```
$ git clone https://github.com/ashishbijlani/StackFS
$ cd StackFS
$ make
$ export LIB_PATH=$HOME/libfuse/lib/.libs:$HOME/extfuse
$ sudo sh -c "LD_LIBRARY_PATH=$LIB_PATH ./StackFS_ll -o max_write=131072 -o writeback_cache -o splice_read -o splice_write -o splice_move -r $ROOT_DIR $MNT_DIR -o allow_other"
```
