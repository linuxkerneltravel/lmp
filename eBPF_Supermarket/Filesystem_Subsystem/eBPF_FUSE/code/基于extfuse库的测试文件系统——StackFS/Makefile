all: StackFS_ll

ifndef EXTFUSE_REPO_PATH
	$(error EXTFUSE_REPO_PATH is not set)
endif

CFLAGS += -D_FILE_OFFSET_BITS=64 -Wall -Werror #-DENABLE_STATS -DDEBUG

STACKFS_LL_SRCS = StackFS_LL.c

STACKFS_LL_CFLAGS = \
	$(shell pkg-config --cflags fuse3) \
	-I$(EXTFUSE_REPO_PATH)/include \
	-I$(EXTFUSE_REPO_PATH)

STACKFS_LL_LDFLAGS = \
	$(shell pkg-config --libs fuse3) \
	-L$(EXTFUSE_REPO_PATH) -lextfuse

# Use '-DUSE_SPLICE=0' for default fuse (no optimizations)
# Use '-DUSE_SPLICE=1' for optimized fuse
# Use '-DCACHE_ENTRY_ATTR' FUSE entry/attr caching enabled
# Use '-DENABLE_EXTFUSE' to enable ExtFUSE
# Use '-DENABLE_EXTFUSE_LOOKUP' to cache lookup replies in the kernel with ExtFUSE
# Use '-DENABLE_EXTFUSE_ATTR' to cache attr replies in the kernel with ExtFUSE

# ExtFUSE enabled, LOOKUP and ATTR requests are cached in the kernel
StackFS_ll: $(STACKFS_LL_SRCS) attr.c lookup.c
	gcc $(CFLAGS) \
		-DUSE_SPLICE=1 \
		-DENABLE_EXTFUSE_LOOKUP \
		-DENABLE_EXTFUSE_ATTR \
		-DENABLE_EXTFUSE \
		$(STACKFS_LL_CFLAGS) $^ \
		$(STACKFS_LL_LDFLAGS) -o $@

clean:
	rm -f StackFS_ll
