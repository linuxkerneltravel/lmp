# Generated config
# user can control verbosity similar to kernel builds (e.g., V=1)
ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif
ifeq ($(VERBOSE),1)
  Q =
else
  Q = @
endif
ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
endif


ifeq ($(VERBOSE), 0)
    QUIET_CC       = @echo '    CC       '$@;
    QUIET_CLANG    = @echo '    CLANG    '$@;
    QUIET_LLC      = @echo '    LLC      '$@;
    QUIET_LINK     = @echo '    LINK     '$@;
    QUIET_INSTALL  = @echo '    INSTALL  '$@;
    QUIET_GEN      = @echo '    GEN      '$@;
    QUIET_COPY     = @echo '    COPY     '$@;
endif
PKG_CONFIG:=pkg-config
CC:=gcc
CLANG:=clang
LLC:=llc
BPFTOOL:=bpftool
ARCH_INCLUDES:=-I/usr/include/x86_64-linux-gnu 
SYSTEM_LIBBPF:=n
LDLIBS += -l:libbpf.a
OBJECT_LIBBPF = $(LIB_DIR)/install/lib/libbpf.a
HAVE_ELF:=y
CFLAGS += -DHAVE_ELF
LDLIBS +=  -lelf
HAVE_ZLIB:=y
CFLAGS += -DHAVE_ZLIB
LDLIBS +=  -lz
HAVE_LIBBPF_PERF_BUFFER__CONSUME:=y
SYSTEM_LIBXDP:=y
CFLAGS += 
LDLIBS +=  -lxdp
OBJECT_LIBXDP = 
