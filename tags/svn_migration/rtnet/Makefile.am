moduledir = $(DESTDIR)@RTNET_MODULE_DIR@

OPTDIRS =

if CONFIG_RTNET_RTCAP
OPTDIRS += rtcap
endif

if CONFIG_RTNET_RTCFG
OPTDIRS += rtcfg
endif

if CONFIG_RTNET_ENCLOSED_RTAI_RTDM
OPTDIRS += rtai_rtdm
endif

if CONFIG_RTNET_EXAMPLES
OPTDIRS += examples
endif

SUBDIRS = driver ethernet ipv4 lib packet rtmac tools include $(OPTDIRS)

noinst_LIBRARIES = librtnet.a

EXTRA_LIBRARIES = libnetproxy.a

librtnet_a_SOURCES = \
	iovec.c \
	rtdev.c \
	rtdev_mgr.c \
	rtnet_chrdev.c \
	rtnet_module.c \
	rtnet_rtpc.c \
	rtnet_syms.c \
	rtskb.c \
	socket.c \
	stack_mgr.c

RTNET_BUILTIN_OBJS = \
	ethernet/eth.o \
	ipv4/ipv4.o \
	lib/crc32.o \
	packet/packet.o

OBJS = rtnet.o

if CONFIG_RTNET_PROXY
libnetproxy_a_SOURCES = rtnetproxy.c
OBJS += rtnetproxy.o
endif

rtnet.o: librtnet.a $(RTNET_BUILTIN_OBJS)
	$(LD) --whole-archive $^ -r -o $@

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	@RTAI_KMOD_CFLAGS@

all-local: $(OBJS)

install-exec-local: $(OBJS)
	$(mkinstalldirs) $(moduledir)
	$(INSTALL_DATA) $^ $(moduledir)
