moduledir = $(DESTDIR)@RTNET_MODULE_DIR@

noinst_LIBRARIES = librtdm.a

nobase_include_HEADERS = rtdm.h rtdm_driver.h

librtdm_a_SOURCES = \
	rtdm.c

AM_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	@RTAI_KMOD_CFLAGS@

rtai_rtdm.o: librtdm.a
	$(LD) --whole-archive $< -r -o $@

all-local: rtai_rtdm.o

install-exec-local: rtai_rtdm.o
	$(mkinstalldirs) $(moduledir)
	$(INSTALL_DATA) $^ $(moduledir)
