noinst_LIBRARIES = libraw_packets.a

libraw_packets_a_SOURCES = raw_packets.c


libraw_packets_a_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	@RTAI_KMOD_CFLAGS@


raw_packets.o: libraw_packets.a
	$(LD) --whole-archive $< -r -o $@

all-local: raw_packets.o
