subdirs		= tulip

noinst_LIBRARIES = lib3c59x-rt.a lib8139too-rt.a libeepro100-rt.a

lib3c59x_rt_a_SOURCES = 3c59x-rt.c

lib8139too_rt_a_SOURCES = 8139too-rt.c

libeepro100_rt_a_SOURCES = eepro100-rt.c

INCLUDES = \
	@RTAI_KMOD_CFLAGS@ \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib

all-local: 3c59x-rt.o 8139too-rt.o eepro100-rt.o
