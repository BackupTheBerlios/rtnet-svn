ALL_SUB_DIRS	:= 
MOD_SUB_DIRS	:= 
SUB_DIRS	:= 

M_OBJS		+= 8139too-rt.o eepro100-rt.o 3c59x-rt.o loopback-rt.o
MI_OBJS		:=
MIX_OBJS	+= 

EXTRA_CFLAGS	:= -I../lib -I../include -I../rtmac/include

ifdef TOPDIR
include $(TOPDIR)/Rules.make
else
all:
	make -C ../.. modules SUBDIRS=rtnet/driver
clean:
	make -C ../.. subclean SUBDIRS=rtnet/driver
endif



