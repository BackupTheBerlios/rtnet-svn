noinst_LIBRARIES = libtulip-rt.a

libtulip_rt_a_SOURCES = tulip_core.c \
			eeprom.c \
			interrupt.c \
			media.c \
			timer.c \
			21142.c \
			pnic.c \
			pnic2.c

tulip-rt.o: libtulip-rt.a
	rm -rf .extract && mkdir .extract
	cd .extract && $(AR) x ../$<
	$(LD) -r -o $@ .extract/*.o

all-local: tulip-rt.o