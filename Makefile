#.
#.	DMI Decode Python Module
#.
#.	(C) 2008 Nima Talebi <nima@it.net.au>
#.
#.	Licensed under the GNU Public License v3
#.

PY     := $(shell python -V 2>&1 |sed -e 's/.\(ython\) \(2\.[0-9]\)\..*/p\1\2/')
CC     := gcc
RM     := rm -f
CFLAGS  = -g -D_XOPEN_SOURCE=600
CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-align
CFLAGS += -Wwrite-strings -Wmissing-prototypes -Winline -Wundef #-Wcast-qual
CFLAGS += -pthread -fno-strict-aliasing -DNDEBUG -fPIC
CFLAGS += -I/usr/include/$(PY)
CFLAGS += -O3
#CFLAGS += -DNDEBUG
#CFLAGS += -DBIGENDIAN
#CFLAGS += -DALIGNMENT_WORKAROUND
#LDFLAGS = -lefence
LDFLAGS =
SOFLAGS = -pthread -shared -L/home/nima/dev-room/projects/dmidecode -lutil
SO      = /usr/lib/$(PY)/site-packages/dmidecode.so


###############################################################################
install: build
	$(PY) setup.py install

build:
	$(PY) setup.py build


###############################################################################
SO: libdmidecode.so
	cp $< $@
	nm -u $@

libdmidecode.so: dmihelper.o util.o dmioem.o dmidecode.o dmidecodemodule.o
	$(CC) $(LDFLAGS) $(SOFLAGS) $^ -o $@

dmidecodemodule.o: dmidecodemodule.c
	$(CC) $(CFLAGS) -c -o $@ $<

dmidecode.o: dmidecode.c version.h types.h util.h config.h dmidecode.h dmioem.h
	$(CC) $(CFLAGS) -c -o $@ $<

dmihelper.o: dmihelper.c dmihelper.h
	$(CC) $(CFLAGS) -c -o $@ $<

util.o: util.c types.h util.h config.h
	$(CC) $(CFLAGS) -c -o $@ $<

dmioem.o: dmioem.c types.h dmidecode.h dmioem.h
	$(CC) $(CFLAGS) -c -o $@ $<



###############################################################################
uninstall:
	rm -f $(SO)

clean :
	$(PY) setup.py clean
	-$(RM) *.so *.o core
	-rm -rf build

.PHONY: install clean uninstall module
