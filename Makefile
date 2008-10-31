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

CFLAGS  = -D_XOPEN_SOURCE=600
CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-align -Wwrite-strings -Wmissing-prototypes -Winline -Wundef #-Wcast-qual
CFLAGS += -pthread -fno-strict-aliasing -DNDEBUG -fPIC
CFLAGS += -I/usr/include/$(PY)
CFLAGS += -g -DNDEBUG
#CFLAGS += -O2 -DNDEBUG
#CFLAGS += -DBIGENDIAN
#CFLAGS += -DALIGNMENT_WORKAROUND


#gcc -D_XOPEN_SOURCE=600 -W -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-align -Wwrite-strings -Wmissing-prototypes -Winline -Wundef -pthread -fno-strict-aliasing -DNDEBUG -fPIC -I/usr/include/python2.4 -L. -g -DNDEBUG -lpython -c -lutil -lpython -o dmidecodemodule.o dmidecodemodule.c *.o
#gcc -pthread -shared -L/home/nima/dev-room/projects/dmidecode -lutil -o build/lib.linux-i686-2.4/dmidecode.so

LDFLAGS = -I/usr/include/$(PY) -lefence

SOFLAGS = -shared -fPIC -L/usr/include/$(PY) -L/home/nima/dev-room/projects/dmidecode -lutil

#
# Shared Objects
#
libdmidecode.so: dmihelper.o util.o dmioem.o dmidecode.o dmidecodemodule.o
	$(CC) $(LDFLAGS) $(SOFLAGS) $^ -o $@
	cp $@ /usr/lib/python2.4/site-packages/dmidecode.so

dmidecodemodule.o: dmidecodemodule.c #dmidecodemodule.h dmihelper.o util.o dmioem.o dmidecode.o
	$(CC) $(CFLAGS) -c -o $@ $< #dmihelper.o util.o dmioem.o dmidecode.o

dmidecode.o: dmidecode.c version.h types.h util.h config.h dmidecode.h dmioem.h
	$(CC) $(CFLAGS) -c -o $@ $<

dmihelper.o: dmihelper.c dmihelper.h
	$(CC) $(CFLAGS) -c -o $@ $<

util.o: util.c types.h util.h config.h
	$(CC) $(CFLAGS) -c -o $@ $<

dmioem.o: dmioem.c types.h dmidecode.h dmioem.h
	$(CC) $(CFLAGS) -c -o $@ $<

dmidecodemodule:
	$(PY) setup.py build

install:
	$(PY) setup.py install

uninstall:

install-doc :
	$(INSTALL_DIR) $(DESTDIR)$(docdir)
	$(INSTALL_DATA) README $(DESTDIR)$(docdir)
	$(INSTALL_DATA) CHANGELOG $(DESTDIR)$(docdir)
	$(INSTALL_DATA) AUTHORS $(DESTDIR)$(docdir)

uninstall-doc :
	$(RM) -r $(DESTDIR)$(docdir)

clean :
	$(PY) setup.py clean
	$(RM) *.so *.o $(PROGRAMS) core
	rm -rf build

.PHONY: install clean module all
