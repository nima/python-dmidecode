#.
#.	DMI Decode Python Extension Module
#.
#.	(C) 2008 Nima Talebi <nima@it.net.au>
#.
#.	Licensed under the GNU Public License v2
#.

VERSION := 3.10.6
PY      := $(shell python -V 2>&1 |sed -e 's/.\(ython\) \(2\.[0-9]\)\..*/p\1\2/')
PY_VER  := $(subst python,,$(PY))
PACKAGE := python-dmidecode
SRCSRV  := /var/www/nima/sites/src.autonomy.net.au/pub

CC      := gcc
RM      := rm -f
SRC_D   := src
OBJ_D   := lib
CFLAGS   = -g -D_XOPEN_SOURCE=600
CFLAGS  += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-align
CFLAGS  += -Wwrite-strings -Wmissing-prototypes -Winline -Wundef #-Wcast-qual
CFLAGS  += -pthread -fno-strict-aliasing -DNDEBUG -fPIC
CFLAGS  += -I/usr/include/$(PY)
CFLAGS  += -O3
#CFLAGS += -DNDEBUG
#CFLAGS += -DBIGENDIAN
#CFLAGS += -DALIGNMENT_WORKAROUND
#LDFLAGS = -lefence
LDFLAGS  =
SOFLAGS  = -pthread -shared -L/home/nima/dev-room/projects/dmidecode -lutil
SO       = build/lib.linux-$(shell uname -m)-$(PY_VER)/dmidecode.so

#. Search
vpath %.o $(OBJ_D)
vpath %.c $(SRC_D)
vpath %.h $(SRC_D)
vpath % $(OBJ_D)


###############################################################################
build: $(PY)-dmidecode.so
$(PY)-dmidecode.so: $(SO)
	cp $< $@

build: $(SO)
$(SO):
	$(PY) src/setup.py build

install:
	$(PY) src/setup.py install

uninstall:
	$(PY) src/setup.py uninstall

clean :
	dh_clean
	$(PY) src/setup.py clean
	-$(RM) *.so lib/*.o core
	-rm -rf build .dpkg

tarball:
	rm -rf $(PACKAGE)-$(VERSION)
	mkdir $(PACKAGE)-$(VERSION)
	cp -r contrib doc examples lib Makefile man README src  $(PACKAGE)-$(VERSION)
	tar -czvf  $(PACKAGE)-$(VERSION).tar.gz  $(PACKAGE)-$(VERSION)

rpm:	tarball
	rm -rf rpm
	mkdir -p rpm/{BUILD,RPMS,SRPMS,SPECS,SOURCES}
	cp contrib/$(PACKAGE).spec rpm/SPECS
	cp $(PACKAGE)-$(VERSION).tar.gz rpm/SOURCES
	rpmbuild -ba --define "_topdir $(shell pwd)/rpm" rpm/SPECS/$(PACKAGE).spec

###############################################################################
libdmidecode.so: dmihelper.o util.o dmioem.o dmidecode.o dmidecodemodule.o
	$(CC) $(LDFLAGS) $(SOFLAGS) $^ -o $@

$(OBJ_D)/dmidecodemodule.o: dmidecodemodule.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_D)/dmidecode.o: dmidecode.c version.h types.h util.h config.h dmidecode.h dmioem.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_D)/dmihelper.o: dmihelper.c dmihelper.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_D)/util.o: util.c types.h util.h config.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_D)/dmioem.o: dmioem.c types.h dmidecode.h dmioem.h
	$(CC) $(CFLAGS) -c -o $@ $<



###############################################################################
.PHONY: install clean uninstall build dupload
.PHONY: srcsrv binary source orig.tar.gz all
