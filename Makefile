#.
#.	DMI Decode Python Extension Module
#.
#.	(C) 2008 Nima Talebi <nima@it.net.au>
#.
#.	Licensed under the GNU Public License v3
#.

VERSION := 2.10
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
build: dmidecode.so
dmidecode.so: $(SO)
	cp $< $(PY)-$@

.srcsrv: $(SRCSRV)/$(PACKAGE)/$(PACKAGE)_$(VERSION).orig.tar.gz
$(SRCSRV)/$(PACKAGE)/$(PACKAGE)_$(VERSION).orig.tar.gz: ../$(PACKAGE)_$(VERSION).orig.tar.gz
	cp $< $@

.src: ../tarballs/$(PACKAGE)_$(VERSION).orig.tar.gz
../tarballs/$(PACKAGE)_$(VERSION).orig.tar.gz: clean .
	dh_clean
	cd .. && tar czvf tarballs/$(PACKAGE)_$(VERSION).orig.tar.gz \
	  --exclude "*.svn" \
	  --exclude debian \
	  --exclude makefile \
	  --exclude BUILD.Linux \
	  --exclude private \
	  $(PACKAGE)

.dpkg: debian .src
	-rm ../build-area/$(PACKAGE)_$(VERSION)*
	svn-buildpackage -us -uc -rfakeroot -enima@it.net.au
	lintian --verbose  -c ../build-area/$(PACKAGE)_$(VERSION)-1_i386.deb
	lintian --verbose -iI ../build-area/$(PACKAGE)_$(VERSION)-1_i386.changes
	touch $@

$(SO):
	$(PY) src/setup.py build

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
uninstall:
	rm -f $(SO)

clean :
	$(PY) src/setup.py clean
	-$(RM) *.so lib/*.o core
	-rm -rf build .dpkg

.PHONY: install clean uninstall module build
