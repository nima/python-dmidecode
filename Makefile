#
#	DMI Decode
#	BIOS Decode
#
#	(C) 2000-2002 Alan Cox <alan@redhat.com>
#	(C) 2002-2007 Jean Delvare <khali@linux-fr.org>
#
#	Licensed under the GNU Public License.
#

#. TODO: mtrace, leaks check... etc.

#. Bug in python2.4 PyString_FromFormat that results in not interpreting printf style formatting with %u and %lu.
PY      = $(shell python -V 2>&1 |sed -e 's/.\(ython\) \(2\.[0-9]\)\..*/p\1\2/')
#PY      = python2.5
CC      = gcc

CFLAGS  = -fno-strict-aliasing -D_XOPEN_SOURCE=600
CFLAGS += -W -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-align -Wwrite-strings -Wmissing-prototypes -Winline -Wundef #-Wcast-qual
CFLAGS += -I/usr/include/$(PY)
#.
#CFLAGS += -DBIGENDIAN
#CFLAGS += -DALIGNMENT_WORKAROUND
#.
#. When debugging, disable -O2 and enable -g.
CFLAGS += -g
#CFLAGS += -O2 -DNDEBUG

SOFLAGS = -shared -fPIC

# Pass linker flags here
#LDFLAGS = -I/usr/include/$(PY) -lefence
LDFLAGS = -I/usr/include/$(PY)

DESTDIR =
prefix  = /usr/local
sbindir = $(prefix)/sbin
mandir  = $(prefix)/share/man
man8dir = $(mandir)/man8
docdir  = $(prefix)/share/doc/dmidecode

INSTALL         := install
INSTALL_DATA    := $(INSTALL) -m 644
INSTALL_DIR     := $(INSTALL) -m 755 -d
INSTALL_PROGRAM := $(INSTALL) -m 755
RM              := rm -f

PROGRAMS := dmidecode
PROGRAMS += $(shell test `uname -m 2>/dev/null` != ia64 && echo biosdecode ownership vpddecode)
# BSD make doesn't understand the $(shell) syntax above, it wants the !=
# syntax below. GNU make ignores the line below so in the end both BSD
# make and GNU make are happy.
PROGRAMS != echo dmidecode ; test `uname -m 2>/dev/null` != ia64 && echo biosdecode ownership vpddecode


all : $(PROGRAMS) module

module:
	$(PY) setup.py build



#
# Shared Objects
#

libdmidecode.so: dmidecode.o util.o
	$(CC) $(LDFLAGS) $(SOFLAGS) $< -o $@

#
# Programs
#

dmidecode: dmidecodebin.c dmihelper.o libdmidecode.so dmidecode.o dmiopt.o dmioem.o util.o
	$(CC) $(LDFLAGS) $< -L. -ldmidecode -l$(PY) dmihelper.o dmidecode.o dmiopt.o dmioem.o util.o -o $@

biosdecode : biosdecode.o util.o
	$(CC) $(LDFLAGS) biosdecode.o util.o -o $@

ownership : ownership.o util.o
	$(CC) $(LDFLAGS) ownership.o util.o -o $@

vpddecode : vpddecode.o vpdopt.o util.o
	$(CC) $(LDFLAGS) vpddecode.o vpdopt.o util.o -o $@

#
# Objects
#

dmidecode.o : dmidecode.c version.h types.h util.h config.h dmidecode.h dmiopt.h dmioem.h
	$(CC) $(CFLAGS) -c $< -o $@

dmiopt.o : dmiopt.c config.h types.h util.h dmidecode.h dmiopt.h
	$(CC) $(CFLAGS) -c $< -o $@

dmioem.o : dmioem.c types.h dmidecode.h dmioem.h
	$(CC) $(CFLAGS) -c $< -o $@

biosdecode.o : biosdecode.c version.h types.h util.h config.h
	$(CC) $(CFLAGS) -c $< -o $@

ownership.o : ownership.c version.h types.h util.h config.h
	$(CC) $(CFLAGS) -c $< -o $@

vpddecode.o : vpddecode.c version.h types.h util.h config.h vpdopt.h
	$(CC) $(CFLAGS) -c $< -o $@

vpdopt.o : vpdopt.c config.h util.h vpdopt.h
	$(CC) $(CFLAGS) -c $< -o $@

util.o : util.c types.h util.h config.h
	$(CC) $(CFLAGS) -c $< -o $@

dmihelper.o: dmihelper.c dmihelper.h
	$(CC) $(CFLAGS) -c $< -o $@

#
# Commands
#

strip : $(PROGRAMS)
	strip $(PROGRAMS)

install : install-module install-bin install-man install-doc

uninstall : uninstall-bin uninstall-man uninstall-doc

install-bin : $(PROGRAMS)
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	for program in $(PROGRAMS) ; do \
	$(INSTALL_PROGRAM) $$program $(DESTDIR)$(sbindir) ; done

uninstall-bin :
	for program in $(PROGRAMS) ; do \
	$(RM) $(DESTDIR)$(sbindir)/$$program ; done

install-man :
	$(INSTALL_DIR) $(DESTDIR)$(man8dir)
	for program in $(PROGRAMS) ; do \
	$(INSTALL_DATA) man/$$program.8 $(DESTDIR)$(man8dir) ; done

uninstall-man :
	for program in $(PROGRAMS) ; do \
	$(RM) $(DESTDIR)$(man8dir)/$$program.8

install-module:
	$(PY) setup.py install

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
