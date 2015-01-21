#. ******* coding:utf-8 AUTOHEADER START v1.2 *******
#. vim: fileencoding=utf-8 syntax=Makefile sw=4 ts=4 et
#.
#. © 2007-2010 Nima Talebi <nima@autonomy.net.au>
#. © 2009-2010 David Sommerseth <davids@redhat.com>
#. © 2002-2008 Jean Delvare <khali@linux-fr.org>
#. © 2000-2002 Alan Cox <alan@redhat.com>
#.
#. This file is part of python-dmidecode.
#.
#.     python-dmidecode is free software: you can redistribute it and/or modify
#.     it under the terms of the GNU General Public License as published by
#.     the Free Software Foundation, either version 2 of the License, or
#.     (at your option) any later version.
#.
#.     python-dmidecode is distributed in the hope that it will be useful,
#.     but WITHOUT ANY WARRANTY; without even the implied warranty of
#.     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#.     GNU General Public License for more details.
#.
#.     You should have received a copy of the GNU General Public License
#.     along with python-dmidecode.  If not, see <http://www.gnu.org/licenses/>.
#.
#. THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
#. WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#. MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
#. EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
#. INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#. LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#. PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#. LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
#. OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
#. ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#.
#. ADAPTED M. STONE & T. PARKER DISCLAIMER: THIS SOFTWARE COULD RESULT IN INJURY
#. AND/OR DEATH, AND AS SUCH, IT SHOULD NOT BE BUILT, INSTALLED OR USED BY ANYONE.
#.
#. $AutoHeaderSerial::20100225                                                 $
#. ******* AUTOHEADER END v1.2 *******

PY_BIN  := python2
VERSION := $(shell cd src;$(PY_BIN) -c "from setup_common import *; print(get_version());")
PACKAGE := python-dmidecode
PY_VER  := $(shell $(PY_BIN) -c 'import sys; print("%d.%d"%sys.version_info[0:2])')
PY_MV   := $(shell echo $(PY_VER) | cut -b 1)
PY      := python$(PY_VER)
SO_PATH := build/lib.linux-$(shell uname -m)-$(PY_VER)
ifeq ($(PY_MV),2)
	SO  := $(SO_PATH)/dmidecodemod.so
else
	SOABI := $(shell $(PY_BIN) -c 'import sysconfig; print(sysconfig.get_config_var("SOABI"))')
	SO  := $(SO_PATH)/dmidecodemod.$(SOABI).so
endif
SHELL	:= /bin/bash

###############################################################################
.PHONY: build dmidump install uninstall clean tarball rpm unit version

all : build dmidump

build: $(PY)-dmidecodemod.so
$(PY)-dmidecodemod.so: $(SO)
	cp $< $@
$(SO):
	$(PY) src/setup.py build

dmidump : src/util.o src/efi.o src/dmilog.o
	$(CC) -o $@ src/dmidump.c $^ -g -Wall -D_DMIDUMP_MAIN_

install:
	$(PY) src/setup.py install

uninstall:
	$(PY) src/setup.py uninstall

clean:
	-$(PY) src/setup.py clean --all
	-rm -f *.so lib/*.o core dmidump src/*.o
	-rm -rf build
	-rm -rf rpm
	-rm -rf src/setup_common.py[oc]
	-rm -rf __pycache__ src/__pycache__
	-rm -rf $(PACKAGE)-$(VERSION) $(PACKAGE)-$(VERSION).tar.gz
	$(MAKE) -C unit-tests clean

tarball:
	rm -rf $(PACKAGE)-$(VERSION)
	mkdir $(PACKAGE)-$(VERSION)
	cp -r contrib doc examples Makefile man README src dmidecode.py unit-tests/ $(PACKAGE)-$(VERSION)
	tar -czvf  $(PACKAGE)-$(VERSION).tar.gz  $(PACKAGE)-$(VERSION)

rpm-prep:
	mkdir -p rpm/{BUILD,RPMS,SRPMS,SPECS,SOURCES}
	cp contrib/$(PACKAGE).spec rpm/SPECS
	cp $(PACKAGE)-$(VERSION).tar.gz rpm/SOURCES

rpm: tarball rpm-prep
	rpmbuild -ba --define "_topdir $(shell pwd)/rpm" rpm/SPECS/$(PACKAGE).spec

rpm-md5: tarball rpm-prep
	rpmbuild-md5 -ba --define "_topdir $(shell pwd)/rpm" rpm/SPECS/$(PACKAGE).spec

unit:
	$(MAKE) -C unit-tests

version:
	@echo "python-dmidecode: $(VERSION)"
	@echo "python version: $(PY_VER) ($(PY))"

conflicts:
	@comm -12 \
	  <(dpkg-deb -c ../../DPKGS/python-dmidecode_$(VERSION)-1_amd64.deb | awk '$$NF!~/\/$$/{print$$NF}'|sort) \
	  <(dpkg-deb -c ../../DPKGS/python-dmidecode-dbg_$(VERSION)-1_amd64.deb | awk '$$NF!~/\/$$/{print$$NF}'|sort)

