#.
#.	DMI Decode Python Extension Module
#.
#.	(C) 2008 Nima Talebi <nima@it.net.au>
#.
#.	Licensed under the GNU Public License v2
#.

PACKAGE := python-dmidecode
PY_VER  := $(shell python -c 'import sys; print "python%d.%d"%sys.version_info[0:2]')
PY      := python$(PY_VER)
SO       = build/lib.linux-$(shell uname -m)-$(PY_VER)/dmidecodemod.so

###############################################################################
.PHONY: build install uninstall clean tarball rpm unit

build: $(PY)-dmidecodemod.so
$(PY)-dmidecodemod.so: $(SO)
	cp $< $@
$(SO):
	$(PY) src/setup.py build

install:
	$(PY) src/setup.py install

uninstall:
	$(PY) src/setup.py uninstall

clean:
	-$(PY) src/setup.py clean --all
	-rm -f *.so lib/*.o core
	-rm -rf build
	-rm -rf rpm
	-rm -rf src/setup_common.py[oc]
	cd unit-tests && $(MAKE) clean

tarball:
	rm -rf $(PACKAGE)-$(VERSION)
	mkdir $(PACKAGE)-$(VERSION)
	cp -r contrib doc examples lib Makefile man README src dmidecode.py redhat.spec $(PACKAGE)-$(VERSION)
	tar -czvf  $(PACKAGE)-$(VERSION).tar.gz  $(PACKAGE)-$(VERSION)

rpm: tarball
	mkdir -p rpm/{BUILD,RPMS,SRPMS,SPECS,SOURCES}
	cp contrib/$(PACKAGE).spec rpm/SPECS
	cp $(PACKAGE)-$(VERSION).tar.gz rpm/SOURCES
	rpmbuild -ba --define "_topdir $(shell pwd)/rpm" rpm/SPECS/$(PACKAGE).spec

unit:
	$(MAKE) -C unit-tests

