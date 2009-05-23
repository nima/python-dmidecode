## This one is important to get right ...
## We need to link in the libxml2mod.so file from here
PYLIBDIR := /usr/lib64/python2.5/site-packages
PYLIBDIR := /usr/lib/python-support/python-libxml2/python2.5

# Defaults, should be fine
CFLAGS=-I. $(shell xml2-config --cflags) -g -Wall $(shell python-config --cflags)

LIBS=$(shell xml2-config --libs) -lxml2mod $(shell python-config --libs)
LIBDIR=-L $(PYLIBDIR)

.SUFFIX=.c .o .so

all : test

demomodule.so : demo.o dmixml.o
	@echo "Linking: $@"
	@gcc -fPIC --shared -o $@ $^ $(LIBS) $(LIBDIR)

.c.o :
	@echo "Compiling $<"
	@gcc -fPIC -c $< $(CFLAGS)

test : demomodule.so
	@echo "=========================================="
	@echo " Running proof-of-concept code"
	@echo "=========================================="
	@echo ""
	@python unit

clean :
	rm -f demomodule.so *.{py[oc],o} *~

