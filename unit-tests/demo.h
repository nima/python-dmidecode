#include <Python.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include "libxml_wrap.h"

#include "dmixml.h"

extern PyObject* demo_dump(void);
PyMODINIT_FUNC initdemomodule(void);
PyObject* demo_dump_doc(void);
PyObject* demo_dump_node(void);
