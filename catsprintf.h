#ifndef CAT
#define CAT 1

#include <Python.h>

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define MAXVAL 1024

typedef struct _dmi_codes_major {
  const unsigned short code;
  const char *id;
  const char *desc;
} dmi_codes_major;

typedef struct _dmi_minor {
  long id;
  dmi_codes_major* major;
  char *key;
  char value[MAXVAL];
  struct _dmi_minor* next;
} dmi_minor;

int catsprintf(char *buf, const char *format, ...);
dmi_minor* dmiAppendObject(long code, char const *key, const char *format, ...);
int dmiSetItem(PyObject* dict, const char *key, const char *format, ...);

#endif
