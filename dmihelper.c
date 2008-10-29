#include <stdio.h>
#include <strings.h>

#include "dmihelper.h"

dmi_minor* dmiAppendObject(long code, char const *key, const char *format, ...) {
  static dmi_minor* last = NULL;

  //. int minor = code&0x00FF;
  //. int major = code>>8;

  va_list arg;
  va_start(arg, format);

  dmi_minor *o = (dmi_minor *)malloc(sizeof(dmi_minor));
  o->next = last;
  o->id = code;
  o->major = (dmi_codes_major *)&dmiCodesMajor[map_maj[code>>8]];
  o->key = (char *)key;

  if(format != NULL)
    if(vsnprintf(o->value, MAXVAL-1, format, arg) > MAXVAL) {
      free(o);
      o = NULL;
      //. TODO: Make this a python exception.
      printf("dmidecode: Internal (python module) error; Value too long.\n");
    }

  last = o;
  va_end(arg); /* cleanup */

  return o;
}

int dmiSetItem(PyObject* dict, const char *key, const char *format, ...) {
  va_list arg;
  va_start(arg, format);
  char buffer[2048];
  vsprintf(buffer, format, arg);
  va_end(arg);
  //printf("DEBUG: Setting k:%s, f:%s s:%s...", key, format, buffer);
  PyDict_SetItem(dict, PyString_FromString(key), PyString_FromString(buffer));
  //printf("Done.\n");
  return 0;
}


/* NOTE: Decomissioned helper function...
void dmiAppendData(PyObject *pydata, const int count) {
  dmi_minor* last = dmiAppendObject(count, "JUNK", "NODATA");

  const char *id = last->major->id;
  PyObject *_key, *_val;

  PyObject *pymajor = PyDict_New();

  _key = PyString_FromString("code");
  _val = PyInt_FromLong((long)last->major->code);
  PyDict_SetItem(pymajor, _key, _val);
  Py_DECREF(_key);
  Py_DECREF(_val);

  _key = PyString_FromString("id");
  _val = PyString_FromString(last->major->id);
  PyDict_SetItem(pymajor, _key, _val);
  Py_DECREF(_key);
  Py_DECREF(_val);

  _key = PyString_FromString("name");
  _val = PyString_FromString(last->major->desc);
  PyDict_SetItem(pymajor, _key, _val);
  Py_DECREF(_key);
  Py_DECREF(_val);

  PyObject *pyminor = PyDict_New();
  while((last = last->next)) {
    //printf("%d:<%s, %s> | %ld:[%s => %s]\n", last->major->code, last->major->id, last->major->desc, last->id, last->key, last->value);
    _key = PyString_FromString(last->key);
    _val = PyString_FromString(last->value);
    PyDict_SetItem(pyminor, _key, _val);
    Py_DECREF(_key);
    Py_DECREF(_val);
  }
  _key  = PyString_FromString("data");
  PyDict_SetItem(pymajor, _key, pyminor);
  Py_DECREF(_key);
  Py_DECREF(pyminor);

  _key  = PyString_FromString(id);
  PyDict_SetItem(pydata, _key, pymajor);
  Py_DECREF(_key);
  Py_DECREF(pymajor);
}
*/

/* NOTE: Decomissioned helper function...
int catsprintf(char *buf, const char *format, ...) {
  if(format == NULL) {
    bzero(buf, strlen(buf));
    return 0;
  }

  va_list arg; // will point to each unnamed argument in turn
  va_start(arg, format); // point to first element after fmt

  char b[8192];
  int c = vsprintf (b, format, arg);

  strcat(buf, b);
  va_end(arg); // cleanp

  return c;
}
*/
