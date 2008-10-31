#include "dmidecodemodule.h"
#include <mcheck.h>

options opt;
static void init(void) {
  /* sanity check */
  if(sizeof(u8)!=1 || sizeof(u16)!=2 || sizeof(u32)!=4 || '\0'!=0)
    fprintf(stderr, "%s: compiler incompatibility\n", "dmidecodemodule");

  opt.devmem = DEFAULT_MEM_DEV;
  opt.dumpfile = NULL;
  opt.flags=0;
  opt.type = NULL;
}


u8 *parse_opt_type(u8 *p, const char *arg) {

  /* Allocate memory on first call only */
  if(p == NULL) {
    if(!(p = (u8 *)calloc(256, sizeof(u8)))) {
      perror("calloc");
      return NULL;
    }
  }

  unsigned int i, j;
  /* First try as a keyword */
  for(i = 0; i < ARRAY_SIZE(opt_type_keyword); i++) {
    if(!strcasecmp(arg, opt_type_keyword[i].keyword)) {
      j = 0;
      while(opt_type_keyword[i].type[j] != 255)
        p[opt_type_keyword[i].type[j++]] = 1;
      return p;
    }
  }

  /* Else try as a number */
  while(*arg != '\0') {
    unsigned long val;
    char *next;

    val = strtoul(arg, &next, 0);
    if(next == arg) {
      fprintf(stderr, "Invalid type keyword: %s\n", arg);
      free(p);
      return NULL;
    }
    if (val > 0xff) {
      fprintf(stderr, "Invalid type number: %lu\n", val);
      free(p);
      return NULL;
    }

    p[val] = 1;
    arg = next;
    while(*arg == ',' || *arg == ' ')
      arg++;
  }

  return p;
}




static PyObject* dmidecode_get(PyObject *self, const char* section) {
  //mtrace();


  /* This is `embedding API', not applicable to this dmidecode module which is `Extending'
  Py_SetProgramName("dmidecode");
  int argc = 3;
  char *argv[4];
  argv[0] = "dmidecode";
  argv[1] = "--type";
  argv[2] = section;
  argv[3] = NULL;
  */

  int ret=0;
  int found=0;
  size_t fp;
  int efi;
  u8 *buf;

  if(sizeof(u8)!=1 || sizeof(u16)!=2 || sizeof(u32)!=4 || '\0'!=0) {
    fprintf(stderr, "%s: compiler incompatibility\n", "dmidecodemodule");
    //exit(255);
    return NULL;
  }

  /* Set default option values */
  opt.devmem = DEFAULT_MEM_DEV;
  opt.flags=0;
  opt.type = NULL;
  opt.type=parse_opt_type(opt.type, section);
  if(opt.type==NULL) return NULL;

  PyObject* pydata = PyDict_New();

  /* First try EFI (ia64, Intel-based Mac) */
  efi = address_from_efi(&fp);
  if(efi == EFI_NOT_FOUND) {
    /* Fallback to memory scan (x86, x86_64) */
    if((buf=mem_chunk(0xF0000, 0x10000, opt.devmem))==NULL) {
      ret = 1;
    } else {
      for(fp=0; fp<=0xFFF0; fp+=16) {
        if(memcmp(buf+fp, "_SM_", 4)==0 && fp<=0xFFE0) {
          if(smbios_decode(buf+fp, opt.devmem, pydata)) found++;
          fp+=16;
        } else if(memcmp(buf+fp, "_DMI_", 5)==0) {
          if(legacy_decode(buf+fp, opt.devmem, pydata)) found++;
        }
      }
    }
  } else if(efi == EFI_NO_SMBIOS) {
    ret = 1;
  } else {
    if((buf=mem_chunk(fp, 0x20, opt.devmem))==NULL) {
      ret = 1;
    } else {
      if(smbios_decode(buf, opt.devmem, pydata)) found++;
    }
    //. TODO: dmiSetItem(pydata, "efi_address", efiAddress);
  }

  if(ret==0) {
    free(buf);

    if(!found)
      dmiSetItem(pydata, "detect", "No SMBIOS nor DMI entry point found, sorry G.");
  }


  free(opt.type);

  /*
  PyObject* raw = PyUnicode_Splitlines(Py_BuildValue("s", buffer), 1);
  int i;
  char* nextLine;
  for(i=0; i<PyList_Size(raw); i++) {
    nextLine = PyString_AS_STRING(PySequence_ITEM(raw, i));
    if(strstr(nextLine, "Handle") != NULL) {
      printf("woohoo!: %s\n", nextLine);
    } else {
      printf(" --> %i %s\n", i, nextLine);
    }
  }*/

  if(ret == 1) return NULL;

  /*
  PyObject* data = PyDict_New();
  PyObject* s = NULL;
  PyObject* d = NULL;
  PyObject* key = NULL;
  while(nextLine != NULL) {
    if(memcmp(nextLine, "Handle", 6) == 0) {
      key = PyInt_FromLong(strtol(nextLine+7, NULL, 16));
      d = PyList_New(0);
      PyDict_SetItem(data, key, d);
    } else if(key) {
      s = Py_BuildValue("s", nextLine);
      PyList_Append(d, s);
    }
    nextLine = strtok(NULL, "\n");
  }
  */

  //muntrace();
  return pydata;
}

static PyObject* dmidecode_get_bios(PyObject *self, PyObject *args) { return dmidecode_get(self, "bios"); }
static PyObject* dmidecode_get_system(PyObject *self, PyObject *args) { return dmidecode_get(self, "system"); }
static PyObject* dmidecode_get_baseboard(PyObject *self, PyObject *args) { return dmidecode_get(self, "baseboard"); }
static PyObject* dmidecode_get_chassis(PyObject *self, PyObject *args) { return dmidecode_get(self, "chassis"); }
static PyObject* dmidecode_get_processor(PyObject *self, PyObject *args) { return dmidecode_get(self, "processor"); }
static PyObject* dmidecode_get_memory(PyObject *self, PyObject *args) { return dmidecode_get(self, "memory"); }
static PyObject* dmidecode_get_cache(PyObject *self, PyObject *args) { return dmidecode_get(self, "cache"); }
static PyObject* dmidecode_get_connector(PyObject *self, PyObject *args) { return dmidecode_get(self, "connector"); }
static PyObject* dmidecode_get_slot(PyObject *self, PyObject *args) { return dmidecode_get(self, "slot"); }
static PyObject* dmidecode_get_type(PyObject *self, PyObject *args) {
  const char *s;
  if(PyArg_ParseTuple(args, "s", &s))
    return dmidecode_get(self, s);
  return Py_None;
}

static PyObject* dmidecode_dump(PyObject *self, PyObject *args) { return Py_False; }
static PyObject* dmidecode_load(PyObject *self, PyObject *args) { return Py_False; }

static PyObject* dmidecode_get_dev(PyObject *self, PyObject *null) {
  if(opt.dumpfile != NULL) return opt.dumpfile;
  else return PyString_FromString(opt.devmem);
}
static PyObject* dmidecode_set_dev(PyObject *self, PyObject *arg)  {
  if(PyString_Check(arg)) {
    if(opt.dumpfile) { Py_DECREF(opt.dumpfile); }
    opt.dumpfile = arg;
    Py_INCREF(opt.dumpfile);
    Py_RETURN_TRUE;
  } else {
    Py_RETURN_FALSE;
  }
  //PyErr_Occurred()
}



PyMethodDef DMIDataMethods[] = {
  { "dump",    dmidecode_dump,    METH_NOARGS, "Dump dmidata to set file" },
  { "load",    dmidecode_load,    METH_NOARGS, "Load dmidata from set file" },
  { "get_dev", dmidecode_get_dev, METH_NOARGS, "Set an alternative memory device file" },
  { "set_dev", dmidecode_set_dev, METH_O,      "Set an alternative memory device file" },

  { "bios",      dmidecode_get_bios,      METH_VARARGS, "BIOS Data" },
  { "system",    dmidecode_get_system,    METH_VARARGS, "System Data" },
  { "baseboard", dmidecode_get_baseboard, METH_VARARGS, "Baseboard Data" },
  { "chassis",   dmidecode_get_chassis,   METH_VARARGS, "Chassis Data" },
  { "processor", dmidecode_get_processor, METH_VARARGS, "Processor Data" },
  { "memory",    dmidecode_get_memory,    METH_VARARGS, "Memory Data" },
  { "cache",     dmidecode_get_cache,     METH_VARARGS, "Cache Data" },
  { "connector", dmidecode_get_connector, METH_VARARGS, "Connector Data" },
  { "slot",      dmidecode_get_slot,      METH_VARARGS, "Slot Data" },
  { "type",      dmidecode_get_type,      METH_VARARGS, "By Type" },
  { NULL, NULL, 0, NULL }
};


PyMODINIT_FUNC initdmidecode(void) {
  init();
  (void) Py_InitModule("dmidecode", DMIDataMethods);
}
