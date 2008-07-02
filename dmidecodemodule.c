#include "dmidecodemodule.h"

static PyObject* dmidecode_get(PyObject *self, char* section) {
  bzero(buffer, 50000);

  //Py_Initialize();
  //if(!Py_IsInitialized())
  //  return NULL;

  /*
  int argc = 3;
  char *argv[4];
  argv[0] = "dmidecode";
  argv[1] = "--type";
  argv[2] = section;
  argv[3] = NULL;
  */

  int ret=0;                  /* Returned value */
  int found=0;
  size_t fp;
  int efi;
  u8 *buf;

  if(sizeof(u8)!=1 || sizeof(u16)!=2 || sizeof(u32)!=4 || '\0'!=0) {
    fprintf(stderr, "%s: compiler incompatibility\n", "dmidecodemodule");
    exit(255);
  }

  /* Set default option values */
  opt.devmem = DEFAULT_MEM_DEV;
  opt.flags=0;
  opt.type = NULL;
  opt.type=parse_opt_type(opt.type, section);
  if(opt.type==NULL) return -1;

  /* First try EFI (ia64, Intel-based Mac) */
  efi = address_from_efi(&fp);
  switch(efi) {
    case EFI_NOT_FOUND:
      //. XXX
      goto memory_scan;
    case EFI_NO_SMBIOS:
      ret = 1;
      goto exit_free;
  }

  if((buf=mem_chunk(fp, 0x20, opt.devmem))==NULL) {
    ret = 1;
    goto exit_free;
  }

  if(smbios_decode(buf, opt.devmem)) found++;

  goto done;

memory_scan:
  /* Fallback to memory scan (x86, x86_64) */
  if((buf=mem_chunk(0xF0000, 0x10000, opt.devmem))==NULL) {
    ret = 1;
    goto exit_free;
  }

  for(fp=0; fp<=0xFFF0; fp+=16) {
    if(memcmp(buf+fp, "_SM_", 4)==0 && fp<=0xFFE0) {
      if(smbios_decode(buf+fp, opt.devmem)) found++;
      fp+=16;
    } else if(memcmp(buf+fp, "_DMI_", 5)==0) {
      if(legacy_decode(buf+fp, opt.devmem)) found++;
    }
  }

done:
  free(buf);

  if(!found && !(opt.flags & FLAG_QUIET))
    catsprintf(buffer, -1, "# No SMBIOS nor DMI entry point found, sorry.\n");

exit_free:
  //Py_Finalize();

  //. FIXME: Why does this cause crash?
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

  PyObject* data = PyDict_New();

  char *nextLine = strtok(buffer, "\n");
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

  return data;
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

PyMethodDef DMIDataMethods[] = {
  { "bios", dmidecode_get_bios, METH_VARARGS, "BIOS Data" },
  { "system", dmidecode_get_system, METH_VARARGS, "System Data" },
  { "baseboard", dmidecode_get_baseboard, METH_VARARGS, "Baseboard Data" },
  { "chassis", dmidecode_get_chassis, METH_VARARGS, "Chassis Data" },
  { "processor", dmidecode_get_processor, METH_VARARGS, "Processor Data" },
  { "memory", dmidecode_get_memory, METH_VARARGS, "Memory Data" },
  { "cache", dmidecode_get_cache, METH_VARARGS, "Cache Data" },
  { "connector", dmidecode_get_connector, METH_VARARGS, "Connector Data" },
  { "slot", dmidecode_get_slot, METH_VARARGS, "Slot Data" },
  { NULL, NULL, 0, NULL }
};


PyMODINIT_FUNC initdmidecode(void) {
  (void) Py_InitModule("dmidecode", DMIDataMethods);
}


/*
static PyObject* dmidecode_xget(PyObject *self, PyObject *args) {
  bzero(buffer, 50000);

  PyObject *list = PyList_New(0);

  //const char *command;
  //if(!PyArg_ParseTuple(args, "s", &command))
  //  return NULL;

  //for(i=0; i<len(args); i++)
  //  PyList_Append(list, Py_BuildValue("s", args[i]));
  //  PyList_Append(list, PyInt_FromLong(3));
  //  PyList_Append(list, PyInt_FromLong(4));
  //PyList_Append(list, Py_BuildValue("s", command));

  int i;
  int argc = PySequence_Size(args) + 1; //. 1 for $0, 1 for trailing NULL
  char *argv[argc+1];
  argv[0] = "dmidecode";
  for(i=1; i<argc; i++) {
    argv[i] = PyString_AS_STRING(PySequence_ITEM(args, i-1));
    PyList_Append(list, PySequence_ITEM(args, i-1));
  }
  argv[argc] = NULL;

  for(i=0; i<argc; i++) printf(">>> %d: %s\n", i, argv[i]);
  submain(buffer, argc, argv);
  PyList_Append(list, PyUnicode_Splitlines(Py_BuildValue("s", buffer), 1));

  //PyList_Append(list, PySequence_List(args));
  //PyList_Append(list, Py_BuildValue("i", PySequence_Size(args)));

  return list;
}
*/
