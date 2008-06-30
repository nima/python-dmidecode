#include "dmidecodemodule.h"

static PyObject* dmidecode_get(PyObject *self, PyObject *args) {
  PyObject *list = PyList_New(0);

  //const char *command;
  //if(!PyArg_ParseTuple(args, "s", &command))
  //  return NULL;

  //for(i=0; i<len(args); i++)
  //  PyList_Append(list, Py_BuildValue("s", args[i]));
  PyList_Append(list, PyInt_FromLong(3));
  PyList_Append(list, PyInt_FromLong(4));
  //PyList_Append(list, Py_BuildValue("s", command));
  PyList_Append(list, Py_BuildValue("i", PySequence_Size(args)));

  int i;
  int argc = PySequence_Size(args);
  char *argv[argc];
  for(i=0; i<argc; i++) {
    argv[i] = PyString_AS_STRING(PySequence_ITEM(args, i));
    printf(">> %s <<\n", argv[i]);
    PyList_Append(list, PySequence_ITEM(args, i));
  }
  bzero(buffer, 50000);
  //submain(buffer, argc, argv);

  return list;
}

PyMethodDef DMIDataMethods[] = {
  { "dmidecode", dmidecode_get, METH_VARARGS, "Get hardware data as a list" },
  { NULL, NULL, 0, NULL }
};


PyMODINIT_FUNC initdmidecode(void) {
  (void) Py_InitModule("dmidecode", DMIDataMethods);
}


int submain(char* buffer, int argc, char * const argv[])
{
        int ret=0;                  /* Returned value */
	int found=0;
	size_t fp;
	int efi;
	u8 *buf;

	if(sizeof(u8)!=1 || sizeof(u16)!=2 || sizeof(u32)!=4 || '\0'!=0)
	{
		fprintf(stderr, "%s: compiler incompatibility\n", argv[0]);
		exit(255);
	}

	/* Set default option values */
	opt.devmem=DEFAULT_MEM_DEV;
	opt.flags=0;

	if(parse_command_line(argc, argv)<0)
	{
		ret=2;
		goto exit_free;
	}

	if(opt.flags & FLAG_HELP)
	{
		print_help();
		goto exit_free;
	}

	if(opt.flags & FLAG_VERSION)
	{
		printf("%s\n", VERSION);
		goto exit_free;
	}

	if(!(opt.flags & FLAG_QUIET))
		printf("# dmidecode %s\n", VERSION);

	/* First try EFI (ia64, Intel-based Mac) */
	efi=address_from_efi(&fp);
	switch(efi)
	{
		case EFI_NOT_FOUND:
			goto memory_scan;
		case EFI_NO_SMBIOS:
			ret=1;
			goto exit_free;
	}

	if((buf=mem_chunk(fp, 0x20, opt.devmem))==NULL)
	{
		ret=1;
		goto exit_free;
	}

	if(smbios_decode(buf, opt.devmem))
		found++;
	goto done;

memory_scan:
	/* Fallback to memory scan (x86, x86_64) */
	if((buf=mem_chunk(0xF0000, 0x10000, opt.devmem))==NULL)
	{
		ret=1;
		goto exit_free;
	}

	for(fp=0; fp<=0xFFF0; fp+=16)
	{
		if(memcmp(buf+fp, "_SM_", 4)==0 && fp<=0xFFE0)
		{
			if(smbios_decode(buf+fp, opt.devmem))
				found++;
			fp+=16;
		}
		else if(memcmp(buf+fp, "_DMI_", 5)==0)
		{
			if (legacy_decode(buf+fp, opt.devmem))
				found++;
		}
	}

done:
	free(buf);

	if(!found && !(opt.flags & FLAG_QUIET))
		printf("# No SMBIOS nor DMI entry point found, sorry.\n");

exit_free:
	free(opt.type);

        printf("%s\n", buffer);
	return ret;
}
