#include "dmidecodemodule.h"
#include <mcheck.h>

options opt;
static void init(void)
{
        /* sanity check */
        if(sizeof(u8) != 1 || sizeof(u16) != 2 || sizeof(u32) != 4 || '\0' != 0)
                fprintf(stderr, "%s: compiler incompatibility\n", "dmidecodemodule");

        opt.devmem = DEFAULT_MEM_DEV;
        opt.dumpfile = NULL;
        opt.flags = 0;
        opt.type = NULL;
}

u8 *parse_opt_type(u8 * p, const char *arg)
{

        /* Allocate memory on first call only */
        if(p == NULL) {
                if(!(p = (u8 *) calloc(256, sizeof(u8)))) {
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
                if(val > 0xff) {
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

static int dmidecode_set_version(PyObject ** pydata)
{
        int ret = 0;
        int found = 0;
        size_t fp;
        int efi;
        u8 *buf;

        /* Set default option values */
        opt.devmem = DEFAULT_MEM_DEV;

  /***********************************/
        /* Read from dump if so instructed */
        if(opt.dumpfile != NULL) {
                const char *dumpfile = PyString_AS_STRING(opt.dumpfile);

                //. printf("Reading SMBIOS/DMI data from file %s.\n", dumpfile);
                if((buf = mem_chunk(0, 0x20, dumpfile)) != NULL) {
                        if(memcmp(buf, "_SM_", 4) == 0) {
                                if(smbios_decode_set_version(buf, dumpfile, pydata))
                                        found++;
                        } else if(memcmp(buf, "_DMI_", 5) == 0) {
                                if(legacy_decode_set_version(buf, dumpfile, pydata))
                                        found++;
                        }
                } else
                        ret = 1;
        } else {                /* Read from /dev/mem */
                /* First try EFI (ia64, Intel-based Mac) */
                efi = address_from_efi(&fp);
                if(efi == EFI_NOT_FOUND) {
                        /* Fallback to memory scan (x86, x86_64) */
                        if((buf = mem_chunk(0xF0000, 0x10000, opt.devmem)) != NULL) {
                                for(fp = 0; fp <= 0xFFF0; fp += 16) {
                                        if(memcmp(buf + fp, "_SM_", 4) == 0 && fp <= 0xFFE0) {
                                                if(smbios_decode_set_version
                                                   (buf + fp, opt.devmem, pydata))
                                                        found++;
                                                fp += 16;
                                        } else if(memcmp(buf + fp, "_DMI_", 5) == 0) {
                                                if(legacy_decode_set_version
                                                   (buf + fp, opt.devmem, pydata))
                                                        found++;
                                        }
                                }
                        } else
                                ret = 1;
                } else if(efi == EFI_NO_SMBIOS) {
                        ret = 1;
                } else {
                        if((buf = mem_chunk(fp, 0x20, opt.devmem)) == NULL)
                                ret = 1;
                        else if(smbios_decode_set_version(buf, opt.devmem, pydata))
                                found++;
                        //. TODO: dmixml_AddAttribute(dmixml_n, "efi_address", efiAddress);
                }
        }

        if(ret == 0) {
                free(buf);
                if(!found) {
                        fprintf(stderr, "No SMBIOS nor DMI entry point found, sorry G.");
                }
        }
        free(opt.type);
        return ret;
}

static PyObject *dmidecode_get(PyObject * self, const char *section)
{
        //mtrace();

        int ret = 0;
        int found = 0;
        size_t fp;
        int efi;
        u8 *buf;

        /* Set default option values */
        opt.devmem = DEFAULT_MEM_DEV;
        opt.flags = 0;
        opt.type = NULL;
        opt.type = parse_opt_type(opt.type, section);
        if(opt.type == NULL)
                return NULL;

        const char *f = opt.dumpfile ? PyString_AsString(opt.dumpfile) : opt.devmem;

        if(access(f, R_OK) < 0)
                PyErr_SetString(PyExc_IOError, "Permission denied to memory file/device");

        PyObject *pydata = NULL;
        xmlNode *dmixml_n = xmlNewNode(NULL, (xmlChar *) "dmidecode");
        assert( dmixml != NULL );

  /***********************************/
        /* Read from dump if so instructed */
        if(opt.dumpfile != NULL) {
                const char *dumpfile = PyString_AS_STRING(opt.dumpfile);

                //. printf("Reading SMBIOS/DMI data from file %s.\n", dumpfile);
                if((buf = mem_chunk(0, 0x20, dumpfile)) != NULL) {
                        if(memcmp(buf, "_SM_", 4) == 0) {
                                if(smbios_decode(buf, dumpfile, dmixml_n))
                                        found++;
                        } else if(memcmp(buf, "_DMI_", 5) == 0) {
                                if(legacy_decode(buf, dumpfile, dmixml_n))
                                        found++;
                        }
                } else
                        ret = 1;
        } else {                /* Read from /dev/mem */
                /* First try EFI (ia64, Intel-based Mac) */
                efi = address_from_efi(&fp);
                if(efi == EFI_NOT_FOUND) {
                        /* Fallback to memory scan (x86, x86_64) */
                        if((buf = mem_chunk(0xF0000, 0x10000, opt.devmem)) != NULL) {
                                for(fp = 0; fp <= 0xFFF0; fp += 16) {
                                        if(memcmp(buf + fp, "_SM_", 4) == 0 && fp <= 0xFFE0) {
                                                if(smbios_decode(buf + fp, opt.devmem, dmixml_n)) {
                                                        found++;
                                                        fp += 16;
                                                }
                                        } else if(memcmp(buf + fp, "_DMI_", 5) == 0) {
                                                if(legacy_decode(buf + fp, opt.devmem, dmixml_n))
                                                        found++;
                                        }
                                }
                        } else
                                ret = 1;
                } else if(efi == EFI_NO_SMBIOS) {
                        ret = 1;
                } else {
                        if((buf = mem_chunk(fp, 0x20, opt.devmem)) == NULL)
                                ret = 1;
                        else if(smbios_decode(buf, opt.devmem, dmixml_n))
                                found++;
                        //. TODO: dmiSetItem(pydata, "efi_address", efiAddress);
                }
        }

        free(opt.type);
        if(ret == 0) {
                free(buf);
        } else {
                xmlFreeNode(dmixml_n);
                if( pydata != NULL ) {
                        PyDECREF(pydata);
                        pydata = NULL;
                }
        }

        //muntrace();
        return pydata;
}

static PyObject *dmidecode_get_bios(PyObject * self, PyObject * args)
{
        return dmidecode_get(self, "bios");
}
static PyObject *dmidecode_get_system(PyObject * self, PyObject * args)
{
        return dmidecode_get(self, "system");
}
static PyObject *dmidecode_get_baseboard(PyObject * self, PyObject * args)
{
        return dmidecode_get(self, "baseboard");
}
static PyObject *dmidecode_get_chassis(PyObject * self, PyObject * args)
{
        return dmidecode_get(self, "chassis");
}
static PyObject *dmidecode_get_processor(PyObject * self, PyObject * args)
{
        return dmidecode_get(self, "processor");
}
static PyObject *dmidecode_get_memory(PyObject * self, PyObject * args)
{
        return dmidecode_get(self, "memory");
}
static PyObject *dmidecode_get_cache(PyObject * self, PyObject * args)
{
        return dmidecode_get(self, "cache");
}
static PyObject *dmidecode_get_connector(PyObject * self, PyObject * args)
{
        return dmidecode_get(self, "connector");
}
static PyObject *dmidecode_get_slot(PyObject * self, PyObject * args)
{
        return dmidecode_get(self, "slot");
}
static PyObject *dmidecode_get_type(PyObject * self, PyObject * args)
{
        long unsigned int lu;

        if(PyArg_ParseTuple(args, (char *)"i", &lu)) {
                if(lu < 256) {
                        char s[8];

                        sprintf(s, "%lu", lu);
                        return dmidecode_get(self, s);
                }
                return Py_False;
        }
        return Py_None;
}

static PyObject *dmidecode_dump(PyObject * self, PyObject * null)
{
        const char *f;

        f = opt.dumpfile ? PyString_AsString(opt.dumpfile) : opt.devmem;
        struct stat _buf;

        stat(f, &_buf);

        if((access(f, F_OK) != 0) || ((access(f, W_OK) == 0) && S_ISREG(_buf.st_mode)))
                if(dump(PyString_AS_STRING(opt.dumpfile)))
                        Py_RETURN_TRUE;
        Py_RETURN_FALSE;
}

static PyObject *dmidecode_get_dev(PyObject * self, PyObject * null)
{
        PyObject *dev;

        if(opt.dumpfile != NULL)
                dev = opt.dumpfile;
        else
                dev = PyString_FromString(opt.devmem);
        Py_INCREF(dev);
        return dev;
}

static PyObject *dmidecode_set_dev(PyObject * self, PyObject * arg)
{
        if(PyString_Check(arg)) {
                if(opt.dumpfile == arg)
                        Py_RETURN_TRUE;

                struct stat buf;
                char *f = PyString_AsString(arg);

                stat(f, &buf);
                if(opt.dumpfile) {
                        Py_DECREF(opt.dumpfile);
                }

                if(S_ISCHR(buf.st_mode)) {
                        if(memcmp(PyString_AsString(arg), "/dev/mem", 8) == 0) {
                                opt.dumpfile = NULL;
                                Py_RETURN_TRUE;
                        } else {
                                Py_RETURN_FALSE;
                        }
                } else if(!S_ISDIR(buf.st_mode)) {
                        opt.dumpfile = arg;
                        Py_INCREF(opt.dumpfile);
                        Py_RETURN_TRUE;
                }
        }
        Py_RETURN_FALSE;
        //PyErr_Occurred();
}

/*
typedef struct {
  PyObject_HEAD char *version;
} ivars;

static PyMemberDef DMIDataMembers[] = {
  { (char *)"fred", T_STRING, offsetof(ivars, version), 0, "2.10" },
  { NULL }
};
*/

static PyMethodDef DMIDataMethods[] = {
        {(char *)"dump", dmidecode_dump, METH_NOARGS, (char *)"Dump dmidata to set file"},
        {(char *)"get_dev", dmidecode_get_dev, METH_NOARGS,
         (char *)"Get an alternative memory device file"},
        {(char *)"set_dev", dmidecode_set_dev, METH_O,
         (char *)"Set an alternative memory device file"},

        {(char *)"bios", dmidecode_get_bios, METH_VARARGS, (char *)"BIOS Data"},
        {(char *)"system", dmidecode_get_system, METH_VARARGS, (char *)"System Data"},
        {(char *)"baseboard", dmidecode_get_baseboard, METH_VARARGS, (char *)"Baseboard Data"},
        {(char *)"chassis", dmidecode_get_chassis, METH_VARARGS, (char *)"Chassis Data"},
        {(char *)"processor", dmidecode_get_processor, METH_VARARGS, (char *)"Processor Data"},
        {(char *)"memory", dmidecode_get_memory, METH_VARARGS, (char *)"Memory Data"},
        {(char *)"cache", dmidecode_get_cache, METH_VARARGS, (char *)"Cache Data"},
        {(char *)"connector", dmidecode_get_connector, METH_VARARGS, (char *)"Connector Data"},
        {(char *)"slot", dmidecode_get_slot, METH_VARARGS, (char *)"Slot Data"},

        {(char *)"type", dmidecode_get_type, METH_VARARGS, (char *)"By Type"},

        {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initdmidecode(void)
{
        init();

        PyObject *module =
            Py_InitModule3((char *)"dmidecode", DMIDataMethods,
                           "Python extension module for dmidecode");

        PyObject *version = PyString_FromString("2.10");

        Py_INCREF(version);
        PyModule_AddObject(module, "version", version);

        PyObject *dmi_version = NULL;

        dmidecode_set_version(&dmi_version);
        PyModule_AddObject(module, "dmi", dmi_version ? dmi_version : Py_None);
}
