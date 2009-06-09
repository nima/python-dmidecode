
/*. ******* coding:utf-8 AUTOHEADER START v1.1 *******
 *. vim: fileencoding=utf-8 syntax=c sw=8 ts=8 et
 *.
 *. © 2007-2009 Nima Talebi <nima@autonomy.net.au>
 *. © 2009      David Sommerseth <davids@redhat.com>
 *. © 2002-2008 Jean Delvare <khali@linux-fr.org>
 *. © 2000-2002 Alan Cox <alan@redhat.com>
 *.
 *. This file is part of Python DMI-Decode.
 *.
 *.     Python DMI-Decode is free software: you can redistribute it and/or modify
 *.     it under the terms of the GNU General Public License as published by
 *.     the Free Software Foundation, either version 2 of the License, or
 *.     (at your option) any later version.
 *.
 *.     Python DMI-Decode is distributed in the hope that it will be useful,
 *.     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *.     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *.     GNU General Public License for more details.
 *.
 *.     You should have received a copy of the GNU General Public License
 *.     along with Python DMI-Decode.  If not, see <http://www.gnu.org/licenses/>.
 *.
 *. THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *. WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *. MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
 *. EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *. INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *. LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *. PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *. LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 *. OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *. ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *.
 *. ADAPTED M. STONE & T. PARKER DISCLAIMER: THIS SOFTWARE COULD RESULT IN INJURY
 *. AND/OR DEATH, AND AS SUCH, IT SHOULD NOT BE BUILT, INSTALLED OR USED BY ANYONE.
 *.
 *. $AutoHeaderSerial::20090522                                                 $
 *. ******* AUTOHEADER END v1.1 ******* */

#include <Python.h>

#include <libxml/tree.h>

#include "xmlpythonizer.h"
#include "dmidecodemodule.h"
#include "dmixml.h"
#include <mcheck.h>

static void init(options *opt)
{
        /* sanity check */
        if(sizeof(u8) != 1 || sizeof(u16) != 2 || sizeof(u32) != 4 || '\0' != 0)
                fprintf(stderr, "%s: compiler incompatibility\n", "dmidecodemodule");

        opt->devmem = DEFAULT_MEM_DEV;
        opt->dumpfile = NULL;
        opt->flags = 0;
        opt->type = -1;
        opt->dmiversion_n = NULL;
        opt->mappingxml = NULL;
        opt->python_xml_map = strdup(PYTHON_XML_MAP);
}

int parse_opt_type(const char *arg)
{
        while(*arg != '\0') {
                int val;
                char *next;

                val = strtoul(arg, &next, 0);
                if(next == arg) {
                        fprintf(stderr, "Invalid type keyword: %s\n", arg);
                        return -1;
                }
                if(val > 0xff) {
                        fprintf(stderr, "Invalid type number: %i\n", val);
                        return -1;
                }

                if( val >= 0 ) {
                        return val;
                }
                arg = next;
                while(*arg == ',' || *arg == ' ')
                        arg++;
        }
        return -1;
}


xmlNode *dmidecode_get_version(options *opt)
{
        int found = 0;
        size_t fp;
        int efi;
        u8 *buf = NULL;
        xmlNode *ver_n = NULL;

        /* Set default option values */
        if( opt->devmem == NULL ) {
                opt->devmem = DEFAULT_MEM_DEV;
        }

        /* Read from dump if so instructed */
        if(opt->dumpfile != NULL) {
                //. printf("Reading SMBIOS/DMI data from file %s.\n", dumpfile);
                if((buf = mem_chunk(0, 0x20, opt->dumpfile)) != NULL) {
                        if(memcmp(buf, "_SM_", 4) == 0) {
                                ver_n = smbios_decode_get_version(buf, opt->dumpfile);
                                if( dmixml_GetAttrValue(ver_n, "unknown") == NULL ) {
                                        found++;
                                }
                        } else if(memcmp(buf, "_DMI_", 5) == 0) {
                                ver_n = legacy_decode_get_version(buf, opt->dumpfile);
                                if( dmixml_GetAttrValue(ver_n, "unknown") == NULL ) {
                                        found++;
                                }
                        }
                }
        } else {          /* Read from /dev/mem */
                /* First try EFI (ia64, Intel-based Mac) */
                efi = address_from_efi(&fp);
                if(efi == EFI_NOT_FOUND) {
                        /* Fallback to memory scan (x86, x86_64) */
                        if((buf = mem_chunk(0xF0000, 0x10000, opt->devmem)) != NULL) {
                                for(fp = 0; fp <= 0xFFF0; fp += 16) {
                                        if(memcmp(buf + fp, "_SM_", 4) == 0 && fp <= 0xFFE0) {
                                                ver_n = smbios_decode_get_version(buf + fp, opt->devmem);
                                                if( dmixml_GetAttrValue(ver_n, "unknown") == NULL ) {
                                                        found++;
                                                }
                                                fp += 16;
                                        } else if(memcmp(buf + fp, "_DMI_", 5) == 0) {
                                                ver_n = legacy_decode_get_version (buf + fp, opt->devmem);
                                                if( dmixml_GetAttrValue(ver_n, "unknown") == NULL ) {
                                                        found++;
                                                }
                                        }
                                }
                        }
                } else if(efi == EFI_NO_SMBIOS) {
                        ver_n = NULL;
                } else {
                        // Process as EFI
                        if((buf = mem_chunk(fp, 0x20, opt->devmem)) != NULL) {
                                ver_n = smbios_decode_get_version(buf, opt->devmem);
                                if( dmixml_GetAttrValue(ver_n, "unknown") == NULL ) {
                                        found++;
                                }
                                //. TODO: dmixml_AddAttribute(dmixml_n, "efi_address", efiAddress);
                        }
                }
        }
        if( buf != NULL ) {
                free(buf);
        }
        if( !found ) {
                fprintf(stderr, "No SMBIOS nor DMI entry point found, sorry.");
        }
        return ver_n;
}

int dmidecode_get_xml(options *opt, xmlNode* dmixml_n)
{
        assert(dmixml_n != NULL);
        if(dmixml_n == NULL) {
                return 0;
        }
        //mtrace();

        int ret = 0;
        int found = 0;
        size_t fp;
        int efi;
        u8 *buf = NULL;

        const char *f = opt->dumpfile ? opt->dumpfile : opt->devmem;
        if(access(f, R_OK) < 0)
                PyErr_SetString(PyExc_IOError, "Permission denied to memory file/device");

        /* Read from dump if so instructed */
        if(opt->dumpfile != NULL) {
                //  printf("Reading SMBIOS/DMI data from file %s.\n", dumpfile);
                if((buf = mem_chunk(0, 0x20, opt->dumpfile)) != NULL) {
                        if(memcmp(buf, "_SM_", 4) == 0) {
                                if(smbios_decode(opt->type, buf, opt->dumpfile, dmixml_n))
                                        found++;
                        } else if(memcmp(buf, "_DMI_", 5) == 0) {
                                if(legacy_decode(opt->type, buf, opt->dumpfile, dmixml_n))
                                        found++;
                        }
                } else {
                        ret = 1;
                }
        } else {                /* Read from /dev/mem */
                /* First try EFI (ia64, Intel-based Mac) */
                efi = address_from_efi(&fp);
                if(efi == EFI_NOT_FOUND) {
                        /* Fallback to memory scan (x86, x86_64) */
                        if((buf = mem_chunk(0xF0000, 0x10000, opt->devmem)) != NULL) {
                                for(fp = 0; fp <= 0xFFF0; fp += 16) {
                                        if(memcmp(buf + fp, "_SM_", 4) == 0 && fp <= 0xFFE0) {
                                                if(smbios_decode(opt->type, buf + fp, opt->devmem, dmixml_n)) {
                                                        found++;
                                                        fp += 16;
                                                }
                                        } else if(memcmp(buf + fp, "_DMI_", 5) == 0) {
                                                if(legacy_decode(opt->type, buf + fp, opt->devmem, dmixml_n))
                                                        found++;
                                        }
                                }
                        } else
                                ret = 1;
                } else if(efi == EFI_NO_SMBIOS) {
                        ret = 1;
                } else {
                        if((buf = mem_chunk(fp, 0x20, opt->devmem)) == NULL)
                                ret = 1;
                        else if(smbios_decode(opt->type, buf, opt->devmem, dmixml_n))
                                found++;
                        //  TODO: dmixml_AddAttribute(dmixml_n, "efi_address", "0x%08x", efiAddress);
                }
        }
        if(ret == 0) {
                free(buf);
        }
        //muntrace();
        return ret;
}

xmlNode* load_mappingxml(options *opt) {
        xmlNode *group_n = NULL;

       if( opt->mappingxml == NULL ) {
                // Load mapping into memory
                opt->mappingxml = xmlReadFile(opt->python_xml_map, NULL, 0);
                if( opt->mappingxml == NULL ) {
                        PyErr_SetString(PyExc_SystemError, "Could not open XML mapping file\n");
                        assert( opt->mappingxml != NULL );
                        return NULL;
                }
       }


        if( (group_n = dmiMAP_GetRootElement(opt->mappingxml)) == NULL ) {
                PyErr_SetString(PyExc_SystemError, "Invalid XML mapping file\n");
                assert( group_n != NULL );
                return NULL;
        }

       return group_n;
}

static PyObject *dmidecode_get_group(options *opt, const char *section)
{
        PyObject *pydata = NULL;
        xmlNode *dmixml_n = NULL;
        xmlNode *group_n = NULL;
        ptzMAP *mapping = NULL;

        /* Set default option values */
        if( opt->devmem == NULL ) {
                opt->devmem = DEFAULT_MEM_DEV;
        }
        opt->flags = 0;

        dmixml_n = xmlNewNode(NULL, (xmlChar *) "dmidecode");
        assert( dmixml_n != NULL );
        // Append DMI version info
        if( opt->dmiversion_n != NULL ) {
                xmlAddChild(dmixml_n, xmlCopyNode(opt->dmiversion_n, 1));
        }

        // Fetch the Mapping XML file
        if( (group_n = load_mappingxml(opt)) == NULL) {
                return NULL;
        }

        // Find the section in the XML containing the group mappings
        if( (group_n = dmixml_FindNode(group_n, "GroupMapping")) == NULL ) {
                PyErr_SetString(PyExc_SystemError,
                                "Could not find the GroupMapping section in the XML mapping\n");
                assert( group_n != NULL );
                return NULL;
        }

        // Find the XML node containing the Mapping section requested to be decoded
        if( (group_n = dmixml_FindNodeByAttr(group_n, "Mapping", "name", section)) == NULL ) {
                PyErr_SetString(PyExc_SystemError,
                                "Could not find the given Mapping section in the XML mapping\n");
                assert( group_n != NULL );
                return NULL;
        }

        if( group_n->children == NULL ) {
                PyErr_SetString(PyExc_SystemError,
                                "Mapping is empty for the given section in the XML mapping\n");
                assert( group_n->children != NULL );
                return NULL;
        }

        // Go through all TypeMap's belonging to this Mapping section
        foreach_xmlnode(dmixml_FindNode(group_n, "TypeMap"), group_n) {
                char *typeid = dmixml_GetAttrValue(group_n, "id");

                if( group_n->type != XML_ELEMENT_NODE ) {
                        continue;
                }

                // The children of <Mapping> tags must only be <TypeMap> and
                // they must have an 'id' attribute
                if( (typeid == NULL) || (xmlStrcmp(group_n->name, (xmlChar *) "TypeMap") != 0) ) {
                        PyErr_SetString(PyExc_SystemError,
                                        "Invalid Mapping node in mapping XML\n");
                        return NULL;
                }

                // Parse the typeid string to a an integer
                opt->type = parse_opt_type(typeid);
                if(opt->type == -1) {
                        PyErr_SetString(PyExc_SystemError, "Unexpected: opt->type is -1");
                        return NULL;
                }

                // Parse the DMI data and put the result into dmixml_n node chain.
                if( dmidecode_get_xml(opt, dmixml_n) != 0 ) {
                        PyErr_SetString(PyExc_SystemError,
                                        "Error decoding DMI data\n");
                        return NULL;
                }
        }
#if 0  // DEBUG - will dump generated XML to stdout
        xmlDoc *doc = xmlNewDoc((xmlChar *) "1.0");
        xmlDocSetRootElement(doc, xmlCopyNode(dmixml_n, 1));
        xmlSaveFormatFileEnc("-", doc, "UTF-8", 1);
        xmlFreeDoc(doc);
#endif

        // Convert the retrieved XML nodes to a Python dictionary
        mapping = dmiMAP_ParseMappingXML_GroupName(opt->mappingxml, section);
        if( mapping == NULL ) {
                return NULL;
        }

        // Generate Python dict out of XML node
        pydata = pythonizeXMLnode(mapping, dmixml_n);
        if( pydata == NULL ) {
                PyErr_SetString(PyExc_SystemError,
                                "Error converting XML to Python data.\n");
        }

        // Clean up and return the resulting Python dictionary
        ptzmap_Free(mapping);
        xmlFreeNode(dmixml_n);

        return pydata;
}


static PyObject *dmidecode_get_typeid(options *opt, int typeid)
{
        PyObject *pydata = NULL;
        xmlNode *dmixml_n = NULL;
        ptzMAP *mapping = NULL;

        /* Set default option values */
        if( opt->devmem == NULL ) {
                opt->devmem = DEFAULT_MEM_DEV;
        }
        opt->flags = 0;

        dmixml_n = xmlNewNode(NULL, (xmlChar *) "dmidecode");
        assert( dmixml_n != NULL );
        // Append DMI version info
        if( opt->dmiversion_n != NULL ) {
                xmlAddChild(dmixml_n, xmlCopyNode(opt->dmiversion_n, 1));
        }

        // Fetch the Mapping XML file
        if( load_mappingxml(opt) == NULL) {
                return NULL;
        }

        // Parse the DMI data and put the result into dmixml_n node chain.
        opt->type = typeid;
        if( dmidecode_get_xml(opt, dmixml_n) != 0 ) {
                PyErr_SetString(PyExc_SystemError,
                                "Error decoding DMI data\n");
                return NULL;
        }

        // Convert the retrieved XML nodes to a Python dictionary
        mapping = dmiMAP_ParseMappingXML_TypeID(opt->mappingxml, opt->type);
        if( mapping == NULL ) {
                return NULL;
        }

        // Generate Python dict out of XML node
        pydata = pythonizeXMLnode(mapping, dmixml_n);
        if( pydata == NULL ) {
                PyErr_SetString(PyExc_SystemError,
                                "Error converting XML to Python data.\n");
        }

        // Clean up and return the resulting Python dictionary
        ptzmap_Free(mapping);
        xmlFreeNode(dmixml_n);

        return pydata;
}


// This global variable should only be available for the "first-entry" functions
// which is defined in PyMethodDef DMIDataMethods[].
options *global_options = NULL;

static PyObject *dmidecode_get_bios(PyObject * self, PyObject * args)
{
        return dmidecode_get_group(global_options, "bios");
}
static PyObject *dmidecode_get_system(PyObject * self, PyObject * args)
{
        return dmidecode_get_group(global_options, "system");
}
static PyObject *dmidecode_get_baseboard(PyObject * self, PyObject * args)
{
        return dmidecode_get_group(global_options, "baseboard");
}
static PyObject *dmidecode_get_chassis(PyObject * self, PyObject * args)
{
        return dmidecode_get_group(global_options, "chassis");
}
static PyObject *dmidecode_get_processor(PyObject * self, PyObject * args)
{
        return dmidecode_get_group(global_options, "processor");
}
static PyObject *dmidecode_get_memory(PyObject * self, PyObject * args)
{
        return dmidecode_get_group(global_options, "memory");
}
static PyObject *dmidecode_get_cache(PyObject * self, PyObject * args)
{
        return dmidecode_get_group(global_options, "cache");
}
static PyObject *dmidecode_get_connector(PyObject * self, PyObject * args)
{
        return dmidecode_get_group(global_options, "connector");
}
static PyObject *dmidecode_get_slot(PyObject * self, PyObject * args)
{
        return dmidecode_get_group(global_options, "slot");
}
static PyObject *dmidecode_get_type(PyObject * self, PyObject * args)
{
        int typeid;
        char msg[8194];
        PyObject *pydata = NULL;

        if(PyArg_ParseTuple(args, (char *)"i", &typeid)) {
                if( (typeid >= 0) && (typeid < 256) ) {
                        pydata = dmidecode_get_typeid(global_options, typeid);
                } else {
                        snprintf(msg, 8192, "Types are bound between 0 and 255 (inclusive)."
                                 "Type value used was '%i'%c", typeid, 0);
                        pydata = NULL;
                }
        } else {
                snprintf(msg, 8192, "Invalid type identifier%c", 0);
                pydata = NULL;
        }

        if( pydata == NULL ) {
                PyErr_SetString(PyExc_SystemError, msg);
        }
        return pydata;
}

static PyObject *dmidecode_dump(PyObject * self, PyObject * null)
{
        const char *f;
        struct stat _buf;

        f = (global_options->dumpfile ? global_options->dumpfile : global_options->devmem);
        stat(f, &_buf);

        if((access(f, F_OK) != 0) || ((access(f, W_OK) == 0) && S_ISREG(_buf.st_mode)))
                if(dump(PyString_AS_STRING(global_options->dumpfile)))
                        Py_RETURN_TRUE;
        Py_RETURN_FALSE;
}

static PyObject *dmidecode_get_dev(PyObject * self, PyObject * null)
{
        PyObject *dev = NULL;
        dev = PyString_FromString((global_options->dumpfile != NULL
                                   ? global_options->dumpfile : global_options->devmem));
        Py_INCREF(dev);
        return dev;
}

static PyObject *dmidecode_set_dev(PyObject * self, PyObject * arg)
{
        if(PyString_Check(arg)) {
                struct stat buf;
                char *f = PyString_AsString(arg);

                if( (f != NULL) && (global_options->dumpfile != NULL )
                    && (strcmp(global_options->dumpfile, f) == 0) ) {
                        Py_RETURN_TRUE;
                }

                stat(f, &buf);
                if(S_ISCHR(buf.st_mode)) {
                        if(memcmp(PyString_AsString(arg), "/dev/mem", 8) == 0) {
                                if( global_options->dumpfile != NULL ) {
                                        free(global_options->dumpfile);
                                        global_options->dumpfile = NULL;
                                }
                                Py_RETURN_TRUE;
                        } else {
                                Py_RETURN_FALSE;
                        }
                } else if(!S_ISDIR(buf.st_mode)) {
                        global_options->dumpfile = strdup(f);
                        Py_RETURN_TRUE;
                }
        }
        Py_RETURN_FALSE;
        //PyErr_Occurred();
}

static PyObject *dmidecode_set_pythonxmlmap(PyObject * self, PyObject * arg)
{
        if(PyString_Check(arg)) {
                struct stat fileinfo;
                char *fname = PyString_AsString(arg);

                memset(&fileinfo, 0, sizeof(struct stat));

                if( stat(fname, &fileinfo) != 0 ) {
                        PyErr_SetString(PyExc_IOError, "Could not access the given python map XML file");
                        return NULL;
                }

                free(global_options->python_xml_map);
                global_options->python_xml_map = strdup(fname);
                Py_RETURN_TRUE;
        } else {
                Py_RETURN_FALSE;
        }
}


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

        {(char *)"pythonmap", dmidecode_set_pythonxmlmap, METH_O,
         (char *) "Use another python dict map definition. The default file is " PYTHON_XML_MAP},

        {NULL, NULL, 0, NULL}
};

void destruct_options(void *ptr) {
        options *opt = (options *) ptr;

        if( opt->mappingxml != NULL ) {
                xmlFreeDoc(opt->mappingxml);
                opt->mappingxml = NULL;
        }

        if( opt->python_xml_map != NULL ) {
                free(opt->python_xml_map);
                opt->python_xml_map = NULL;
        }

        if( opt->dmiversion_n != NULL ) {
                xmlFreeNode(opt->dmiversion_n);
                opt->dmiversion_n = NULL;
        }

        if( opt->dumpfile != NULL ) {
                free(opt->dumpfile);
                opt->dumpfile = NULL;
        }

        free(ptr);
}


PyMODINIT_FUNC initdmidecode(void)
{
        char *dmiver = NULL;
        PyObject *module = NULL;
        PyObject *version = NULL;
        options *opt;

        xmlInitParser();
        xmlXPathInit();

        opt = (options *) malloc(sizeof(options)+2);
        memset(opt, 0, sizeof(options)+2);
        init(opt);
        module = Py_InitModule3((char *)"dmidecode", DMIDataMethods,
                                "Python extension module for dmidecode");

        version = PyString_FromString("3.10.6");
        Py_INCREF(version);
        PyModule_AddObject(module, "version", version);

        opt->dmiversion_n = dmidecode_get_version(opt);
        dmiver = dmixml_GetContent(opt->dmiversion_n);
        PyModule_AddObject(module, "dmi", dmiver ? PyString_FromString(dmiver) : Py_None);

        // Assign this options struct to the module as well with a destructor, that way it will
        // clean up the memory for us.
        PyModule_AddObject(module, "options", PyCObject_FromVoidPtr(opt, destruct_options));
        global_options = opt;
}
