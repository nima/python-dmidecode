/*   Converts XML docs and nodes to Python dicts and lists by
 *   using an XML file which describes the Python dict layout
 *
 *   Copyright 2009      David Sommerseth <davids@redhat.com>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 *   For the avoidance of doubt the "preferred form" of this code is one which
 *   is in an open unpatent encumbered format. Where cryptographic key signing
 *   forms part of the process of creating an executable the information
 *   including keys needed to generate an equivalently functional executable
 *   are deemed to be part of the source code.
 */

#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include "dmixml.h"
#include "xmlpythonizer.h"

ptzMAP *ptzmap_Add(const ptzMAP *chain, char *rootp,
                   ptzTYPES ktyp, const char *key,
                   ptzTYPES vtyp, const char *value,
                   ptzMAP *child)
{
        ptzMAP *ret = NULL;

        assert( (ktyp == ptzCONST) || (ktyp == ptzSTR) || (ktyp == ptzINT) || (ktyp == ptzFLOAT) );
        assert( key != NULL );
        // Make sure that value and child are not used together
        assert( ((value == NULL) && child != NULL) || ((value != NULL) && (child == NULL)) );

        ret = (ptzMAP *) malloc(sizeof(ptzMAP)+2);
        assert( ret != NULL );
        memset(ret, 0, sizeof(ptzMAP)+2);

        if( rootp != NULL ) {
                ret->rootpath = strdup(rootp);
        }

        ret->type_key = ktyp;
        ret->key = strdup(key);

        ret->type_value = vtyp;
        if( value != NULL ) {
                ret->value = strdup(value);
                ret->child = NULL;
        } else if( child != NULL ) {
                ret->value = NULL;
                ret->child = child;
        }

        if( chain != NULL ) {
                ret->next = (ptzMAP *) chain;
        }
        return ret;
};

void ptzmap_SetFixedList(ptzMAP *map_p, const char *index, int size) {
        assert( map_p != NULL );

        switch( map_p->type_value ) {
        case ptzLIST_STR:
        case ptzLIST_INT:
        case ptzLIST_FLOAT:
        case ptzLIST_BOOL:
                map_p->list_index = strdup(index);
                map_p->fixed_list_size = size;
                break;

        default:
                break;
        }
}

void ptzmap_Free_func(ptzMAP *ptr)
{
        if( ptr == NULL ) {
                return;
        }

        if( ptr->rootpath != NULL ) {
                free(ptr->rootpath);
                ptr->rootpath = NULL;
        }

        if( ptr->list_index != NULL ) {
                free(ptr->list_index);
                ptr->list_index = NULL;
        }

        if( ptr->emptyValue != NULL ) {
                free(ptr->emptyValue);
                ptr->emptyValue = NULL;
        }

        free(ptr->key);
        ptr->key = NULL;

        if( ptr->value != NULL ) {
                free(ptr->value);
                ptr->value = NULL;
        }

        if( ptr->child != NULL ) {
                ptzmap_Free(ptr->child);
        }
        if( ptr->next != NULL ) {
                ptzmap_Free(ptr->next);
        }
        free(ptr);
}


#if 0
// DEBUG FUNCTIONS
static const char *ptzTYPESstr[] = { "ptzCONST", "ptzSTR", "ptzINT", "ptzFLOAT", "ptzBOOL",
                                     "ptzLIST_STR", "ptzLIST_INT", "ptzLIST_FLOAT", "ptzLIST_BOOL",
                                     "ptzDICT", NULL };

void indent(int lvl)
{
        int i = 0;
        if( lvl == 0 ) {
                return;
        }

        for( i = 0; i < (lvl * 3); i++ ) {
                printf(" ");
        }
}

#define ptzmap_Dump(ptr) { ptzmap_Dump_func(ptr, 0); }
void ptzmap_Dump_func(const ptzMAP *ptr, int level)
{
        if( ptr == NULL ) {
                return;
        }

        if( ptr->rootpath != NULL ) {
                indent(level); printf("root path: %s\n", ptr->rootpath);
        }
        indent(level); printf("key type:   (%i) %-13.13s - key:   %s\n",
                              ptr->type_key, ptzTYPESstr[ptr->type_key], ptr->key);
        indent(level); printf("value type: (%i) %-13.13s - value: %s %s\n",
                              ptr->type_value, ptzTYPESstr[ptr->type_value], ptr->value,
                              (ptr->num_emptyIsNone ? "(EmptyIsNone)": ""));
        if( ptr->list_index != NULL ) {
                indent(level);
                printf("List index: %s - Fixed size: %i\n",
                       ptr->list_index, ptr->fixed_list_size);
        }
        if( ptr->child != NULL ) {
                indent(level); printf(" ** CHILD\n");
                ptzmap_Dump_func(ptr->child, level + 1);
                indent(level); printf(" ** ---------\n");
        }
        if( ptr->next != NULL ) {
                printf("\n");
                ptzmap_Dump_func(ptr->next, level);
        }
}
#endif // END OF DEBUG FUNCTIONS

//
//  Parser for the XML -> Python mapping XML file
//
//  This mappipng XML file describes how the Python result
//  should look like and where it should pick the data from
//  when later on parsing the dmidecode XML data.
//

// Valid key and value types for the mapping file
inline ptzTYPES _convert_maptype(const char *str) {
        if( strcmp(str, "string") == 0 ) {
                return ptzSTR;
        } else if( strcmp(str, "constant") == 0 ) {
                return ptzCONST;
        } else if( strcmp(str, "integer") == 0 ) {
                return ptzINT;
        } else if( strcmp(str, "float") == 0 ) {
                return ptzFLOAT;
        } else if( strcmp(str, "boolean") == 0 ) {
                return ptzBOOL;
        } else if( strcmp(str, "list:string") == 0 ) {
                return ptzLIST_STR;
        } else if( strcmp(str, "list:integer") == 0 ) {
                return ptzLIST_INT;
        } else if( strcmp(str, "list:float") == 0 ) {
                return ptzLIST_FLOAT;
        } else if( strcmp(str, "list:boolean") == 0 ) {
                return ptzLIST_BOOL;
        } else if( strcmp(str, "dict") == 0 ) {
                return ptzDICT;
        } else {
                fprintf(stderr, "Unknown field type: %s - defaulting to 'string'\n", str);
                return ptzSTR;
        }
}

// Internal parser
ptzMAP *_do_dmimap_parsing(xmlNode *node) {
        ptzMAP *retmap = NULL;
        xmlNode *ptr_n = NULL, *map_n = NULL;;

        // Go to the next XML_ELEMENT_NODE
        for( map_n = node; map_n != NULL; map_n = map_n->next ) {
                if( map_n->type == XML_ELEMENT_NODE ) {
                        break;
                }
        }
        if( map_n == NULL ) {
                return NULL;
        }

        // Go to the first <Map> node
        if( xmlStrcmp(node->name, (xmlChar *) "Map") != 0 ) {
                map_n = dmixml_FindNode(node, "Map");
                if( map_n == NULL ) {
                        return NULL;
                }
        }

        // Loop through it's children
        for( ptr_n = map_n ; ptr_n != NULL; ptr_n = ptr_n->next ) {
                ptzTYPES type_key, type_value;
                char *key = NULL, *value = NULL;
                char *rootpath = NULL;
                char *listidx = NULL;
                int fixedsize = 0;
                if( ptr_n->type != XML_ELEMENT_NODE ) {
                        continue;
                }

                // Get the attributes defining key, keytype, value and valuetype
                key = dmixml_GetAttrValue(ptr_n, "key");
                type_key = _convert_maptype(dmixml_GetAttrValue(ptr_n, "keytype"));

                value = dmixml_GetAttrValue(ptr_n, "value");
                type_value = _convert_maptype(dmixml_GetAttrValue(ptr_n, "valuetype"));

                rootpath = dmixml_GetAttrValue(ptr_n, "rootpath");

                listidx = dmixml_GetAttrValue(ptr_n, "index_attr");
                if( listidx != NULL ) {
                        char *fsz = dmixml_GetAttrValue(ptr_n, "fixedsize");
                        fixedsize = (fsz != NULL ? atoi(fsz) : 0);
                }

                if( type_value == ptzDICT ) {
                        // When value type is ptzDICT, traverse the children nodes
                        // - should contain another Map set instead of a value attribute
                        if( ptr_n->children == NULL ) {
                                continue;
                        }
                        // Recursion
                        retmap = ptzmap_Add(retmap, rootpath, type_key, key, type_value, NULL,
                                            _do_dmimap_parsing(ptr_n->children->next));
                } else {
                        char *tmpstr = NULL;

                        // Append the value as a normal value when the
                        // value type is not a Python Dict
                        retmap = ptzmap_Add(retmap, rootpath, type_key, key, type_value, value, NULL);

                        // Set emptyIsNone flag
                        if( (tmpstr = dmixml_GetAttrValue(ptr_n, "emptyIsNone")) != NULL ) {
                                switch( retmap->type_value ) {
                                case ptzSTR:
                                case ptzINT:
                                case ptzFLOAT:
                                case ptzBOOL:
                                case ptzLIST_STR:
                                case ptzLIST_INT:
                                case ptzLIST_FLOAT:
                                case ptzLIST_BOOL:
                                        retmap->emptyIsNone = (tmpstr[0] == '1' ? 1 : 0);
                                        break;
                                default:
                                        break;
                                }
                        }
                        if( (tmpstr = dmixml_GetAttrValue(ptr_n, "emptyValue")) != NULL ) {
                                retmap->emptyValue = strdup(tmpstr);
                        }
                }

                if( (retmap != NULL) && (listidx != NULL) && (fixedsize > 0) ) {
                        ptzmap_SetFixedList(retmap, listidx, fixedsize);
                }

                value = NULL;
                key = NULL;
        }
        return retmap;
}

// Main parser function for the mapping XML
ptzMAP *dmiMAP_ParseMappingXML(xmlDoc *xmlmap, const char *mapname) {
        ptzMAP *map = NULL;
        xmlNode *node = NULL;

        // Find the root tag and locate our mapping
        node = xmlDocGetRootElement(xmlmap);
        assert( node != NULL );

        // Verify that the root node got the right name
        if( (node == NULL)
            || (xmlStrcmp(node->name, (xmlChar *) "dmidecode_fieldmap") != 0 )) {
                PyErr_SetString(PyExc_IOError, "Invalid XML-Python mapping file");
                return NULL;
        }

        // Verify that it's of a version we support
        if( strcmp(dmixml_GetAttrValue(node, "version"), "1") != 0 ) {
                PyErr_SetString(PyExc_IOError, "Unsupported XML-Python mapping file format");
                return NULL;
        }

        // Find the <Mapping> section matching our request (mapname)
        for( node = node->children->next; node != NULL; node = node->next ) {
                if( xmlStrcmp(node->name, (xmlChar *) "Mapping") == 0) {
                        char *name = dmixml_GetAttrValue(node, "name");
                        if( (name != NULL) && (strcmp(name, mapname) == 0) ) {
                                break;
                        }
                }
        }

        if( node == NULL ) {
                char msg[8194];
                snprintf(msg, 8193, "No mapping for '%s' was found "
                         "in the XML-Python mapping file%c", mapname, 0);
                PyErr_SetString(PyExc_IOError, msg);
                return NULL;
        }

        // Start creating an internal map structure based on the mapping XML.
        map = _do_dmimap_parsing(node);

        return map;
}


//
//  Parser routines for converting XML data into Python structures
//
inline PyObject *StringToPyObj(ptzMAP *val_m, const char *instr) {
        PyObject *value;
        const char *workstr = NULL;

        if( instr == NULL ) {
                return Py_None;
        }

        if( (val_m->emptyIsNone == 1) || (val_m->emptyValue != NULL) ) {
                char *cp = strdup(instr);
                char *cp_p = NULL;
                assert( cp != NULL );

                // Trim the string for trailing spaces
                cp_p = cp + strlen(cp) - 1;
                while( (cp_p >= cp) && (*cp_p == ' ') ) {
                        *cp_p = 0;
                        cp_p--;
                }

                // If our copy pointer is the same
                // or less than the starting point,
                // there is no data here
                if( cp_p <= cp ) {
                        free(cp);
                        if( val_m->emptyIsNone == 1 ) {
                                return Py_None;
                        }
                        if( val_m->emptyValue != NULL ) {
                                workstr = (const char *)val_m->emptyValue;
                        }
                } else {
                        free(cp);
                }
        }

        if( workstr == NULL ) {
                workstr = instr;
        }


        switch( val_m->type_value ) {
        case ptzINT:
        case ptzLIST_INT:
                value = PyInt_FromLong(atoi(workstr));
                break;

        case ptzFLOAT:
        case ptzLIST_FLOAT:
                value = PyFloat_FromDouble(atof(workstr));
                break;

        case ptzBOOL:
        case ptzLIST_BOOL:
                value = PyBool_FromLong((atoi(workstr) == 1 ? 1:0));
                break;

        case ptzSTR:
        case ptzLIST_STR:
                value = PyString_FromString(workstr);
                break;

        default:
                fprintf(stderr, "Invalid type '%i' for value '%s'\n", val_m->type_value, instr);
                value = Py_None;
        }
        return value;
}

// Retrieve a value from the XML doc (XPath Context) based on a XPath query
xmlXPathObject *_get_xpath_values(xmlXPathContext *xpctx, const char *xpath) {
        xmlChar *xp_xpr = NULL;
        xmlXPathObject *xp_obj = NULL;

        if( xpath == NULL ) {
                return NULL;
        }

        xp_xpr = xmlCharStrdup(xpath);
        xp_obj = xmlXPathEvalExpression(xp_xpr, xpctx);
        assert( xp_obj != NULL );
        free(xp_xpr);

        return xp_obj;
}

char *_get_key_value(char *key, size_t buflen, ptzMAP *map_p, xmlXPathContext *xpctx, int idx) {
        xmlXPathObject *xpobj = NULL;

        memset(key, 0, buflen);

        switch( map_p->type_key ) {
        case ptzCONST:
                strncpy(key, map_p->key, buflen-1);
                break;

        case ptzSTR:
        case ptzINT:
        case ptzFLOAT:
                xpobj = _get_xpath_values(xpctx, map_p->key);
                if( xpobj == NULL ) {
                        return NULL;
                }
                if( dmixml_GetXPathContent(key, buflen, xpobj, idx) == NULL ) {
                        xmlXPathFreeObject(xpobj);
                        return NULL;
                }
                xmlXPathFreeObject(xpobj);
                break;

        default:
                fprintf(stderr, "Unknown key type: %i\n", map_p->type_key);
                return NULL;
        }
        // We consider to have a key, if the first byte is a readable
        // character (usually starting at 0x20/32d)
        return ((key != NULL) && (strlen(key) > 0) ? key : NULL) ;
}



#define PyADD_DICT_VALUE(p, k, v) {                                \
                PyDict_SetItemString(p, k, v);                     \
                Py_DECREF(v);                                      \
        }

inline void _add_xpath_result(PyObject *pydat, xmlXPathContext *xpctx, ptzMAP *map_p, xmlXPathObject *value) {
        int i = 0;
        char *key = NULL;
        char *val = NULL;

        assert( pydat != NULL && value != NULL );

        key = (char *) malloc(258);
        assert( key != NULL );

        val = (char *) malloc(4098);
        assert( val != NULL );

        switch( value->type ) {
        case XPATH_NODESET:
                if( value->nodesetval == NULL ) {
                        break;
                }
                if( value->nodesetval->nodeNr == 0 ) {
                        if( _get_key_value(key, 256, map_p, xpctx, 0) != NULL ) {
                                PyADD_DICT_VALUE(pydat, key, Py_None);
                        }
                } else {
                        for( i = 0; i < value->nodesetval->nodeNr; i++ ) {
                                if( _get_key_value(key, 256, map_p, xpctx, i) != NULL ) {
                                        dmixml_GetXPathContent(val, 4097, value, i);
                                        PyADD_DICT_VALUE(pydat, key, StringToPyObj(map_p, val));
                                }
                        }
                }
                break;
        default:
                if( _get_key_value(key, 256, map_p, xpctx, 0) != NULL ) {
                        dmixml_GetXPathContent(val, 4097, value, 0);
                        PyADD_DICT_VALUE(pydat, key, StringToPyObj(map_p, val));
                }
                break;
        }
        free(key);
        free(val);
}


// Internal XML parser routine, which traverses the given mapping table,
// returning a Python structure accordingly to the map.
PyObject *_deep_pythonize(PyObject *retdata, ptzMAP *map_p, xmlNode *data_n, int elmtid) {
        char *key = NULL;
        xmlXPathContext *xpctx = NULL;
        xmlDoc *xpdoc = NULL;
        xmlXPathObject *xpo = NULL;
        PyObject *value = NULL;
        int i;

        xpdoc = xmlNewDoc((xmlChar *) "1.0");
        assert( xpdoc != NULL );
        xmlDocSetRootElement(xpdoc, xmlCopyNode(data_n, 1));

        xpctx = xmlXPathNewContext(xpdoc);
        assert( xpctx != NULL );
        xpctx->node = data_n;

        key = (char *) malloc(258);
        assert( key != NULL );

        // Extract value
        switch( map_p->type_value ) {
        case ptzCONST:
                if( _get_key_value(key, 256, map_p, xpctx, 0) != NULL ) {
                        value = PyString_FromString(map_p->value);
                        PyADD_DICT_VALUE(retdata, key, value);
                } else {
                        char msg[8094];
                        snprintf(msg, 8092, "Could not get key value: %s [%i] (Defining key: %s)%c",
                                 map_p->rootpath, elmtid, map_p->key, 0);
                        PyErr_SetString(PyExc_LookupError, msg);
                }
                break;

        case ptzSTR:
        case ptzINT:
        case ptzFLOAT:
        case ptzBOOL:
                xpo = _get_xpath_values(xpctx, map_p->value);
                if( xpo != NULL ) {
                        _add_xpath_result(retdata, xpctx, map_p, xpo);
                        xmlXPathFreeObject(xpo);
                }
                break;

        case ptzLIST_STR:
        case ptzLIST_INT:
        case ptzLIST_FLOAT:
        case ptzLIST_BOOL:
                xpo = _get_xpath_values(xpctx, map_p->value);
                if( xpo != NULL ) {
                        if( _get_key_value(key, 256, map_p, xpctx, 0) != NULL ) {
                                if( xpo->nodesetval->nodeNr > 0 ) {
                                        value = PyList_New(0);

                                        // If we're working on a fixed list, create one which contains
                                        // only Py_None objects.  Otherwise the list will be filled with
                                        // <nil> elements.
                                        if( map_p->fixed_list_size > 0 ) {
                                                for( i = 0; i < map_p->fixed_list_size; i++ ) {
                                                        PyList_Append(value, Py_None);
                                                }
                                        }

                                        for( i = 0; i < xpo->nodesetval->nodeNr; i++ ) {
                                                char *valstr = NULL;
                                                valstr = (char *) malloc(4098);
                                                dmixml_GetXPathContent(valstr, 4097, xpo, i);

                                                // If we have a fixed list and we have a index value for the list
                                                if( (map_p->fixed_list_size > 0) && (map_p->list_index != NULL) ) {
                                                        char *idx = NULL;

                                                        idx = dmixml_GetAttrValue(xpo->nodesetval->nodeTab[i],
                                                                                  map_p->list_index);
                                                        if( idx != NULL ) {
                                                                PyList_SetItem(value, atoi(idx)-1,
                                                                               StringToPyObj(map_p, valstr)
                                                                               );
                                                        }
                                                } else {
                                                        PyList_Append(value, StringToPyObj(map_p, valstr));
                                                }
                                                free(valstr);
                                        }
                                } else {
                                        value = Py_None;
                                }
                                PyADD_DICT_VALUE(retdata, key, value);
                                xmlXPathFreeObject(xpo);
                        } else {
                                char msg[8094];
                                snprintf(msg, 8092, "Could not get key value: "
                                         "%s [%i] (Defining key: %s)%c",
                                         map_p->rootpath, elmtid, map_p->key, 0);
                                PyErr_SetString(PyExc_LookupError, msg);
                        }
                }
                break;

        case ptzDICT:
                // Traverse children nodes
                if( map_p->child == NULL ) {
                        break;
                }
                if( _get_key_value(key, 256, map_p, xpctx, 0) == NULL ) {
                        char msg[8094];
                        snprintf(msg, 8092, "Could not get key value: %s [%i] (Defining key: %s)%c",
                                 map_p->rootpath, elmtid, map_p->key, 0);
                        PyErr_SetString(PyExc_LookupError, msg);
                        break;
                }
                // Use recursion when procession child elements
                value = pythonizeXMLnode(map_p->child, data_n);
                PyADD_DICT_VALUE(retdata, key, (value != NULL ? value : Py_None));
                break;

        default:
                fprintf(stderr, "Unknown value type: %i\n", map_p->type_value);
                break;
        }

        free(key);
        xmlXPathFreeContext(xpctx);
        xmlFreeDoc(xpdoc);
        return retdata;
}

// Convert a xmlNode to a Python object, based on the given map
PyObject *pythonizeXMLnode(ptzMAP *in_map, xmlNode *data_n) {
        xmlXPathContext *xpctx = NULL;
        xmlDoc *xpdoc = NULL;
        PyObject *retdata = NULL;
        ptzMAP *map_p = NULL;
        char *key = NULL;

        if( (in_map == NULL) || (data_n == NULL) ) {
                PyErr_SetString(PyExc_LookupError, "XMLnode or map is NULL");
                return NULL;
        }

        key = (char *) malloc(258);
        assert( key != NULL );

        // Loop through all configured elements
        retdata = PyDict_New();
        for( map_p = in_map; map_p != NULL; map_p = map_p->next ) {
                if( (map_p->type_value == ptzDICT) && (map_p->rootpath != NULL) ) {
                        xmlXPathObject *xpo = NULL;
                        int i;

                        // Set the root node in the XPath context
                        xpdoc = xmlNewDoc((xmlChar *) "1.0");
                        assert( xpdoc != NULL );
                        xmlDocSetRootElement(xpdoc, xmlCopyNode(data_n, 1));

                        xpctx = xmlXPathNewContext(xpdoc);
                        assert( xpctx != NULL );
                        xpctx->node = data_n;

                        xpo = _get_xpath_values(xpctx, map_p->rootpath);
                        if( (xpo == NULL) || (xpo->nodesetval == NULL) || (xpo->nodesetval->nodeNr == 0) ) {
                                char msg[8094];
                                snprintf(msg, 8092, "Could not locate XML path node: %s (Defining key: %s)%c",
                                         map_p->rootpath, map_p->key, 0);
                                fprintf(stderr, msg);
                                PyErr_SetString(PyExc_LookupError, msg);

                                if( xpo != NULL ) {
                                        xmlXPathFreeObject(xpo);
                                }
                                xmlFreeDoc(xpdoc);
                                xmlXPathFreeContext(xpctx);
                                return NULL;
                        }

                        for( i = 0; i < xpo->nodesetval->nodeNr; i++ ) {
                                xpctx->node = xpo->nodesetval->nodeTab[i];

                                if( _get_key_value(key, 256, map_p, xpctx, 0) != NULL ) {
                                        _deep_pythonize(retdata, map_p,
                                                        xpo->nodesetval->nodeTab[i], i);
                                }
                        }
                        xmlXPathFreeObject(xpo);
                        xmlXPathFreeContext(xpctx);
                        xmlFreeDoc(xpdoc);
                } else {
                        _deep_pythonize(retdata, map_p, data_n, 0);
                }
        }
        free(key);
        return retdata;
}


// Convert a xmlDoc to a Python object, based on the given map
PyObject *pythonizeXMLdoc(ptzMAP *map, xmlDoc *doc)
{
        xmlNode *node = NULL;

        node = xmlDocGetRootElement(doc);
        return pythonizeXMLnode(map, node);
}


#if 0
// Simple independent main function - only for debugging
int main(int argc, char **argv) {
        xmlDoc *doc = NULL, *data = NULL;
        ptzMAP *map = NULL;
        PyObject *pydat = NULL;

        Py_Initialize();

        doc = xmlReadFile("pythonmap.xml", NULL, 0);
        assert( doc != NULL );

        map = dmiMAP_ParseMappingXML(doc, argv[1]);
        ptzmap_Dump(map);
        printf("----------------------\n");


        data = xmlReadFile(argv[2], NULL, 0);
        assert( data != NULL );

        pydat = pythonizeXMLdoc(map, data);
        Py_INCREF(pydat);
        PyObject_Print(pydat, stdout, 0);
        Py_DECREF(pydat);
        printf("\n");
        ptzmap_Free(map);
        xmlFreeDoc(data);
        xmlFreeDoc(doc);

        return 0;
}
#endif

#if 0
// Simple test module for Python - only for debugging
PyObject* demo_xmlpy()
{
        xmlDoc *doc = NULL, *mapping_xml = NULL;
        ptzMAP *mapping = NULL;
        PyObject *ret = NULL;

        // Read the XML-Python mapping setup
        mapping_xml = xmlReadFile("pythonmap.xml", NULL, 0);
        assert( mapping_xml != NULL );

        mapping = dmiMAP_ParseMappingXML(mapping_xml, "bios");
        assert( mapping != NULL );

        // Read XML data from file
        doc = xmlReadFile("cpu.xml", NULL, 0);
        assert( doc != NULL );

        // Create a PyObject out of the XML indata
        ret = pythonizeXMLdoc(mapping, doc);

        // Clean up and return the data
        ptzmap_Free(mapping);
        xmlFreeDoc(doc);
        xmlFreeDoc(mapping_xml);

        return ret;
}

static PyMethodDef DemoMethods[] = {
        {"xmlpy", demo_xmlpy, METH_NOARGS, ""},
        {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initxmlpythonizer(void) {
        PyObject *module =
                Py_InitModule3((char *)"xmlpythonizer", DemoMethods,
                               "XML to Python Proof-of-Concept Python Module");

        PyObject *version = PyString_FromString("2.10");
        Py_INCREF(version);
        PyModule_AddObject(module, "version", version);
}
#endif // Python test module


