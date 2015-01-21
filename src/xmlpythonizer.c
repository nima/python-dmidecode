/*. ******* coding:utf-8 AUTOHEADER START v1.1 *******
 *. vim: fileencoding=utf-8 syntax=c sw=8 ts=8 et
 *.
 *. © 2009      David Sommerseth <davids@redhat.com>
 *. © 2007-2009 Nima Talebi <nima@autonomy.net.au>
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

/*   Converts XML docs and nodes to Python dicts and lists by
 *   using an XML file which describes the Python dict layout
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

/**
 * @file xmlpythonizer.c
 * @brief Generic parser for converting XML documents or XML nodes
 *        into Python Dictionaries
 * @author David Sommerseth <davids@redhat.com>
 * @author Nima Talebi <nima@autonomy.net.au>
 */


#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include "util.h"
#include "dmixml.h"
#include "dmierror.h"
#include "dmilog.h"
#include "xmlpythonizer.h"
#include "version.h"
#include "compat.h"


/**
 * This functions appends a new ptzMAP structure to an already existing chain
 * @author David Sommerseth <davids@redhat.com>
 * @param ptzMAP*    Pointer to the chain the new ptzMAP is to be appended
 * @param ptzMAP*    Pointer to the new ptzMAP to be appended to the already existing ptzMAP
 * @return ptzMAP*   Pointer to the ptzMAP which includes the newly added ptzMAP
 */
ptzMAP *ptzmap_AppendMap(const ptzMAP *chain, ptzMAP *newmap)
{
        if( chain != NULL ) {
                newmap->next = (ptzMAP *) chain;
        }
        return newmap;
}


/**
 * This function creates a new ptzMAP mapping record.  This defines the key/value relationship in
 * the resulting Python Dictionaries.
 * @author David Sommerseth <davids@redhat.com>
 * @param ptzMAP*       Pointer to the chain the new mapping will be appended
 * @param char*         XPath root of the given key and value XPath expressions.
 *                      If NULL, the key and value XPath expressions must be absolute.
 * @param ptzTYPES      Type of the 'key' value
 * @param const char*   XPath expression or constant string for the 'key' value
 * @param ptzTYPES      Type of the 'value' value
 * @param const char*   XPath expression or constant string for the 'value' value
 * @param ptzMAP*       Used if the value type is of one of the ptzDICT types, contains a new
 *                      mapping level for the children
 * @return ptzMAP*      Pointer to the ptzMAP which includes the newly added ptzMAP
 */
ptzMAP *ptzmap_Add(const ptzMAP *chain, char *rootp,
                   ptzTYPES ktyp, const char *key,
                   ptzTYPES vtyp, const char *value,
                   ptzMAP *child)
{
        ptzMAP *ret = NULL;

        assert( (ktyp == ptzCONST) || (ktyp == ptzSTR) || (ktyp == ptzINT) || (ktyp == ptzFLOAT) );
        assert( key != NULL );

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
        }

        if( child != NULL ) {
                ret->child = child;
        }

        return ptzmap_AppendMap(chain, ret);
};


/**
 * This functions sets an ptzLIST typed map entry as a fixed list
 * @author David Sommerseth <davids@redhat.com>
 * @param ptzMAP*      Pointer to the ptzMAP elemnt to be updated
 * @param const char*  Attribute name of the XML node of the 'key' to use as the list index
 * @param int          Defines the size of the list
 */
void ptzmap_SetFixedList(ptzMAP *map_p, const char *index, int size)
{
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


/**
 * This functions frees up a complete pointer chain.  This is normally called via #define ptzmap_Free()
 * @author David Sommerseth <davids@redhat.com>
 * @param ptzMAP*    Pointer to the ptzMAP to free
 */
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
                                     "ptzDICT", "ptzLIST_DICT", NULL };

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
                              (ptr->emptyIsNone ? "(EmptyIsNone)": ""));
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


/**
 * This functions converts a string to valid ptzTYPES values.  This is used when parsing the XML mapping nodes
 * @author David Sommerseth <davids@redhat.com>
 * @param const char*    String value containing the key/value type
 * @return ptzTYPES      The type value
 */
inline ptzTYPES _convert_maptype(Log_t *logp, const char *str) {
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
        } else if( strcmp(str, "list:dict") == 0 ) {
                return ptzLIST_DICT;
        } else {
                log_append(logp, LOGFL_NORMAL, LOG_WARNING,
			   "Unknown field type: %s - defaulting to 'constant'", str);
                return ptzCONST;
        }
}


/**
 * This functions is the internal parser - SubMapper (Individual Types of a Group)
 * @author David Sommerseth <davids@redhat.com>
 * @param xmlNode*   Node of the starting point for the parsing
 * @return ptzMAP*   The ptzMAP version of the XML definition
 */
ptzMAP *_do_dmimap_parsing_typeid(Log_t *logp, xmlNode *node) {
        ptzMAP *retmap = NULL;
        xmlNode *ptr_n = NULL, *map_n = NULL;;

        // Go to the next XML_ELEMENT_NODE
        foreach_xmlnode(node, map_n) {
                if( map_n->type == XML_ELEMENT_NODE ) {
                        break;
                }
        }
        if( map_n == NULL ) {
                PyReturnError(PyExc_NameError, "No mapping nodes were found");
        }

        // Go to the first <Map> node
        if( xmlStrcmp(node->name, (xmlChar *) "Map") != 0 ) {
                map_n = dmixml_FindNode(node, "Map");
                if( map_n == NULL ) {
                        // If we don't find a <Map> node, we just exit now.
                        // Other checks will raise an exception if needed.
                        return NULL;
                }
        }

        // Loop through it's children
        foreach_xmlnode(map_n, ptr_n) {
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
                type_key = _convert_maptype(logp, dmixml_GetAttrValue(ptr_n, "keytype"));

                value = dmixml_GetAttrValue(ptr_n, "value");
                type_value = _convert_maptype(logp, dmixml_GetAttrValue(ptr_n, "valuetype"));

                rootpath = dmixml_GetAttrValue(ptr_n, "rootpath");

                listidx = dmixml_GetAttrValue(ptr_n, "index_attr");
                if( listidx != NULL ) {
                        char *fsz = dmixml_GetAttrValue(ptr_n, "fixedsize");
                        fixedsize = (fsz != NULL ? atoi(fsz) : 0);
                }

                if( (type_value == ptzDICT) || (type_value == ptzLIST_DICT) ) {
                        // When value type is ptzDICT, traverse the children nodes
                        // - should contain another Map set instead of a value attribute
                        if( ptr_n->children == NULL ) {
                                continue;
                        }
                        // Recursion
                        retmap = ptzmap_Add(retmap, rootpath, type_key, key, type_value,
                                            (type_value == ptzLIST_DICT ? value : NULL),
                                            _do_dmimap_parsing_typeid(logp, ptr_n->children->next));
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

/**
 * This functions validates and retrieves the root node of the dmidecode_mapping XML node from an XML document
 * @author David Sommerseth <davids@redhat.com>
 * @param xmlDoc*   XML mapping document pointer
 * @return xmlNode* The root xmlNode of a valid XML mapping document.  On invalid document NULL is returned.
 */
xmlNode *dmiMAP_GetRootElement(xmlDoc *mapdoc) {
       xmlNode *rootnode = NULL;

        // Find the root tag and locate our mapping
        rootnode = xmlDocGetRootElement(mapdoc);
        assert( rootnode != NULL );

        // Verify that the root node got the right name
        if( (rootnode == NULL)
            || (xmlStrcmp(rootnode->name, (xmlChar *) "dmidecode_mapping") != 0 )) {
                PyReturnError(PyExc_IOError, "Invalid XML-Python mapping file. "
                              "Root node is not 'dmidecode_mapping'");
        }

        // Verify that it's of a version we support
        if( strcmp(dmixml_GetAttrValue(rootnode, "version"), "1") != 0 ) {
                PyReturnError(PyExc_RuntimeError, "Unsupported XML-Python mapping file format. "
                              "Only version 1 is supported");
        }
        return rootnode;
}


/**
 * Internal function which looks up the given Type ID among TypeMap nodes and and parses
 * the found XML nodes into a ptzMAP
 * @author David Sommerseth <davids@redhat.com>
 * @param xmlNode*     The node where the TypeMapping tags are found
 * @param const char*  The typeid to parse to a ptzMAP
 * @return ptzMAP*     The parsed result of the XML nodes
 */
ptzMAP *_dmimap_parse_mapping_node_typeid(Log_t *logp, xmlNode *mapnode, const char *typeid) {
        xmlNode *node = NULL;

        assert( mapnode != NULL);

        // Find the <TypeMap> tag with our type ID
        node = dmixml_FindNodeByAttr_NoCase(mapnode, "TypeMap", "id", typeid);
        if( node == NULL ) {
                // No exception handling possible here, as we don't return PyObject
                log_append(logp, LOGFL_NODUPS, LOG_WARNING, "** WARNING: Could not find any XML->Python "
			   "mapping for type ID '%s'", typeid);
                return NULL;
        }
        // Create an internal map structure and return this structure
        return _do_dmimap_parsing_typeid(logp, node);
}


/**
 * Exported function for parsing a XML mapping document for a given Type ID to a ptzMAP
 * @author David Sommerseth <davids@redhat.com>
 * @param xmlDoc*     Pointer to the XML mapping document
 * @param const char* The Type ID to create the map for
 * @return ptzMAP*    The parsed XML containing as a ptzMAP
 */
ptzMAP *dmiMAP_ParseMappingXML_TypeID(Log_t *logp, xmlDoc *xmlmap, int typeid) {
        xmlNode *node = NULL;
        char typeid_s[16];

        node = dmiMAP_GetRootElement(xmlmap);
        if( node == NULL ) {
                PyReturnError(PyExc_RuntimeError, "Could not locate root XML node for mapping file");
        }

        memset(&typeid_s, 0, 16);
        snprintf(typeid_s, 14, "0x%02X", typeid);

        // Find the <TypeMapping> section
        node = dmixml_FindNode(node, "TypeMapping");
        assert( node != NULL );
        return _dmimap_parse_mapping_node_typeid(logp, node, typeid_s);
}


/**
 * Internal parser for GroupMapping (group of types).  Converts a given GroupMapping to a ptzMAP
 * from a XML node set
 * @author Nima Talebi <nima@autonomy.net.au>
 * @author David Sommerseth <davids@redhat.com>
 * @param xmlNode*  The source XML nodes of what to parse to a ptzMAP
 * @param xmlDoc*   A pointer to the source map, used for further parsing of each type defined in the GroupMapping
 * @return ptzMAP*  The resulting ptzMAP of the parsed xmlNode group mapping
 */
ptzMAP *_do_dmimap_parsing_group(Log_t *logp, xmlNode *node, xmlDoc *xmlmap) {
        ptzMAP *retmap = NULL;
        xmlNode *ptr_n = NULL, *map_n = NULL, *typemap = NULL;
        char *type_id;

        // Go to the next XML_ELEMENT_NODE
        foreach_xmlnode(node, map_n) {
                if( map_n->type == XML_ELEMENT_NODE ) {
                        break;
                }
        }
        if( map_n == NULL ) {
                PyReturnError(PyExc_RuntimeError, "Could not find any valid XML nodes");
        }

        // Check that our "root" node is as expected
        if( xmlStrcmp(node->name, (xmlChar *) "Mapping") != 0 ) {
                PyReturnError(PyExc_NameError, "Expected to find <Mapping> node");
        }

        // Go to the first <TypeMap> node
        map_n = dmixml_FindNode(node, "TypeMap");
        if( map_n == NULL ) {
                PyReturnError(PyExc_NameError, "Could not locate any <TypeMap> nodes");
        }

        // Get the root element of the <TypeMapping> tag, needed for further parsing
        typemap = dmixml_FindNode(xmlDocGetRootElement(xmlmap), "TypeMapping");
        if( typemap == NULL ) {
                PyReturnError(PyExc_NameError, "Could not locate the <TypeMapping> node");
        }

        // Loop through it's children
        foreach_xmlnode(map_n, ptr_n) {
                // Validate if we have the right node name
                if( xmlStrcmp(ptr_n->name, (xmlChar *) "TypeMap") != 0 ) {
                        continue; // Skip unexpected tag names
                }

                // Make sure that we have an id attribute before trying to locate that in th
                if( (type_id = dmixml_GetAttrValue(ptr_n, "id")) != NULL) {
                        ptzMAP *map = NULL;

                        map = _dmimap_parse_mapping_node_typeid(logp, typemap, type_id);
                        if( map ) {
                                retmap = ptzmap_AppendMap(retmap, map);
                        }
                }
        }
        return retmap;
}


/**
 * Exported function which parses a given GroupMapping (consisting of
 * one or more TypeMaps) into a ptzMAP
 * @author David Sommerseth <davids@redhat.com>
 * @param xmlDoc*      Pointer to the XML document holding the mapping
 * @param const char*  Defines which group mapping to parse to a ptzMAP
 * @return ptzMAP*     The parsed XML mapping in a ptzMAP
 */
ptzMAP *dmiMAP_ParseMappingXML_GroupName(Log_t *logp, xmlDoc *xmlmap, const char *mapname) {
        xmlNode *node = NULL;

        // Validate the XML mapping document and get the root element
        node = dmiMAP_GetRootElement(xmlmap);
        if( node == NULL ) {
                PyReturnError(PyExc_RuntimeError, "No valid mapping XML received");
        }

        // Find the <GroupMapping> section
        node = dmixml_FindNode(node, "GroupMapping");
        if( node == NULL ) {
                PyReturnError(PyExc_NameError, "Could not find the <GroupMapping> node");
        }

        // Find the <Mapping> section matching our request (mapname)
        node = dmixml_FindNodeByAttr(node, "Mapping", "name", mapname);
        if( node == NULL ) {
                PyReturnError(PyExc_NameError, "No group mapping for '%s' was found "
                              "in the XML-Python mapping file", mapname);
        }

        // Create an internal map structure and return this structure
        return _do_dmimap_parsing_group(logp, node, xmlmap);
}


/**
 * Internal function for converting a given mapped value to the appropriate Python data type
 * @author David Sommerseth <davids@redhat.com>
 * @param ptzMAP*      Pointer to the current mapping entry being parsed
 * @param const char * String which contains the value to be converted to a Python value
 * @return PyObject *  The converted value as a Python object
 */
inline PyObject *StringToPyObj(Log_t *logp, ptzMAP *val_m, const char *instr) {
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
                value = PYNUMBER_FROMLONG(atoi(workstr));
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
                value = PyBytes_FromString(workstr);
                break;

        default:
                log_append(logp, LOGFL_NODUPS, LOG_WARNING,
			   "Invalid type '%i' for value '%s'",
			   val_m->type_value, instr);
                value = Py_None;
        }
        return value;
}


/**
 * Retrieves a value from the data XML doc (via XPath Context) based on a XPath query
 * @author David Sommerseth <davids@redhat.com>
 * @param xmlXPathContext*  Pointer to the XPath context holding the source data
 * @param const char*       The XPath expression where to find the data
 * @return xmlXPathObject*  If data is found, it is returned in an XPath object for further processing
 */

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


/**
 * Retrieves the value which is to be used as the key value in a Python dictionary.
 * @author David Sommerseth <davids@redhat.com>
 * @param  char*             Pointer to the return buffer for the value
 * @param  size_t            Size of the return buffer
 * @param  ptzMAP*           Pointer to the current mapping entry which is being parsed
 * @param  xmlXPathContext*  Pointer to the XPath context containing the source data
 * @param  int               Defines which of the XPath results to use, if more is found
 * @returns char*            Returns a pointer to the return buffer (parameter 1) if key value
 *                           is found, or NULL if not found
 */
char *_get_key_value(Log_t *logp, char *key, size_t buflen,
		     ptzMAP *map_p, xmlXPathContext *xpctx, int idx)
{
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
                if( dmixml_GetXPathContent(logp, key, buflen, xpobj, idx) == NULL ) {
                        xmlXPathFreeObject(xpobj);
                        return NULL;
                }
                xmlXPathFreeObject(xpobj);
                break;

        default:
                log_append(logp, LOGFL_NODUPS, LOG_WARNING, "Unknown key type: %i", map_p->type_key);
                return NULL;
        }
        // We consider to have a key, if the first byte is a readable
        // character (usually starting at 0x20/32d)
        return ((key != NULL) && (strlen(key) > 0) ? key : NULL) ;
}


/**
 * Simple define to properly add a key/value pair to a Python dictionary
 * @author David Sommerseth <davids@redhat.com>
 * @param PyObject*    Pointer to the Python dictionary to be updated
 * @param const char*  String containing the key value
 * @param PyObject*    Pointer to the Python value
 */

#define PyADD_DICT_VALUE(p, k, v) {                                     \
                PyDict_SetItemString(p, k, v);                          \
                if( v != Py_None ) {                                    \
                        Py_DECREF(v);                                   \
                }                                                       \
        }


/**
 * Internal function for adding a XPath result to the resulting Python dictionary
 * @author David Sommerseth <davids@redhat.com>
 * @param PyObject*         Pointer to the resulting Python dictionary
 * @param xmlXPathContext*  Pointer to the XPath context containing the source data
 *                          (used for retrieving the key value)
 * @param ptzMAP*           Pointer to the current mapping entry being parsed
 * @param xmlXPathObject*   Pointer to XPath object containing the data value(s) for the dictionary
 */
inline void _add_xpath_result(Log_t *logp, PyObject *pydat, xmlXPathContext *xpctx, ptzMAP *map_p, xmlXPathObject *value) {
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
                        if( _get_key_value(logp, key, 256, map_p, xpctx, 0) != NULL ) {
                                PyADD_DICT_VALUE(pydat, key, Py_None);
                        }
                } else {
                        for( i = 0; i < value->nodesetval->nodeNr; i++ ) {
                                if( _get_key_value(logp, key, 256, map_p, xpctx, i) != NULL ) {
                                        dmixml_GetXPathContent(logp, val, 4097, value, i);
                                        PyADD_DICT_VALUE(pydat, key, StringToPyObj(logp, map_p, val));
                                }
                        }
                }
                break;
        default:
                if( _get_key_value(logp, key, 256, map_p, xpctx, 0) != NULL ) {
                        dmixml_GetXPathContent(logp, val, 4097, value, 0);
                        PyADD_DICT_VALUE(pydat, key, StringToPyObj(logp, map_p, val));
                }
                break;
        }
        free(key);
        free(val);
}


/**
 *  Internal XML parser routine, which traverses the given mapping table,
 *  returning a Python structure accordingly to the map.  Data for the Python dictionary is
 *  take from the input XML node.
 *  @author David Sommerseth <davids@redhat.com>
 *  @param PyObject*     Pointer to the Python dictionary of the result
 *  @param ptzMAP*       Pointer to the starting point for the further parsing
 *  @param xmlNode*      Pointer to the XML node containing the source data
 *  @param int           For debug purpose only, to keep track of which element being parsed
 *  @return PyObject*    Pointer to the input Python dictionary
 */
PyObject *_deep_pythonize(Log_t *logp, PyObject *retdata,
			  ptzMAP *map_p, xmlNode *data_n, int elmtid)
{
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
                if( _get_key_value(logp, key, 256, map_p, xpctx, 0) != NULL ) {
                        value = PyBytes_FromString(map_p->value);
                        PyADD_DICT_VALUE(retdata, key, value);
                } else {
                        PyReturnError(PyExc_ValueError, "Could not get key value: %s [%i] (Defining key: %s)",
                                      map_p->rootpath, elmtid, map_p->key);
                }
                break;

        case ptzSTR:
        case ptzINT:
        case ptzFLOAT:
        case ptzBOOL:
                xpo = _get_xpath_values(xpctx, map_p->value);
                if( xpo != NULL ) {
                        _add_xpath_result(logp, retdata, xpctx, map_p, xpo);
                        xmlXPathFreeObject(xpo);
                }
                break;

        case ptzLIST_STR:
        case ptzLIST_INT:
        case ptzLIST_FLOAT:
        case ptzLIST_BOOL:
                xpo = _get_xpath_values(xpctx, map_p->value);
                if( xpo != NULL ) {
                        if( _get_key_value(logp, key, 256, map_p, xpctx, 0) != NULL ) {
                                if( (xpo->nodesetval != NULL) && (xpo->nodesetval->nodeNr > 0) ) {
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
                                                dmixml_GetXPathContent(logp, valstr, 4097, xpo, i);

                                                // If we have a fixed list and we have a index value for the list
                                                if( (map_p->fixed_list_size > 0) && (map_p->list_index != NULL) ) {
                                                        char *idx = NULL;

                                                        idx = dmixml_GetAttrValue(xpo->nodesetval->nodeTab[i],
                                                                                  map_p->list_index);
                                                        if( idx != NULL ) {
                                                                PyList_SetItem(value, atoi(idx)-1,
                                                                               StringToPyObj(logp,
											     map_p, valstr)
                                                                               );
                                                        }
                                                } else {
                                                        // No list index - append the value
                                                        PyList_Append(value,StringToPyObj(logp,map_p,valstr));
                                                }
                                                free(valstr);
                                        }
                                } else {
                                        value = Py_None;
                                }
                                PyADD_DICT_VALUE(retdata, key, value);
                                xmlXPathFreeObject(xpo);
                        } else {
                                PyReturnError(PyExc_ValueError, "Could not get key value: "
                                              "%s [%i] (Defining key: %s)",
                                              map_p->rootpath, elmtid, map_p->key);
                        }
                }
                break;

        case ptzDICT:
                // Traverse children nodes
                if( map_p->child == NULL ) {
                        break;
                }
                if( _get_key_value(logp, key, 256, map_p, xpctx, 0) == NULL ) {
                        PyReturnError(PyExc_ValueError,
                                      "Could not get key value: %s [%i] (Defining key: %s)",
                                      map_p->rootpath, elmtid, map_p->key);
                }
                // Use recursion when procession child elements
                value = pythonizeXMLnode(logp, map_p->child, data_n);
                PyADD_DICT_VALUE(retdata, key, (value != NULL ? value : Py_None));
                break;

        case ptzLIST_DICT:  // List of dict arrays
                if( map_p->child == NULL ) {
                        break;
                }
                if( _get_key_value(logp, key, 256, map_p, xpctx, 0) == NULL ) {
                        PyReturnError(PyExc_ValueError,
                                      "Could not get key value: %s [%i] (Defining key: %s)",
                                      map_p->rootpath, elmtid, map_p->key);
                }

                // Iterate all nodes which is found in the 'value' XPath
                xpo = _get_xpath_values(xpctx, map_p->value);
                if( (xpo == NULL) || (xpo->nodesetval == NULL) || (xpo->nodesetval->nodeNr == 0) ) {
                        if( xpo != NULL ) {
                                xmlXPathFreeObject(xpo);
                        }
                        PyReturnError(PyExc_ValueError,
                                      "Could not get key value: %s [%i] (Defining key: %s)",
                                      map_p->rootpath, elmtid, map_p->key);
                }

                // Prepare a data list
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
                        PyObject *dataset = NULL;

                        dataset = pythonizeXMLnode(logp, map_p->child, xpo->nodesetval->nodeTab[i]);
                        if( dataset != NULL ) {
                                // If we have a fixed list and we have a index value for the list
                                if( (map_p->fixed_list_size > 0) && (map_p->list_index != NULL) ) {
                                        char *idx = NULL;
                                        idx = dmixml_GetAttrValue(xpo->nodesetval->nodeTab[i],
                                                                  map_p->list_index);
                                        if( idx != NULL ) {
                                                PyList_SetItem(value, atoi(idx)-1, dataset);
                                        }
                                } else {
                                        // No list index - append the value
                                        PyList_Append(value, dataset);
                                }
                        } else {
                                // If NULL, something is wrong - exception is already set.
                                return NULL;
                        }
                }
                PyADD_DICT_VALUE(retdata, key, value);
                xmlXPathFreeObject(xpo);
                break;

        default:
                log_append(logp, LOGFL_NODUPS, LOG_WARNING, "Unknown value type: %i", map_p->type_value);
                break;
        }

        free(key);
        xmlXPathFreeContext(xpctx);
        xmlFreeDoc(xpdoc);
        return retdata;
}


/**
 * Exported function, for parsing a XML node to a Python dictionary based on the given ptzMAP
 * @author David Sommerseth <davids@redhat.com>
 * @param ptzMAP*    The map descriping the resulting Python dictionary
 * @param xmlNode*   XML node pointer to the source data to be used for populating the Python dictionary
 */
PyObject *pythonizeXMLnode(Log_t *logp, ptzMAP *in_map, xmlNode *data_n) {
        xmlXPathContext *xpctx = NULL;
        xmlDoc *xpdoc = NULL;
        PyObject *retdata = NULL;
        ptzMAP *map_p = NULL;
        char *key = NULL;

        if( (in_map == NULL) || (data_n == NULL) ) {
                PyReturnError(PyExc_RuntimeError, "pythonXMLnode() - xmlNode or ptzMAP is NULL");
        }

        key = (char *) malloc(258);
        if( key == NULL ) {
                PyReturnError(PyExc_MemoryError, "Could not allocate temporary buffer");
        }

        // Loop through all configured elements
        retdata = PyDict_New();
        foreach_xmlnode(in_map, map_p) {
                if( (map_p->type_value == ptzDICT) && (map_p->rootpath != NULL) ) {
                        xmlXPathObject *xpo = NULL;
                        int i;

                        // Set the root node in the XPath context
                        xpdoc = xmlNewDoc((xmlChar *) "1.0");
                        assert( xpdoc != NULL );
                        xmlDocSetRootElement(xpdoc, xmlCopyNode(data_n, 1));

                        xpctx = xmlXPathNewContext(xpdoc);
                        if( xpctx == NULL ) {
                                PyReturnError(PyExc_MemoryError, "Could not setup new XPath context");
                        }
                        xpctx->node = data_n;

                        xpo = _get_xpath_values(xpctx, map_p->rootpath);
                        if( (xpo != NULL) && (xpo->nodesetval != NULL) && (xpo->nodesetval->nodeNr > 0) ) {
                                for( i = 0; i < xpo->nodesetval->nodeNr; i++ ) {
                                        xpctx->node = xpo->nodesetval->nodeTab[i];

                                        if( _get_key_value(logp, key, 256, map_p, xpctx, 0) != NULL ) {
                                                PyObject *res = _deep_pythonize(logp, retdata, map_p,
                                                                                xpo->nodesetval->nodeTab[i], i);
                                                if( res == NULL ) {
                                                        // Exit if we get NULL - something is wrong
                                                        //and exception is set
                                                        return NULL;
                                                }
                                        }
                                }
                                xmlXPathFreeContext(xpctx);
                                xmlFreeDoc(xpdoc);
                        }
#ifdef DEBUG
                        else {
                                log_append(logp, LOGFL_NODUPS, LOG_WARNING,
					   "** pythonizeXMLnode :: Could not locate node for key value: "
					   "root path '%s', key '%s'", map_p->rootpath, map_p->key);
                        }
#endif
                        if( xpo != NULL ) {
                                xmlXPathFreeObject(xpo); xpo = NULL;
                        }
                } else {
                        PyObject *res = _deep_pythonize(logp, retdata, map_p, data_n, 0);
                        if( res == NULL ) {
                                // Exit if we get NULL - something is wrong
                                //and exception is set
                                return NULL;
                        }
                }
        }
        free(key);
        return retdata;
}


/**
 * Exported function, for parsing a XML document to a Python dictionary based on the given ptzMAP
 * @author David Sommerseth <davids@redhat.com>
 * @param ptzMAP*    The map descriping the resulting Python dictionary
 * @param xmlDoc*    XML document pointer to the source data to be used for populating the Python dictionary
 */
PyObject *pythonizeXMLdoc(Log_t *logp, ptzMAP *map, xmlDoc *doc)
{
        xmlNode *node = NULL;

        node = xmlDocGetRootElement(doc);
        return pythonizeXMLnode(logp, map, node);
}


#if 0
// Simple independent main function - only for debugging
int main(int argc, char **argv) {
        xmlDoc *doc = NULL, *data = NULL;
        ptzMAP *map = NULL;
        PyObject *pydat = NULL;

        Py_Initialize();

        doc = xmlReadFile("pymap.xml", NULL, 0);
        assert( doc != NULL );

        map = dmiMAP_ParseMappingXML_GroupName(doc, argv[1]);
        // map = dmiMAP_ParseMappingXML_TypeID(doc, atoi(rgv[1]));
        ptzmap_Dump(map);
        printf("----------------------\n");
        assert(map != NULL);

        data = xmlReadFile(argv[2], NULL, 0);
        assert( data != NULL );

        pydat = pythonizeXMLdoc(map, data);
        assert( pydat != NULL );

        Py_INCREF(pydat);
        printf("\n\n");
        PyObject_Print(pydat, stdout, 0);
        Py_DECREF(pydat);
        printf("\n\n");
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

        PyObject *version = PyString_FromString(VERSION);
        Py_INCREF(version);
        PyModule_AddObject(module, "version", version);
}
#endif // Python test module


