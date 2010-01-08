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

#ifndef _XMLPYTHONIZER_H
#define _XMLPYTHONIZER_H

typedef enum ptzTYPES_e { ptzCONST, ptzSTR, ptzINT, ptzFLOAT, ptzBOOL,
                          ptzLIST_STR, ptzLIST_INT, ptzLIST_FLOAT, ptzLIST_BOOL,
                          ptzDICT, ptzLIST_DICT } ptzTYPES;

typedef struct ptzMAP_s {
        char *rootpath;         // XML root path for the data - if NULL, XML document is the root document.

        ptzTYPES type_key;      // Valid types: ptzCONST, ptzSTR, ptzINT, ptzFLOAT
        char *key;              // for ptzCONST key contains a static string, other types an XPath to XML data
        ptzTYPES type_value;
        char *value;            // for ptzCONST key contains a static string,
                                // the rest of types, an XPath to XML data
        int fixed_list_size;    // Only to be used on lists
        char *list_index ;      // Only to be used on fixed lists
        int emptyIsNone;        // If set to 1, empty input (right trimmed) strings sets the result to Py_None
        char *emptyValue;       // If set, this value will be used when input is empty
        struct ptzMAP_s *child; // Only used for type_value == (ptzDICT || ptzLIST_DICT)
        struct ptzMAP_s *next;  // Pointer chain

} ptzMAP;

xmlNode *dmiMAP_GetRootElement(xmlDoc *mapdoc);
ptzMAP *dmiMAP_ParseMappingXML_TypeID(Log_t *logp, xmlDoc *xmlmap, int typeid);
ptzMAP *dmiMAP_ParseMappingXML_GroupName(Log_t *logp, xmlDoc *xmlmap, const char *mapname);
#define ptzmap_Free(ptr) { ptzmap_Free_func(ptr); ptr = NULL; }
void ptzmap_Free_func(ptzMAP *ptr);

PyObject *pythonizeXMLdoc(Log_t *logp, ptzMAP *map, xmlDoc *xmldoc);
PyObject *pythonizeXMLnode(Log_t *logp, ptzMAP *map, xmlNode *nodes);

#endif // _XMLPYTHONIZER_H
