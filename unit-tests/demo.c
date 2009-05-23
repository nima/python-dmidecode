/*
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

#include "demo.h"

xmlNode *gen_nodes(const char *entry ) {
        xmlNode *c_xmlNode_root = NULL;
        xmlNode *c_xmlNode_tag  = NULL;

        // Prepare a root node
        c_xmlNode_root = xmlNewNode(NULL, (xmlChar *) "dmixml_demo");
        assert( c_xmlNode_root != NULL );

        dmixml_AddAttribute(c_xmlNode_root, "entrypoint", "%s", entry);

        // Populate XML
        dmixml_AddTextChild(c_xmlNode_root, "Test", "Yes, just testing");

        c_xmlNode_tag = dmixml_AddTextChild(c_xmlNode_root, "tag1", "Another test");
        dmixml_AddAttribute(c_xmlNode_tag, "TestTagID", "%i", 1);

        c_xmlNode_tag = c_xmlNode_root;
        int i;
        for(i = 0; i <= 3; ++i) {
                c_xmlNode_tag = xmlNewChild(c_xmlNode_tag, NULL, (xmlChar *) "subtag", NULL);
                dmixml_AddAttribute(c_xmlNode_tag, "SubLevel", "%i", i);
        }
        dmixml_AddTextContent(c_xmlNode_tag, "%s - Adding data to the tag at sublevel %i", "TEST", i-1);

        return c_xmlNode_root;
}




PyObject* demo_dump_doc() {
        PyObject *py_xmlDoc     = NULL;
        xmlDoc *c_xmlDoc        = NULL;

        // Create an XML document
        c_xmlDoc = xmlNewDoc((xmlChar *) "1.0");
        assert( c_xmlDoc != NULL );

        // Generate XML nodes and assign the root node to the document
        xmlDocSetRootElement( c_xmlDoc, gen_nodes("demo_dump_doc") );

        py_xmlDoc  = libxml_xmlDocPtrWrap((xmlDocPtr) c_xmlDoc);
        Py_INCREF(py_xmlDoc);

        return py_xmlDoc;
}

PyObject* demo_dump_node() {
        PyObject *py_xmlNode    = NULL;
        xmlNode *nodes = NULL;

        nodes = gen_nodes("demo_dump_node");
        py_xmlNode = libxml_xmlNodePtrWrap((xmlNodePtr) nodes);
        Py_INCREF(py_xmlNode);

        return py_xmlNode;
}



static PyMethodDef DemoMethods[] = {
        { "dump_doc", demo_dump_doc, METH_NOARGS, (char *)"Return an XML document" },
        { "dump_node", demo_dump_node, METH_NOARGS, (char *)"Retuen an XML node" },
        { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initdemomodule(void) {
        PyObject *module =
            Py_InitModule3((char *)"demomodule", DemoMethods,
                           "LibXML2 DMIDecode Proof-of-Concept Python Module");

        PyObject *version = PyString_FromString("0.10");
        Py_INCREF(version);
        PyModule_AddObject(module, "version", version);
}
