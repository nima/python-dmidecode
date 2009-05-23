/*  Simplified XML API for dmidecode
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

#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlstring.h>

// Internal function for dmixml_* functions ... builds up a variable xmlChar* string
xmlChar *dmixml_buildstr(size_t len, const char *fmt, va_list ap) {
        xmlChar *ret = NULL, *xmlfmt = NULL;
        xmlChar *ptr = NULL;

        ret = (xmlChar *) malloc(len+2);
        assert( ret != NULL );
        memset(ret, 0, len+2);

        xmlfmt = xmlCharStrdup(fmt);
        assert( xmlfmt != NULL );

        xmlStrVPrintf(ret, len, xmlfmt, ap);
        free(xmlfmt);

        // Right trim the string
        ptr = ret + xmlStrlen(ret)-1;
        while( (ptr >= ret) && (*ptr == ' ') ) {
                *ptr = 0;
                ptr--;
        }
        return ret;
}


// Adds an XML property/attribute to the given XML node
//
//  xmldata_n = "<test/>";
//  dmixml_AddAttribute(xmldata_n, "value", "1234");
//  gives: xmldata_n = "<test value="1234/>"
//

xmlAttr *dmixml_AddAttribute(xmlNode *node, const char *atrname, const char *fmt, ...)
{
        xmlChar *val_s = NULL, *atrname_s = NULL;
        xmlAttr *res = NULL;
        va_list ap;

        if( (node == NULL) || (atrname == NULL) || (fmt == NULL) ) {
                return NULL;
        }

        atrname_s = xmlCharStrdup(atrname);
        assert( atrname_s != NULL );

        va_start(ap, fmt);
        val_s = dmixml_buildstr(2048, fmt, ap);
        va_end(ap);

        res = xmlNewProp(node, atrname_s,
                         (xmlStrcmp(val_s, (xmlChar *) "(null)") == 0 ? NULL : val_s));

        free(atrname_s);
        free(val_s);

        assert( res != NULL );
        return res;
}


// Adds a new XML tag to the current node with the given tag name and value.
//
//  xmldata_n = "<test>";
//  dmixml_AddTextChild(xmldata_n, "sublevel1", "value");
//  gives: xmldata_n = "<test><sublevel1>value</sublevel1></test>"
//
xmlNode *dmixml_AddTextChild(xmlNode *node, const char *tagname, const char *fmt, ...)
{
        xmlChar *val_s = NULL, *tagname_s = NULL;
        xmlNode *res = NULL;
        va_list ap;

        if( (node == NULL) || (tagname == NULL) || (fmt == NULL) ) {
                return NULL;
        }

        tagname_s = xmlCharStrdup(tagname);
        assert( tagname_s != NULL );

        va_start(ap, fmt);
        val_s = dmixml_buildstr(2048, fmt, ap);
        va_end(ap);

        // Do not add any contents if the string contents is "(null)"
        res = xmlNewTextChild(node, NULL, tagname_s,
                              (xmlStrcmp(val_s, (xmlChar *) "(null)") == 0 ? NULL : val_s));

        free(tagname_s);
        free(val_s);

        assert( res != NULL );
        return res;
}

// Adds a text node child to the current XML node
//
//  xmldata_n = "<testdata/>;
//  dmixml_AddTextContent(xmldata_n, "some data value");
//  gives: xmldata_n = "<testdata>some data value</testdata>"
//
xmlNode *dmixml_AddTextContent(xmlNode *node, const char *fmt, ...)
{
        xmlChar *val_s = NULL;
        xmlNode *res = NULL;
        va_list ap;

        if( (node == NULL) || (fmt == NULL) ) {
                return NULL;
        }

        va_start(ap, fmt);
        val_s = dmixml_buildstr(2048, fmt, ap);
        va_end(ap);

        if( xmlStrcmp(val_s, (xmlChar *) "(null)") != 0 ) {
                res = xmlAddChild(node, xmlNewText(val_s));
        } else {
                res = node;
        }
        free(val_s);

        assert( res != NULL );
        return res;
}


char *dmixml_GetAttrValue(xmlNode *node, const char *key) {
        xmlAttr *aptr = NULL;
        xmlChar *key_s = NULL;

        if( node == NULL ) {
                return NULL;
        }

        key_s = xmlCharStrdup(key);
        assert( key_s != NULL );

        for( aptr = node->properties; aptr != NULL; aptr = aptr->next ) {
                if( xmlStrcmp(aptr->name, key_s) == 0 ) {
                        free(key_s); key_s = NULL;
                        // FIXME: Should find better way how to return UTF-8 data
                        return (char *)(aptr->children != NULL ? aptr->children->content : NULL);
                }
        }
        free(key_s); key_s = NULL;
        return NULL;
}

xmlNode *dmixml_FindNodeByAttr(xmlNode *node, const char *key, const char *val) {
        xmlNode *ptr_n = NULL;
        xmlChar *key_s = NULL;
        xmlChar *val_s = NULL;
        xmlChar *_val_s = NULL;

        if( node->children == NULL ) {
                return NULL;
        }

        key_s = xmlCharStrdup(key);
        assert( key_s != NULL );
        val_s = xmlCharStrdup(val);
        assert( val_s != NULL );

        for( ptr_n = node->children; ptr_n != NULL; ptr_n = ptr_n->next ) {
                _val_s = xmlCharStrdup(dmixml_GetAttrValue(ptr_n, (const char *)key_s));
                if( (ptr_n->type == XML_ELEMENT_NODE)
                    && (xmlStrcmp(val_s, _val_s) == 0) ) {
                        free(val_s); val_s = NULL;
                        free(key_s); key_s = NULL;
                        return ptr_n;
                }
                free(_val_s);
        }
        free(key_s); key_s = NULL;
        free(val_s); val_s = NULL;
        return NULL;
}

xmlNode *dmixml_FindNode(xmlNode *node, const char *key) {
        xmlNode *ptr_n = NULL;
        xmlChar *key_s = NULL;

        if( node->children == NULL ) {
                return NULL;
        }

        key_s = xmlCharStrdup(key);
        assert( key_s != NULL );

        for( ptr_n = node->children; ptr_n != NULL; ptr_n = ptr_n->next ) {
                if( (ptr_n->type == XML_ELEMENT_NODE)
                    && (xmlStrcmp(ptr_n->name, key_s) == 0) ) {
                        free(key_s); key_s = NULL;
                        return ptr_n;
                }
        }
        free(key_s); key_s = NULL;
        return NULL;
}

inline char *dmixml_GetContent(xmlNode *node) {
        // FIXME: Should find better way how to return UTF-8 data
        return (((node != NULL) && (node->children != NULL)) ? (char *) node->children->content : NULL);
}

inline char *dmixml_GetNodeContent(xmlNode *node, const char *key) {
        return dmixml_GetContent(dmixml_FindNode(node, key));
}

char *dmixml_GetXPathContent(char *buf, size_t buflen, xmlXPathObject *xpo, int idx) {
        memset(buf, 0, buflen);

        if( xpo == NULL ) {
                return NULL;
        }

        switch( xpo->type ) {
        case XPATH_STRING:
                strncpy(buf, (char *)xpo->stringval, buflen-1);
                break;

        case XPATH_NUMBER:
                snprintf(buf, buflen-1, "%f", xpo->floatval);
                break;

        case XPATH_NODESET:
                if( (xpo->nodesetval != NULL) && (xpo->nodesetval->nodeNr >= (idx+1)) ) {
                        char *str = dmixml_GetContent(xpo->nodesetval->nodeTab[idx]);
                        if( str != NULL ) {
                                strncpy(buf, str, buflen-1);
                        } else {
                                memset(buf, 0, buflen);
                        }
                }
                break;

        default:
                fprintf(stderr, "dmixml_GetXPathContent(...):: "
                        "Do not know how to handle XPath type %i\n",
                        xpo->type);
                return NULL;
        }
        return buf;
}

