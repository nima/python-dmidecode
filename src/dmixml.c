/*  Simplified XML API for dmidecode
 *
 *   Copyright 2009      David Sommerseth <davids@redhat.com>
 *   Copyright 2009      Nima Talebi <nima@autonomy.net.au>
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
 * @file dmixml.c
 * @brief  Helper functions for XML nodes and documents.
 * @author David Sommerseth <davids@redhat.com>
 * @author Nima Talebi <nima@autonomy.net.au>
 */



#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlstring.h>

#include "dmilog.h"
#include "dmixml.h"

/**
 * Internal function for dmixml_* functions.  The function will allocate a buffer and populate it
 * according to the format string
 * @author David Sommerseth <davids@redhat.com>
 * @param  size_t       The requested size for the new buffer
 * @param  const char*  The format of the string being built (uses vsnprintf())
 * @param  ...          The needed variables to build up the string
 * @return xmlChar*     Pointer to the buffer of the string
 */
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


/**
 * Add an XML property/attribute to the given XML node
 * @author David Sommerseth <davids@redhat.com>
 * @param  xmlNode*      A pointer to the xmlNode being updated
 * @param  const char*   The name of the attribute
 * @param  const char*   Value of the string (can make use of string formating options)
 * @return xmlAttr*      Pointer to the new attribute node.  On errors an assert is
 *                       triggered and return value should be NULL.
 */
xmlAttr *dmixml_AddAttribute(xmlNode *node, const char *atrname, const char *fmt, ...)
{
        xmlChar *val_s = NULL, *atrname_s = NULL;
        xmlAttr *res = NULL;
        va_list ap;

        if( (node == NULL) || (atrname == NULL) ) {
                return NULL;
        }

        atrname_s = xmlCharStrdup(atrname);
        assert( atrname_s != NULL );

	if( fmt == NULL ) {
		res = xmlNewProp(node, atrname_s, NULL);
		goto exit;
	}

        va_start(ap, fmt);
        val_s = dmixml_buildstr(2048, fmt, ap);
        va_end(ap);

        res = xmlNewProp(node, atrname_s,
                         (xmlStrcmp(val_s, (xmlChar *) "(null)") == 0 ? NULL : val_s));

        free(val_s);
 exit:
        free(atrname_s);

        assert( res != NULL );
        return res;
}


/**
 * Adds a new XML tag to the given node with the given tag name and value.
 * @author David Sommerseth <davids@redhat.com>
 * @param  xmlNode*      Pointer to the parent node for this new node
 * @param  const char*   Name of the new tag
 * @param  const char*   Contents of the new tag (can make use of string formating options)
 * @return xmlNode*      Pointer to the new tag. On errors an assert is triggered and return
 *                       value should be NULL.
 */
xmlNode *dmixml_AddTextChild(xmlNode *node, const char *tagname, const char *fmt, ...)
{
        xmlChar *val_s = NULL, *tagname_s = NULL;
        xmlNode *res = NULL;
        va_list ap;

        if( (node == NULL) || (tagname == NULL) ) {
                return NULL;
        }

        tagname_s = xmlCharStrdup(tagname);
        assert( tagname_s != NULL );

	if( fmt == NULL ) {
		res = xmlNewChild(node, NULL, tagname_s, NULL);
		goto exit;
	}

        va_start(ap, fmt);
        val_s = dmixml_buildstr(2048, fmt, ap);
        va_end(ap);

        // Do not add any contents if the string contents is "(null)"
        res = xmlNewTextChild(node, NULL, tagname_s,
                              (xmlStrcmp(val_s, (xmlChar *) "(null)") == 0 ? NULL : val_s));

        free(val_s);
 exit:
        free(tagname_s);

        assert( res != NULL );
        return res;
}

/**
 * Adds a text node child to the given  XML node.  If input is NULL, the tag contents will be empty.
 * @author David Sommerseth <davids@redhat.com>
 * @param xmlNode*        Pointer to the current node which will get the text child
 * @param const char*     Contents of the tag (can make use of string formating options)
 * @return xmlNode*       Pointer to the tags content node
 */
xmlNode *dmixml_AddTextContent(xmlNode *node, const char *fmt, ...)
{
        xmlChar *val_s = NULL;
        xmlNode *res = NULL;
        va_list ap;

        if( (node == NULL) || (fmt == NULL) ) {
                // Return node and not NULL, as node may not be NULL but fmt can be,
                // thus doing a similar string check (val_s != "(null)") as later on
                return node;
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

/**
 * Retrieve the contents of a named attribute in a given XML node
 * @author David Sommerseth <davids@redhat.com>
 * @param  xmlNode*     Pointer to the XML node of which we want to extract the attribute value
 * @param  const char*  The name of the attribute to be extracted
 * @return char*        Pointer to the attribute contents if found, otherwise NULL.  This value
 *                      must NOT be freed, as it points directly into the value in the XML document.
 */
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

/**
 * Internal function - Retrieve a pointer to an XML node based on tag name and a specified attribute
 * value.  To get a hit, tag name and the attribute must be found and the value of the attribute must
 * match as well.  The function will traverse all children nodes of the given input node, but it will
 * not go deeper.
 * @author David Sommerseth <davids@redhat.com>
 * @author Nima Talebi <nima@autonomy.net.au>
 * @param  xmlNode*      Pointer to the XML node of where to start searching
 * @param  const char*   Tag name the function will search for
 * @param  const char*   Attribute to check for in the tag
 * @param  const char*   Value of the attribute which must match to have a hit
 * @param  int           Be case sensitive or not.  1 == case sensitive, 0 == case insensitive
 * @return xmlNode*      Pointer to the found XML node, NULL if no tag was found.
 */
xmlNode *__dmixml_FindNodeByAttr(xmlNode *node, const char *tagkey, const char *attrkey,
                                 const char *val, int casesens) {
        xmlNode *ptr_n = NULL;
        xmlChar *tag_s = NULL;
        int (*compare_func) (const char *, const char *);

        assert( node != NULL );
        if( node->children == NULL ) {
                return NULL;
        }

        tag_s = xmlCharStrdup(tagkey);
        assert( tag_s != NULL );

        compare_func = (casesens == 1 ? strcmp : strcasecmp);

        foreach_xmlnode(node->children, ptr_n) {
                // To return the correct node, we need to check node type,
                // tag name and the attribute value of the given attribute.
                if( (ptr_n->type == XML_ELEMENT_NODE)
                    && (xmlStrcmp(ptr_n->name, tag_s) == 0)
                    && (compare_func(dmixml_GetAttrValue(ptr_n, attrkey), val) == 0 ) ) {
                        goto exit;
                }
        }
 exit:
        free(tag_s); tag_s = NULL;
        return ptr_n;
}

/**
 * Retrieve a poitner to an XML node with the given name.  The function will traverse
 * all children nodes of the given input node, but it will not go deeper.  The function
 * will only return the first hit.
 * @author David Sommerseth <davids@redhat.com>
 * @param  xmlNode*     Pointer to the XML node of where to start searching
 * @param  const char*  Name of the tag name the function will look for.
 * @return xmlNode*     Pointer to the found XML node, NULL if no tag was found.
 */
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

/**
 * Retrieve the text contents of the given XML node
 * @author David Sommerseth <davids@redhat.com>
 * @param  xmlNode*     Pointer to the XML node of which we want to extract the contents
 * @return char*        Pointer to the tag contents if found, otherwise NULL.  This value
 *                      must NOT be freed, as it points directly into the value in the XML document.
 */
inline char *dmixml_GetContent(xmlNode *node) {
        // FIXME: Should find better way how to return UTF-8 data
        return (((node != NULL) && (node->children != NULL)) ? (char *) node->children->content : NULL);
}

/**
 * Retrieve the text content of a given tag.  The function will traverse
 * all children nodes of the given input node, but it will not go deeper.
 * The function will only return the first hit.
 * @author David Sommerseth <davids@redhat.com>
 * @param  xmlNode*     Pointer to the XML node of where to start searching
 * @param  const char*  Name of the tag the function will look for
 * @return char*        Pointer to the tag contents if found, otherwise NULL.  This value
 *                      must NOT be freed, as it points directly into the value in the XML document.
 */
inline char *dmixml_GetNodeContent(xmlNode *node, const char *key) {
        return dmixml_GetContent(dmixml_FindNode(node, key));
}

/**
 * Retrieve the contents from an XPath object.
 * @author David Sommerseth <davids@redhat.com>
 * @param  char*            Pointer to a buffer where to return the value
 * @param  size_t           Size of the return buffer
 * @param  xmlXPathObject*  Pointer to the XPath object containing the data
 * @param  int              If the XPath object contains a node set, this defines
 *                          which of the elements to be extracted.
 * @return char*            Points at the return buffer if a value is found, otherwise NULL is returned.
 */
char *dmixml_GetXPathContent(Log_t *logp, char *buf, size_t buflen, xmlXPathObject *xpo, int idx) {
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
                log_append(logp, LOGFL_NORMAL, LOG_WARNING, "dmixml_GetXPathContent(...):: "
                           "Do not know how to handle XPath type %i",
                           xpo->type);
                return NULL;
        }
        return buf;
}
