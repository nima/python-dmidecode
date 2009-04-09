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
#include <libxml/xmlstring.h>

// Internal function for dmixml_* functions ... builds up a variable xmlChar* string
xmlChar *dmixml_buildstr(size_t len, const char *fmt, va_list ap) {
        xmlChar *ret = NULL, *xmlfmt = NULL;

        ret = (xmlChar *) malloc(len+2);
        assert( ret != NULL );
        memset(ret, 0, len+2);

        xmlfmt = xmlCharStrdup(fmt);
        assert( xmlfmt != NULL );

        xmlStrVPrintf(ret, len, xmlfmt, ap);
        free(xmlfmt);

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

        res = xmlNewProp(node, atrname_s, val_s);

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

        res = xmlNewTextChild(node, NULL, tagname_s, val_s);

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

        res = xmlAddChild(node, xmlNewText(val_s));
        free(val_s);

        assert( res != NULL );
        return res;
}

