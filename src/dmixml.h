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

#ifndef _XMLHELPER_H
#define _XMLHELPER_H

#include <stdarg.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

#define foreach_xmlnode(n, itn) for( itn = n; itn != NULL; itn = itn->next )

xmlAttr *dmixml_AddAttribute(xmlNode *node, const char *atrname, const char *fmt, ...);
xmlNode *dmixml_AddTextChild(xmlNode *node, const char *tagname, const char *fmt, ...);
xmlNode *dmixml_AddDMIstring(xmlNode *node, const char *tagname, const struct dmi_header *dm, u8 s);
xmlNode *dmixml_AddTextContent(xmlNode *node, const char *fmt, ...);

char *dmixml_GetAttrValue(xmlNode *node, const char *key);

xmlNode *__dmixml_FindNodeByAttr(xmlNode *, const char *, const char *, const char *, int);

/**
 * Retrieve a pointer to an XML node based on tag name and a specified attribute value.  To get
 * a hit, tag name and the attribute must be found and the value of the attribute must match as well.
 * The function will traverse all children nodes of the given input node, but it will not go deeper.
 * Matching is case sensitive.
 * @author David Sommerseth <davids@redhat.com>
 * @author Nima Talebi <nima@autonomy.net.au>
 * @param  xmlNode*      Pointer to the XML node of where to start searching
 * @param  const char*   Tag name the function will search for
 * @param  const char*   Attribute to check for in the tag
 * @param  const char*   Value of the attribute which must match to have a hit
 * @return xmlNode*      Pointer to the found XML node, NULL if no tag was found.
 */
#define dmixml_FindNodeByAttr(n, t, a, v) __dmixml_FindNodeByAttr(n, t, a, v, 1)

/**
 * Retrieve a pointer to an XML node based on tag name and a specified attribute value.  To get
 * a hit, tag name and the attribute must be found and the value of the attribute must match as well.
 * The function will traverse all children nodes of the given input node, but it will not go deeper.
 * Matching is case INsensitive.
 * @author David Sommerseth <davids@redhat.com>
 * @author Nima Talebi <nima@autonomy.net.au>
 * @param  xmlNode*      Pointer to the XML node of where to start searching
 * @param  const char*   Tag name the function will search for
 * @param  const char*   Attribute to check for in the tag
 * @param  const char*   Value of the attribute which must match to have a hit
 * @return xmlNode*      Pointer to the found XML node, NULL if no tag was found.
 */
#define dmixml_FindNodeByAttr_NoCase(n, t, a, v) __dmixml_FindNodeByAttr(n, t, a, v, 0)


xmlNode *dmixml_FindNode(xmlNode *, const char *key);
inline char *dmixml_GetContent(xmlNode *node);
inline char *dmixml_GetNodeContent(xmlNode *node, const char *key);
char *dmixml_GetXPathContent(Log_t *logp, char *buf, size_t buflen, xmlXPathObject *xpo, int idx);

#endif
