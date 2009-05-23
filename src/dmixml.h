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

xmlAttr *dmixml_AddAttribute(xmlNode *node, const char *atrname, const char *fmt, ...);
xmlNode *dmixml_AddTextChild(xmlNode *node, const char *tagname, const char *fmt, ...);
xmlNode *dmixml_AddTextContent(xmlNode *node, const char *fmt, ...);

char *dmixml_GetAttrValue(xmlNode *node, const char *key);
xmlNode *dmixml_FindNodeByAttr(xmlNode *node, const char *key, const char *val);
xmlNode *dmixml_FindNode(xmlNode *, const char *key);
inline char *dmixml_GetContent(xmlNode *node);
inline char *dmixml_GetNodeContent(xmlNode *node, const char *key);
char *dmixml_GetXPathContent(char *buf, size_t buflen, xmlXPathObject *xpo, int idx);

#endif
