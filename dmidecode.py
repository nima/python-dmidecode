#
#   dmidecode.py
#   Module front-end for the python-dmidecode module.
#
#   Copyright 2009      David Sommerseth <davids@redhat.com>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
#
#   For the avoidance of doubt the "preferred form" of this code is one which
#   is in an open unpatent encumbered format. Where cryptographic key signing
#   forms part of the process of creating an executable the information
#   including keys needed to generate an equivalently functional executable
#   are deemed to be part of the source code.
#

import xml.etree.ElementTree as ET
from dmidecodemod import *

DMIXML_NODE='n'
DMIXML_DOC='d'

class XmlNode:
    """
    Wrapper class to provide libxml2.xmlNode-like interface using ElementTree.Element
    """
    def __init__(self, element):
        self.element = element
        self._obj = element  # Maintain compatibility with libxml2 interface
    
    def __getattr__(self, name):
        """Delegate attribute access to the underlying Element"""
        element = object.__getattribute__(self, 'element')
        return getattr(element, name)

class XmlDoc:
    """
    Wrapper class to provide libxml2.xmlDoc-like interface using ElementTree.ElementTree
    """
    def __init__(self, element_tree):
        self.element_tree = element_tree
        self._obj = element_tree.getroot()  # Maintain compatibility
    
    def getroot(self):
        """Get the root element"""
        return self.element_tree.getroot()
    
    def __getattr__(self, name):
        """Delegate attribute access to the underlying ElementTree"""
        element_tree = object.__getattribute__(self, 'element_tree')
        return getattr(element_tree, name)

class dmidecodeXML:
    "Native Python API for retrieving dmidecode information as XML"

    def __init__(self):
        self.restype = DMIXML_NODE;

    def SetResultType(self, type):
        """
        Sets the result type of queries.  The value can be DMIXML_NODE or DMIXML_DOC,
        which will return an XmlNode or XmlDoc object, respectively
        """

        if type == DMIXML_NODE:
            self.restype = DMIXML_NODE
        elif type == DMIXML_DOC:
            self.restype = DMIXML_DOC
        else:
            raise TypeError("Invalid result type value")
        return True

    def _create_xml_from_string(self, xml_string):
        """
        Internal method to create XML objects from string representation
        This will be used when the C extension returns XML as bytes (or str)
        """
        try:
            element = ET.fromstring(xml_string)
            if self.restype == DMIXML_NODE:
                return XmlNode(element)
            else:  # DMIXML_DOC
                tree = ET.ElementTree(element)
                return XmlDoc(tree)
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse XML: {e}") from e

    def QuerySection(self, sectname):
        """
        Queries the DMI data structure for a given section name.  A section
        can often contain several DMI type elements
        """
        # Get XML data as string from C extension
        xml_string = xmlapi('s', self.restype, sectname)
        
        # Convert to appropriate XML object
        return self._create_xml_from_string(xml_string)

    def QueryTypeId(self, tpid):
        """
        Queries the DMI data structure for a specific DMI type.
        """
        # Get XML data as string from C extension
        xml_string = xmlapi('t', self.restype, tpid)
        
        # Convert to appropriate XML object
        return self._create_xml_from_string(xml_string)
