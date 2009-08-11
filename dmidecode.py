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

import libxml2
from dmidecodemod import *

DMIXML_NODE='n'
DMIXML_DOC='d'

class dmidecodeXML:
    "Native Python API for retrieving dmidecode information as XML"

    def __init__(self):
        self.restype = DMIXML_NODE;

    def SetResultType(self, type):
        """
        Sets the result type of queries.  The value can be DMIXML_NODE or DMIXML_DOC,
        which will return an libxml2::xmlNode or libxml2::xmlDoc object, respectively
        """

        if type == DMIXML_NODE:
            self.restype = DMIXML_NODE
        elif type == DMIXML_DOC:
            self.restype = DMIXML_DOC
        else:
            raise TypeError, "Invalid result type value"
        return True

    def QuerySection(self, sectname):
        """
        Queries the DMI data structure for a given section name.  A section
        can often contain several DMI type elements
        """
        if self.restype == DMIXML_NODE:
            ret = libxml2.xmlNode( _obj = xmlapi(query_type='s',
                                                           result_type=self.restype,
                                                           section=sectname) )
        elif self.restype == DMIXML_DOC:
            ret = libxml2.xmlDoc( _obj = xmlapi(query_type='s',
                                                          result_type=self.restype,
                                                          section=sectname) )
        else:
            raise TypeError, "Invalid result type value"

        return ret


    def QueryTypeId(self, tpid):
        """
        Queries the DMI data structure for a specific DMI type.
        """
        if self.restype == DMIXML_NODE:
            ret = libxml2.xmlNode( _obj = xmlapi(query_type='t',
                                                           result_type=self.restype,
                                                           typeid=tpid))
        elif self.restype == DMIXML_DOC:
            ret = libxml2.xmlDoc( _obj = xmlapi(query_type='t',
                                                          result_type=self.restype,
                                                          typeid=tpid))
        else:
            raise TypeError, "Invalid result type value"

        return ret

