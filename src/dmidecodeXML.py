import libxml2
import dmidecode

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
            ret = libxml2.xmlNode( _obj = dmidecode.xmlapi(query_type='s',
                                                           result_type=self.restype,
                                                           section=sectname) )
        elif self.restype == DMIXML_DOC:
            ret = libxml2.xmlDoc( _obj = dmidecode.xmlapi(query_type='s',
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
            ret = libxml2.xmlNode( _obj = dmidecode.xmlapi(query_type='t',
                                                           result_type=self.restype,
                                                           typeid=tpid))
        elif self.restype == DMIXML_DOC:
            ret = libxml2.xmlDoc( _obj = dmidecode.xmlapi(query_type='t',
                                                          result_type=self.restype,
                                                          typeid=tpid))
        else:
            raise TypeError, "Invalid result type value"

        return ret

