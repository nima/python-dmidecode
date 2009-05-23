import libxml2
import demomodule # This is our core module

class POCDemo:
    """Demo of a wrapper class to return proper python libxml2 objects"""

    def GetXMLdoc(self):
        return libxml2.xmlDoc( _obj = demomodule.dump_doc() )

    def GetXMLnode(self):
        return libxml2.xmlNode( _obj = demomodule.dump_node() )

