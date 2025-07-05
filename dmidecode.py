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

try:
    from lxml import etree
except ImportError:
    raise ImportError("lxml is required. Install with: pip install lxml")

from dmidecodemod import *
from lxml import etree
from dmidecodemod import xmlapi

DMIXML_NODE = 'n'
DMIXML_DOC = 'd'

class dmidecodeXML:
    "Native Python API for retrieving dmidecode information as XML"
    
    def __init__(self):
        self.restype = DMIXML_NODE

    def SetResultType(self, type):
        if type == DMIXML_NODE:
            self.restype = DMIXML_NODE
        elif type == DMIXML_DOC:
            self.restype = DMIXML_DOC
        else:
            raise TypeError("Invalid result type value")
        return True

    def QuerySection(self, sectname):
        try:
            query_args = {
                'query_type': 's',
                'result_type': 'n' if self.restype == DMIXML_NODE else 'd',
                'section': sectname
            }

            xml_string = xmlapi(**query_args)

            if not xml_string or not isinstance(xml_string, str):
                raise RuntimeError("C module did not return a valid XML string")

            if self.restype == DMIXML_NODE:
                return etree.fromstring(xml_string)
            elif self.restype == DMIXML_DOC:
                return etree.ElementTree(etree.fromstring(xml_string))
            else:
                raise TypeError("Invalid result type value")

        except Exception as e:
            raise RuntimeError(f"Failed to query section '{sectname}': {str(e)}")

    def QueryTypeId(self, tpid):
        try:
            tpid = int(tpid)
            query_args = {
                'query_type': 't',
                'result_type': 'n' if self.restype == DMIXML_NODE else 'd',
                'typeid': tpid
            }

            xml_string = xmlapi(**query_args)

            if not xml_string or not isinstance(xml_string, str):
                raise RuntimeError("C module did not return a valid XML string")

            if self.restype == DMIXML_NODE:
                return etree.fromstring(xml_string)
            elif self.restype == DMIXML_DOC:
                return etree.ElementTree(etree.fromstring(xml_string))
            else:
                raise TypeError("Invalid result type value")

        except Exception as e:
            raise RuntimeError(f"Failed to query type ID '{tpid}': {str(e)}")

# Convenience functions for backward compatibility
def query_section(sectname, result_type=DMIXML_NODE):
    """
    Convenience function to query a section and return lxml object
    """
    dmi = dmidecodeXML()
    dmi.SetResultType(result_type)
    return dmi.QuerySection(sectname)

def query_type_id(tpid, result_type=DMIXML_NODE):
    """
    Convenience function to query a type ID and return lxml object
    """
    dmi = dmidecodeXML()
    dmi.SetResultType(result_type)
    return dmi.QueryTypeId(tpid)

# Backward compatibility class for older API
class DMIDecode:
    def __init__(self):
        self.dmi = dmidecodeXML()

    def get(self, section=None, type_id=None):
        try:
            if section is not None:
                section = str(section)
                xml_data = self.dmi.QuerySection(section)
            elif type_id is not None:
                if isinstance(type_id, dict):
                    try:
                        type_id = int(list(type_id.keys())[0], 16)
                    except Exception as e:
                        raise ValueError(f"Invalid type_id dict format: {type_id}") from e
                else:
                    type_id = int(type_id)
                xml_data = self.dmi.QueryTypeId(type_id)
            else:
                raise ValueError("Either section or type_id must be specified")

            if xml_data is None:
                return {}

            return self._xml_to_dict(xml_data)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return {}

    def _xml_to_dict(self, xml_element):
        result = {}
        if xml_element.attrib:
            result.update(xml_element.attrib)
        if xml_element.text and xml_element.text.strip():
            if len(xml_element) == 0:
                return xml_element.text.strip()
            else:
                result['_text'] = xml_element.text.strip()
        for child in xml_element:
            child_data = self._xml_to_dict(child)
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
        return result

    def system(self):
        """Get system information"""
        return self.get(section="system")
    
    def bios(self):
        """Get BIOS information"""
        return self.get(type_id=0)
    
    def baseboard(self):
        """Get baseboard information"""
        return self.get(type_id=2)
    
    def chassis(self):
        """Get chassis information"""
        return self.get(type_id=3)
    
    def processor(self):
        """Get processor information"""
        return self.get(type_id=4)
    
    def memory(self):
        """Get memory information"""
        return self.get(section="memory")
    
    def model(self):
        """Get system model information"""
        try:
            system_info = self.get(section="system")
            if system_info and isinstance(system_info, dict):
                # Try to find model/product name in the system info
                # Look for common keys that might contain model info
                for key in ['product', 'model', 'product_name', 'system_product_name']:
                    if key in system_info:
                        return system_info[key]
                
                # If it's nested, try to find it in nested structures
                for value in system_info.values():
                    if isinstance(value, dict):
                        for subkey in ['product', 'model', 'product_name']:
                            if subkey in value:
                                return value[subkey]
            
            return "Unknown"
        except Exception as e:
            print(f"Error getting model info: {e}")
            return "Unknown"
    
    def manufacturer(self):
        """Get system manufacturer"""
        try:
            system_info = self.get(section="system")
            if system_info and isinstance(system_info, dict):
                for key in ['manufacturer', 'vendor', 'system_manufacturer']:
                    if key in system_info:
                        return system_info[key]
                
                # Check nested structures
                for value in system_info.values():
                    if isinstance(value, dict):
                        for subkey in ['manufacturer', 'vendor']:
                            if subkey in value:
                                return value[subkey]
            
            return "Unknown"
        except Exception as e:
            print(f"Error getting manufacturer info: {e}")
            return "Unknown"
    
    def version(self):
        """Get system version"""
        try:
            system_info = self.get(section="system")
            if system_info and isinstance(system_info, dict):
                for key in ['version', 'system_version']:
                    if key in system_info:
                        return system_info[key]
                
                # Check nested structures
                for value in system_info.values():
                    if isinstance(value, dict):
                        if 'version' in value:
                            return value['version']
            
            return "Unknown"
        except Exception as e:
            print(f"Error getting version info: {e}")
            return "Unknown"
    
    def serial(self):
        """Get system serial number"""
        try:
            system_info = self.get(section="system")
            if system_info and isinstance(system_info, dict):
                for key in ['serial', 'serial_number', 'system_serial']:
                    if key in system_info:
                        return system_info[key]
                
                # Check nested structures
                for value in system_info.values():
                    if isinstance(value, dict):
                        for subkey in ['serial', 'serial_number']:
                            if subkey in value:
                                return value[subkey]
            
            return "Unknown"
        except Exception as e:
            print(f"Error getting serial info: {e}")
            return "Unknown"
    
    def cpu_type(self):
        """Get CPU type/model information"""
        try:
            # Try processor section first
            proc_info = self.get(type_id=4)  # Type 4 is processor
            if proc_info and isinstance(proc_info, dict):
                # Look for CPU model/type info
                for key in ['version', 'model', 'name', 'processor_version', 'processor_name']:
                    if key in proc_info:
                        return proc_info[key]
                
                # Check nested structures
                for value in proc_info.values():
                    if isinstance(value, dict):
                        for subkey in ['version', 'model', 'name']:
                            if subkey in value:
                                return value[subkey]
            
            # If that fails, try a different approach
            return "Unknown"
        except Exception as e:
            print(f"Error getting CPU type: {e}")
            return "Unknown"
    
    def cpu(self):
        """Alias for cpu_type() for compatibility"""
        return self.cpu_type()

# Example usage functions
def get_system_info():
    """
    Get system information as a convenient dictionary
    """
    try:
        root = query_section("system")
        if root is None:
            return None
        
        system_info = {}
        
        # Extract common system information
        for elem in root.iter():
            if elem.tag == "manufacturer":
                system_info["manufacturer"] = elem.text
            elif elem.tag == "product":
                system_info["product"] = elem.text
            elif elem.tag == "version":
                system_info["version"] = elem.text
            elif elem.tag == "serial":
                system_info["serial"] = elem.text
            elif elem.tag == "uuid":
                system_info["uuid"] = elem.text
            elif elem.tag == "family":
                system_info["family"] = elem.text
        
        return system_info
    except Exception as e:
        print(f"Error getting system info: {e}")
        return None

def get_memory_info():
    """
    Get memory information as a list of memory modules
    """
    try:
        root = query_section("memory")
        if root is None:
            return None
        
        memory_modules = []
        
        # This is a simplified example - you'd need to adjust based on actual XML structure
        for device in root.findall(".//memory_device"):
            module = {}
            for child in device:
                module[child.tag] = child.text
            memory_modules.append(module)
        
        return memory_modules
    except Exception as e:
        print(f"Error getting memory info: {e}")
        return None
