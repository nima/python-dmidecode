#!/usr/bin/env python3
"""
Test script to verify the ElementTree port works correctly.
This tests the Python API changes without requiring the C extension to be rebuilt.
"""

import sys
import os

# Add the current directory to Python path so we can import our modified dmidecode
sys.path.insert(0, '.')

# Mock the dmidecodemod module before importing dmidecode
import mock_dmidecodemod
sys.modules['dmidecodemod'] = mock_dmidecodemod

def test_imports():
    """Test that we can import the module and it uses ElementTree"""
    try:
        import xml.etree.ElementTree as ET
        print("✅ Successfully imported xml.etree.ElementTree")
        
        # Try to import our modified dmidecode
        import dmidecode
        print("✅ Successfully imported dmidecode module")
        
        # Check that it's using our new classes
        assert hasattr(dmidecode, 'XmlNode'), "XmlNode class not found"
        assert hasattr(dmidecode, 'XmlDoc'), "XmlDoc class not found"
        print("✅ Found XmlNode and XmlDoc classes")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False
    except AssertionError as e:
        print(f"❌ Assertion failed: {e}")
        return False

def test_wrapper_classes():
    """Test that our wrapper classes work correctly"""
    try:
        import dmidecode
        import xml.etree.ElementTree as ET
        
        # Create a test XML element
        test_xml = """<?xml version="1.0"?>
        <dmi>
            <system_information>
                <manufacturer>Test Manufacturer</manufacturer>
                <product_name>Test Product</product_name>
            </system_information>
        </dmi>"""
        
        # Parse with ElementTree
        root = ET.fromstring(test_xml)
        
        # Test XmlNode wrapper
        xml_node = dmidecode.XmlNode(root)
        assert hasattr(xml_node, 'element'), "XmlNode missing element attribute"
        assert hasattr(xml_node, '_obj'), "XmlNode missing _obj attribute"
        print("✅ XmlNode wrapper class works correctly")
        
        # Test XmlDoc wrapper
        tree = ET.ElementTree(root)
        xml_doc = dmidecode.XmlDoc(tree)
        assert hasattr(xml_doc, 'element_tree'), "XmlDoc missing element_tree attribute"
        assert hasattr(xml_doc, '_obj'), "XmlDoc missing _obj attribute"
        assert hasattr(xml_doc, 'getroot'), "XmlDoc missing getroot method"
        print("✅ XmlDoc wrapper class works correctly")
        
        return True
        
    except Exception as e:
        print(f"❌ Wrapper class test failed: {e}")
        return False

def test_dmidecode_xml_class():
    """Test that the dmidecodeXML class works with our changes"""
    try:
        import dmidecode
        
        # Create instance
        dmi_xml = dmidecode.dmidecodeXML()
        assert dmi_xml.restype == dmidecode.DMIXML_NODE, "Default restype should be DMIXML_NODE"
        print("✅ dmidecodeXML instance created successfully")
        
        # Test SetResultType
        result = dmi_xml.SetResultType(dmidecode.DMIXML_NODE)
        assert result is True, "SetResultType should return True"
        assert dmi_xml.restype == dmidecode.DMIXML_NODE
        
        result = dmi_xml.SetResultType(dmidecode.DMIXML_DOC)
        assert result is True, "SetResultType should return True"
        assert dmi_xml.restype == dmidecode.DMIXML_DOC
        print("✅ SetResultType method works correctly")
        
        # Test invalid type
        try:
            dmi_xml.SetResultType('invalid')
            print("❌ SetResultType should have raised TypeError for invalid type")
            return False
        except TypeError:
            print("✅ SetResultType correctly rejects invalid types")
        
        return True
        
    except Exception as e:
        print(f"❌ dmidecodeXML class test failed: {e}")
        return False

def test_xml_parsing():
    """Test that our XML parsing method works"""
    try:
        import dmidecode
        
        # Create instance
        dmi_xml = dmidecode.dmidecodeXML()
        
        # Test XML string parsing
        test_xml = """<?xml version="1.0"?>
        <system_information>
            <manufacturer>Test Manufacturer</manufacturer>
            <product_name>Test Product</product_name>
        </system_information>"""
        
        # Test with DMIXML_NODE
        dmi_xml.SetResultType(dmidecode.DMIXML_NODE)
        result = dmi_xml._create_xml_from_string(test_xml)
        assert isinstance(result, dmidecode.XmlNode), f"Expected XmlNode, got {type(result)}"
        assert hasattr(result, 'element'), "Result should have element attribute"
        print("✅ XML parsing for DMIXML_NODE works correctly")
        
        # Test with DMIXML_DOC
        dmi_xml.SetResultType(dmidecode.DMIXML_DOC)
        result = dmi_xml._create_xml_from_string(test_xml)
        assert isinstance(result, dmidecode.XmlDoc), f"Expected XmlDoc, got {type(result)}"
        assert hasattr(result, 'element_tree'), "Result should have element_tree attribute"
        print("✅ XML parsing for DMIXML_DOC works correctly")
        
        # Test invalid XML
        try:
            dmi_xml._create_xml_from_string("<invalid xml")
            print("❌ Should have raised ValueError for invalid XML")
            return False
        except ValueError as e:
            print(f"✅ Correctly handles invalid XML: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ XML parsing test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("Testing ElementTree port implementation...")
    print("=" * 50)
    
    tests = [
        ("Import Tests", test_imports),
        ("Wrapper Class Tests", test_wrapper_classes),
        ("dmidecodeXML Class Tests", test_dmidecode_xml_class),
        ("XML Parsing Tests", test_xml_parsing),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🧪 Running {test_name}...")
        if test_func():
            passed += 1
        else:
            print(f"❌ {test_name} failed")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The ElementTree port is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Please check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())