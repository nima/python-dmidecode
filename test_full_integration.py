#!/usr/bin/env python3
"""
Full integration test for the ElementTree port.
Tests the complete workflow including the mock C extension interface.
"""

import sys
import xml.etree.ElementTree as ET

# Mock the dmidecodemod module before importing dmidecode
import mock_dmidecodemod
sys.modules['dmidecodemod'] = mock_dmidecodemod

# Now import our modified dmidecode
import dmidecode

def test_query_section_functionality():
    """Test QuerySection method with various sections"""
    print("🧪 Testing QuerySection functionality...")
    
    dmi_xml = dmidecode.dmidecodeXML()
    
    # Test with DMIXML_NODE (default)
    result = dmi_xml.QuerySection('bios')
    assert isinstance(result, dmidecode.XmlNode), f"Expected XmlNode, got {type(result)}"
    assert hasattr(result, 'element'), "Result should have element attribute"
    
    # Verify the XML content
    element = result.element
    assert element.tag == 'dmi', f"Expected root tag 'dmi', got '{element.tag}'"
    bios = element.find('bios')
    assert bios is not None, "Should have bios element"
    vendor = bios.find('vendor')
    assert vendor is not None and vendor.text == 'Test BIOS Vendor', f"Expected vendor text, got {vendor.text if vendor is not None else 'None'}"
    print("✅ QuerySection with DMIXML_NODE works correctly")
    
    # Test with DMIXML_DOC
    dmi_xml.SetResultType(dmidecode.DMIXML_DOC)
    result = dmi_xml.QuerySection('system')
    assert isinstance(result, dmidecode.XmlDoc), f"Expected XmlDoc, got {type(result)}"
    assert hasattr(result, 'element_tree'), "Result should have element_tree attribute"
    
    # Verify the XML content
    tree = result.element_tree
    root = tree.getroot()
    assert root.tag == 'dmi', f"Expected root tag 'dmi', got '{root.tag}'"
    system_info = root.find('system_information')
    assert system_info is not None, "Should have system_information element"
    manufacturer = system_info.find('manufacturer')
    assert manufacturer is not None and manufacturer.text == 'Test Manufacturer', f"Expected manufacturer text, got {manufacturer.text if manufacturer is not None else 'None'}"
    print("✅ QuerySection with DMIXML_DOC works correctly")
    
    # Test with unknown section
    result = dmi_xml.QuerySection('unknown_section')
    assert isinstance(result, dmidecode.XmlDoc), "Should still return XmlDoc for unknown sections"
    element = result.element_tree.getroot()
    unknown_section = element.find('unknown_section_information')
    assert unknown_section is not None, "Should have created generic section info"
    print("✅ QuerySection handles unknown sections correctly")

def test_query_typeid_functionality():
    """Test QueryTypeId method with various type IDs"""
    print("🧪 Testing QueryTypeId functionality...")
    
    dmi_xml = dmidecode.dmidecodeXML()
    dmi_xml.SetResultType(dmidecode.DMIXML_NODE)
    
    # Test with known type (0 = BIOS)
    result = dmi_xml.QueryTypeId(0)
    assert isinstance(result, dmidecode.XmlNode), f"Expected XmlNode, got {type(result)}"
    element = result.element
    
    # Debug: print the XML structure
    print(f"Debug: Root element tag: '{element.tag}'")
    for child in element:
        print(f"Debug: Child element: '{child.tag}'")
    
    bios_info = element.find('bios_information')
    assert bios_info is not None, f"Should have bios_information element, but root is '{element.tag}'"
    assert bios_info.get('type') == '0', f"Expected type='0', got {bios_info.get('type')}"
    print("✅ QueryTypeId with known type works correctly")
    
    # Test with unknown type
    result = dmi_xml.QueryTypeId(99)
    assert isinstance(result, dmidecode.XmlNode), "Should still return XmlNode for unknown types"
    element = result.element
    type_info = element.find('type_99_information')
    assert type_info is not None, "Should have created generic type info"
    print("✅ QueryTypeId handles unknown types correctly")
    
    # Test with DMIXML_DOC
    dmi_xml.SetResultType(dmidecode.DMIXML_DOC)
    result = dmi_xml.QueryTypeId(1)
    assert isinstance(result, dmidecode.XmlDoc), f"Expected XmlDoc, got {type(result)}"
    tree = result.element_tree
    root = tree.getroot()
    system_info = root.find('system_information')
    assert system_info is not None, "Should have system_information element"
    assert system_info.get('type') == '1', f"Expected type='1', got {system_info.get('type')}"
    print("✅ QueryTypeId with DMIXML_DOC works correctly")

def test_xml_structure_preservation():
    """Test that XML structure is preserved correctly"""
    print("🧪 Testing XML structure preservation...")
    
    dmi_xml = dmidecode.dmidecodeXML()
    result = dmi_xml.QuerySection('baseboard')
    
    # Parse the original XML to compare
    original_xml = mock_dmidecodemod.xmlapi('s', 'n', 'baseboard')
    original_root = ET.fromstring(original_xml)
    
    # Get the result XML
    result_xml = ET.tostring(result.element, encoding='unicode')
    result_root = ET.fromstring(result_xml)
    
    # Compare structure
    assert original_root.tag == result_root.tag, f"Root tags don't match: {original_root.tag} vs {result_root.tag}"
    
    # Find corresponding elements
    original_board = original_root.find('base_board_information')
    result_board = result_root.find('base_board_information')
    
    assert original_board is not None and result_board is not None, "Both should have base_board_information"
    
    # Compare content
    for child in original_board:
        result_child = result_board.find(child.tag)
        assert result_child is not None, f"Missing child element: {child.tag}"
        assert child.text == result_child.text, f"Text mismatch for {child.tag}: {child.text} vs {result_child.text}"
    
    print("✅ XML structure is preserved correctly")

def test_error_handling():
    """Test error handling in the new implementation"""
    print("🧪 Testing error handling...")
    
    dmi_xml = dmidecode.dmidecodeXML()
    
    # Test invalid result type
    try:
        dmi_xml.SetResultType('invalid_type')
        print("❌ Should have raised TypeError for invalid result type")
        return False
    except TypeError:
        print("✅ Correctly handles invalid result types")
    
    # Test invalid XML parsing (this is tested through the _create_xml_from_string method)
    try:
        dmi_xml._create_xml_from_string("<invalid xml")
        print("❌ Should have raised ValueError for invalid XML")
        return False
    except ValueError:
        print("✅ Correctly handles invalid XML")
    
    return True

def test_backward_compatibility():
    """Test that the API maintains backward compatibility where possible"""
    print("🧪 Testing backward compatibility...")
    
    dmi_xml = dmidecode.dmidecodeXML()
    
    # Test that the constants are still available
    assert hasattr(dmidecode, 'DMIXML_NODE'), "DMIXML_NODE constant should be available"
    assert hasattr(dmidecode, 'DMIXML_DOC'), "DMIXML_DOC constant should be available"
    assert dmidecode.DMIXML_NODE == 'n', "DMIXML_NODE should still be 'n'"
    assert dmidecode.DMIXML_DOC == 'd', "DMIXML_DOC should still be 'd'"
    print("✅ Constants maintain backward compatibility")
    
    # Test that the class interface is similar
    assert hasattr(dmi_xml, 'SetResultType'), "SetResultType method should exist"
    assert hasattr(dmi_xml, 'QuerySection'), "QuerySection method should exist"
    assert hasattr(dmi_xml, 'QueryTypeId'), "QueryTypeId method should exist"
    assert hasattr(dmi_xml, 'restype'), "restype attribute should exist"
    print("✅ Class interface maintains compatibility")
    
    return True

def main():
    """Run all integration tests"""
    print("Running Full Integration Tests for ElementTree Port")
    print("=" * 60)
    
    tests = [
        test_query_section_functionality,
        test_query_typeid_functionality,
        test_xml_structure_preservation,
        test_error_handling,
        test_backward_compatibility,
    ]
    
    passed = 0
    total = len(tests)
    
    for test_func in tests:
        try:
            if test_func() is not False:  # Handle functions that return None vs False
                passed += 1
        except Exception as e:
            print(f"❌ Test {test_func.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"Integration Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All integration tests passed!")
        print("The ElementTree port is working correctly and maintains compatibility.")
        return 0
    else:
        print("❌ Some integration tests failed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())