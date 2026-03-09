#!/usr/bin/env python3
"""
Mock version of dmidecodemod for testing the ElementTree port.
This mock provides the same interface as the C extension but returns test XML data.
"""

def xmlapi(query_type, result_type, section=None, typeid=None):
    """
    Mock xmlapi function that returns test XML data as strings.
    This simulates what the modified C extension will return.
    """
    
    # Test XML data for different query types
    test_data = {
        'bios': """<?xml version="1.0"?>
        <dmi>
            <bios>
                <vendor>Test BIOS Vendor</vendor>
                <version>1.2.3</version>
                <release_date>01/01/2023</release_date>
            </bios>
        </dmi>""",
        
        'system': """<?xml version="1.0"?>
        <dmi>
            <system_information>
                <manufacturer>Test Manufacturer</manufacturer>
                <product_name>Test Product</product_name>
                <version>1.0</version>
                <serial_number>TEST123456</serial_number>
            </system_information>
        </dmi>""",
        
        'baseboard': """<?xml version="1.0"?>
        <dmi>
            <base_board_information>
                <manufacturer>Test Board Manufacturer</manufacturer>
                <product>Test Board</product>
                <version>1.0</version>
                <serial_number>BOARD123</serial_number>
            </base_board_information>
        </dmi>""",
        
        '0': """<?xml version="1.0"?>
        <dmi>
            <bios_information type="0">
                <vendor>Test BIOS Vendor</vendor>
                <version>1.2.3</version>
                <release_date>01/01/2023</release_date>
            </bios_information>
        </dmi>""",
        
        '1': """<?xml version="1.0"?>
        <dmi>
            <system_information type="1">
                <manufacturer>Test Manufacturer</manufacturer>
                <product_name>Test Product</product_name>
                <version>1.0</version>
                <serial_number>TEST123456</serial_number>
            </system_information>
        </dmi>""",
        
        '2': """<?xml version="1.0"?>
        <dmi>
            <base_board_information type="2">
                <manufacturer>Test Board Manufacturer</manufacturer>
                <product>Test Board</product>
                <version>1.0</version>
                <serial_number>BOARD123</serial_number>
            </base_board_information>
        </dmi>""",
    }
    
    # Determine what data to return based on query type
    if query_type == 's':  # Section query
        if section in test_data:
            return test_data[section]
        else:
            # Return a generic response for unknown sections
            return f"""<?xml version="1.0"?>
            <dmi>
                <{section}_information>
                    <manufacturer>Test Manufacturer</manufacturer>
                </{section}_information>
            </dmi>"""
    
    elif query_type == 't':  # Type ID query
        # The real extension passes typeid as a positional argument in the
        # third slot when using the simplified xmlapi('t', rtype, tpid) API.
        if typeid is None and section is not None:
            typeid = section
        typeid_str = str(typeid)
        if typeid_str in test_data:
            return test_data[typeid_str]
        else:
            # Return a generic response for unknown types
            return f"""<?xml version="1.0"?>
            <dmi>
                <type_{typeid}_information>
                    <manufacturer>Test Manufacturer</manufacturer>
                </type_{typeid}_information>
            </dmi>"""
    
    else:
        return """<?xml version="1.0"?>
        <dmi>
            <error>Unknown query type</error>
        </dmi>"""

# Mock other functions that might be imported
version = "3.12.3 (ElementTree Port)"
dmi = "Test DMI String"
