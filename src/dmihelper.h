#ifndef HELPER
#define HELPER 1

#include <Python.h>

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <libxml/tree.h>

#include "types.h"

#define MAXVAL 1024

typedef struct _dmi_codes_major {
        const unsigned short code;
        const char *id;
        const char *desc;
        const char *tagname;
} dmi_codes_major;

static const dmi_codes_major dmiCodesMajor[] = {
        {0, "3.3.1", "BIOS Information", "BIOSinfo"},
        {1, "3.3.2", "System Information", "SystemInfo"},
        {2, "3.3.3", "Base Board Information", "BaseBoardInfo"},
        {3, "3.3.4", "Chassis Information", "ChassisInfo"},
        {4, "3.3.5", "Processor Information", "ProcessorInfo"},
        {5, "3.3.6", "Memory Controller Information", "MemoryCtrlInfo"},
        {6, "3.3.7", "Memory Module Information", "MemoryModuleInfo"},
        {7, "3.3.8", "Cache Information", "CacheInfo"},
        {8, "3.3.9", "Port Connector Information", "PortConnectorInfo"},
        {9, "3.3.10", "System Slots", "SystemSlots"},
        {10, "3.3.11", "On Board Devices Information", "OnBoardDevicesInfo"},
        {11, "3.3.12", "OEM Strings", "OEMstrings"},
        {12, "3.3.13", "System Configuration Options", "SysConfigOptions"},
        {13, "3.3.14", "BIOS Language Information", "BIOSlanguage"},
        {14, "3.3.15", "Group Associations", "GroupAssoc"},
        {15, "3.3.16", "System Event Log", "SysEventLog"},
        {16, "3.3.17", "Physical Memory Array", "PhysicalMemoryArray"},
        {17, "3.3.18", "Memory Device", "MemoryDevice"},
        {18, "3.3.19", "32-bit Memory Error Information", "MemoryErrorInfo"},
        {19, "3.3.20", "Memory Array Mapped Address", "MemoryArrayMappedAddress"},
        {20, "3.3.21", "Memory Device Mapped Address", "MemoryDeviceMappedAddress"},
        {21, "3.3.22", "Built-in Pointing Device", "BuiltIntPointingDevice"},
        {22, "3.3.23", "Portable Battery", "PortableBattery"},
        {23, "3.3.24", "System Reset", "SystemReset"},
        {24, "3.3.25", "Hardware Security", "HardwareSecurity"},
        {25, "3.3.26", "System Power Controls", "SystemPowerCtrls"},
        {26, "3.3.27", "Voltage Probe", "Probe"},
        {27, "3.3.28", "Cooling Device", "CoolingDevice"},
        {28, "3.3.29", "Temperature Probe", "Probe"},
        {29, "3.3.30", "Electrical Current Probe", "Probe"},
        {30, "3.3.31", "Out-of-band Remote Access", "RemoteAccess"},
        {31, "3.3.32", "Boot Integrity Services Entry Point", "BootIntegrity"},
        {32, "3.3.33", "System Boot Information", "SystemBootInfo"},
        {33, "3.3.34", "64-bit Memory Error Information", "MemoryErrorInfo"},
        {34, "3.3.35", "Management Device", "ManagementDevice"},
        {35, "3.3.36", "Management Device Component", "ManagementDevice"},
        {36, "3.3.37", "Management Device Threshold Data", "ManagementDevice"},
        {37, "3.3.38", "Memory Channel", "MemoryChannel"},
        {38, "3.3.39", "IPMI Device Information", "IPMIdeviceInfo"},
        {39, "3.3.40", "System Power Supply", "SystemPowerSupply"},
        {40, "3.3.41", "-------------------", "Unknown"},
        {41, "3.3.42", "-------------------", "Unknown"},
        {126, "3.3.41", "Inactive", "Inactive"},
        {127, "3.3.42", "End Of Table", "EndOfTable"},
        {-1, NULL, NULL, NULL}
};

typedef struct _dmi_minor {
        long id;
        dmi_codes_major *major;
        char *key;
        char value[MAXVAL];
        struct _dmi_minor *next;
} dmi_minor;

/*** dmiopt.h ***/
typedef struct _options {
        const char *devmem;
        unsigned int flags;
        u8 *type;
        xmlDoc *mappingxml;
        char *python_xml_map;
        xmlNode *dmiversion_n;
        char *dumpfile;
} options;

#endif
