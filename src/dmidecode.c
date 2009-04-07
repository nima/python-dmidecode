
/*
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * DMI Decode
 *
 *   Copyright 2000-2002 Alan Cox <alan@redhat.com>
 *   Copyright 2002-2008 Jean Delvare <khali@linux-fr.org>
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
 *
 * Unless specified otherwise, all references are aimed at the "System
 * Management BIOS Reference Specification, Version 2.6" document,
 * available from http://www.dmtf.org/standards/smbios/.
 *
 * Note to contributors:
 * Please reference every value you add or modify, especially if the
 * information does not come from the above mentioned specification.
 *
 * Additional references:
 *  - Intel AP-485 revision 32
 *    "Intel Processor Identification and the CPUID Instruction"
 *    http://developer.intel.com/design/xeon/applnots/241618.htm
 *  - DMTF Common Information Model
 *    CIM Schema version 2.19.1
 *    http://www.dmtf.org/standards/cim/
 *  - IPMI 2.0 revision 1.0
 *    "Intelligent Platform Management Interface Specification"
 *    http://developer.intel.com/design/servers/ipmi/spec.htm
 *  - AMD publication #25481 revision 2.28
 *    "CPUID Specification"
 *    http://www.amd.com/us-en/assets/content_type/white_papers_and_tech_docs/25481.pdf
 *  - BIOS Integrity Services Application Programming Interface version 1.0
 *    http://www.intel.com/design/archives/wfm/downloads/bisspec.htm
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * DMI Decode Python Module (Extension)
 *
 *   Copyright: 2007-2008 Nima Talebi <nima@autonomy.net.au>
 *   License:   GPLv3
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */

#include <Python.h>

/*
#undef NDEBUG
#include <assert.h>
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libxml/tree.h>

#include "version.h"
#include "config.h"
#include "types.h"
#include "util.h"
#include "dmixml.h"
#include "dmidecode.h"
#include "dmioem.h"

#include "dmihelper.h"

#define EFI_NOT_FOUND   (-1)
#define EFI_NO_SMBIOS   (-2)

static const char *out_of_spec = "<OUT OF SPEC>";
static const char *bad_index = "<BAD INDEX>";

#define BAD_INDEX   PyString_FromString("<BAD INDEX>")
#define OUT_OF_SPEC PyString_FromString("<OUT OF SPEC>")

/*******************************************************************************
** Type-independant Stuff
*/

static PyObject *dmi_string_py(const struct dmi_header *dm, u8 s)
{
        char *bp = (char *)dm->data;
        size_t i, len;

        PyObject *data;

        if(s == 0)
                data = PyString_FromString("Not Specified");
        else {
                bp += dm->length;
                while(s > 1 && *bp) {
                        bp += strlen(bp);
                        bp++;
                        s--;
                }

                if(!*bp)
                        data = BAD_INDEX;
                else {
                        /* ASCII filtering */
                        len = strlen(bp);
                        for(i = 0; i < len; i++)
                                if(bp[i] < 32 || bp[i] == 127)
                                        bp[i] = '.';
                        data = PyString_FromString(bp);
                }
        }
        return data;
}

const char *dmi_string(const struct dmi_header *dm, u8 s)
{
        char *bp = (char *)dm->data;
        size_t i, len;

        if(s == 0)
                return "Not Specified";

        bp += dm->length;
        while(s > 1 && *bp) {
                bp += strlen(bp);
                bp++;
                s--;
        }

        if(!*bp)
                return bad_index;

        /* ASCII filtering */
        len = strlen(bp);
        for(i = 0; i < len; i++)
                if(bp[i] < 32 || bp[i] == 127)
                        bp[i] = '.';

        return bp;
}

xmlNode *dmi_smbios_structure_type(xmlNode *node, u8 code)
{
        static struct {
                const char *descr;
                const char *tagname;
                const char *attrname;
                const char *attrvalue;
        } types[] = {
                /* *INDENT-OFF* */
                {"BIOS",                            "BIOS",                 NULL, NULL},  /* 0 */
                {"System",                          "System",               NULL, NULL},
                {"Base Board",                      "BaseBoard",            NULL, NULL},
                {"Chassis",                         "Chassis",              NULL, NULL},
                {"Processor",                       "Processor",            NULL, NULL},
                {"Memory Controller",               "Memory",               "type", "controller"},
                {"Memory Module",                   "Memory",               "type", "module"},
                {"Cache",                           "Cache",                NULL, NULL},
                {"Port Connector",                  "PortConnectors",       NULL, NULL},
                {"System Slots",                    "Slots",                NULL, NULL},
                {"On Board Devices",                "OnBoardDevices",       NULL, NULL},
                {"OEM Strings",                     "OEMstrings",           NULL, NULL},
                {"System Configuration Options",    "SysConfigOpts",        NULL, NULL},
                {"BIOS Language",                   "BIOS",                 "type", "language"},
                {"Group Associations",              "GroupAssociations",    NULL, NULL},
                {"System Event Log",                "EventLog",             NULL, NULL},
                {"Physical Memory Array",           "PhysicalMemoryArray",  NULL, NULL},
                {"Memory Device",                   "Memory",               "type", "device"},
                {"32-bit Memory Error",             "MemoryError",          "bit", "32"},
                {"Memory Array Mapped Address",     "MemoryAddressMap",     "type", "MemoryArray"},
                {"Memory Device Mapped Address",    "MemoryAddressMap",     "type", "Device"},
                {"Built-in Pointing Device",        "BuiltinPointingDevice",NULL, NULL},
                {"Portable Battery",                "PortableBattery",      NULL, NULL},
                {"System Reset",                    "SystemReset",          NULL, NULL},
                {"Hardware Security",               "HWsecurity",           NULL, NULL},
                {"System Power Controls",           "SysPowerCtrl",         NULL, NULL},
                {"Voltage Probe",                   "Probe",                "type", "Voltage"},
                {"Cooling Device",                  "CoolingDevice",        NULL, NULL},
                {"Temperature Probe",               "Probe",                "type", "Temperature"},
                {"Electrical Current Probe",        "Probe",                "type", "ElectricalCurrent"},
                {"Out-of-band Remote Access",       "RemoteAccess",         NULL, NULL},
                {"Boot Integrity Services",         "BootIntegritySrv",     NULL, NULL},
                {"System Boot",                     "SystemBoot",           NULL, NULL},
                {"64-bit Memory Error",             "MemoryError",          "bit", "64"},
                {"Management Device",               "ManagementDevice",     NULL, NULL},
                {"Management Device Component",     "ManagementDevice",     "type", "component"},
                {"Management Device Threshold Data","ManagementDevice",     "type", "Threshold Data"},
                {"Memory Channel",                  "MemoryChannel",        NULL, NULL},
                {"IPMI Device",                     "IPMIdevice",           NULL, NULL},
                {"Power Supply",                    "PowerSupply",          NULL, NULL}  /* 39 */
                /* *INDENT-ON* */
        };
        xmlNode *type_n = NULL;

        if(code <= 39) {
                type_n = xmlNewChild(node, NULL, (xmlChar *)types[code].tagname, NULL);
                assert( type_n != NULL );

                dmixml_AddAttribute(type_n, "flags", "0x%04x", code);
                dmixml_AddTextChild(type_n, "Description", "%s", types[code].descr);

                if( (types[code].attrname != NULL) && (types[code].attrvalue != NULL) ) {
                        dmixml_AddAttribute(type_n, types[code].attrname, "%s", types[code].attrvalue);
                }
        } else {
                type_n = xmlNewChild(node, NULL, (xmlChar *) "UnknownSMBiosType", NULL);
                dmixml_AddAttribute(type_n, "flags", "0x%04x", code);
        }

        return type_n;
}

static int dmi_bcd_range(u8 value, u8 low, u8 high)
{
        if(value > 0x99 || (value & 0x0F) > 0x09)
                return 0;
        if(value < low || value > high)
                return 0;
        return 1;
}

PyObject *dmi_dump(struct dmi_header * h)
{
        int row, i;
        const char *s;

        PyObject *data = PyDict_New();
        PyObject *data1 = PyList_New(0);

        for(row = 0; row < ((h->length - 1) >> 4) + 1; row++) {
                for(i = 0; i < 16 && i < h->length - (row << 4); i++)
                        PyList_Append(data1,
                                      PyString_FromFormat("0x%02x", (h->data)[(row << 4) + i]));
        }
        PyDict_SetItemString(data, "Header and Data", data1);

        if((h->data)[h->length] || (h->data)[h->length + 1]) {
                i = 1;
                PyObject *data2 = PyList_New(0);

                while((s = dmi_string(h, i++)) != bad_index) {
                        //. FIXME: DUMP
                        /*
                         * if(opt.flags & FLAG_DUMP) {
                         * int j, l = strlen(s)+1;
                         * for(row=0; row<((l-1)>>4)+1; row++) {
                         * for(j=0; j<16 && j<l-(row<<4); j++)
                         * PyList_Append(data1, PyString_FromFormat("0x%02x", s[(row<<4)+j]));
                         * }
                         * fprintf(stderr, "\"%s\"|", s);
                         * }
                         * else fprintf(stderr, "%s|", s);
                         */
                        PyList_Append(data1, PyString_FromFormat("%s", s));
                }
                PyDict_SetItemString(data, "Strings", data2);
        }
        return data;
}

/*******************************************************************************
** 3.3.1 BIOS Information (Type 0)
*/

static PyObject *dmi_bios_runtime_size(u32 code)
{
        if(code & 0x000003FF)
                return PyString_FromFormat("%i bytes", code);
        else
                return PyString_FromFormat("%i kB", code >> 10);
}

/* 3.3.1.1 */
void dmi_bios_characteristics(xmlNode *node, u64 code)
{
        static const char *characteristics[] = {
                "BIOS characteristics not supported",   /* 3 */
                "ISA is supported",
                "MCA is supported",
                "EISA is supported",
                "PCI is supported",
                "PC Card (PCMCIA) is supported",
                "PNP is supported",
                "APM is supported",
                "BIOS is upgradeable",
                "BIOS shadowing is allowed",
                "VLB is supported",
                "ESCD support is available",
                "Boot from CD is supported",
                "Selectable boot is supported",
                "BIOS ROM is socketed",
                "Boot from PC Card (PCMCIA) is supported",
                "EDD is supported",
                "Japanese floppy for NEC 9800 1.2 MB is supported (int 13h)",
                "Japanese floppy for Toshiba 1.2 MB is supported (int 13h)",
                "5.25\"/360 KB floppy services are supported (int 13h)",
                "5.25\"/1.2 MB floppy services are supported (int 13h)",
                "3.5\"/720 KB floppy services are supported (int 13h)",
                "3.5\"/2.88 MB floppy services are supported (int 13h)",
                "Print screen service is supported (int 5h)",
                "8042 keyboard services are supported (int 9h)",
                "Serial services are supported (int 14h)",
                "Printer services are supported (int 17h)",
                "CGA/mono video services are supported (int 10h)",
                "NEC PC-98"     /* 31 */
        };
        dmixml_AddAttribute(node, "dmispec", "3.3.1.1");
        dmixml_AddAttribute(node, "flags", "0x%04x", code);

        if(code.l & (1 << 3)) {
                dmixml_AddAttribute(node, "unavailable", "1");
                dmixml_AddTextContent(node, characteristics[0]);
        } else {
                int i = 0;
                xmlNode *flags_n = xmlNewChild(node, NULL, (xmlChar *) "flags", NULL);
                assert( flags_n != NULL );

                for(i = 4; i <= 31; i++)
                        if( code.l & (1 << i) ) {
                                dmixml_AddTextChild(flags_n, "flag", characteristics[i - 3]);
                        }
        }
}

/* 3.3.1.2.1 */
void dmi_bios_characteristics_x1(xmlNode *node, u8 code)
{
        int i = 0;
        static const char *characteristics[] = {
                "ACPI",         /* 0 */
                "USB legacy",
                "AGP",
                "I2O boot",
                "LS-120 boot",
                "ATAPI Zip drive boot",
                "IEEE 1394 boot",
                "Smart battery" /* 7 */
        };

        dmixml_AddAttribute(node, "dmispec", "3.3.1.2.1");
        dmixml_AddAttribute(node, "flags", "0x%04x", code);

        for(i = 0; i <= 7; i++) {
                if( code.l & (1 << i) ) {
                        dmixml_AddTextChild(node, "characteristic", characteristics[i]);
                }
        }
}

/* 3.3.1.2.2 */
void dmi_bios_characteristics_x2(xmlNode *node, u8 code)
{
        int i = 0;
        static const char *characteristics[] = {
                "BIOS boot specification",      /* 0 */
                "Function key-initiated network boot",
                "Targeted content distribution" /* 2 */
        };

        dmixml_AddAttribute(node, "dmispec", "3.3.1.2.2");
        dmixml_AddAttribute(node, "flags", "0x%04x", code);

        for(i = 0; i <= 2; i++) {
                if( code.l & (1 << i) ) {
                        dmixml_AddTextChild(node, "characteristic", characteristics[i]);
                }
        }
}

/*******************************************************************************
** 3.3.2 System Information (Type 1)
*/

void dmi_system_uuid(xmlNode *node, const u8 * p, u16 ver)
{
        int only0xFF = 1, only0x00 = 1;
        int i;
        xmlNode *uuid_n = NULL;

        for(i = 0; i < 16 && (only0x00 || only0xFF); i++) {
                if(p[i] != 0x00)
                        only0x00 = 0;
                if(p[i] != 0xFF)
                        only0xFF = 0;
        }

        uuid_n = xmlNewChild(node, NULL, (xmlChar *) "SystemUUID", NULL);
        dmixml_AddAttribute(uuid_n, "dmispec", "3.3.2");

        if(only0xFF )  {
                dmixml_AddAttribute(uuid_n, "unavailable", "1");
                dmixml_AddTextContent(uuid_n, "Not Present");
                return;
        }

        if(only0x00){
                dmixml_AddAttribute(uuid_n, "unavailable", "1");
                dmixml_AddTextContent(uuid_n,"Not Settable");
                return;
        }

        /*
         * As off version 2.6 of the SMBIOS specification, the first 3
         * fields of the UUID are supposed to be encoded on little-endian.
         * The specification says that this is the defacto standard,
         * however I've seen systems following RFC 4122 instead and use
         * network byte order, so I am reluctant to apply the byte-swapping
         * for older versions.
         */
        if(ver >= 0x0206) {
                dmixml_AddTextContent(uuid_n,
                                      "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                                      p[3],  p[2],  p[1],  p[0],  p[5], p[4], p[7], p[6], p[8], p[9], p[10],
                                      p[11], p[12], p[13], p[14], p[15]);
        } else {
                dmixml_AddTextContent(uuid_n,
                                      "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                      p[0],  p[1],  p[2],  p[3],  p[4], p[5], p[6], p[7], p[8], p[9], p[10],
                                      p[11], p[12], p[13], p[14], p[15]);
        }
}

/* 3.3.2.1 */
void dmi_system_wake_up_type(xmlNode *node, u8 code)
{
        static const char *type[] = {
                "Reserved",     /* 0x00 */
                "Other",
                "Unknown",
                "APM Timer",
                "Modem Ring",
                "LAN Remote",
                "Power Switch",
                "PCI PME#",
                "AC Power Restored"     /* 0x08 */
        };
        xmlNode *swut_n = xmlNewChild(node, NULL, (xmlChar *) "SystemWakeUpType", NULL);
        assert( swut_n != NULL );
        dmixml_AddAttribute(swut_n, "dmispec", "3.3.2.1");
        dmixml_AddAttribute(swut_n, "flags", "0x%04x", code);

        if(code <= 0x08) {
                dmixml_AddTextContent(swut_n, type[code]);
        } else {
                dmixml_AddAttribute(swut_n, "outofspec", "1");
        }
}

/*******************************************************************************
** 3.3.3 Base Board Information (Type 2)
*/

/* 3.3.3.1 */
void dmi_base_board_features(xmlNode *node, u8 code)
{
        static const char *features[] = {
                "Board is a hosting board",     /* 0 */
                "Board requires at least one daughter board",
                "Board is removable",
                "Board is replaceable",
                "Board is hot swappable"        /* 4 */
        };

        xmlNode *feat_n = xmlNewChild(node, NULL, (xmlChar *) "Features", NULL);
        assert( feat_n != NULL );
        dmixml_AddAttribute(feat_n, "dmispec", "3.3.3.1");
        dmixml_AddAttribute(feat_n, "flags", "0x%04x", code);

        if((code & 0x1F) != 0) {
                int i;

                for(i = 0; i <= 4; i++) {
                        if(code & (1 << i)) {
                                dmixml_AddTextChild(feat_n, "feature", features[i]);
                        }
                }
        } else {
                dmixml_AddAttribute(feat_n, "unavailable", "1");
        }
}

void dmi_base_board_type(xmlNode *node, const char *tagname, u8 code)
{
        /* 3.3.3.2 */
        static const char *type[] = {
                "Unknown",      /* 0x01 */
                "Other",
                "Server Blade",
                "Connectivity Switch",
                "System Management Module",
                "Processor Module",
                "I/O Module",
                "Memory Module",
                "Daughter Board",
                "Motherboard",
                "Processor+Memory Module",
                "Processor+I/O Module",
                "Interconnect Board"    /* 0x0D */
        };
        xmlNode *type_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( type_n != NULL );
        dmixml_AddAttribute(type_n, "dmispec", "3.3.3.2");
        dmixml_AddAttribute(type_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x0D) {
                dmixml_AddTextContent(type_n, "%s", type[code - 0x01]);
        } else {
                dmixml_AddAttribute(type_n, "unavailable", "1");
        }
}

void dmi_base_board_handles(xmlNode *node, u8 count, const u8 * p)
{
        int i;
        xmlNode *dict_n = NULL;

        dict_n = xmlNewChild(node, NULL, (xmlChar *) "ContainedObjectHandles", NULL);
        assert( dict_n != NULL );

        dmixml_AddAttribute(dict_n, "count", "%i", count);

        for(i = 0; i < count; i++) {
                xmlNode *elmt_n = xmlNewChild(dict_n, NULL, (xmlChar *) "Handle", NULL);
                assert( elmt_n != NULL );
                dmixml_AddTextContent(elmt_n, "0x%04x", WORD(p + sizeof(u16) * i));
        }
}

/*******************************************************************************
** 3.3.4 Chassis Information (Type 3)
*/

/* 3.3.4.1 */
void dmi_chassis_type(xmlNode *node, u8 code)
{
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Desktop",
                "Low Profile Desktop",
                "Pizza Box",
                "Mini Tower",
                "Tower",
                "Portable",
                "Laptop",
                "Notebook",
                "Hand Held",
                "Docking Station",
                "All In One",
                "Sub Notebook",
                "Space-saving",
                "Lunch Box",
                "Main Server Chassis",  /* CIM_Chassis.ChassisPackageType says "Main System Chassis" */
                "Expansion Chassis",
                "Sub Chassis",
                "Bus Expansion Chassis",
                "Peripheral Chassis",
                "RAID Chassis",
                "Rack Mount Chassis",
                "Sealed-case PC",
                "Multi-system",
                "CompactPCI",
                "AdvancedTCA",  /* 0x1B */
                "Blade",
                "Blade Enclosing"       /* 0x1D */
        };
        xmlNode *type_n = xmlNewChild(node, NULL, (xmlChar *)"ChassisType", NULL);
        assert( type_n != NULL );
        dmixml_AddAttribute(type_n, "dmispec", "3.3.4.1");
        dmixml_AddAttribute(type_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x1B) {
                dmixml_AddAttribute(type_n, "available", "1");
                dmixml_AddTextContent(type_n, "%s", type[code - 0x01]);
        } else {
                dmixml_AddAttribute(type_n, "available", "0");
        }
}

void dmi_chassis_lock(xmlNode *node, u8 code)
{
        static const char *lock[] = {
                "Not Present",  /* 0x00 */
                "Present"       /* 0x01 */
        };
        xmlNode *lock_n = xmlNewChild(node, NULL, (xmlChar *) "ChassisLock", NULL);
        assert( lock_n != NULL );
        dmixml_AddAttribute(lock_n, "dmispec", "3.3.4");
        dmixml_AddAttribute(lock_n, "flags", "0x%04x", code);
        dmixml_AddTextContent(lock_n, "%s", lock[code]);
}

/* 3.3.4.2 */
void dmi_chassis_state(xmlNode *node, const char *tagname, u8 code)
{
        static const char *state[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Safe",         /* master.mif says OK */
                "Warning",
                "Critical",
                "Non-recoverable"       /* 0x06 */
        };
        xmlNode *state_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( state_n != NULL );
        dmixml_AddAttribute(state_n, "dmispec", "3.3.4.2");
        dmixml_AddAttribute(state_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x06) {
                dmixml_AddTextContent(state_n, "%s", state[code - 0x01]);
        } else {
                dmixml_AddAttribute(state_n, "unavailable", "1");
        }
}

/* 3.3.4.3 */
void dmi_chassis_security_status(xmlNode *node, u8 code)
{
        static const char *status[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "None",
                "External Interface Locked Out",
                "External Interface Enabled"    /* 0x05 */
        };
        xmlNode *secstat_n = xmlNewChild(node, NULL, (xmlChar *) "SecurityStatus", NULL);
        assert( secstat_n != NULL );
        dmixml_AddAttribute(secstat_n, "dmispec", "3.3.4.3");
        dmixml_AddAttribute(secstat_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x05) {
                dmixml_AddTextContent(secstat_n, "%s", status[code - 0x01]);
        } else {
                dmixml_AddAttribute(secstat_n, "unavailable", "1");
        }
}

void dmi_chassis_height(xmlNode *node, u8 code)
{
        xmlNode *hght_n = xmlNewChild(node, NULL, (xmlChar *) "ChassisHeight", NULL);
        assert( hght_n != NULL );

        if(code == 0x00) {
                dmixml_AddAttribute(hght_n, "unspecified", "1");
        } else {
                dmixml_AddAttribute(hght_n, "unit", "U");
                dmixml_AddTextContent(hght_n, "%i", code);
        }
}

void dmi_chassis_power_cords(xmlNode *node, u8 code)
{
        xmlNode *pwrc_n = xmlNewChild(node, NULL, (xmlChar *) "PowerCords", NULL);
        assert( pwrc_n != NULL );

        if(code == 0x00) {
                dmixml_AddAttribute(pwrc_n, "unspecified", "1");
        } else {
                dmixml_AddTextContent(pwrc_n, "%i", code);
        }
}

void dmi_chassis_elements(xmlNode *node, u8 count, u8 len, const u8 * p)
{
        int i;
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "ChassisElements", NULL);
        assert( data_n != NULL );

        dmixml_AddAttribute(data_n, "count", "%i", count);

        for(i = 0; i < count; i++) {
                if(len >= 0x03) {
                        xmlNode *key_n = NULL;

                        if( p[i * len] & 0x80 ) {
                                key_n = dmi_smbios_structure_type(data_n, p[i * len] & 0x7F);
                        } else {
                                key_n = xmlNewChild(data_n, NULL, (xmlChar *) "BaseboardElement", NULL);
                                dmi_base_board_type(key_n, "Description", p[i * len] & 0x7F);
                        }
                        assert( key_n != NULL );

                        if(p[1 + i * len] == p[2 + i * len]) {
                                dmixml_AddTextChild(key_n, "Value", "%i", p[1 + i * len]);
                        } else {
                                dmixml_AddTextChild(key_n, "Value", "%i-%i", p[1 + i * len], p[2 + i * len]);
                        }
                }
        }
}

/*******************************************************************************
** 3.3.5 Processor Information (Type 4)
*/

void dmi_processor_type(xmlNode *node, u8 code)
{
        /* 3.3.5.1 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Central Processor",
                "Math Processor",
                "DSP Processor",
                "Video Processor"       /* 0x06 */
        };
        xmlNode *proct_n = xmlNewChild(node, NULL, (xmlChar *) "Type", NULL);
        assert( proct_n != NULL );
        dmixml_AddAttribute(proct_n, "dmispec", "3.3.5");
        dmixml_AddAttribute(proct_n, "flags", "0x%04x", code);
        if(code >= 0x01 && code <= 0x06) {
                dmixml_AddTextContent(proct_n, type[code - 0x01]);
        } else {
                dmixml_AddAttribute(proct_n, "outofspec", "1");
        }
}

void dmi_processor_family(xmlNode *node, const struct dmi_header *h)
{
        const u8 *data = h->data;
        unsigned int i, low, high;
        u16 code;

        /* 3.3.5.2 */
        static struct {
                int value;
                const char *name;
        } family2[] = {
          /* *INDENT-OFF* */
          { 0x01, "Other" },
          { 0x02, "Unknown" },
          { 0x03, "8086" },
          { 0x04, "80286" },
          { 0x05, "80386" },
          { 0x06, "80486" },
          { 0x07, "8087" },
          { 0x08, "80287" },
          { 0x09, "80387" },
          { 0x0A, "80487" },
          { 0x0B, "Pentium" },
          { 0x0C, "Pentium Pro" },
          { 0x0D, "Pentium II" },
          { 0x0E, "Pentium MMX" },
          { 0x0F, "Celeron" },
          { 0x10, "Pentium II Xeon" },
          { 0x11, "Pentium III" },
          { 0x12, "M1" },
          { 0x13, "M2" },
          { 0x14, "Celeron M" }, /* From CIM_Processor.Family */
          { 0x15, "Pentium 4 HT" }, /* From CIM_Processor.Family */

          { 0x18, "Duron" },
          { 0x19, "K5" },
          { 0x1A, "K6" },
          { 0x1B, "K6-2" },
          { 0x1C, "K6-3" },
          { 0x1D, "Athlon" },
          { 0x1E, "AMD29000" },
          { 0x1F, "K6-2+" },
          { 0x20, "Power PC" },
          { 0x21, "Power PC 601" },
          { 0x22, "Power PC 603" },
          { 0x23, "Power PC 603+" },
          { 0x24, "Power PC 604" },
          { 0x25, "Power PC 620" },
          { 0x26, "Power PC x704" },
          { 0x27, "Power PC 750" },
          { 0x28, "Core Duo" }, /* From CIM_Processor.Family */
          { 0x29, "Core Duo Mobile" }, /* From CIM_Processor.Family */
          { 0x2A, "Core Solo Mobile" }, /* From CIM_Processor.Family */
          { 0x2B, "Atom" }, /* From CIM_Processor.Family */

          { 0x30, "Alpha" },
          { 0x31, "Alpha 21064" },
          { 0x32, "Alpha 21066" },
          { 0x33, "Alpha 21164" },
          { 0x34, "Alpha 21164PC" },
          { 0x35, "Alpha 21164a" },
          { 0x36, "Alpha 21264" },
          { 0x37, "Alpha 21364" },

          { 0x40, "MIPS" },
          { 0x41, "MIPS R4000" },
          { 0x42, "MIPS R4200" },
          { 0x43, "MIPS R4400" },
          { 0x44, "MIPS R4600" },
          { 0x45, "MIPS R10000" },

          { 0x50, "SPARC" },
          { 0x51, "SuperSPARC" },
          { 0x52, "MicroSPARC II" },
          { 0x53, "MicroSPARC IIep" },
          { 0x54, "UltraSPARC" },
          { 0x55, "UltraSPARC II" },
          { 0x56, "UltraSPARC IIi" },
          { 0x57, "UltraSPARC III" },
          { 0x58, "UltraSPARC IIIi" },

          { 0x60, "68040" },
          { 0x61, "68xxx" },
          { 0x62, "68000" },
          { 0x63, "68010" },
          { 0x64, "68020" },
          { 0x65, "68030" },

          { 0x70, "Hobbit" },

          { 0x78, "Crusoe TM5000" },
          { 0x79, "Crusoe TM3000" },
          { 0x7A, "Efficeon TM8000" },

          { 0x80, "Weitek" },

          { 0x82, "Itanium" },
          { 0x83, "Athlon 64" },
          { 0x84, "Opteron" },
          { 0x85, "Sempron" },
          { 0x86, "Turion 64" },
          { 0x87, "Dual-Core Opteron" },
          { 0x88, "Athlon 64 X2" },
          { 0x89, "Turion 64 X2" },
          { 0x8A, "Quad-Core Opteron" }, /* From CIM_Processor.Family */
          { 0x8B, "Third-Generation Opteron" }, /* From CIM_Processor.Family */
          { 0x8C, "Phenom FX" }, /* From CIM_Processor.Family */
          { 0x8D, "Phenom X4" }, /* From CIM_Processor.Family */
          { 0x8E, "Phenom X2" }, /* From CIM_Processor.Family */
          { 0x8F, "Athlon X2" }, /* From CIM_Processor.Family */
          { 0x90, "PA-RISC" },
          { 0x91, "PA-RISC 8500" },
          { 0x92, "PA-RISC 8000" },
          { 0x93, "PA-RISC 7300LC" },
          { 0x94, "PA-RISC 7200" },
          { 0x95, "PA-RISC 7100LC" },
          { 0x96, "PA-RISC 7100" },

          { 0xA0, "V30" },
          { 0xA1, "Quad-Core Xeon 3200" }, /* From CIM_Processor.Family */
          { 0xA2, "Dual-Core Xeon 3000" }, /* From CIM_Processor.Family */
          { 0xA3, "Quad-Core Xeon 5300" }, /* From CIM_Processor.Family */
          { 0xA4, "Dual-Core Xeon 5100" }, /* From CIM_Processor.Family */
          { 0xA5, "Dual-Core Xeon 5000" }, /* From CIM_Processor.Family */
          { 0xA6, "Dual-Core Xeon LV" }, /* From CIM_Processor.Family */
          { 0xA7, "Dual-Core Xeon ULV" }, /* From CIM_Processor.Family */
          { 0xA8, "Dual-Core Xeon 7100" }, /* From CIM_Processor.Family */
          { 0xA9, "Quad-Core Xeon 5400" }, /* From CIM_Processor.Family */
          { 0xAA, "Quad-Core Xeon" }, /* From CIM_Processor.Family */

          { 0xB0, "Pentium III Xeon" },
          { 0xB1, "Pentium III Speedstep" },
          { 0xB2, "Pentium 4" },
          { 0xB3, "Xeon" },
          { 0xB4, "AS400" },
          { 0xB5, "Xeon MP" },
          { 0xB6, "Athlon XP" },
          { 0xB7, "Athlon MP" },
          { 0xB8, "Itanium 2" },
          { 0xB9, "Pentium M" },
          { 0xBA, "Celeron D" },
          { 0xBB, "Pentium D" },
          { 0xBC, "Pentium EE" },
          { 0xBD, "Core Solo" },
          /* 0xBE handled as a special case */
          { 0xBF, "Core 2 Duo" },
          { 0xC0, "Core 2 Solo" }, /* From CIM_Processor.Family */
          { 0xC1, "Core 2 Extreme" }, /* From CIM_Processor.Family */
          { 0xC2, "Core 2 Quad" }, /* From CIM_Processor.Family */
          { 0xC3, "Core 2 Extreme Mobile" }, /* From CIM_Processor.Family */
          { 0xC4, "Core 2 Duo Mobile" }, /* From CIM_Processor.Family */
          { 0xC5, "Core 2 Solo Mobile" }, /* From CIM_Processor.Family */

          { 0xC8, "IBM390" },
          { 0xC9, "G4" },
          { 0xCA, "G5" },
          { 0xCB, "ESA/390 G6" },
          { 0xCC, "z/Architectur" },

          { 0xD2, "C7-M" },
          { 0xD3, "C7-D" },
          { 0xD4, "C7" },
          { 0xD5, "Eden" },

          { 0xFA, "i860" },
          { 0xFB, "i960" },

          { 0x104, "SH-3" },
          { 0x105, "SH-4" },

          { 0x118, "ARM" },
          { 0x119, "StrongARM" },

          { 0x12C, "6x86" },
          { 0x12D, "MediaGX" },
          { 0x12E, "MII" },

          { 0x140, "WinChip" },

          { 0x15E, "DSP" },

          { 0x1F4, "Video Processor" },
          /* *INDENT-ON* */
        };

        /* Linear Search - Slow
         * for(i=0; i<ARRAY_SIZE(family2); i++)
         * if (family2[i].value == code)
         * return family2[i].name;
         */

        xmlNode *family_n = xmlNewChild(node, NULL, (xmlChar *) "Family", NULL);
        assert( family_n != NULL );
        dmixml_AddAttribute(family_n, "dmispec", "3.3.3.5");

        code = (data[0x06] == 0xFE && h->length >= 0x2A) ? WORD(data + 0x28) : data[0x06];

        dmixml_AddAttribute(family_n, "flags", "0x%04x", code);

        /* Special case for ambiguous value 0xBE */
        if(code == 0xBE) {
                const char *manufacturer = dmi_string(h, data[0x07]);

                /* Best bet based on manufacturer string */
                if(strstr(manufacturer, "Intel") != NULL ||
                   strncasecmp(manufacturer, "Intel", 5) == 0) {
                        dmixml_AddTextContent(family_n, "Core 2");
                        return;
                }

                if(strstr(manufacturer, "AMD") != NULL
                   || strncasecmp(manufacturer, "AMD", 3) == 0) {
                        dmixml_AddTextContent(family_n, "K7");
                        return;
                }
                dmixml_AddTextContent(family_n, "Core 2 or K7");
                return;
        }

        /* Perform a binary search */
        low = 0;
        high = ARRAY_SIZE(family2) - 1;
        while(1) {
                i = (low + high) / 2;
                if(family2[i].value == code) {
                        dmixml_AddTextContent(family_n, family2[i].name);
                        return;
                }

                if(low == high) { /* Not found */
                        dmixml_AddAttribute(family_n, "outofspec", "1");
                        return;
                }

                if(code < family2[i].value)
                        high = i;
                else
                        low = i + 1;
        }

        dmixml_AddAttribute(family_n, "outofspec", "1");
}

xmlNode *dmi_processor_id(xmlNode *node, u8 type, const u8 * p, const char *version)
{
        /* Intel AP-485 revision 31, table 3-4 */
        static struct _cpuflags {
                const char *flag;
                const char *descr;
        } flags[] = {
                /* *INDENT-OFF* */
                {"FPU", "Floating-point unit on-chip"},    /* 0 */
                {"VME", "Virtual mode extension"},
                {"DE", "Debugging extension"},
                {"PSE", "Page size extension"},
                {"TSC", "Time stamp counter"},
                {"MSR", "Model specific registers"},
                {"PAE", "Physical address extension"},
                {"MCE", "Machine check exception"},
                {"CX8", "CMPXCHG8 instruction supported"},
                {"APIC", "On-chip APIC hardware supported"},
                {NULL, NULL},           /* 10 */
                {"SEP", "Fast system call"},
                {"MTRR", "Memory type range registers"},
                {"PGE", "Page global enable"},
                {"MCA", "Machine check architecture"},
                {"CMOV", "Conditional move instruction supported"},
                {"PAT", "Page attribute table"},
                {"PSE-36", "36-bit page size extension"},
                {"PSN", "Processor serial number present and enabled"},
                {"CLFSH", "CLFLUSH instruction supported"},
                {NULL, NULL },           /* 20 */
                {"DS", "Debug store"},
                {"ACPI", "ACPI supported"},
                {"MMX", "MMX technology supported"},
                {"FXSR", "Fast floating-point save and restore"},
                {"SSE", "Streaming SIMD extensions"},
                {"SSE2", "Streaming SIMD extensions 2"},
                {"SS", "Self-snoop"},
                {"HTT", "Hyper-threading technology"},
                {"TM", "Thermal monitor supported"},
                {"IA64", "IA64 capabilities"},
                {"PBE", "Pending break enabled"}   /* 31 */
                /* *INDENT-ON* */
        };

        xmlNode *flags_n = NULL;
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "CPUCore", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.5");

        /*
         ** Extra flags are now returned in the ECX register when one calls
         ** the CPUID instruction. Their meaning is explained in table 3-5, but
         ** DMI doesn't support this yet.
         */
        u32 eax, edx;
        int sig = 0;

        /*
         ** This might help learn about new processors supporting the
         ** CPUID instruction or another form of identification.
         */

        //. TODO: PyString_FromFormat does not support %x (yet?)...
        dmixml_AddTextChild(data_n, "ID",
                            "%02x %02x %02x %02x %02x %02x %02x %02x",
                            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

        if(type == 0x05) {      /* 80386 */
                u16 dx = WORD(p);

                /*
                 ** 80386 have a different signature.
                 */
                dmixml_AddTextChild(data_n, "Signature",
                                    "Type %i, Family %i, Major Stepping %i, Minor Stepping %i",
                                    dx >> 12, (dx >> 8) & 0xF, (dx >> 4) & 0xF, dx & 0xF);
                return data_n;
        }

        if(type == 0x06) {      /* 80486 */
                u16 dx = WORD(p);

                /*
                 ** Not all 80486 CPU support the CPUID instruction, we have to find
                 ** wether the one we have here does or not. Note that this trick
                 ** works only because we know that 80486 must be little-endian.
                 */
                if( (dx & 0x0F00) == 0x0400
                    && ((dx & 0x00F0) == 0x0040 || (dx & 0x00F0) >= 0x0070)
                    && ((dx & 0x000F) >= 0x0003) ) {
                        sig = 1;
                } else {
                        dmixml_AddTextChild(data_n, "Signature",
                                            "Type %i, Family %i, Model %i, Stepping %i",
                                            (dx >> 12) & 0x3, (dx >> 8) & 0xF, (dx >> 4) & 0xF,
                                            dx & 0xF);
                        return data_n;
                }
        } else if((type >= 0x0B && type <= 0x15)        /* Intel, Cyrix */
                  ||(type >= 0x28 && type <= 0x2B)      /* Intel */
                  ||(type >= 0xA1 && type <= 0xAA)      /* Intel */
                  ||(type >= 0xB0 && type <= 0xB3)      /* Intel */
                  ||type == 0xB5        /* Intel */
                  || (type >= 0xB9 && type <= 0xC5)     /* Intel */
                  ||(type >= 0xD2 && type <= 0xD5)      /* VIA */
                  ) {

                sig = 1;

        } else if((type >= 0x18 && type <= 0x1D)  /* AMD */
                ||type == 0x1F  /* AMD */
                || (type >= 0x83 && type <= 0x8F)       /* AMD */
                ||(type >= 0xB6 && type <= 0xB7)        /* AMD */
                ||(type >= 0xE6 && type <= 0xEB)        /* AMD */
                ) {

                sig = 2;

        } else if(type == 0x01 || type == 0x02) {
                /*
                 ** Some X86-class CPU have family "Other" or "Unknown". In this case,
                 ** we use the version string to determine if they are known to
                 ** support the CPUID instruction.
                 */
                if(strncmp(version, "Pentium III MMX", 15) == 0
                   || strncmp(version, "Intel(R) Core(TM)2", 18) == 0
                   || strncmp(version, "Intel(R) Pentium(R)", 19) == 0
                   || strcmp(version, "Genuine Intel(R) CPU U1400") == 0
                   ) {

                        sig = 1;

                } else if(strncmp(version, "AMD Athlon(TM)", 14) == 0
                          || strncmp(version, "AMD Opteron(tm)", 15) == 0
                          || strncmp(version, "Dual-Core AMD Opteron(tm)", 25) == 0) {

                        sig = 2;

                } else {
                        return data_n;
                }
        } else {                 /* not X86-class */
                return data_n;
        }

        eax = DWORD(p);
        edx = DWORD(p + 4);
        switch (sig) {
        case 1:                /* Intel */
                dmixml_AddTextChild(data_n, "Signature",
                                    "Type %i, Family %i, Model %i, Stepping %i",
                                    (eax >> 12) & 0x3, ((eax >> 20) & 0xFF) + ((eax >> 8) & 0x0F),
                                    ((eax >> 12) & 0xF0) + ((eax >> 4) & 0x0F), eax & 0xF);
                break;
        case 2:                /* AMD, publication #25481 revision 2.28  */
                dmixml_AddTextChild(data_n, "Signature",
                                    "Family %i, Model %i, Stepping %i",
                                    ((eax >> 8) & 0xF) + (((eax >> 8) & 0xF) == 0xF
                                                          ? (eax >> 20) & 0xFF : 0),
                                    ((eax >> 4) & 0xF) | (((eax >> 8) & 0xF) == 0xF
                                                          ? (eax >> 12) & 0xF0 : 0),
                                    eax & 0xF);
                break;
        }

        edx = DWORD(p + 4);
        flags_n = xmlNewChild(data_n, NULL, (xmlChar *) "cpu_flags", NULL);
        if((edx & 0xFFEFFBFF) != 0) {
                int i;

                for(i = 0; i <= 31; i++) {
                        // Only add those flags which are present
                        if( (flags[i].flag != NULL) && (edx & (1 << i)) ) {
                                xmlNode *flg_n = dmixml_AddTextChild(flags_n, "flag", "%s", flags[i].descr);
                                dmixml_AddAttribute(flg_n, "flag", "%s", flags[i].flag);
                        }
                }
        }
        return data_n;
}

/* 3.3.5.4 */
void dmi_processor_voltage(xmlNode *node, u8 code)
{
        static const char *voltage[] = {
                "5.0",        /* 0 */
                "3.3",
                "2.9"         /* 2 */
        };
        int i;
        xmlNode *vltg_n = xmlNewChild(node, NULL, (xmlChar *) "Voltages", NULL);
        assert( vltg_n != NULL );
        dmixml_AddAttribute(vltg_n, "dmispec", "3.3.5.4");
        dmixml_AddAttribute(vltg_n, "flags", "0x%04x", code);

        if(code & 0x80) {
                dmixml_AddTextChild(vltg_n, "Voltage", "%.1f", (float)(code & 0x7f) / 10);
                dmixml_AddAttribute(vltg_n, "unit", "V");
        } else if( code == 0x00 ) {
                dmixml_AddAttribute(vltg_n, "unknown_value", "1");
        } else {
                for(i = 0; i <= 2; i++) {
                        if( code & (1 << i) ) {
                                xmlNode *v_n = dmixml_AddTextChild(vltg_n, "Voltage", "%s", voltage[i]);
                                dmixml_AddAttribute(v_n, "unit", "V");
                        }
                }
        }
}

int dmi_processor_frequency(const u8 * p)
{
        u16 code = WORD(p);

        if(code)
                return code;    //. Value measured in MHz
        else
                return -1;      //. Unknown
}

void dmi_processor_status(xmlNode *node, u8 code)
{
        static const char *status[] = {
                "Unknown",      /* 0x00 */
                "Enabled",
                "Disabled By User",
                "Disabled By BIOS",
                "Idle",         /* 0x04 */
                "Other"         /* 0x07 */
        };
        xmlNode *prst_n = xmlNewChild(node, NULL, (xmlChar *) "Populated", NULL);
        assert( prst_n != NULL );

        dmixml_AddAttribute(prst_n, "flags", "0x%04x", code);

        if(code <= 0x04) {
                dmixml_AddTextContent(prst_n, "%s", status[code]);
        } else if( code == 0x07 ) {
                dmixml_AddTextContent(prst_n, "%s", status[5]);
        } else {
                dmixml_AddAttribute(prst_n, "outofspec", "1");
        }
}

void dmi_processor_upgrade(xmlNode *node, u8 code)
{
        /* 3.3.5.5 */
        static const char *upgrade[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Daughter Board",
                "ZIF Socket",
                "Replaceable Piggy Back",
                "None",
                "LIF Socket",
                "Slot 1",
                "Slot 2",
                "370-pin Socket",
                "Slot A",
                "Slot M",
                "Socket 423",
                "Socket A (Socket 462)",
                "Socket 478",
                "Socket 754",
                "Socket 940",
                "Socket 939",
                "Socket mPGA604",
                "Socket LGA771",
                "Socket LGA775",        /* 0x15 */
                "Socket S1",
                "Socket AM2",
                "Socket F (1207)"       /* 0x18 */
        };
        xmlNode *upgr_n = xmlNewChild(node, NULL, (xmlChar *) "Upgrade", NULL);
        assert( upgr_n != NULL );
        dmixml_AddAttribute(upgr_n, "dmispec", "3.3.5.5");
        dmixml_AddAttribute(upgr_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x15) {
                dmixml_AddTextContent(upgr_n, "%s", upgrade[code - 0x01]);
        } else {
                dmixml_AddAttribute(upgr_n, "outofspec", "1");
        }
}

void dmi_processor_cache(xmlNode *cache_n, u16 code, u16 ver)
{
        assert( cache_n != NULL );

        dmixml_AddAttribute(cache_n, "flags", "0x%04x", code);
        dmixml_AddAttribute(cache_n, "ver", "0x%04x", ver);

        if(code == 0xFFFF) {
                if(ver >= 0x0203) {
                        dmixml_AddAttribute(cache_n, "provided", "0");
                        dmixml_AddAttribute(cache_n, "available", "1");
                } else {
                        dmixml_AddAttribute(cache_n, "available", "0");
                }
        } else {
                dmixml_AddAttribute(cache_n, "provided", "1");
                dmixml_AddAttribute(cache_n, "available", "1");
                dmixml_AddTextChild(cache_n, "Handle", "0x%04x", code);
        }
}

/* 3.3.5.9 */
void dmi_processor_characteristics(xmlNode *node, u16 code)
{
        static const char *characteristics[] = {
                NULL,
                "Unknown"               /* 1 */
                "64-bit capable"        /* 2 */
        };

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Characteristics", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.5.9");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if((code & 0x0004) != 0) {
                int i;

                for(i = 1; i <= 2; i++) {
                        if(code & (1 << i)) {
                                dmixml_AddTextChild(data_n, "Flag", "%s", characteristics[i - 1]);
                        }
                }
        }
}

/*******************************************************************************
** 3.3.6 Memory Controller Information (Type 5)
*/

void dmi_memory_controller_ed_method(xmlNode *node, u8 code)
{
        /* 3.3.6.1 */
        static const char *method[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "None",
                "8-bit Parity",
                "32-bit ECC",
                "64-bit ECC",
                "128-bit ECC",
                "CRC"           /* 0x08 */
        };
        xmlNode *ercm_n = xmlNewChild(node, NULL, (xmlChar *) "CorrectionMethod", NULL);
        assert( ercm_n != NULL );
        dmixml_AddAttribute(ercm_n, "dmispec", "3.3.6.1");
        dmixml_AddAttribute(ercm_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x08) {
                dmixml_AddTextContent(ercm_n, method[code - 0x01]);
        } else {
                dmixml_AddAttribute(ercm_n, "outofspec", "1");
        }
}

/* 3.3.6.2 */
void dmi_memory_controller_ec_capabilities(xmlNode *node, const char *tagname, u8 code)
{
        static const char *capabilities[] = {
                "Other",        /* 0 */
                "Unknown",
                "None",
                "Single-bit Error Correcting",
                "Double-bit Error Correcting",
                "Error Scrubbing"       /* 5 */
        };

        xmlNode *cap_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( cap_n != NULL );
        dmixml_AddAttribute(cap_n, "dmispec", "3.3.6.2");
        dmixml_AddAttribute(cap_n, "flags", "0x%04x", code);

        if((code & 0x3F) != 0) {
                int i;
                for(i = 0; i <= 5; i++) {
                        if(code & (1 << i)) {
                                xmlNode *c_n = dmixml_AddTextChild(cap_n, "Capability", "%s", capabilities[i]);
                                assert( c_n != NULL );
                                dmixml_AddAttribute(c_n, "index", "%i", i);
                        }
                }
        }
}

void dmi_memory_controller_interleave(xmlNode *node, const char *tagname, u8 code)
{
        /* 3.3.6.3 */
        static const char *interleave[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "One-way Interleave",
                "Two-way Interleave",
                "Four-way Interleave",
                "Eight-way Interleave",
                "Sixteen-way Interleave"        /* 0x07 */
        };
        xmlNode *mci_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( mci_n != NULL );
        dmixml_AddAttribute(mci_n, "dmispec", "3.3.6.3");
        dmixml_AddAttribute(mci_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x07) {
                dmixml_AddTextContent(mci_n, interleave[code - 0x01]);
        } else {
                dmixml_AddAttribute(mci_n, "outofspec", "1");
        }
}

/* 3.3.6.4 */
void dmi_memory_controller_speeds(xmlNode *node, u16 code)
{
        static struct {
                const char *value;
                const char *unit;
        } const speeds[] = {
                {"Other",   NULL},      /* 0 */
                {"Unknown", NULL},
                {"70",      "ns"},
                {"60",      "ns"},
                {"50",      "ns"}       /* 4 */
        };
        xmlNode *mcs_n = xmlNewChild(node, NULL, (xmlChar *) "SupportedSpeeds", NULL);
        assert( mcs_n != NULL );
        dmixml_AddAttribute(mcs_n, "dmispec", "3.3.6.4");
        dmixml_AddAttribute(mcs_n, "flags", "0x%04x", code);

        if((code & 0x001F) == 0) {
                int i;
                for(i = 0; i <= 4; i++) {
                        if(code & (1 << i)) {
                                xmlNode *ms_n = dmixml_AddTextChild(mcs_n, "Speed", "%s", speeds[i].value);
                                assert( ms_n != NULL );
                                dmixml_AddAttribute(ms_n, "index", "%i", i);
                                if( speeds[i].unit != NULL ) {
                                        dmixml_AddAttribute(ms_n, "unit", speeds[i].unit);
                                }
                                ms_n = NULL;
                        }
                }
        }
}

void dmi_memory_controller_slots(xmlNode *node, u8 count, const u8 * p)
{
        int i;
        xmlNode *mslts_n = xmlNewChild(node, NULL, (xmlChar *) "AssociatedMemorySlots", NULL);
        assert( mslts_n != NULL );

        for(i = 0; i < count; i++) {
                xmlNode *sl_n = dmixml_AddTextChild(mslts_n, "Slot", "0x%04x:", WORD(p + sizeof(u16) * i));
                dmixml_AddAttribute(sl_n, "index", "%i", i);
        }
}

/*******************************************************************************
** 3.3.7 Memory Module Information (Type 6)
*/

/* 3.3.7.1 */
void dmi_memory_module_types(xmlNode *node, const char *tagname, u16 code)
{
        static const char *types[] = {
                "Other",        /* 0 */
                "Unknown",
                "Standard",
                "FPM",
                "EDO",
                "Parity",
                "ECC",
                "SIMM",
                "DIMM",
                "Burst EDO",
                "SDRAM"         /* 10 */
        };
        xmlNode *mmt_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( mmt_n != NULL );
        dmixml_AddAttribute(mmt_n, "dmispec", "3.3.7.1");
        dmixml_AddAttribute(mmt_n, "flags", "0x%04x", code);

        if((code & 0x07FF) != 0) {
                int i;

                for(i = 0; i <= 10; i++) {
                        if(code & (1 << i)) {
                                xmlNode *mt_n = dmixml_AddTextChild(mmt_n, "ModuleType", types[i]);
                                assert( mt_n != NULL );
                                dmixml_AddAttribute(mt_n, "index", "%i", i);
                        }
                }
        }
}

void dmi_memory_module_connections(xmlNode *node, u8 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "BankConnections", NULL);
        assert( data_n != NULL );

        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code != 0xFF) {
                if((code & 0xF0) != 0xF0) {
                        dmixml_AddTextContent(data_n, "%ld", (code >> 4));
                }
                if((code & 0x0F) != 0x0F) {
                        dmixml_AddTextContent(data_n, "%ld", (code & 0x0F));
                }
        }
}

void dmi_memory_module_speed(xmlNode *node, const char *tagname, u8 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );

        dmixml_AddAttribute(data_n, "code", "0x%04x", code);

        if(code != 0) {
                dmixml_AddAttribute(data_n, "unit", "ns");
                dmixml_AddTextContent(data_n, "%i", code);
        }
}

/* 3.3.7.2 */
void dmi_memory_module_size(xmlNode *node, const char *tagname, u8 code)
{
        int check_conn = 1;
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );

        dmixml_AddAttribute(data_n, "dmispec", "3.3.7.2");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        switch (code & 0x7F) {
        case 0x7D:
                dmixml_AddAttribute(data_n, "Error", "Size not determinable");
                break;
        case 0x7E:
                dmixml_AddAttribute(data_n, "Error", "Disabled");
                break;
        case 0x7F:
                dmixml_AddAttribute(data_n, "installed", "0");
                check_conn = 0;
        default:
                dmixml_AddAttribute(data_n, "installed", "1");
                dmixml_AddAttribute(data_n, "unit", "MB");
                dmixml_AddTextContent(data_n, "%i", 1 << (code & 0x7F));
        }

        if(check_conn) {
                dmixml_AddAttribute(data_n, "Connection", ((code & 0x80) ? "Double-bank" : "Single-bank"));
        }
}

void dmi_memory_module_error(xmlNode *node, u8 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "ModuleErrorStatus", NULL);
        assert( data_n != NULL );

        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if( !(code & (1 << 2)) ) {
                if((code & 0x03) == 0) {
                        dmixml_AddAttribute(data_n, "Error", "1");
                }
                if(code & (1 << 0)) {
                        dmixml_AddTextContent(data_n, "Uncorrectable Errors");
                }
                if(code & (1 << 1)) {
                        dmixml_AddTextContent(data_n, "Correctable Errors");
                }
        }
}

/*******************************************************************************
** 3.3.8 Cache Information (Type 7)
*/
static const char *dmi_cache_mode(u8 code)
{
        static const char *mode[] = {
                "Write Through",        /* 0x00 */
                "Write Back",
                "Varies With Memory Address",
                "Unknown"       /* 0x03 */
        };

        return mode[code];
}

void dmi_cache_location(xmlNode *node, u8 code)
{
        static const char *location[4] = {
                "Internal",     /* 0x00 */
                "External",
                NULL,           /* 0x02 */
                "Unknown"       /* 0x03 */
        };

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "CacheLocation", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.8");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(location[code] != NULL) {
                dmixml_AddTextContent(data_n, location[code]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_cache_size(xmlNode *node, const char *tagname, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "CacheLocation", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.8");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code & 0x8000) {
                dmixml_AddAttribute(data_n, "unit", "KB");
                dmixml_AddTextContent(data_n, "%i", (code & 0x7FFF) << 6);
        } else {
                dmixml_AddAttribute(data_n, "unit", "KB");
                dmixml_AddTextContent(data_n, "%i", code);
        }
}

/* 3.3.8.2 */
void dmi_cache_types(xmlNode *node, const char *tagname, u16 code)
{
        static const char *types[] = {
                "Other",        /* 0 */
                "Unknown",
                "Non-burst",
                "Burst",
                "Pipeline Burst",
                "Synchronous",
                "Asynchronous"  /* 6 */
        };

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.8.2");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);


        if((code & 0x007F) != 0) {
                int i;
                for(i = 0; i <= 6; i++) {
                        if(code & (1 << i)) {
                                xmlNode *n = dmixml_AddTextContent(data_n, "%s", types[i]);
                                dmixml_AddAttribute(n, "index", "%i", i);
                        }
                }
        }
}

void dmi_cache_ec_type(xmlNode *node, u8 code)
{
        /* 3.3.8.3 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "None",
                "Parity",
                "Single-bit ECC",
                "Multi-bit ECC" /* 0x06 */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "ErrorCorrectionType", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.8.3");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x06) {
                dmixml_AddTextContent(data_n, type[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_cache_type(xmlNode *node, u8 code)
{
        /* 3.3.8.4 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Instruction",
                "Data",
                "Unified"       /* 0x05 */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "SystemType", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.8.4");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x05) {
                dmixml_AddTextContent(data_n, type[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_cache_associativity(xmlNode *node, u8 code)
{
        /* 3.3.8.5 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Direct Mapped",
                "2-way Set-associative",
                "4-way Set-associative",
                "Fully Associative",
                "8-way Set-associative",
                "16-way Set-associative"        /* 0x08 */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Associativity", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.8.5");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x08) {
                dmixml_AddTextContent(data_n, type[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

/*******************************************************************************
** 3.3.9 Port Connector Information (Type 8)
*/

void dmi_port_connector_type(xmlNode *node, const char *tpref, u8 code)
{
        /* 3.3.9.2 */
        static const char *type[] = {
                "None",         /* 0x00 */
                "Centronics",
                "Mini Centronics",
                "Proprietary",
                "DB-25 male",
                "DB-25 female",
                "DB-15 male",
                "DB-15 female",
                "DB-9 male",
                "DB-9 female",
                "RJ-11",
                "RJ-45",
                "50 Pin MiniSCSI",
                "Mini DIN",
                "Micro DIN",
                "PS/2",
                "Infrared",
                "HP-HIL",
                "Access Bus (USB)",
                "SSA SCSI",
                "Circular DIN-8 male",
                "Circular DIN-8 female",
                "On Board IDE",
                "On Board Floppy",
                "9 Pin Dual Inline (pin 10 cut)",
                "25 Pin Dual Inline (pin 26 cut)",
                "50 Pin Dual Inline",
                "68 Pin Dual Inline",
                "On Board Sound Input From CD-ROM",
                "Mini Centronics Type-14",
                "Mini Centronics Type-26",
                "Mini Jack (headphones)",
                "BNC",
                "IEEE 1394",
                "SAS/SATA Plug Receptacle"      /* 0x22 */
        };
        static const char *type_0xA0[] = {
                "PC-98",        /* 0xA0 */
                "PC-98 Hireso",
                "PC-H98",
                "PC-98 Note",
                "PC-98 Full"    /* 0xA4 */
        };

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Connector", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.9.2");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);
        dmixml_AddAttribute(data_n, "type", "%s", tpref);

        if(code <= 0x22) {
                dmixml_AddTextContent(data_n, type[code]);
        } else if(code >= 0xA0 && code <= 0xA4) {
                dmixml_AddTextContent(data_n, type_0xA0[code - 0xA0]);
        } else if(code == 0xFF) {
                dmixml_AddTextContent(data_n, "Other");
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_port_type(xmlNode *node, u8 code)
{
        /* 3.3.9.3 */
        static const char *type[] = {
                "None",         /* 0x00 */
                "Parallel Port XT/AT Compatible",
                "Parallel Port PS/2",
                "Parallel Port ECP",
                "Parallel Port EPP",
                "Parallel Port ECP/EPP",
                "Serial Port XT/AT Compatible",
                "Serial Port 16450 Compatible",
                "Serial Port 16550 Compatible",
                "Serial Port 16550A Compatible",
                "SCSI Port",
                "MIDI Port",
                "Joystick Port",
                "Keyboard Port",
                "Mouse Port",
                "SSA SCSI",
                "USB",
                "Firewire (IEEE P1394)",
                "PCMCIA Type I",
                "PCMCIA Type II",
                "PCMCIA Type III",
                "Cardbus",
                "Access Bus Port",
                "SCSI II",
                "SCSI Wide",
                "PC-98",
                "PC-98 Hireso",
                "PC-H98",
                "Video Port",
                "Audio Port",
                "Modem Port",
                "Network Port",
                "SATA",
                "SAS"           /* 0x21 */
        };
        static const char *type_0xA0[] = {
                "8251 Compatible",      /* 0xA0 */
                "8251 FIFO Compatible"  /* 0xA1 */
        };

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "PortType", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.9.3");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code <= 0x21) {
                dmixml_AddTextContent(data_n, type[code]);
        } else if(code >= 0xA0 && code <= 0xA1) {
                dmixml_AddTextContent(data_n, type_0xA0[code - 0xA0]);
        } else if(code == 0xFF) {
                dmixml_AddTextContent(data_n, "Other");
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

/*******************************************************************************
** 3.3.10 System Slots (Type 9)
*/

void dmi_slot_type(xmlNode *node, u8 code)
{
        /* 3.3.10.1 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "ISA",
                "MCA",
                "EISA",
                "PCI",
                "PC Card (PCMCIA)",
                "VLB",
                "Proprietary",
                "Processor Card",
                "Proprietary Memory Card",
                "I/O Riser Card",
                "NuBus",
                "PCI-66",
                "AGP",
                "AGP 2x",
                "AGP 4x",
                "PCI-X",
                "AGP 8x"        /* 0x13 */
        };
        static const char *type_0xA0[] = {
                "PC-98/C20",    /* 0xA0 */
                "PC-98/C24",
                "PC-98/E",
                "PC-98/Local Bus",
                "PC-98/Card",
                "PCI Express",
                "PCI Express x1",
                "PCI Express x2",
                "PCI Express x4",
                "PCI Express x8",
                "PCI Express x16"       /* 0xAA */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "SlotType", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.10.1");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x13) {
                dmixml_AddTextContent(data_n, "%s", type[code - 0x01]);
        } else if(code >= 0xA0 && code <= 0xAA) {
                dmixml_AddTextContent(data_n, "%s", type_0xA0[code - 0xA0]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_slot_bus_width(xmlNode *node, u8 code)
{
        /* 3.3.10.2 */
        static const char *width[] = {
                "",             /* 0x01, "Other" */
                "",             /* "Unknown" */
                "8-bit ",
                "16-bit ",
                "32-bit ",
                "64-bit ",
                "128-bit ",
                "x1 ",
                "x2 ",
                "x4 ",
                "x8 ",
                "x12 ",
                "x16 ",
                "x32 "          /* 0x0E */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "SlotWidth", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.10.2");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if( (code >= 0x01) && (code <= 0x0E) ) {
                dmixml_AddTextContent(data_n, "%s", width[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_slot_current_usage(xmlNode *node, u8 code)
{
        /* 3.3.10.3 */
        static const char *usage[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Available",
                "In Use"        /* 0x04 */
        };

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "CurrentUsage", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.10.3");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);


        if(code >= 0x01 && code <= 0x04) {
                dmixml_AddTextContent(data_n, usage[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

/* 3.3.1O.4 */
void dmi_slot_length(xmlNode *node, u8 code)
{
        static const char *length[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Short",
                "Long"          /* 0x04 */
        };

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "SlotLength", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.10.4");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x04) {
                dmixml_AddTextContent(data_n, length[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

/* 3.3.10.5 */
void dmi_slot_id(xmlNode *node, u8 code1, u8 code2, u8 type)
{
        dmixml_AddAttribute(node, "dmispec", "3.3.10.5");
        switch (type) {
        case 0x04:             /* MCA */
                dmixml_AddAttribute(node, "id", "%i", code1);
                break;
        case 0x05:             /* EISA */
                dmixml_AddAttribute(node, "id", "%i", code1);
                break;
        case 0x06:             /* PCI */
        case 0x0E:             /* PCI */
        case 0x0F:             /* AGP */
        case 0x10:             /* AGP */
        case 0x11:             /* AGP */
        case 0x12:             /* PCI-X */
        case 0x13:             /* AGP */
        case 0xA5:             /* PCI Express */
                dmixml_AddAttribute(node, "id", "%i", code1);
                break;
        case 0x07:             /* PCMCIA */
                dmixml_AddAttribute(node, "adapter", "%i", code1);
                dmixml_AddAttribute(node, "id", "%i", code2);
                break;
        default:
                break;
        }
}

void dmi_slot_characteristics(xmlNode *node, u8 code1, u8 code2)
{
        /* 3.3.10.6 */
        static const char *characteristics1[] = {
                "5.0 V is provided",    /* 1 */
                "3.3 V is provided",
                "Opening is shared",
                "PC Card-16 is supported",
                "Cardbus is supported",
                "Zoom Video is supported",
                "Modem ring resume is supported"        /* 7 */
        };

        /* 3.3.10.7 */
        static const char *characteristics2[] = {
                "PME signal is supported",      /* 0 */
                "Hot-plug devices are supported",
                "SMBus signal is supported"     /* 2 */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "SlotCharacteristics", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.10.6");
        dmixml_AddAttribute(data_n, "flags1", "0x%04x", code1);
        dmixml_AddAttribute(data_n, "flags2", "0x%04x", code2);

        if(code1 & (1 << 0)) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else if((code1 & 0xFE) == 0 && (code2 & 0x07) == 0) {
                // Nothing - empty tag
        } else {
                int i;

                for(i = 1; i <= 7; i++) {
                        if(code1 & (1 << i)) {
                                xmlNode *c_n = dmixml_AddTextChild(data_n, "Characteristic", "%s",
                                                                   characteristics1[i - 1]);
                                dmixml_AddAttribute(c_n, "index", "%i", i);
                                c_n = NULL;
                        }
                }
                for(i = 0; i <= 2; i++) {
                        if(code2 & (1 << i)) {
                                xmlNode *c_n = dmixml_AddTextChild(data_n, "Characteristic", "%s",
                                                                   characteristics2[i]);
                                dmixml_AddAttribute(c_n, "index", "%i", i);
                                c_n = NULL;
                        }
                }
        }
}

static PyObject *dmi_slot_segment_bus_func(u16 code1, u8 code2, u8 code3)
{
        /* 3.3.10.8 */
        PyObject *data;

        if(!(code1 == 0xFFFF && code2 == 0xFF && code3 == 0xFF))
                data =
                    PyString_FromFormat("%04x:%02x:%02x.%x", code1, code2, code3 >> 3, code3 & 0x7);
        else
                data = Py_None;
        return data;
}

/*******************************************************************************
** 3.3.11 On Board Devices Information (Type 10)
*/

static const char *dmi_on_board_devices_type(xmlNode *node, u8 code)
{
        /* 3.3.11.1 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Video",
                "SCSI Controller",
                "Ethernet",
                "Token Ring",
                "Sound",
                "PATA Controller",
                "SATA Controller",
                "SAS Controller"        /* 0x0A */
        };

        dmixml_AddAttribute(node, "dmispec", "3.3.11.1");
        dmixml_AddAttribute(node, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x0A) {
                dmixml_AddTextChild(node, "Type", "%s", type[code - 0x01]);
        } else {
                dmixml_AddAttribute(node, "outofspec", "1");
        }
}

void dmi_on_board_devices(xmlNode *node, const char *tagname, struct dmi_header *h)
{
        u8 *p = h->data + 4;
        u8 count = (h->length - 0x04) / 2;
        int i;

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.11");

        for(i = 0; i < count; i++) {
                xmlNode *dev_n = xmlNewChild(data_n, NULL, (xmlChar *) "Device", NULL);
                assert( dev_n != NULL );

                dmi_on_board_devices_type(dev_n, p[2 * i] & 0x7F);
                dmixml_AddAttribute(dev_n, "Enabled", "%i", ((p[2 * i] & 0x80) ? 1 : 0));
                dmixml_AddTextChild(dev_n, "Description", "%s", dmi_string(h, p[2 * i + 1]));
                dev_n = NULL;
        }
}

/*******************************************************************************
 * 3.3.12 OEM Strings (Type 11)
 */

void dmi_oem_strings(xmlNode *node, struct dmi_header *h)
{
        u8 *p = h->data + 4;
        u8 count = p[0x00];
        int i;

        dmixml_AddAttribute(node, "dmispec", "3.3.12");
        dmixml_AddAttribute(node, "count", "%i", count);

        for(i = 1; i <= count; i++) {
                xmlNode *str_n = dmixml_AddTextChild(node, "Record", "%s", dmi_string(h, i));
                assert( str_n != NULL );
                dmixml_AddAttribute(str_n, "index", "%i", i);
        }
}

/*******************************************************************************
** 3.3.13 System Configuration Options (Type 12)
*/

void dmi_system_configuration_options(xmlNode *node, struct dmi_header *h)
{
        u8 *p = h->data + 4;
        u8 count = p[0x00];
        int i;

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Options", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.13");
        dmixml_AddAttribute(data_n, "count", "%i", count);

        for(i = 1; i <= count; i++) {
                xmlNode *o_n = dmixml_AddTextChild(data_n, "Option", "%s", dmi_string(h, i));
                assert( o_n != NULL );

                dmixml_AddAttribute(o_n, "index", "%ld", i);
        }
}

/*******************************************************************************
** 3.3.14 BIOS Language Information (Type 13)
*/

void dmi_bios_languages(xmlNode *node, struct dmi_header *h)
{
        u8 *p = h->data + 4;
        u8 count = p[0x00];
        int i;

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Installed", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.14");
        dmixml_AddAttribute(data_n, "count", "%i", count);

        for(i = 1; i <= count; i++) {
                xmlNode *l_n = dmixml_AddTextChild(data_n, "Language", "%s", dmi_string_py(h, i));
                assert( l_n != NULL );
                dmixml_AddAttribute(l_n, "index", "%i", i);
        }
}

/*******************************************************************************
** 3.3.15 Group Associations (Type 14)
*/

void dmi_group_associations_items(xmlNode *node, u8 count, const u8 * p)
{
        dmixml_AddAttribute(node, "dmispec", "3.3.15");
        dmixml_AddAttribute(node, "items", "%i", count);

        int i;
        for(i = 0; i < count; i++) {
                xmlNode *grp_n = xmlNewChild(node, NULL, (xmlChar *) "Group", NULL);
                assert( grp_n != NULL );

                dmixml_AddAttribute(grp_n, "handle", "0x%04x", WORD(p + 3 * i + 1));
                dmi_smbios_structure_type(grp_n, p[3 * i]);
        }
}

/*******************************************************************************
** 3.3.16 System Event Log (Type 15)
*/

void dmi_event_log_method(xmlNode *node, u8 code)
{
        static const char *method[] = {
                "Indexed I/O, one 8-bit index port, one 8-bit data port",       /* 0x00 */
                "Indexed I/O, two 8-bit index ports, one 8-bit data port",
                "Indexed I/O, one 16-bit index port, one 8-bit data port",
                "Memory-mapped physical 32-bit address",
                "General-purpose non-volatile data functions"   /* 0x04 */
        };

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "AccessMethod", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.16");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code <= 0x04) {
                dmixml_AddTextContent(data_n, "%s", method[code]);
        } else if(code >= 0x80){
                dmixml_AddTextContent(data_n, "OEM-specific");
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_event_log_status(xmlNode *node, u8 code)
{
        static const char *valid[] = {
                "Invalid",      /* 0 */
                "Valid"         /* 1 */
        };
        static const char *full[] = {
                "Not Full",     /* 0 */
                "Full"          /* 1 */
        };

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Status", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.16");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        // FIXME: Should we use 0/1 instead of strings?
        dmixml_AddAttribute(data_n, "Full", "%s", full[(code >> 1) & 1]);
        dmixml_AddAttribute(data_n, "Valid", "%s", valid[(code >> 0) & 1]);
}

void dmi_event_log_address(xmlNode *node, u8 method, const u8 * p)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Address", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.16.3");
        dmixml_AddAttribute(data_n, "method", "0x%04x", method);

        /* 3.3.16.3 */
        switch (method) {
        case 0x00:
        case 0x01:
        case 0x02:
                dmixml_AddAttribute(data_n, "Index", "0x%04x", WORD(p));
                dmixml_AddAttribute(data_n, "Data", "0x%04x", WORD(p + 2));
                break;
        case 0x03:
                dmixml_AddAttribute(data_n, "Data", "0x%08x", DWORD(p));
                break;
        case 0x04:
                dmixml_AddAttribute(data_n, "Data", "0x%04x", WORD(p));
                break;
        default:
                dmixml_AddAttribute(data_n, "unknown", "1");
        }
}

void dmi_event_log_header_type(xmlNode *node, u8 code)
{
        static const char *type[] = {
                "No Header",    /* 0x00 */
                "Type 1"        /* 0x01 */
        };

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Format", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.16");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code <= 0x01) {
                dmixml_AddTextContent(data_n, type[code]);
        } else if(code >= 0x80) {
                dmixml_AddTextContent(data_n, "OEM-specific");
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_event_log_descriptor_type(xmlNode *node, u8 code)
{
        /* 3.3.16.6.1 */
        static const char *type[] = {
                NULL,           /* 0x00 */
                "Single-bit ECC memory error",
                "Multi-bit ECC memory error",
                "Parity memory error",
                "Bus timeout",
                "I/O channel block",
                "Software NMI",
                "POST memory resize",
                "POST error",
                "PCI parity error",
                "PCI system error",
                "CPU failure",
                "EISA failsafe timer timeout",
                "Correctable memory log disabled",
                "Logging disabled",
                NULL,           /* 0x0F */
                "System limit exceeded",
                "Asynchronous hardware timer expired",
                "System configuration information",
                "Hard disk information",
                "System reconfigured",
                "Uncorrectable CPU-complex error",
                "Log area reset/cleared",
                "System boot"   /* 0x17 */
        };

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Descriptor", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.16.6.1");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code <= 0x17 && type[code] != NULL) {
                dmixml_AddTextContent(data_n, "%s", type[code]);
        } else if(code >= 0x80 && code <= 0xFE) {
                dmixml_AddTextContent(data_n, "OEM-specific");
        } else if(code == 0xFF) {
                dmixml_AddTextContent(data_n, "End of log");
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_event_log_descriptor_format(xmlNode *node, u8 code)
{
        /* 3.3.16.6.2 */
        static const char *format[] = {
                "None",         /* 0x00 */
                "Handle",
                "Multiple-event",
                "Multiple-event handle",
                "POST results bitmap",
                "System management",
                "Multiple-event system management"      /* 0x06 */
        };

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Format", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.16.6.2");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code <= 0x06) {
                dmixml_AddTextContent(data_n, format[code]);
        } else if(code >= 0x80) {
                dmixml_AddTextContent(data_n, "OEM-specific");
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_event_log_descriptors(xmlNode *node, u8 count, const u8 len, const u8 * p)
{
        /* 3.3.16.1 */
        int i;

        dmixml_AddAttribute(node, "dmispec", "3.3.16.1");

        for(i = 0; i < count; i++) {
                if(len >= 0x02) {
                        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "LogType", NULL);
                        assert( data_n != NULL );

                        dmi_event_log_descriptor_type(data_n, p[i * len]);
                        dmi_event_log_descriptor_format(data_n, p[i * len + 1]);
                }
        }
}

/*******************************************************************************
** 3.3.17 Physical Memory Array (Type 16)
*/

static PyObject *dmi_memory_array_location(u8 code)
{
        /* 3.3.17.1 */
        static const char *location[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "System Board Or Motherboard",
                "ISA Add-on Card",
                "EISA Add-on Card",
                "PCI Add-on Card",
                "MCA Add-on Card",
                "PCMCIA Add-on Card",
                "Proprietary Add-on Card",
                "NuBus"         /* 0x0A, master.mif says 16 */
        };
        static const char *location_0xA0[] = {
                "PC-98/C20 Add-on Card",        /* 0xA0 */
                "PC-98/C24 Add-on Card",
                "PC-98/E Add-on Card",
                "PC-98/Local Bus Add-on Card",
                "PC-98/Card Slot Add-on Card"   /* 0xA4, from master.mif */
        };

        if(code >= 0x01 && code <= 0x0A)
                return PyString_FromString(location[code - 0x01]);
        if(code >= 0xA0 && code <= 0xA4)
                return PyString_FromString(location_0xA0[code - 0xA0]);
        return OUT_OF_SPEC;
}

static PyObject *dmi_memory_array_use(u8 code)
{
        /* 3.3.17.2 */
        static const char *use[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "System Memory",
                "Video Memory",
                "Flash Memory",
                "Non-volatile RAM",
                "Cache Memory"  /* 0x07 */
        };

        if(code >= 0x01 && code <= 0x07)
                return PyString_FromString(use[code - 0x01]);
        return OUT_OF_SPEC;
}

static PyObject *dmi_memory_array_ec_type(u8 code)
{
        /* 3.3.17.3 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "None",
                "Parity",
                "Single-bit ECC",
                "Multi-bit ECC",
                "CRC"           /* 0x07 */
        };

        if(code >= 0x01 && code <= 0x07)
                return PyString_FromString(type[code - 0x01]);
        return OUT_OF_SPEC;
}

static PyObject *dmi_memory_array_capacity(u32 code)
{
        PyObject *data;

        if(code == 0x8000000)
                data = PyString_FromString("Unknown");
        else {
                if((code & 0x000FFFFF) == 0)
                        data = PyString_FromFormat("%i GB", code >> 20);
                else if((code & 0x000003FF) == 0)
                        data = PyString_FromFormat("%i MB", code >> 10);
                else
                        data = PyString_FromFormat("%i kB", code);
        }
        return data;
}

static PyObject *dmi_memory_array_error_handle(u16 code)
{
        PyObject *data;

        if(code == 0xFFFE)
                data = PyString_FromString("Not Provided");
        else if(code == 0xFFFF)
                data = PyString_FromString("No Error");
        else
                data = PyString_FromFormat("0x%04x", code);
        return data;
}

/*******************************************************************************
** 3.3.18 Memory Device (Type 17)
*/

static PyObject *dmi_memory_device_width(u16 code)
{
        /*
         ** If no memory module is present, width may be 0
         */
        PyObject *data;

        if(code == 0xFFFF || code == 0)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%i bits", code);
        return data;
}

static PyObject *dmi_memory_device_size(u16 code)
{
        PyObject *data = NULL;

        if(code == 0)
                data = Py_None; //. No Module Installed
        else if(code == 0xFFFF)
                data = PyString_FromString("Unknown");  //. Unknown
        else {
                //. Keeping this as String rather than Int as it has KB and MB representations...
                if(code & 0x8000)
                        data = PyString_FromFormat("%d KB", code & 0x7FFF);
                else
                        data = PyString_FromFormat("%d MB", code);
        }
        return data;
}

static PyObject *dmi_memory_device_form_factor(u8 code)
{
        /* 3.3.18.1 */
        static const char *form_factor[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "SIMM",
                "SIP",
                "Chip",
                "DIP",
                "ZIP",
                "Proprietary Card",
                "DIMM",
                "TSOP",
                "Row Of Chips",
                "RIMM",
                "SODIMM",
                "SRIMM",
                "FB-DIMM"       /* 0x0F */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x0F)
                return data = PyString_FromString(form_factor[code - 0x01]);
        return data = OUT_OF_SPEC;
}

static PyObject *dmi_memory_device_set(u8 code)
{
        PyObject *data;

        if(code == 0)
                data = Py_None;
        else if(code == 0xFF)
                data = PyString_FromString("Unknown");
        else
                data = PyInt_FromLong(code);
        return data;
}

static PyObject *dmi_memory_device_type(u8 code)
{
        /* 3.3.18.2 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "DRAM",
                "EDRAM",
                "VRAM",
                "SRAM",
                "RAM",
                "ROM",
                "Flash",
                "EEPROM",
                "FEPROM",
                "EPROM",
                "CDRAM",
                "3DRAM",
                "SDRAM",
                "SGRAM",
                "RDRAM",
                "DDR",
                "DDR2",
                "DDR2 FB-DIMM"  /* 0x14 */
        };

        if(code >= 0x01 && code <= 0x14)
                return PyString_FromString(type[code - 0x01]);
        return OUT_OF_SPEC;
}

static PyObject *dmi_memory_device_type_detail(u16 code)
{
        /* 3.3.18.3 */
        static const char *detail[] = {
                "Other",        /* 1 */
                "Unknown",
                "Fast-paged",
                "Static Column",
                "Pseudo-static",
                "RAMBus",
                "Synchronous",
                "CMOS",
                "EDO",
                "Window DRAM",
                "Cache DRAM",
                "Non-Volatile"  /* 12 */
        };

        PyObject *data;

        if((code & 0x1FFE) == 0)
                data = Py_None;
        else {
                int i;

                data = PyList_New(12);
                for(i = 1; i <= 12; i++)
                        if(code & (1 << i))
                                PyList_SET_ITEM(data, i - 1, PyString_FromString(detail[i - 1]));
                        else
                                PyList_SET_ITEM(data, i - 1, Py_None);
        }
        return data;
}

static PyObject *dmi_memory_device_speed(u16 code)
{
        PyObject *data;

        if(code == 0)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%i MHz (%.1f ns)", code, (float)1000 / code);
        return data;
}

/*******************************************************************************
* 3.3.19 32-bit Memory Error Information (Type 18)
*/

static PyObject *dmi_memory_error_type(u8 code)
{
        /* 3.3.19.1 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "OK",
                "Bad Read",
                "Parity Error",
                "Single-bit Error",
                "Double-bit Error",
                "Multi-bit Error",
                "Nibble Error",
                "Checksum Error",
                "CRC Error",
                "Corrected Single-bit Error",
                "Corrected Error",
                "Uncorrectable Error"   /* 0x0E */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x0E)
                data = PyString_FromString(type[code - 0x01]);
        data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_memory_error_granularity(u8 code)
{
        /* 3.3.19.2 */
        static const char *granularity[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Device Level",
                "Memory Partition Level"        /* 0x04 */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x04)
                data = PyString_FromString(granularity[code - 0x01]);
        else
                data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_memory_error_operation(u8 code)
{
        /* 3.3.19.3 */
        static const char *operation[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Read",
                "Write",
                "Partial Write" /* 0x05 */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x05)
                data = PyString_FromString(operation[code - 0x01]);
        else
                data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_memory_error_syndrome(u32 code)
{
        PyObject *data;

        if(code == 0x00000000)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("0x%08x", code);
        return data;
}

static PyObject *dmi_32bit_memory_error_address(u32 code)
{
        PyObject *data;

        if(code == 0x80000000)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("0x%08x", code);
        return data;
}

/*******************************************************************************
** 3.3.20 Memory Array Mapped Address (Type 19)
*/

static PyObject *dmi_mapped_address_size(u32 code)
{
        PyObject *data;

        if(code == 0)
                data = PyString_FromString("Invalid");
        else if((code & 0x000FFFFF) == 0)
                data = PyString_FromFormat("%i GB", code >> 20);
        else if((code & 0x000003FF) == 0)
                data = PyString_FromFormat("%i MB", code >> 10);
        else
                data = PyString_FromFormat("%i kB", code);
        return data;
}

/*******************************************************************************
** 3.3.21 Memory Device Mapped Address (Type 20)
*/

static PyObject *dmi_mapped_address_row_position(u8 code)
{
        PyObject *data;

        if(code == 0)
                data = OUT_OF_SPEC;
        else if(code == 0xFF)
                data = PyString_FromString("Unknown");
        else
                data = PyInt_FromLong(code);
        return data;
}

static PyObject *dmi_mapped_address_interleave_position(u8 code)
{
        PyObject *data;

        if(code != 0) {
                data = PyDict_New();
                PyDict_SetItemString(data, "Interleave Position",
                                     (code ==
                                      0xFF) ? PyString_FromString("Unknown") :
                                     PyInt_FromLong(code));
        } else
                data = Py_None;
        return data;
}

static PyObject *dmi_mapped_address_interleaved_data_depth(u8 code)
{
        PyObject *data;

        if(code != 0) {
                data = PyDict_New();
                PyDict_SetItemString(data, "Interleave Data Depth",
                                     (code ==
                                      0xFF) ? PyString_FromString("Unknown") :
                                     PyInt_FromLong(code));
        } else
                data = Py_None;
        return data;
}

/*******************************************************************************
** 3.3.22 Built-in Pointing Device (Type 21)
*/

static PyObject *dmi_pointing_device_type(u8 code)
{
        /* 3.3.22.1 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Mouse",
                "Track Ball",
                "Track Point",
                "Glide Point",
                "Touch Pad",
                "Touch Screen",
                "Optical Sensor"        /* 0x09 */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x09)
                data = PyString_FromString(type[code - 0x01]);
        else
                data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_pointing_device_interface(u8 code)
{
        /* 3.3.22.2 */
        static const char *interface[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Serial",
                "PS/2",
                "Infrared",
                "HIP-HIL",
                "Bus Mouse",
                "ADB (Apple Desktop Bus)"       /* 0x08 */
        };
        static const char *interface_0xA0[] = {
                "Bus Mouse DB-9",       /* 0xA0 */
                "Bus Mouse Micro DIN",
                "USB"           /* 0xA2 */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x08)
                data = PyString_FromString(interface[code - 0x01]);
        else if(code >= 0xA0 && code <= 0xA2)
                data = PyString_FromString(interface_0xA0[code - 0xA0]);
        else
                data = OUT_OF_SPEC;
        return data;
}

/*******************************************************************************
** 3.3.23 Portable Battery (Type 22)
*/

static PyObject *dmi_battery_chemistry(u8 code)
{
        /* 3.3.23.1 */
        static const char *chemistry[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Lead Acid",
                "Nickel Cadmium",
                "Nickel Metal Hydride",
                "Lithium Ion",
                "Zinc Air",
                "Lithium Polymer"       /* 0x08 */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x08)
                data = PyString_FromString(chemistry[code - 0x01]);
        data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_battery_capacity(u16 code, u8 multiplier)
{
        PyObject *data;

        if(code == 0)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%i mWh", code * multiplier);
        return data;
}

static PyObject *dmi_battery_voltage(u16 code)
{
        PyObject *data;

        if(code == 0)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%i mV", code);
        return data;
}

static PyObject *dmi_battery_maximum_error(u8 code)
{
        PyObject *data;

        if(code == 0xFF)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%i%%", code);
        return data;
}

/*******************************************************************************
** 3.3.24 System Reset (Type 23)
*/

static PyObject *dmi_system_reset_boot_option(u8 code)
{
        static const char *option[] = {
                "Operating System",     /* 0x1 */
                "System Utilities",
                "Do Not Reboot" /* 0x3 */
        };
        PyObject *data;

        if(code >= 0x1)
                data = PyString_FromString(option[code - 0x1]);
        else
                data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_system_reset_count(u16 code)
{
        PyObject *data;

        if(code == 0xFFFF)
                data = PyString_FromString("Unknown");
        else
                data = PyInt_FromLong(code);
        return data;
}

static PyObject *dmi_system_reset_timer(u16 code)
{
        PyObject *data;

        if(code == 0xFFFF)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%i min", code);
        return data;
}

/*******************************************************************************
 * 3.3.25 Hardware Security (Type 24)
 */

static PyObject *dmi_hardware_security_status(u8 code)
{
        static const char *status[] = {
                "Disabled",     /* 0x00 */
                "Enabled",
                "Not Implemented",
                "Unknown"       /* 0x03 */
        };

        return PyString_FromString(status[code]);
}

/*******************************************************************************
** 3.3.26 System Power Controls (Type 25)
*/

static PyObject *dmi_power_controls_power_on(const u8 * p)
{
        /* 3.3.26.1 */
        PyObject *data = PyList_New(5);

        PyList_SET_ITEM(data, 0,
                        dmi_bcd_range(p[0], 0x01, 0x12) ? PyString_FromFormat(" %02x",
                                                                              p[0]) :
                        PyString_FromString(" *"));
        PyList_SET_ITEM(data, 1,
                        dmi_bcd_range(p[1], 0x01, 0x31) ? PyString_FromFormat("-%02x",
                                                                              p[1]) :
                        PyString_FromString("-*"));
        PyList_SET_ITEM(data, 2,
                        dmi_bcd_range(p[2], 0x00, 0x23) ? PyString_FromFormat(" %02x",
                                                                              p[2]) :
                        PyString_FromString(" *"));
        PyList_SET_ITEM(data, 3,
                        dmi_bcd_range(p[3], 0x00, 0x59) ? PyString_FromFormat(":%02x",
                                                                              p[3]) :
                        PyString_FromString(":*"));
        PyList_SET_ITEM(data, 4,
                        dmi_bcd_range(p[4], 0x00, 0x59) ? PyString_FromFormat(":%02x",
                                                                              p[4]) :
                        PyString_FromString(":*"));

        return data;
}

/*******************************************************************************
* 3.3.27 Voltage Probe (Type 26)
*/

static PyObject *dmi_voltage_probe_location(u8 code)
{
        /* 3.3.27.1 */
        static const char *location[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Processor",
                "Disk",
                "Peripheral Bay",
                "System Management Module",
                "Motherboard",
                "Memory Module",
                "Processor Module",
                "Power Unit",
                "Add-in Card"   /* 0x0B */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x0B)
                data = PyString_FromString(location[code - 0x01]);
        else
                data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_probe_status(u8 code)
{
        /* 3.3.27.1 */
        static const char *status[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "OK",
                "Non-critical",
                "Critical",
                "Non-recoverable"       /* 0x06 */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x06)
                data = PyString_FromString(status[code - 0x01]);
        else
                data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_voltage_probe_value(u16 code)
{
        PyObject *data;

        if(code == 0x8000)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%.3f V", (float)(i16) code / 1000);
        return data;
}

static PyObject *dmi_voltage_probe_resolution(u16 code)
{
        PyObject *data;

        if(code == 0x8000)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%.1f mV", (float)code / 10);
        return data;
}

static PyObject *dmi_probe_accuracy(u16 code)
{
        PyObject *data;

        if(code == 0x8000)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%.2f%%", (float)code / 100);
        return data;
}

/*******************************************************************************
** 3.3.28 Cooling Device (Type 27)
*/

static PyObject *dmi_cooling_device_type(u8 code)
{
        /* 3.3.28.1 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Fan",
                "Centrifugal Blower",
                "Chip Fan",
                "Cabinet Fan",
                "Power Supply Fan",
                "Heat Pipe",
                "Integrated Refrigeration"      /* 0x09 */
        };
        static const char *type_0x10[] = {
                "Active Cooling",       /* 0x10, master.mif says 32 */
                "Passive Cooling"       /* 0x11, master.mif says 33 */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x09)
                data = PyString_FromString(type[code - 0x01]);
        else if(code >= 0x10 && code <= 0x11)
                data = PyString_FromString(type_0x10[code - 0x10]);
        else
                data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_cooling_device_speed(u16 code)
{
        PyObject *data;

        if(code == 0x8000)
                data = PyString_FromString("Unknown Or Non-rotating");
        else
                data = PyString_FromFormat("%i rpm", code);
        return data;
}

/*******************************************************************************
** 3.3.29 Temperature Probe (Type 28)
*/

static PyObject *dmi_temperature_probe_location(u8 code)
{
        /* 3.3.29.1 */
        static const char *location[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Processor",
                "Disk",
                "Peripheral Bay",
                "System Management Module",     /* master.mif says SMB Master */
                "Motherboard",
                "Memory Module",
                "Processor Module",
                "Power Unit",
                "Add-in Card",
                "Front Panel Board",
                "Back Panel Board",
                "Power System Board",
                "Drive Back Plane"      /* 0x0F */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x0F)
                data = PyString_FromString(location[code - 0x01]);
        else
                data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_temperature_probe_value(u16 code)
{
        PyObject *data;

        if(code == 0x8000)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%.1f deg C", (float)(i16) code / 10);
        return data;
}

static PyObject *dmi_temperature_probe_resolution(u16 code)
{
        PyObject *data;

        if(code == 0x8000)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%.3f deg C", (float)code / 1000);
        return data;
}

/*******************************************************************************
** 3.3.30 Electrical Current Probe (Type 29)
*/

static PyObject *dmi_current_probe_value(u16 code)
{
        PyObject *data;

        if(code == 0x8000)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%.3f A", (float)(i16) code / 1000);
        return data;
}

static PyObject *dmi_current_probe_resolution(u16 code)
{
        PyObject *data;

        if(code == 0x8000)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%.1f mA", (float)code / 10);
        return data;
}

/*******************************************************************************
** 3.3.33 System Boot Information (Type 32)
*/

static PyObject *dmi_system_boot_status(u8 code)
{
        static const char *status[] = {
                "No errors detected",   /* 0 */
                "No bootable media",
                "Operating system failed to load",
                "Firmware-detected hardware failure",
                "Operating system-detected hardware failure",
                "User-requested boot",
                "System security violation",
                "Previously-requested image",
                "System watchdog timer expired" /* 8 */
        };
        PyObject *data;

        if(code <= 8)
                data = PyString_FromString(status[code]);
        else if(code >= 128 && code <= 191)
                data = PyString_FromString("OEM-specific");
        else if(code >= 192)
                data = PyString_FromString("Product-specific");
        else
                data = OUT_OF_SPEC;
        return data;
}

/*******************************************************************************
** 3.3.34 64-bit Memory Error Information (Type 33)
*/

static PyObject *dmi_64bit_memory_error_address(u64 code)
{
        PyObject *data;

        if(code.h == 0x80000000 && code.l == 0x00000000)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("0x%08x%08x", code.h, code.l);
        return data;
}

/*******************************************************************************
** 3.3.35 Management Device (Type 34)
*/

static PyObject *dmi_management_device_type(u8 code)
{
        /* 3.3.35.1 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "LM75",
                "LM78",
                "LM79",
                "LM80",
                "LM81",
                "ADM9240",
                "DS1780",
                "MAX1617",
                "GL518SM",
                "W83781D",
                "HT82H791"      /* 0x0D */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x0D)
                data = PyString_FromString(type[code - 0x01]);
        else
                data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_management_device_address_type(u8 code)
{
        /* 3.3.35.2 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "I/O Port",
                "Memory",
                "SMBus"         /* 0x05 */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x05)
                data = PyString_FromString(type[code - 0x01]);
        else
                data = OUT_OF_SPEC;
        return data;
}

/*******************************************************************************
** 3.3.38 Memory Channel (Type 37)
*/

static PyObject *dmi_memory_channel_type(u8 code)
{
        /* 3.3.38.1 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "RamBus",
                "SyncLink"      /* 0x04 */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x04)
                data = PyString_FromString(type[code - 0x01]);
        else
                data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_memory_channel_devices(u8 count, const u8 * p)
{
        PyObject *data = PyDict_New();
        PyObject *subdata, *val;
        int i;

        for(i = 1; i <= count; i++) {
                subdata = PyList_New(2);

                val = PyString_FromFormat("Load: %i", p[3 * i]);
                PyList_SET_ITEM(subdata, 0, val);
                Py_DECREF(val);

                val = PyString_FromFormat("Handle: 0x%04x", WORD(p + 3 * i + 1));
                PyList_SET_ITEM(subdata, 1, val);
                Py_DECREF(val);

                PyDict_SetItem(data, PyInt_FromLong(i), subdata);
                Py_DECREF(subdata);
        }
        return data;
}

/*******************************************************************************
** 3.3.39 IPMI Device Information (Type 38)
*/

static PyObject *dmi_ipmi_interface_type(u8 code)
{
        /* 3.3.39.1 and IPMI 2.0, appendix C1, table C1-2 */
        static const char *type[] = {
                "Unknown",      /* 0x00 */
                "KCS (Keyboard Control Style)",
                "SMIC (Server Management Interface Chip)",
                "BT (Block Transfer)",
                "SSIF (SMBus System Interface)" /* 0x04 */
        };
        PyObject *data;

        if(code <= 0x04)
                data = PyString_FromString(type[code]);
        else
                data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_ipmi_base_address(u8 type, const u8 * p, u8 lsb)
{
        PyObject *data;

        if(type == 0x04) {      /* SSIF */
                data = PyString_FromFormat("0x%02x (SMBus)", (*p) >> 1);
        } else {
                u64 address = QWORD(p);

                data =
                    PyString_FromFormat("0x%08x%08x (%s)", address.h, (address.l & ~1) | lsb,
                                        address.l & 1 ? "I/O" : "Memory-mapped");
        }
        return data;
}

static PyObject *dmi_ipmi_register_spacing(u8 code)
{
        /* IPMI 2.0, appendix C1, table C1-1 */
        static const char *spacing[] = {
                "Successive Byte Boundaries",   /* 0x00 */
                "32-bit Boundaries",
                "16-byte Boundaries"    /* 0x02 */
        };
        PyObject *data;

        if(code <= 0x02)
                return data = PyString_FromString(spacing[code]);
        return data = OUT_OF_SPEC;
}

/*******************************************************************************
** 3.3.40 System Power Supply (Type 39)
*/

static PyObject *dmi_power_supply_power(u16 code)
{
        PyObject *data;

        if(code == 0x8000)
                data = PyString_FromString("Unknown");
        else
                data = PyString_FromFormat("%.3f W", (float)code / 1000);
        return data;
}

static PyObject *dmi_power_supply_type(u8 code)
{
        /* 3.3.40.1 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Linear",
                "Switching",
                "Battery",
                "UPS",
                "Converter",
                "Regulator"     /* 0x08 */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x08)
                data = PyString_FromString(type[code - 0x01]);
        else
                data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_power_supply_status(u8 code)
{
        /* 3.3.40.1 */
        static const char *status[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "OK",
                "Non-critical",
                "Critical"      /* 0x05 */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x05)
                data = PyString_FromString(status[code - 0x01]);
        else
                data = OUT_OF_SPEC;
        return data;
}

static PyObject *dmi_power_supply_range_switching(u8 code)
{
        /* 3.3.40.1 */
        static const char *switching[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Manual",
                "Auto-switch",
                "Wide Range",
                "N/A"           /* 0x06 */
        };
        PyObject *data;

        if(code >= 0x01 && code <= 0x06)
                data = PyString_FromString(switching[code - 0x01]);
        else
                data = OUT_OF_SPEC;
        return data;
}

/*
** 3.3.41 Additional Information (Type 40)
**
** Proper support of this entry type would require redesigning a large part of
** the code, so I am waiting to see actual implementations of it to decide
** whether it's worth the effort.
*/

static PyObject *dmi_additional_info(const struct dmi_header *h, const char *prefix)
{
        u8 *p = h->data + 4;
        u8 count = *p++;
        u8 length;
        int i, offset = 5;
        PyObject *data = PyList_New(count);

        for(i = 0; i < count; i++) {
                PyObject *subdata = PyDict_New();

                /* Check for short entries */
                if(h->length < offset + 1)
                        break;
                length = p[0x00];
                if(length < 0x05 || h->length < offset + length)
                        break;

                PyDict_SetItemString(subdata,
                                     "Referenced Handle",
                                     PyString_FromFormat("0x%04x", WORD(p + 0x01))
                    );

                PyDict_SetItemString(subdata,
                                     "Referenced Offset", PyString_FromFormat("0x%02x", p[0x03])
                    );

                PyDict_SetItemString(subdata, "String", dmi_string_py(h, p[0x04])
                    );

                PyObject *_val;

                switch (length - 0x05) {
                case 1:
                        _val = PyString_FromFormat("0x%02x", p[0x05]);
                        break;
                case 2:
                        _val = PyString_FromFormat("0x%04x", WORD(p + 0x05));
                        break;
                case 4:
                        _val = PyString_FromFormat("0x%08x", DWORD(p + 0x05));
                        break;
                default:
                        _val = PyString_FromString("Unexpected size");
                        break;
                }
                PyDict_SetItemString(subdata, "Value", _val);
                Py_DECREF(_val);

                p += length;
                offset += length;
                PyList_SET_ITEM(data, i, subdata);
        }
        return data;
}

/*******************************************************************************
** Main
*/

void dmi_decode(xmlNode *handle_n, struct dmi_header * h, u16 ver)
{
        const u8 *data = h->data;
        xmlNode *sect_n = NULL, *sub_n = NULL, *sub2_n = NULL;
        //. 0xF1 --> 0xF100
        //int minor = h->type<<8;

        //dmi_codes_major *dmiMajor = (dmi_codes_major *)&dmiCodesMajor[map_maj[h->type]];
        dmi_codes_major *dmiMajor = (dmi_codes_major *) &dmiCodesMajor[h->type];

        dmixml_AddAttribute(handle_n, "id", "%s", dmiMajor->id);
        dmixml_AddAttribute(handle_n, "type", "%s", h->type);
        dmixml_AddTextChild(handle_n, "description", "%s", dmiMajor->desc);

        switch (h->type) {
        case 0:                /* 3.3.1 BIOS Information */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "BIOS", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.1");

                if(h->length < 0x12)
                        break;

                dmixml_AddTextChild(sect_n, "Vendor", "%s", data[0x04]);
                dmixml_AddTextChild(sect_n, "Version", "%s", data[0x05]);
                dmixml_AddTextChild(sect_n, "ReleaseDate", "%s", data[0x08]);

                /*
                 * On IA-64, the BIOS base address will read 0 because
                 * there is no BIOS. Skip the base address and the
                 * runtime size in this case.
                 */

                if(WORD(data + 0x06) != 0) {
                        dmixml_AddTextChild(sect_n, "Address", "0x%04x0", WORD(data + 0x06));
                        dmixml_AddTextChild(sect_n, "RuntimeSize", "%s",
                                            dmi_bios_runtime_size((0x10000 - WORD(data + 0x06)) << 4));
                }

                dmixml_AddTextChild(sect_n, "ROMsize", "%i kB", (data[0x09] + 1) << 6);

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Characteristics", NULL);
                assert( sub_n != NULL );

                dmixml_AddAttribute(sub_n, "level", "0");
                dmi_bios_characteristics(sub_n, QWORD(data + 0x0A));
                sub_n = NULL;

                if(h->length < 0x13)
                        break;

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Characteristics", NULL);
                assert( sub_n != NULL );

                dmixml_AddAttribute(sub_n, "level", "x1");
                dmi_bios_characteristics_x1(sub_n, data[0x12]);

                if(h->length < 0x14)
                        break;

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Characteristics", NULL);
                assert( sub_n != NULL );

                dmixml_AddAttribute(sub_n, "level", "x2");
                dmi_bios_characteristics_x2(sub_n, data[0x13]);
                sub_n = NULL;

                if(h->length < 0x18)
                        break;

                if(data[0x14] != 0xFF && data[0x15] != 0xFF) {
                        dmixml_AddTextChild(sect_n, "BIOSrevision", "%i.%i", data[0x14], data[0x15]);
                }

                if(data[0x16] != 0xFF && data[0x17] != 0xFF) {
                        dmixml_AddTextChild(sect_n, "FirmwareRevision", "%i.%i", data[0x16], data[0x17]);
                }
                sect_n = NULL;
                break;

        case 1:                /* 3.3.2 System Information */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "SystemInformation", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.2");

                if(h->length < 0x08)
                        break;

                dmixml_AddTextChild(sect_n, "Manufacturer", "%s", dmi_string(h, data[0x04]));
                dmixml_AddTextChild(sect_n, "ProductName", "%s", dmi_string(h, data[0x05]));
                dmixml_AddTextChild(sect_n, "Version", "%s", dmi_string(h, data[0x06]));
                dmixml_AddTextChild(sect_n, "SerialNumber", "%s", dmi_string(h, data[0x07]));

                if(h->length < 0x19)
                        break;

                dmi_system_uuid(sect_n, data + 0x08, ver);

                dmi_system_wake_up_type(sect_n, data[0x18]);

                if(h->length < 0x1B)
                        break;

                dmixml_AddTextChild(sect_n, "SKUnumber", "%s", dmi_string(h, data[0x19]));
                dmixml_AddTextChild(sect_n, "Family", "%s", dmi_string(h, data[0x1A]));
                sect_n = NULL;
                break;

        case 2:                /* 3.3.3 Base Board Information */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "Baseboard", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.3");

                if(h->length < 0x08)
                        break;

                dmixml_AddTextChild(sect_n, "Manufacturer", "%s", dmi_string(h, data[0x04]));
                dmixml_AddTextChild(sect_n, "ProductName", "%s", dmi_string(h, data[0x05]));
                dmixml_AddTextChild(sect_n, "Version", "%s", dmi_string(h, data[0x06]));
                dmixml_AddTextChild(sect_n, "SerialNumber", "%s", dmi_string(h, data[0x07]));

                if(h->length < 0x0F)
                        break;

                dmixml_AddTextChild(sect_n, "AssetTag", "%s", dmi_string(h, data[0x08]));

                dmi_base_board_features(sect_n, data[0x09]);

                dmixml_AddTextChild(sect_n, "ChassisLocation", "%s", dmi_string(h, data[0x0A]));
                dmixml_AddTextChild(sect_n, "ChassisHandle", "0x%04x", WORD(data + 0x0B));

                dmi_base_board_type(sect_n, "Type", data[0x0D]);

                if(h->length < 0x0F + data[0x0E] * sizeof(u16))
                        break;

                dmi_base_board_handles(sect_n, data[0x0E], data + 0x0F);
                sect_n = NULL;
                break;

        case 3:                /* 3.3.4 Chassis Information */
                sect_n= xmlNewChild(handle_n, NULL, (xmlChar *) "Chassis", NULL);
                assert( sect_n != NULL );

                if(h->length < 0x09)
                        break;

                dmixml_AddTextChild(sect_n, "Manufacturer", "%s", dmi_string(h, data[0x04]));
                dmi_chassis_type(sect_n, data[0x05] & 0x7F);
                dmi_chassis_lock(sect_n, data[0x05] >> 7);
                dmixml_AddTextChild(sect_n, "Version", "%s", dmi_string(h, data[0x06]));
                dmixml_AddTextChild(sect_n, "SerialNumber", "%s", dmi_string(h, data[0x07]));
                dmixml_AddTextChild(sect_n, "AssetTag", "%s", dmi_string(h, data[0x08]));

                if(h->length < 0x0D)
                        break;

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "ChassisStates", NULL);
                assert( sub_n != NULL );

                dmi_chassis_state(sub_n, "BootUp", data[0x09]);
                dmi_chassis_state(sub_n, "PowerSupply", data[0x0A]);
                dmi_chassis_state(sub_n, "Thermal", data[0x0B]);

                dmi_chassis_security_status(sect_n, data[0x0C]);

                if(h->length < 0x11)
                        break;

                dmixml_AddTextChild(sect_n, "OEMinformation", "0x%08x", DWORD(data + 0x0D));

                if(h->length < 0x13)
                        break;

                dmi_chassis_height(sect_n, data[0x11]);
                dmi_chassis_power_cords(sect_n, data[0x12]);

                if(h->length < 0x15)
                        break;

                if(h->length < 0x15 + data[0x13] * data[0x14])
                        break;

                dmi_chassis_elements(sect_n, data[0x13], data[0x14], data + 0x15);
                sect_n = NULL;
                break;

        case 4:                /* 3.3.5 Processor Information */

                if(h->length < 0x1A)
                        break;

                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "Processor", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.5");

                dmixml_AddTextChild(sect_n, "SocketDesignation", "%s", dmi_string(h, data[0x04]));
                dmi_processor_type(sect_n, data[0x05]);
                dmi_processor_family(sect_n, h);

                dmi_processor_id(sect_n, data[0x06], data + 8, dmi_string(h, data[0x10]));

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Manufacturer", NULL);
                assert( sub_n != NULL );
                dmixml_AddTextChild(sub_n, "Vendor", dmi_string(h, data[0x07]));

                dmixml_AddTextChild(sub_n, "Version", dmi_string(h, data[0x10]));
                dmi_processor_voltage(sub_n, data[0x11]);
                sub_n = NULL;

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Frequencies", NULL);
                assert( sub_n != NULL );

                dmixml_AddTextChild(sub_n, "ExternalClock", "%i", dmi_processor_frequency(data + 0x12));
                dmixml_AddTextChild(sub_n, "MaxSpeed", "%i", dmi_processor_frequency(data + 0x14));
                dmixml_AddTextChild(sub_n, "CurrentSpeed", "%i", dmi_processor_frequency(data + 0x16));

                /*  TODO: Should CurrentSpeed be renamed to BootSpeed?  Specification
                 *  says this about Current Speed:
                 *
                 *             This field identifies the processor's speed at
                 *             system boot and the Processor ID field implies the
                 *             processor's additional speed characteristics (i.e. single
                 *             speed or multiple speed).
                 */

                if(data[0x18] & (1 << 6)) {
                        dmixml_AddAttribute(sect_n, "populated", "1");
                        dmi_processor_status(sect_n, data[0x18] & 0x07);
                } else {
                        dmixml_AddAttribute(sect_n, "populated", "0");
                }

                dmi_processor_upgrade(sect_n, data[0x19]);

                if(h->length < 0x20)
                        break;

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Cache", NULL);
                assert( sub_n != NULL );

                sub2_n = xmlNewChild(sub_n, NULL, (xmlChar *) "Level", NULL);
                assert( sub2_n != NULL );

                dmixml_AddAttribute(sub2_n, "level", "1");
                dmi_processor_cache(sub2_n, WORD(data + 0x1A), ver);
                sub2_n = NULL;


                sub2_n = xmlNewChild(sub_n, NULL, (xmlChar *) "Level", NULL);
                assert( sub2_n != NULL );

                dmixml_AddAttribute(sub2_n, "level", "2");
                dmi_processor_cache(sub2_n, WORD(data + 0x1C), ver);
                sub2_n = NULL;

                sub2_n = xmlNewChild(sub_n, NULL, (xmlChar *) "Level", NULL);
                assert( sub2_n != NULL );

                dmixml_AddAttribute(sub2_n, "level", "3");
                dmi_processor_cache(sub2_n, WORD(data + 0x1E), ver);
                sub2_n = NULL;
                sub_n = NULL;

                if(h->length < 0x23)
                        break;

                dmixml_AddTextChild(sect_n, "SerialNumber", "%s", dmi_string(h, data[0x20]));
                dmixml_AddTextChild(sect_n, "AssetTag", "%s", dmi_string(h, data[0x21]));
                dmixml_AddTextChild(sect_n, "PartNumber", "%s", dmi_string(h, data[0x22]));

                if(h->length < 0x28)
                        break;

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Cores", NULL);
                assert( cores_n != NULL );

                if(data[0x23] != 0) {
                        dmixml_AddTextChild(sub_n, "CoreCount", "%i", data[0x23]);
                }

                if(data[0x24] != 0) {
                        dmixml_AddTextChild(sub_n, "CoresEnabled", "%i", data[0x24]);
                }

                if(data[0x25] != 0) {
                        dmixml_AddTextChild(sub_n, "ThreadCount", "%i", data[0x25]);
                }

                dmi_processor_characteristics(sub_n, WORD(data + 0x26));
                sub_n = NULL;
                sect_n = NULL;
                break;

        case 5:                /* 3.3.6 Memory Controller Information */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "MemoryController", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.6");

                dmi_on_board_devices(sect_n, "dmi_on_board_devices", h);

                if(h->length < 0x0F)
                        break;

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "ErrorCorrection", NULL);
                assert( errc_n != NULL );

                dmi_memory_controller_ed_method(sub_n, data[0x04]);
                dmi_memory_controller_ec_capabilities(sub_n, "Capabilities", data[0x05]);
                sub_n = NULL;

                dmi_memory_controller_interleave(sect_n, "SupportedInterleave", data[0x06]);
                dmi_memory_controller_interleave(sect_n, "CurrentInterleave", data[0x07]);

                sub_n = dmixml_AddTextChild(sect_n, "MaxMemoryModuleSize",
                                            "%i", (1 << data[0x08]));
                dmixml_AddAttribute(sub_n, "unit", "MB");
                sub_n = NULL;

                sub_n = dmixml_AddTextChild(sect_n, "MaxTotalMemorySize",
                                            "%i", data[0x0E] * (1 << data[0x08]));
                dmixml_AddAttribute(sub_n, "unit", "MB");
                sub_n = NULL;

                dmi_memory_controller_speeds(sect_n, WORD(data + 0x09));
                dmi_memory_module_types(sect_n, "SupportedTypes", WORD(data + 0x0B));
                dmi_processor_voltage(sect_n, data[0x0D]);

                if(h->length < 0x0F + data[0x0E] * sizeof(u16))
                        break;

                dmi_memory_controller_slots(sect_n, data[0x0E], data + 0x0F);

                if(h->length < 0x10 + data[0x0E] * sizeof(u16))
                        break;

                dmi_memory_controller_ec_capabilities(sect_n, "EnabledErrorCorrection",
                                                      data[0x0F + data[0x0E] * sizeof(u16)]);
                sect_n = NULL;
                break;

        case 6:                /* 3.3.7 Memory Module Information */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "MemoryModule", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.7");

                dmi_on_board_devices(sect_n, "dmi_on_board_devices", h);

                if(h->length < 0x0C)
                        break;

                dmixml_AddTextChild(sect_n, "SocketDesignation", "%s", dmi_string(h, data[0x04]));
                dmi_memory_module_connections(sect_n, data[0x05]);
                dmi_memory_module_speed(sect_n, "ModuleSpeed", data[0x06]);
                dmi_memory_module_types(sect_n, "Type", WORD(data + 0x07));

                dmi_memory_module_size(sect_n, "InstalledSize", data[0x09]);
                dmi_memory_module_size(sect_n, "EnabledSize",   data[0x0A]);
                dmi_memory_module_error(sect_n, data[0x0B]);
                sect_n = NULL;
                break;

        case 7:                /* 3.3.8 Cache Information */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "Cache", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.8");

                dmi_on_board_devices(sect_n, "dmi_on_board_devices", h);

                if(h->length < 0x0F)
                        break;

                dmixml_AddTextChild(sect_n, "SocketDesignation", dmi_string(h, data[0x04]));
                dmixml_AddAttribute(sect_n, "Enabled", "%i", (WORD(data + 0x05) & 0x0080 ? 1 : 0));
                dmixml_AddAttribute(sect_n, "Socketed", "%i", (WORD(data + 0x05) & 0x0008 ? 1 : 0));
                dmixml_AddAttribute(sect_n, "Level", "%ld", ((WORD(data + 0x05) & 0x0007) + 1));

                sub_n = dmixml_AddTextChild(sect_n, "OperationalMode", "%s",
                                            dmi_cache_mode((WORD(data + 0x05) >> 8) & 0x0003));
                dmixml_AddAttribute(sub_n, "flags", "0x%04x", (WORD(data + 0x05) >> 8) & 0x0003);

                dmi_cache_location(sect_n, (WORD(data + 0x05) >> 5) & 0x0003);
                dmi_cache_size(sect_n, "InstalledSize", WORD(data + 0x09));
                dmi_cache_size(sect_n, "MaximumSize", WORD(data + 0x07));

                dmi_cache_types(sect_n, "SupportedSRAMtypes", WORD(data + 0x0B));
                dmi_cache_types(sect_n, "InstalledSRAMtypes", WORD(data + 0x0D));

                if(h->length < 0x13)
                        break;

                dmi_memory_module_speed(sect_n, "Speed", data[0x0F]);
                dmi_cache_ec_type(sect_n, data[0x10]);
                dmi_cache_type(sect_n, data[0x11]);
                dmi_cache_associativity(sect_n, data[0x12]);

                sect_n = NULL;
                break;

        case 8:                /* 3.3.9 Port Connector Information */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "Connector", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.9");

                dmi_on_board_devices(sect_n, "dmi_on_board_devices", h);

                if(h->length < 0x09)
                        break;

                sub_n = dmixml_AddTextChild(sect_n, "DesignatorRef", dmi_string(h, data[0x04]));
                assert( sub_n != NULL );
                dmixml_AddAttribute(sub_n, "type", "internal");
                sub_n = NULL;

                dmi_port_connector_type(sect_n, "internal", data[0x05]);

                sub_n = dmixml_AddTextChild(sect_n, "DesignatorRef", dmi_string(h, data[0x06]));
                assert( sub_n != NULL );
                dmixml_AddAttribute(sub_n, "type", "external");
                sub_n = NULL;

                dmi_port_connector_type(sect_n, "external", data[0x07]);
                dmi_port_type(sect_n, data[0x08]);

                sect_n = NULL;
                break;

        case 9:                /* 3.3.10 System Slots */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "Connector", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.10");

                dmi_on_board_devices(sect_n, "dmi_on_board_devices", h);

                if(h->length < 0x0C)
                        break;

                dmixml_AddTextChild(sect_n, "Designation", "%s", dmi_string(h, data[0x04]));

                dmi_slot_bus_width(sect_n, data[0x06]);
                dmi_slot_type(sect_n, data[0x05]);
                dmi_slot_current_usage(sect_n, data[0x07]);
                dmi_slot_length(sect_n, data[0x08]);
                dmi_slot_id(sect_n, data[0x09], data[0x0A], data[0x05]);

                if( h->length < 0x0D ) {
                        dmi_slot_characteristics(sect_n, data[0x0B], 0x00);
                } else {
                        dmi_slot_characteristics(sect_n, data[0x0B], data[0x0C]);
                }

                sect_n = NULL;
                break;

        case 10:               /* 3.3.11 On Board Devices Information */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "OnBoardDevices", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.11");

                dmi_on_board_devices(sect_n, "dmi_on_board_devices", h);

                sect_n = NULL;
                break;

        case 11:               /* 3.3.12 OEM Strings */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "OEMstrings", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.12");

                dmi_on_board_devices(sect_n, "dmi_on_board_devices", h);

                if(h->length < 0x05)
                        break;

                dmi_oem_strings(sect_n, h);

                sect_n = NULL;
                break;

        case 12:               /* 3.3.13 System Configuration Options */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "SystemConfig", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.13");

                if(h->length < 0x05)
                        break;

                dmi_system_configuration_options(sect_n, h);

                sect_n = NULL;
                break;

        case 13:               /* 3.3.14 BIOS Language Information */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "BIOSlanguage", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.14");

                if(h->length < 0x16)
                        break;

                dmixml_AddAttribute(sect_n, "installable_languages", "%i", data[0x04]);

                dmi_bios_languages(sect_n, h);

                sect_n = NULL;
                break;

        case 14:               /* 3.3.15 Group Associations */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "GroupAssociations", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.15");

                if(h->length < 0x05)
                        break;

                dmixml_AddTextChild(sect_n, "Name", "%s", dmi_string(h, data[0x04]));

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Groups", NULL);
                assert( sub_n != NULL );
                dmi_group_associations_items(sub_n, (h->length - 0x05) / 3, data + 0x05);

                sect_n = NULL;
                break;

        case 15:               /* 3.3.16 System Event Log */
                // SysEventLog - sect_n
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "SysEventLog", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.16");

                if(h->length < 0x14)
                        break;

                dmi_event_log_status(sect_n, data[0x0B]);

                // SysEventLog/Access - sub
                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Access", NULL);
                assert( sub_n != NULL );

                dmixml_AddAttribute(sub_n, "AreaLength", "%i", WORD(data + 0x04));
                dmi_event_log_method(sub_n, data[0x0A]);
                dmi_event_log_address(sub_n, data[0x0A], data + 0x10);

                // SysEventLog/Access/Header - sub2
                sub2_n = xmlNewChild(sub_n, NULL, (xmlChar *) "Header", NULL);
                assert( sub2_n != NULL );

                dmixml_AddTextChild(sub2_n, "OffsetStart", "0x%04x", WORD(data + 0x06));

                if((WORD(data + 0x08) - WORD(data + 0x06)) >= 0) {
                        dmixml_AddTextChild(sub2_n, "Length", "%i", WORD(data + 0x08) - WORD(data + 0x06));
                }

                dmixml_AddTextChild(sub2_n, "DataOffset", "0x%04x", WORD(data + 0x08));
                dmixml_AddTextChild(sub2_n, "ChangeToken", "0x%08x", DWORD(data + 0x0C));

                if(h->length < 0x17)
                        break;

                // SysEventLog/Access/Header/Format - sub2_n
                dmi_event_log_header_type(sub2_n, data[0x14]);

                sub2_n = NULL;
                sub_n = NULL;

                // SysEventLog/LogTypes - resuing sub_n
                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "LogTypes", NULL);
                assert( sub_n != NULL );

                // SysEventLog/LogTypes/@count
                dmixml_AddAttribute(sub_n, "count", "%i", data[0x15]);

                if(h->length < 0x17 + data[0x15] * data[0x16])
                        break;

                dmixml_AddAttribute(sub_n, "length", "%i", data[0x16]);

                // SysEventLog/LogTypes/LogType
                dmi_event_log_descriptors(sub_n, data[0x15], data[0x16], data + 0x17);

                sub_n = NULL;
                sect_n = NULL;
                break;

        case 16:               /* 3.3.17 Physical Memory Array */
                sect_n = xmlNewChild(handle_n, NULL, (xmlChar *) "PhysicalMemoryArray", NULL);
                assert( sect_n != NULL );
                dmixml_AddAttribute(sect_n, "dmispec", "3.3.17");

                if(h->length < 0x0F)
                        break;

                /* ** BOOKMARK ** */

                _val = dmi_memory_array_location(data[0x04]);
                PyDict_SetItemString(caseData, "Location", _val);
                Py_DECREF(_val);

                _val = dmi_memory_array_use(data[0x05]);
                PyDict_SetItemString(caseData, "Use", _val);
                Py_DECREF(_val);

                _val = dmi_memory_array_ec_type(data[0x06]);
                PyDict_SetItemString(caseData, "Error Correction Type", _val);
                Py_DECREF(_val);

                _val = dmi_memory_array_capacity(DWORD(data + 0x07));
                PyDict_SetItemString(caseData, "Maximum Capacity", _val);
                Py_DECREF(_val);

                _val = dmi_memory_array_error_handle(WORD(data + 0x0B));
                PyDict_SetItemString(caseData, "Error Information Handle", _val);
                Py_DECREF(_val);

                _val = PyInt_FromLong(WORD(data + 0x0D));
                PyDict_SetItemString(caseData, "Number Of Devices", _val);
                Py_DECREF(_val);
                break;

        case 17:               /* 3.3.18 Memory Device */

                if(h->length < 0x15)
                        break;
                _val = PyString_FromFormat("0x%04x", WORD(data + 0x04));
                PyDict_SetItemString(caseData, "Array Handle", _val);
                Py_DECREF(_val);

                _val = dmi_memory_array_error_handle(WORD(data + 0x06));
                PyDict_SetItemString(caseData, "Error Information Handle", _val);
                Py_DECREF(_val);

                _val = dmi_memory_device_width(WORD(data + 0x08));
                PyDict_SetItemString(caseData, "Total Width", _val);
                Py_DECREF(_val);

                _val = dmi_memory_device_width(WORD(data + 0x0A));
                PyDict_SetItemString(caseData, "Data Width", _val);
                Py_DECREF(_val);

                _val = dmi_memory_device_size(WORD(data + 0x0C));
                PyDict_SetItemString(caseData, "Size", _val);
                Py_DECREF(_val);

                _val = dmi_memory_device_form_factor(data[0x0E]);
                PyDict_SetItemString(caseData, "Form Factor", _val);
                Py_DECREF(_val);

                _val = dmi_memory_device_set(data[0x0F]);
                PyDict_SetItemString(caseData, "Set", _val);
                Py_DECREF(_val);

                _val = dmi_string_py(h, data[0x10]);
                PyDict_SetItemString(caseData, "Locator", _val);
                Py_DECREF(_val);

                _val = dmi_string_py(h, data[0x11]);
                PyDict_SetItemString(caseData, "Bank Locator", _val);
                Py_DECREF(_val);

                _val = dmi_memory_device_type(data[0x12]);
                PyDict_SetItemString(caseData, "Type", _val);
                Py_DECREF(_val);

                _val = dmi_memory_device_type_detail(WORD(data + 0x13));
                PyDict_SetItemString(caseData, "Type Detail", _val);
                Py_DECREF(_val);

                if(h->length < 0x17)
                        break;
                _val = dmi_memory_device_speed(WORD(data + 0x15));
                PyDict_SetItemString(caseData, "Speed", _val);
                Py_DECREF(_val);

                if(h->length < 0x1B)
                        break;
                _val = dmi_string_py(h, data[0x17]);
                PyDict_SetItemString(caseData, "Manufacturer", _val);
                Py_DECREF(_val);

                _val = dmi_string_py(h, data[0x18]);
                PyDict_SetItemString(caseData, "Serial Number", _val);
                Py_DECREF(_val);

                _val = dmi_string_py(h, data[0x19]);
                PyDict_SetItemString(caseData, "Asset Tag", _val);
                Py_DECREF(_val);

                _val = dmi_string_py(h, data[0x1A]);
                PyDict_SetItemString(caseData, "Part Number", _val);
                Py_DECREF(_val);
                break;

        case 18:               /* 3.3.19 32-bit Memory Error Information */

                if(h->length < 0x17)
                        break;
                _val = dmi_memory_error_type(data[0x04]);
                PyDict_SetItemString(caseData, "Type", _val);
                Py_DECREF(_val);

                _val = dmi_memory_error_granularity(data[0x05]);
                PyDict_SetItemString(caseData, "Granularity", _val);
                Py_DECREF(_val);

                _val = dmi_memory_error_operation(data[0x06]);
                PyDict_SetItemString(caseData, "Operation", _val);
                Py_DECREF(_val);

                _val = dmi_memory_error_syndrome(DWORD(data + 0x07));
                PyDict_SetItemString(caseData, "Vendor Syndrome", _val);
                Py_DECREF(_val);

                _val = dmi_32bit_memory_error_address(DWORD(data + 0x0B));
                PyDict_SetItemString(caseData, "Memory Array Address", _val);
                Py_DECREF(_val);

                _val = dmi_32bit_memory_error_address(DWORD(data + 0x0F));
                PyDict_SetItemString(caseData, "Device Address", _val);
                Py_DECREF(_val);

                _val = dmi_32bit_memory_error_address(DWORD(data + 0x13));
                PyDict_SetItemString(caseData, "Resolution", _val);
                Py_DECREF(_val);
                break;

        case 19:               /* 3.3.20 Memory Array Mapped Address */

                if(h->length < 0x0F)
                        break;
                _val =
                    PyString_FromFormat("0x%08x%03x", DWORD(data + 0x04) >> 2,
                                        (DWORD(data + 0x04) & 0x3) << 10);
                PyDict_SetItemString(caseData, "Starting Address", _val);
                Py_DECREF(_val);

                _val =
                    PyString_FromFormat("0x%08x%03x", DWORD(data + 0x08) >> 2,
                                        ((DWORD(data + 0x08) & 0x3) << 10) + 0x3FF);
                PyDict_SetItemString(caseData, "Ending Address", _val);
                Py_DECREF(_val);

                _val = dmi_mapped_address_size(DWORD(data + 0x08) - DWORD(data + 0x04) + 1);
                PyDict_SetItemString(caseData, "Range Size", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("0x%04x", WORD(data + 0x0C));
                PyDict_SetItemString(caseData, "Physical Array Handle", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("%i", data[0x0F]);
                PyDict_SetItemString(caseData, "Partition Width", _val);
                Py_DECREF(_val);
                break;

        case 20:               /* 3.3.21 Memory Device Mapped Address */

                if(h->length < 0x13)
                        break;
                _val =
                    PyString_FromFormat("0x%08x%03x", DWORD(data + 0x04) >> 2,
                                        (DWORD(data + 0x04) & 0x3) << 10);
                PyDict_SetItemString(caseData, "Starting Address", _val);
                Py_DECREF(_val);

                _val =
                    PyString_FromFormat("0x%08x%03x", DWORD(data + 0x08) >> 2,
                                        ((DWORD(data + 0x08) & 0x3) << 10) + 0x3FF);
                PyDict_SetItemString(caseData, "Ending Address", _val);
                Py_DECREF(_val);

                _val = dmi_mapped_address_size(DWORD(data + 0x08) - DWORD(data + 0x04) + 1);
                PyDict_SetItemString(caseData, "Range Size", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("0x%04x", WORD(data + 0x0C));
                PyDict_SetItemString(caseData, "Physical Device Handle", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("0x%04x", WORD(data + 0x0E));
                PyDict_SetItemString(caseData, "Memory Array Mapped Address Handle", _val);
                Py_DECREF(_val);

                _val = dmi_mapped_address_row_position(data[0x10]);
                PyDict_SetItemString(caseData, "Partition Row Position", _val);
                Py_DECREF(_val);

                _val = dmi_mapped_address_interleave_position(data[0x11]);
                PyDict_SetItemString(caseData, ">>>", _val);
                Py_DECREF(_val);

                _val = dmi_mapped_address_interleaved_data_depth(data[0x12]);
                PyDict_SetItemString(caseData, ">>>", _val);
                Py_DECREF(_val);
                break;

        case 21:               /* 3.3.22 Built-in Pointing Device */

                if(h->length < 0x07)
                        break;
                _val = dmi_pointing_device_type(data[0x04]);
                PyDict_SetItemString(caseData, "Type", _val);
                Py_DECREF(_val);

                _val = dmi_pointing_device_interface(data[0x05]);
                PyDict_SetItemString(caseData, "Interface", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("%i", data[0x06]);
                PyDict_SetItemString(caseData, "Buttons", _val);
                Py_DECREF(_val);
                break;

        case 22:               /* 3.3.23 Portable Battery */

                if(h->length < 0x10)
                        break;
                _val = dmi_string_py(h, data[0x04]);
                PyDict_SetItemString(caseData, "Location", _val);
                Py_DECREF(_val);

                _val = dmi_string_py(h, data[0x05]);
                PyDict_SetItemString(caseData, "Manufacturer", _val);
                Py_DECREF(_val);

                if(data[0x06] || h->length < 0x1A) {
                        _val = dmi_string_py(h, data[0x06]);
                        PyDict_SetItemString(caseData, "Manufacture Date", _val);
                        Py_DECREF(_val);
                }

                if(data[0x07] || h->length < 0x1A) {
                        _val = dmi_string_py(h, data[0x07]);
                        PyDict_SetItemString(caseData, "Serial Number", _val);
                        Py_DECREF(_val);
                }

                _val = dmi_string_py(h, data[0x08]);
                PyDict_SetItemString(caseData, "Name", _val);
                Py_DECREF(_val);

                if(data[0x09] != 0x02 || h->length < 0x1A) {
                        _val = dmi_battery_chemistry(data[0x09]);
                        PyDict_SetItemString(caseData, "Chemistry", _val);
                        Py_DECREF(_val);
                }
                _val =
                    (h->length < 0x1A) ? dmi_battery_capacity(WORD(data + 0x0A),
                                                              1) : dmi_battery_capacity(WORD(data +
                                                                                             0x0A),
                                                                                        data[0x15]);
                PyDict_SetItemString(caseData, "Design Capacity", _val);
                Py_DECREF(_val);

                _val = dmi_battery_voltage(WORD(data + 0x0C));
                PyDict_SetItemString(caseData, "Design Voltage", _val);
                Py_DECREF(_val);

                _val = dmi_string_py(h, data[0x0E]);
                PyDict_SetItemString(caseData, "SBDS Version", _val);
                Py_DECREF(_val);

                _val = dmi_battery_maximum_error(data[0x0F]);
                PyDict_SetItemString(caseData, "Maximum Error", _val);
                Py_DECREF(_val);

                if(h->length < 0x1A)
                        break;
                if(data[0x07] == 0) {
                        _val = PyString_FromFormat("%04x", WORD(data + 0x10));
                        PyDict_SetItemString(caseData, "SBDS Serial Number", _val);
                        Py_DECREF(_val);
                }
                if(data[0x06] == 0) {
                        _val =
                            PyString_FromFormat("%i-%02u-%02u", 1980 + (WORD(data + 0x12) >> 9),
                                                (WORD(data + 0x12) >> 5) & 0x0F,
                                                WORD(data + 0x12) & 0x1F);
                        PyDict_SetItemString(caseData, "SBDS Manufacture Date", _val);
                        Py_DECREF(_val);
                }
                if(data[0x09] == 0x02) {
                        _val = dmi_string_py(h, data[0x14]);
                        PyDict_SetItemString(caseData, "SBDS Chemistry", _val);
                        Py_DECREF(_val);
                }

                _val = PyString_FromFormat("0x%08x", DWORD(data + 0x16));
                PyDict_SetItemString(caseData, "OEM-specific Information", _val);
                Py_DECREF(_val);
                break;

        case 23:               /* 3.3.24 System Reset */

                if(h->length < 0x0D)
                        break;
                _val = PyString_FromFormat("%s", data[0x04] & (1 << 0) ? "Enabled" : "Disabled");
                PyDict_SetItemString(caseData, "Status", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("%s", data[0x04] & (1 << 5) ? "Present" : "Not Present");
                PyDict_SetItemString(caseData, "Watchdog Timer", _val);
                Py_DECREF(_val);

                if(!(data[0x04] & (1 << 5)))
                        break;
                _val = dmi_system_reset_boot_option((data[0x04] >> 1) & 0x3);
                PyDict_SetItemString(caseData, "Boot Option", _val);
                Py_DECREF(_val);

                _val = dmi_system_reset_boot_option((data[0x04] >> 3) & 0x3);
                PyDict_SetItemString(caseData, "Boot Option On Limit", _val);
                Py_DECREF(_val);

                _val = dmi_system_reset_count(WORD(data + 0x05));
                PyDict_SetItemString(caseData, "Reset Count", _val);
                Py_DECREF(_val);

                _val = dmi_system_reset_count(WORD(data + 0x07));
                PyDict_SetItemString(caseData, "Reset Limit", _val);
                Py_DECREF(_val);

                _val = dmi_system_reset_timer(WORD(data + 0x09));
                PyDict_SetItemString(caseData, "Timer Interval", _val);
                Py_DECREF(_val);

                _val = dmi_system_reset_timer(WORD(data + 0x0B));
                PyDict_SetItemString(caseData, "Timeout", _val);
                Py_DECREF(_val);

                break;

        case 24:               /* 3.3.25 Hardware Security */

                if(h->length < 0x05)
                        break;
                _val = dmi_hardware_security_status(data[0x04] >> 6);
                PyDict_SetItemString(caseData, "Power-On Password Status", _val);
                Py_DECREF(_val);

                _val = dmi_hardware_security_status((data[0x04] >> 4) & 0x3);
                PyDict_SetItemString(caseData, "Keyboard Password Status", _val);
                Py_DECREF(_val);

                _val = dmi_hardware_security_status((data[0x04] >> 2) & 0x3);
                PyDict_SetItemString(caseData, "Administrator Password Status", _val);
                Py_DECREF(_val);

                _val = dmi_hardware_security_status(data[0x04] & 0x3);
                PyDict_SetItemString(caseData, "Front Panel Reset Status", _val);
                Py_DECREF(_val);

                break;

        case 25:               /* 3.3.26 System Power Controls */

                if(h->length < 0x09)
                        break;
                _val = dmi_power_controls_power_on(data + 0x04);
                PyDict_SetItemString(caseData, "Next Scheduled Power-on", _val);
                Py_DECREF(_val);

                break;

        case 26:               /* 3.3.27 Voltage Probe */

                if(h->length < 0x14)
                        break;
                _val = dmi_string_py(h, data[0x04]);
                PyDict_SetItemString(caseData, "Description", _val);
                Py_DECREF(_val);

                _val = dmi_voltage_probe_location(data[0x05] & 0x1f);
                PyDict_SetItemString(caseData, "Location", _val);
                Py_DECREF(_val);

                _val = dmi_probe_status(data[0x05] >> 5);
                PyDict_SetItemString(caseData, "Status", _val);
                Py_DECREF(_val);

                _val = dmi_voltage_probe_value(WORD(data + 0x06));
                PyDict_SetItemString(caseData, "Maximum Value", _val);
                Py_DECREF(_val);

                _val = dmi_voltage_probe_value(WORD(data + 0x08));
                PyDict_SetItemString(caseData, "Minimum Value", _val);
                Py_DECREF(_val);

                _val = dmi_voltage_probe_resolution(WORD(data + 0x0A));
                PyDict_SetItemString(caseData, "Resolution", _val);
                Py_DECREF(_val);

                _val = dmi_voltage_probe_value(WORD(data + 0x0C));
                PyDict_SetItemString(caseData, "Tolerance", _val);
                Py_DECREF(_val);

                _val = dmi_probe_accuracy(WORD(data + 0x0E));
                PyDict_SetItemString(caseData, "Accuracy", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("0x%08x", DWORD(data + 0x10));
                PyDict_SetItemString(caseData, "OEM-specific Information", _val);
                Py_DECREF(_val);

                if(h->length < 0x16)
                        break;
                _val = dmi_voltage_probe_value(WORD(data + 0x14));
                PyDict_SetItemString(caseData, "Nominal Value", _val);
                Py_DECREF(_val);

                break;

        case 27:               /* 3.3.28 Cooling Device */

                if(h->length < 0x0C)
                        break;
                if(WORD(data + 0x04) != 0xFFFF) {
                        _val = PyString_FromFormat("0x%04x", WORD(data + 0x04));
                        PyDict_SetItemString(caseData, "Temperature Probe Handle", _val);
                        Py_DECREF(_val);
                }

                _val = dmi_cooling_device_type(data[0x06] & 0x1f);
                PyDict_SetItemString(caseData, "Type", _val);
                Py_DECREF(_val);

                _val = dmi_probe_status(data[0x06] >> 5);
                PyDict_SetItemString(caseData, "Status", _val);
                Py_DECREF(_val);

                if(data[0x07] != 0x00) {
                        _val = PyString_FromFormat("%i", data[0x07]);
                        PyDict_SetItemString(caseData, "Cooling Unit Group", _val);
                        Py_DECREF(_val);
                }

                _val = PyString_FromFormat("0x%08x", DWORD(data + 0x08));
                PyDict_SetItemString(caseData, "OEM-specific Information", _val);
                Py_DECREF(_val);

                if(h->length < 0x0E)
                        break;
                _val = dmi_cooling_device_speed(WORD(data + 0x0C));
                PyDict_SetItemString(caseData, "Nominal Speed", _val);
                Py_DECREF(_val);

                break;

        case 28:               /* 3.3.29 Temperature Probe */

                if(h->length < 0x14)
                        break;
                _val = dmi_string_py(h, data[0x04]);
                PyDict_SetItemString(caseData, "Description", _val);
                Py_DECREF(_val);

                _val = dmi_temperature_probe_location(data[0x05] & 0x1F);
                PyDict_SetItemString(caseData, "Location", _val);
                Py_DECREF(_val);

                _val = dmi_probe_status(data[0x05] >> 5);
                PyDict_SetItemString(caseData, "Status", _val);
                Py_DECREF(_val);

                _val = dmi_temperature_probe_value(WORD(data + 0x06));
                PyDict_SetItemString(caseData, "Maximum Value", _val);
                Py_DECREF(_val);

                _val = dmi_temperature_probe_value(WORD(data + 0x08));
                PyDict_SetItemString(caseData, "Minimum Value", _val);
                Py_DECREF(_val);

                _val = dmi_temperature_probe_resolution(WORD(data + 0x0A));
                PyDict_SetItemString(caseData, "Resolution", _val);
                Py_DECREF(_val);

                _val = dmi_temperature_probe_value(WORD(data + 0x0C));
                PyDict_SetItemString(caseData, "Tolerance", _val);
                Py_DECREF(_val);

                _val = dmi_probe_accuracy(WORD(data + 0x0E));
                PyDict_SetItemString(caseData, "Accuracy", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("0x%08x", DWORD(data + 0x10));
                PyDict_SetItemString(caseData, "OEM-specific Information", _val);
                Py_DECREF(_val);

                if(h->length < 0x16)
                        break;
                _val = dmi_temperature_probe_value(WORD(data + 0x14));
                PyDict_SetItemString(caseData, "Nominal Value", _val);
                Py_DECREF(_val);

                break;

        case 29:               /* 3.3.30 Electrical Current Probe */

                if(h->length < 0x14)
                        break;
                _val = dmi_string_py(h, data[0x04]);
                PyDict_SetItemString(caseData, "Description", _val);
                Py_DECREF(_val);

                _val = dmi_voltage_probe_location(data[5] & 0x1F);
                PyDict_SetItemString(caseData, "Location", _val);
                Py_DECREF(_val);

                _val = dmi_probe_status(data[0x05] >> 5);
                PyDict_SetItemString(caseData, "Status", _val);
                Py_DECREF(_val);

                _val = dmi_current_probe_value(WORD(data + 0x06));
                PyDict_SetItemString(caseData, "Maximum Value", _val);
                Py_DECREF(_val);

                _val = dmi_current_probe_value(WORD(data + 0x08));
                PyDict_SetItemString(caseData, "Minimum Value", _val);
                Py_DECREF(_val);

                _val = dmi_current_probe_resolution(WORD(data + 0x0A));
                PyDict_SetItemString(caseData, "Resolution", _val);
                Py_DECREF(_val);

                _val = dmi_current_probe_value(WORD(data + 0x0C));
                PyDict_SetItemString(caseData, "Tolerance", _val);
                Py_DECREF(_val);

                _val = dmi_probe_accuracy(WORD(data + 0x0E));
                PyDict_SetItemString(caseData, "Accuracy", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("0x%08x", DWORD(data + 0x10));
                PyDict_SetItemString(caseData, "OEM-specific Information", _val);
                Py_DECREF(_val);

                if(h->length < 0x16)
                        break;
                _val = dmi_current_probe_value(WORD(data + 0x14));
                PyDict_SetItemString(caseData, "Nominal Value", _val);
                Py_DECREF(_val);

                break;

        case 30:               /* 3.3.31 Out-of-band Remote Access */

                if(h->length < 0x06)
                        break;
                _val = dmi_string_py(h, data[0x04]);
                PyDict_SetItemString(caseData, "Manufacturer Name", _val);
                Py_DECREF(_val);

                _val = data[0x05] & (1 << 0) ? Py_True : Py_False;
                PyDict_SetItemString(caseData, "Inbound Connection Enabled", _val);
                Py_DECREF(_val);

                _val = data[0x05] & (1 << 1) ? Py_True : Py_False;
                PyDict_SetItemString(caseData, "Outbound Connection Enabled", _val);
                Py_DECREF(_val);
                break;

        case 31:               /* 3.3.32 Boot Integrity Services Entry Point */

                break;

        case 32:               /* 3.3.33 System Boot Information */

                if(h->length < 0x0B)
                        break;
                _val = dmi_system_boot_status(data[0x0A]);
                PyDict_SetItemString(caseData, "Status", _val);
                Py_DECREF(_val);

                break;

        case 33:               /* 3.3.34 64-bit Memory Error Information */
                if(h->length < 0x1F)
                        break;

                _val = dmi_memory_error_type(data[0x04]);
                PyDict_SetItemString(caseData, "Type", _val);
                Py_DECREF(_val);

                _val = dmi_memory_error_granularity(data[0x05]);
                PyDict_SetItemString(caseData, "Granularity", _val);
                Py_DECREF(_val);

                _val = dmi_memory_error_operation(data[0x06]);
                PyDict_SetItemString(caseData, "Operation", _val);
                Py_DECREF(_val);

                _val = dmi_memory_error_syndrome(DWORD(data + 0x07));
                PyDict_SetItemString(caseData, "Vendor Syndrome", _val);
                Py_DECREF(_val);

                _val = dmi_64bit_memory_error_address(QWORD(data + 0x0B));
                PyDict_SetItemString(caseData, "Memory Array Address", _val);
                Py_DECREF(_val);

                _val = dmi_64bit_memory_error_address(QWORD(data + 0x13));
                PyDict_SetItemString(caseData, "Device Address", _val);
                Py_DECREF(_val);

                _val = dmi_32bit_memory_error_address(DWORD(data + 0x1B));
                PyDict_SetItemString(caseData, "Resolution", _val);
                Py_DECREF(_val);

                break;

        case 34:               /* 3.3.35 Management Device */

                if(h->length < 0x0B)
                        break;
                _val = dmi_string_py(h, data[0x04]);
                PyDict_SetItemString(caseData, "Description", _val);
                Py_DECREF(_val);

                _val = dmi_management_device_type(data[0x05]);
                PyDict_SetItemString(caseData, "Type", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("0x%08x", DWORD(data + 0x06));
                PyDict_SetItemString(caseData, "Address", _val);
                Py_DECREF(_val);

                _val = dmi_management_device_address_type(data[0x0A]);
                PyDict_SetItemString(caseData, "Address Type", _val);
                Py_DECREF(_val);

                break;

        case 35:               /* 3.3.36 Management Device Component */

                if(h->length < 0x0B)
                        break;
                _val = dmi_string_py(h, data[0x04]);
                PyDict_SetItemString(caseData, "Description", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("0x%04x", WORD(data + 0x05));
                PyDict_SetItemString(caseData, "Management Device Handle", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("0x%04x", WORD(data + 0x07));
                PyDict_SetItemString(caseData, "Component Handle", _val);
                Py_DECREF(_val);

                if(WORD(data + 0x09) != 0xFFFF) {
                        _val = PyString_FromFormat("0x%04x", WORD(data + 0x09));
                        PyDict_SetItemString(caseData, "Threshold Handle", _val);
                        Py_DECREF(_val);
                }

                break;

        case 36:               /* 3.3.37 Management Device Threshold Data */

                if(h->length < 0x10)
                        break;
                if(WORD(data + 0x04) != 0x8000) {
                        _val = PyString_FromFormat("%d", (i16) WORD(data + 0x04));
                        PyDict_SetItemString(caseData, "Lower Non-critical Threshold", _val);
                        Py_DECREF(_val);
                }
                if(WORD(data + 0x06) != 0x8000) {
                        _val = PyString_FromFormat("%d", (i16) WORD(data + 0x06));
                        PyDict_SetItemString(caseData, "Upper Non-critical Threshold", _val);
                        Py_DECREF(_val);
                }
                if(WORD(data + 0x08) != 0x8000) {
                        _val = PyString_FromFormat("%d", (i16) WORD(data + 0x08));
                        PyDict_SetItemString(caseData, "Lower Critical Threshold", _val);
                        Py_DECREF(_val);
                }
                if(WORD(data + 0x0A) != 0x8000) {
                        _val = PyString_FromFormat("%d", (i16) WORD(data + 0x0A));
                        PyDict_SetItemString(caseData, "Upper Critical Threshold", _val);
                        Py_DECREF(_val);
                }
                if(WORD(data + 0x0C) != 0x8000) {
                        _val = PyString_FromFormat("%d", (i16) WORD(data + 0x0C));
                        PyDict_SetItemString(caseData, "Lower Non-recoverable Threshold", _val);
                        Py_DECREF(_val);
                }
                if(WORD(data + 0x0E) != 0x8000) {
                        _val = PyString_FromFormat("%d", (i16) WORD(data + 0x0E));
                        PyDict_SetItemString(caseData, "Upper Non-recoverable Threshold", _val);
                        Py_DECREF(_val);
                }

                break;

        case 37:               /* 3.3.38 Memory Channel */

                if(h->length < 0x07)
                        break;
                _val = dmi_memory_channel_type(data[0x04]);
                PyDict_SetItemString(caseData, "Type", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("%i", data[0x05]);
                PyDict_SetItemString(caseData, "Maximal Load", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("%i", data[0x06]);
                PyDict_SetItemString(caseData, "Devices", _val);
                Py_DECREF(_val);

                if(h->length < 0x07 + 3 * data[0x06])
                        break;
                _val = dmi_memory_channel_devices(data[0x06], data + 0x07);
                PyDict_SetItemString(caseData, ">>>", _val);
                Py_DECREF(_val);

                break;

        case 38:               /* 3.3.39 IPMI Device Information */
                /*
                 * We use the word "Version" instead of "Revision", conforming to
                 * the IPMI specification.
                 */

                if(h->length < 0x10)
                        break;
                _val = dmi_ipmi_interface_type(data[0x04]);
                PyDict_SetItemString(caseData, "Interface Type", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("%i.%i", data[0x05] >> 4, data[0x05] & 0x0F);
                PyDict_SetItemString(caseData, "Specification Version", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("0x%02x", data[0x06] >> 1);
                PyDict_SetItemString(caseData, "I2C Slave Address", _val);
                Py_DECREF(_val);

                if(data[0x07] != 0xFF) {
                        _val = PyString_FromFormat("%i", data[0x07]);
                        PyDict_SetItemString(caseData, "NV Storage Device Address", _val);
                        Py_DECREF(_val);
                } else {
                        _val = Py_None;
                        PyDict_SetItemString(caseData, "NV Storage Device: Not Present", _val);
                        Py_DECREF(_val);
                }

                _val =
                    dmi_ipmi_base_address(data[0x04], data + 0x08,
                                          h->length < 0x12 ? 0 : (data[0x10] >> 5) & 1);
                PyDict_SetItemString(caseData, "Base Address", _val);
                Py_DECREF(_val);

                if(h->length < 0x12)
                        break;
                if(data[0x04] != 0x04) {
                        _val = dmi_ipmi_register_spacing(data[0x10] >> 6);
                        PyDict_SetItemString(caseData, "Register Spacing", _val);
                        Py_DECREF(_val);

                        if(data[0x10] & (1 << 3)) {
                                _val =
                                    PyString_FromFormat("%s",
                                                        data[0x10] & (1 << 1) ? "Active High" :
                                                        "Active Low");
                                PyDict_SetItemString(caseData, "Interrupt Polarity", _val);
                                Py_DECREF(_val);

                                _val =
                                    PyString_FromFormat("%s",
                                                        data[0x10] & (1 << 0) ? "Level" : "Edge");
                                PyDict_SetItemString(caseData, "Interrupt Trigger Mode", _val);
                                Py_DECREF(_val);
                        }
                }
                if(data[0x11] != 0x00) {
                        _val = PyString_FromFormat("%x", data[0x11]);
                        PyDict_SetItemString(caseData, "Interrupt Number", _val);
                        Py_DECREF(_val);
                }
                break;

        case 39:               /* 3.3.40 System Power Supply */

                if(h->length < 0x10)
                        break;
                if(data[0x04] != 0x00) {
                        _val = PyString_FromFormat("%i", data[0x04]);
                        PyDict_SetItemString(caseData, "Power Unit Group", _val);
                        Py_DECREF(_val);
                }

                _val = dmi_string_py(h, data[0x05]);
                PyDict_SetItemString(caseData, "Location", _val);
                Py_DECREF(_val);

                _val = dmi_string_py(h, data[0x06]);
                PyDict_SetItemString(caseData, "Name", _val);
                Py_DECREF(_val);

                _val = dmi_string_py(h, data[0x07]);
                PyDict_SetItemString(caseData, "Manufacturer", _val);
                Py_DECREF(_val);

                _val = dmi_string_py(h, data[0x08]);
                PyDict_SetItemString(caseData, "Serial Numberr", _val);
                Py_DECREF(_val);

                _val = dmi_string_py(h, data[0x09]);
                PyDict_SetItemString(caseData, "Asset Tag", _val);
                Py_DECREF(_val);

                _val = dmi_string_py(h, data[0x0A]);
                PyDict_SetItemString(caseData, "Model Part Number", _val);
                Py_DECREF(_val);

                _val = dmi_string_py(h, data[0x0B]);
                PyDict_SetItemString(caseData, "Revision", _val);
                Py_DECREF(_val);

                _val = dmi_power_supply_power(WORD(data + 0x0C));
                PyDict_SetItemString(caseData, "Max Power Capacity", _val);
                Py_DECREF(_val);

                if(WORD(data + 0x0E) & (1 << 1)) {
                        _val = dmi_power_supply_status((WORD(data + 0x0E) >> 7) & 0x07);
                        PyDict_SetItemString(caseData, "Status Present", _val);
                        Py_DECREF(_val);
                } else {
                        _val = PyString_FromString("Not Present");
                        PyDict_SetItemString(caseData, "Status", _val);
                        Py_DECREF(_val);
                }
                _val = dmi_power_supply_type((WORD(data + 0x0E) >> 10) & 0x0F);
                PyDict_SetItemString(caseData, "Type", _val);
                Py_DECREF(_val);

                _val = dmi_power_supply_range_switching((WORD(data + 0x0E) >> 3) & 0x0F);
                PyDict_SetItemString(caseData, "Input Voltage Range Switching", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("%s", WORD(data + 0x0E) & (1 << 2) ? "No" : "Yes");
                PyDict_SetItemString(caseData, "Plugged", _val);
                Py_DECREF(_val);

                _val = PyString_FromFormat("%s", WORD(data + 0x0E) & (1 << 0) ? "Yes" : "No");
                PyDict_SetItemString(caseData, "Hot Replaceable", _val);
                Py_DECREF(_val);

                if(h->length < 0x16)
                        break;
                if(WORD(data + 0x10) != 0xFFFF) {
                        _val = PyString_FromFormat("0x%04x", WORD(data + 0x10));
                        PyDict_SetItemString(caseData, "Input Voltage Probe Handle", _val);
                        Py_DECREF(_val);
                }

                if(WORD(data + 0x12) != 0xFFFF) {
                        _val = PyString_FromFormat("0x%04x", WORD(data + 0x12));
                        PyDict_SetItemString(caseData, "Cooling Device Handle", _val);
                        Py_DECREF(_val);
                }

                if(WORD(data + 0x14) != 0xFFFF) {
                        _val = PyString_FromFormat("0x%04x", WORD(data + 0x14));
                        PyDict_SetItemString(caseData, "Input Current Probe Handle", _val);
                        Py_DECREF(_val);
                }

                break;

        case 40:               /* 3.3.41 Additional Information */
                if(h->length < 0x0B)
                        break;
                _key = PyString_FromFormat("Additional Information");
                _val = dmi_additional_info(h, "");
                PyDict_SetItem(caseData, _key, _val);
                Py_DECREF(_key);
                Py_DECREF(_val);
                break;

        case 41:               /* 3.3.42 Onboard Device Extended Information */
                if(h->length < 0x0B)
                        break;
                PyObject *subdata = PyDict_New();

                _val = dmi_string_py(h, data[0x04]);
                PyDict_SetItemString(subdata, "Reference Designation", _val);
                Py_DECREF(_val);

                _val = PyString_FromString(dmi_on_board_devices_type(data[0x05] & 0x7F));
                PyDict_SetItemString(subdata, "Type", _val);
                Py_DECREF(_val);

                _val = PyString_FromString(data[0x05] & 0x80 ? "Enabled" : "Disabled");
                PyDict_SetItemString(subdata, "Status", _val);
                Py_DECREF(_val);

                _val = PyInt_FromLong(data[0x06]);
                PyDict_SetItemString(subdata, "Type Instance", _val);
                Py_DECREF(_val);

                _val = dmi_slot_segment_bus_func(WORD(data + 0x07), data[0x09], data[0x0A]);
                PyDict_SetItemString(subdata, "Bus Address", _val);
                Py_DECREF(_val);

                PyDict_SetItemString(caseData, "Onboard Device", subdata);
                Py_DECREF(subdata);
                break;

        case 126:              /* 3.3.43 Inactive */
                _val = Py_None;
                PyDict_SetItemString(caseData, "Inactive", _val);
                Py_DECREF(_val);
                break;

        case 127:              /* 3.3.44 End Of Table */
                _val = Py_None;
                PyDict_SetItemString(caseData, "End Of Table", _val);
                Py_DECREF(_val);
                break;

        default:
                if(dmi_decode_oem(h))
                        break;
                _key = PyString_FromFormat("%s Type", h->type >= 128 ? "OEM-specific" : "Unknown");
                _val = dmi_dump(h);
                PyDict_SetItem(caseData, _key, _val);
                Py_DECREF(_key);
                Py_DECREF(_val);
        }
}

void to_dmi_header(struct dmi_header *h, u8 * data)
{
        h->type = data[0];
        h->length = data[1];
        h->handle = WORD(data + 2);
        h->data = data;
}

static void dmi_table_string_py(const struct dmi_header *h, const u8 * data, PyObject * hDict,
                                u16 ver)
{
        int key;
        u8 offset = opt.string->offset;

        if(offset >= h->length)
                return;

        //. TODO: These should have more meaningful dictionary names
        key = (opt.string->type << 8) | offset;
        PyObject *_val;

        switch (key) {
        case 0x108:
                _val = dmi_system_uuid_py(data + offset, ver);
                PyDict_SetItemString(hDict, "0x108", _val);
                break;
        case 0x305:
                _val = dmi_chassis_type_py(data[offset]);
                PyDict_SetItemString(hDict, "0x305", _val);
        case 0x406:
                _val = PyString_FromString(dmi_processor_family(h));
                PyDict_SetItemString(hDict, "0x406", _val);
                break;
        case 0x416:
                _val = dmi_processor_frequency_py((u8 *) data + offset);
                PyDict_SetItemString(hDict, "0x416", _val);
                break;
        default:
                _val = dmi_string_py(h, data[offset]);
                PyDict_SetItemString(hDict, "0x???", _val);
        }
        Py_DECREF(_val);
}

/*
static void dmi_table_dump(u32 base, u16 len, const char *devmem)
{
        u8 *buf;

        if ((buf = mem_chunk(base, len, devmem)) == NULL)
        {
                fprintf(stderr, "Failed to read table, sorry.\n");
                return;
        }

        printf("# Writing %d bytes to %s.\n", len, PyString_AS_STRING(opt.dumpfile));
        write_dump(32, len, buf, PyString_AS_STRING(opt.dumpfile), 0);
        free(buf);
}
*/

/*
 * Build a crafted entry point with table address hard-coded to 32,
 * as this is where we will put it in the output file. We adjust the
 * DMI checksum appropriately. The SMBIOS checksum needs no adjustment.
 */
static void overwrite_dmi_address(u8 * buf)
{
        buf[0x05] += buf[0x08] + buf[0x09] + buf[0x0A] + buf[0x0B] - 32;
        buf[0x08] = 32;
        buf[0x09] = 0;
        buf[0x0A] = 0;
        buf[0x0B] = 0;
}

#define NON_LEGACY 0
#define LEGACY 1
int dumpling(u8 * buf, const char *dumpfile, u8 mode)
{
        u32 base;
        u16 len;

        if(mode == NON_LEGACY) {
                if(!checksum(buf, buf[0x05]) || !memcmp(buf + 0x10, "_DMI_", 5) == 0 ||
                   !checksum(buf + 0x10, 0x0F))
                        return 0;
                base = DWORD(buf + 0x18);
                len = WORD(buf + 0x16);
        } else {
                if(!checksum(buf, 0x0F))
                        return 0;
                base = DWORD(buf + 0x08);
                len = WORD(buf + 0x06);
        }

        u8 *buff;

        if((buff = mem_chunk(base, len, DEFAULT_MEM_DEV)) != NULL) {
                //. Part 1.
                printf("# Writing %d bytes to %s.\n", len, dumpfile);
                write_dump(32, len, buff, dumpfile, 0);
                free(buff);

                //. Part 2.
                if(mode != LEGACY) {
                        u8 crafted[32];

                        memcpy(crafted, buf, 32);
                        overwrite_dmi_address(crafted + 0x10);
                        printf("# Writing %d bytes to %s.\n", crafted[0x05], dumpfile);
                        write_dump(0, crafted[0x05], crafted, dumpfile, 1);
                } else {
                        u8 crafted[16];

                        memcpy(crafted, buf, 16);
                        overwrite_dmi_address(crafted);
                        printf("# Writing %d bytes to %s.\n", 0x0F, dumpfile);
                        write_dump(0, 0x0F, crafted, dumpfile, 1);
                }
        } else {
                fprintf(stderr, "Failed to read table, sorry.\n");
        }

        //. TODO: Cleanup
        return 1;
}

int dump(const char *dumpfile)
{
        /* On success, return found, otherwise return -1 */
        int ret = 0;
        int found = 0;
        size_t fp;
        int efi;
        u8 *buf;

        /* First try EFI (ia64, Intel-based Mac) */
        efi = address_from_efi(&fp);
        if(efi == EFI_NOT_FOUND) {
                /* Fallback to memory scan (x86, x86_64) */
                if((buf = mem_chunk(0xF0000, 0x10000, DEFAULT_MEM_DEV)) != NULL) {
                        for(fp = 0; fp <= 0xFFF0; fp += 16) {
                                if(memcmp(buf + fp, "_SM_", 4) == 0 && fp <= 0xFFE0) {
                                        if(dumpling(buf + fp, dumpfile, NON_LEGACY))
                                                found++;
                                        fp += 16;
                                } else if(memcmp(buf + fp, "_DMI_", 5) == 0) {
                                        if(dumpling(buf + fp, dumpfile, LEGACY))
                                                found++;
                                }
                        }
                } else
                        ret = -1;
        } else if(efi == EFI_NO_SMBIOS) {
                ret = -1;
        } else {
                if((buf = mem_chunk(fp, 0x20, DEFAULT_MEM_DEV)) == NULL)
                        ret = -1;
                else if(dumpling(buf, dumpfile, NON_LEGACY))
                        found++;
        }

        if(ret == 0) {
                free(buf);

                //. TODO: Exception
                //dmiSetItem(pydata, "detect", "No SMBIOS nor DMI entry point found, sorry G.");
                if(!found)
                        ret = -1;
        }

        return ret == 0 ? found : ret;
}

static void dmi_table(u32 base, u16 len, u16 num, u16 ver, const char *devmem, xmlNode *xmlnode)
{
        u8 *buf;
        u8 *data;
        int i = 0;

        if(opt.type == NULL) {
                /* FIXME:  How to interpret this section in XML?  */
                dmiSetItem(pydata, "dmi_table_size", "%i structures occupying %i bytes", num, len);
                /* TODO DUMP
                 * if (!(opt.flags & FLAG_FROM_DUMP))
                 * dmiSetItem(pydata, "dmi_table_base", "Table at 0x%08x", base);
                 */
                dmiSetItem(pydata, "dmi_table_base", "Table at 0x%08x", base);
        }

        if((buf = mem_chunk(base, len, devmem)) == NULL) {
                fprintf(stderr, "Table is unreachable, sorry."
#ifndef USE_MMAP
                        "Try compiling dmidecode with -DUSE_MMAP.";
#endif
                        "\n");
                return;
        }

        data = buf;
        while(i < num && data + 4 <= buf + len) {       /* 4 is the length of an SMBIOS structure header */

                u8 *next;
                struct dmi_header h;
                int display;

                to_dmi_header(&h, data);
                display = ((opt.type == NULL || opt.type[h.type])
                           //      && !(h.type>39 && h.type<=127)
                           && !opt.string);

                /*
                 ** If a short entry is found (less than 4 bytes), not only it
                 ** is invalid, but we cannot reliably locate the next entry.
                 ** Better stop at this point, and let the user know his/her
                 ** table is broken.
                 */
                if(h.length < 4) {
                        fprintf(stderr, "Invalid entry length (%i). DMI table is broken! Stop.",
                                (unsigned int)h.length);
                        break;
                }

                /* In quiet mode (FLAG_QUIET - removed for python-dmidecode all together),
                 * stop decoding at end of table marker
                 */

                xmlNode *handle_n = xmlNewChild(xmlnode, NULL, (xmlChar *) "dmi_handle", NULL);
                assert( handle_n != NULL );
                dmixml_AddAttribute(handle_n, "id", "0x%04x%c", h.handle);
                dmixml_AddAttribute(handle_n, "type", "%d", h.type);
                dmixml_AddAttribute(handle_n, "size", "%d", h.length);

                /* assign vendor for vendor-specific decodes later */
                if(h.type == 0 && h.length >= 5) {
                        /* FIXME:  Need XML API */
                        dmi_set_vendor(dmi_string(&h, data[0x04]));
                }

                /* look for the next handle */
                next = data + h.length;
                while(next - buf + 1 < len && (next[0] != 0 || next[1] != 0)) {
                        next++;
                }
                next += 2;

                if(display) {
                        if(next - buf <= len) {
                                /* TODO: ...
                                 * if(opt.flags & FLAG_DUMP) {
                                 * PyDict_SetItem(hDict, PyString_FromString("lookup"), dmi_dump(&h));
                                 * } else {
                                 * //. TODO: //. Is the value of `i' important?...
                                 * //. TODO: PyDict_SetItem(hDict, PyInt_FromLong(i), dmi_decode(&h, ver));
                                 * //. TODO: ...removed and replaced with `data'...
                                 * PyDict_SetItem(hDict, PyString_FromString("data"), dmi_decode(&h, ver));
                                 * PyDict_SetItem(pydata, PyString_FromString(hid), hDict);
                                 * } */
                                dmi_decode(handle_n, &h, ver);
                        } else
                                fprintf(stderr, "<TRUNCATED>");
                } else if(opt.string != NULL && opt.string->type == h.type) {
                        // <<<---- ** Need to handle this as well **
                        dmi_table_string_py(&h, data, hDict, ver);
                }

                data = next;
                i++;
        }

        if(i != num)
                fprintf(stderr, "Wrong DMI structures count: %d announced, only %d decoded.\n", num,
                        i);
        if(data - buf != len)
                fprintf(stderr,
                        "Wrong DMI structures length: %d bytes announced, structures occupy %d bytes.\n",
                        len, (unsigned int)(data - buf));

        free(buf);
}

int _smbios_decode_check(u8 * buf)
{
        int check = (!checksum(buf, buf[0x05]) || memcmp(buf + 0x10, "_DMI_", 5) != 0 ||
                     !checksum(buf + 0x10, 0x0F)) ? 0 : 1;
        return check;
}
int smbios_decode_set_version(u8 * buf, const char *devmem, PyObject ** pydata)
{
        int check = _smbios_decode_check(buf);
        char vbuf[64];

        bzero(vbuf, 64);
        if(check == 1) {
                u16 ver = (buf[0x06] << 8) + buf[0x07];

                /* Some BIOS report weird SMBIOS version, fix that up */
                int _m, _M;

                _m = 0;
                _M = 0;
                switch (ver) {
                case 0x021F:
                        _m = 31;
                        _M = 3;
                        ver = 0x0203;
                        break;
                case 0x0233:
                        _m = 51;
                        _M = 6;
                        ver = 0x0206;
                        break;
                }
                if(_m || _M)
                        sprintf(vbuf, "SMBIOS %i.%i present (Version fixup 2.%d -> 2.%d)", ver >> 8,
                                ver & 0xFF, _m, _M);
                else
                        sprintf(vbuf, "SMBIOS %i.%i present", ver >> 8, ver & 0xFF);
        } else if(check == 0) {
                sprintf(vbuf, "No SMBIOS nor DMI entry point found");
        }
        if(check == 1) {
                if(*pydata) {
                        Py_DECREF(*pydata);
                }
                *pydata = PyString_FromString(vbuf);
                Py_INCREF(*pydata);
        }
        return check;
}

int smbios_decode(u8 * buf, const char *devmem, xmlNode *xmlnode)
{
        int check = _smbios_decode_check(buf);

        if(check == 1) {
                u16 ver = (buf[0x06] << 8) + buf[0x07];

                switch (ver) {
                case 0x021F:
                        ver = 0x0203;
                        break;
                case 0x0233:
                        ver = 0x0206;
                        break;
                }
                //printf(">>%d @ %d, %d<<\n", DWORD(buf+0x18), WORD(buf+0x16), WORD(buf+0x1C));
                dmi_table(DWORD(buf + 0x18), WORD(buf + 0x16), WORD(buf + 0x1C), ver, devmem,
                          xmlnode);
        }
        return check;
}

int _legacy_decode_check(u8 * buf)
{
        int check;

        if(!checksum(buf, 0x0F))
                check = 0;      //. Bad
        else
                check = 1;      //. Good
        return check;
}
int legacy_decode_set_version(u8 * buf, const char *devmem, PyObject ** pydata)
{
        int check = _legacy_decode_check(buf);
        char vbuf[64];

        bzero(vbuf, 64);
        if(check == 1) {
                sprintf(vbuf, "Legacy DMI %i.%i present", buf[0x0E] >> 4, buf[0x0E] & 0x0F);
        } else if(check == 0) {
                sprintf(vbuf, "No SMBIOS nor DMI entry point found");
        }
        if(check == 1) {
                if(*pydata) {
                        Py_DECREF(*pydata);
                }
                *pydata = PyString_FromString(vbuf);
                Py_INCREF(*pydata);
        }
        return check;
}
int legacy_decode(u8 * buf, const char *devmem, PyObject * pydata)
{
        int check = _legacy_decode_check(buf);

        if(check == 1)
                dmi_table(DWORD(buf + 0x08), WORD(buf + 0x06), WORD(buf + 0x0C),
                          ((buf[0x0E] & 0xF0) << 4) + (buf[0x0E] & 0x0F), devmem, pydata);
        return check;
}

/*******************************************************************************
** Probe for EFI interface
*/
int address_from_efi(size_t * address)
{
        FILE *efi_systab;
        const char *filename;
        char linebuf[64];
        int ret;

        *address = 0;           /* Prevent compiler warning */

        /*
         ** Linux <= 2.6.6: /proc/efi/systab
         ** Linux >= 2.6.7: /sys/firmware/efi/systab
         */
        if((efi_systab = fopen(filename = "/sys/firmware/efi/systab", "r")) == NULL
           && (efi_systab = fopen(filename = "/proc/efi/systab", "r")) == NULL) {
                /* No EFI interface, fallback to memory scan */
                return EFI_NOT_FOUND;
        }
        ret = EFI_NO_SMBIOS;
        while((fgets(linebuf, sizeof(linebuf) - 1, efi_systab)) != NULL) {
                char *addrp = strchr(linebuf, '=');

                *(addrp++) = '\0';
                if(strcmp(linebuf, "SMBIOS") == 0) {
                        *address = strtoul(addrp, NULL, 0);
                        printf("# SMBIOS entry point at 0x%08lx\n", (unsigned long)*address);
                        ret = 0;
                        break;
                }
        }
        if(fclose(efi_systab) != 0)
                perror(filename);

        if(ret == EFI_NO_SMBIOS)
                fprintf(stderr, "%s: SMBIOS entry point missing\n", filename);

        return ret;
}
