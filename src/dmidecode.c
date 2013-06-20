
/*. ******* coding:utf-8 AUTOHEADER START v1.1 *******
 *. vim: fileencoding=utf-8 syntax=c sw=2 ts=2 et
 *.
 *. © 2007-2009 Nima Talebi <nima@autonomy.net.au>
 *. © 2009      David Sommerseth <davids@redhat.com>
 *. © 2002-2008 Jean Delvare <khali@linux-fr.org>
 *. © 2000-2002 Alan Cox <alan@redhat.com>
 *.
 *. This file is part of Python DMI-Decode.
 *.
 *.     Python DMI-Decode is free software: you can redistribute it and/or modify
 *.     it under the terms of the GNU General Public License as published by
 *.     the Free Software Foundation, either version 2 of the License, or
 *.     (at your option) any later version.
 *.
 *.     Python DMI-Decode is distributed in the hope that it will be useful,
 *.     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *.     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *.     GNU General Public License for more details.
 *.
 *.     You should have received a copy of the GNU General Public License
 *.     along with Python DMI-Decode.  If not, see <http://www.gnu.org/licenses/>.
 *.
 *. THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *. WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *. MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
 *. EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *. INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *. LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *. PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *. LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 *. OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *. ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *.
 *. ADAPTED M. STONE & T. PARKER DISCLAIMER: THIS SOFTWARE COULD RESULT IN INJURY
 *. AND/OR DEATH, AND AS SUCH, IT SHOULD NOT BE BUILT, INSTALLED OR USED BY ANYONE.
 *.
 *. $AutoHeaderSerial::20090522                                                 $
 *. ******* AUTOHEADER END v1.1 ******* */

/*
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * DMI Decode
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
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libxml/tree.h>

#include "version.h"
#include "config.h"
#include "types.h"
#include "util.h"
#include "dmidecode.h"
#include "dmixml.h"
#include "dmioem.h"
#include "efi.h"
#include "dmidump.h"

#include "dmihelper.h"

/*******************************************************************************
** Type-independant Stuff
*/

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
                return NULL;

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

void dmi_dump(xmlNode *node, struct dmi_header * h)
{
        int row, i;
        const char *s;
        xmlNode *dump_n = NULL, *row_n = NULL;
        char *tmp_s = NULL;

        dump_n = xmlNewChild(node, NULL, (xmlChar *) "HeaderAndData", NULL);
        assert( dump_n != NULL );

        tmp_s = (char *) malloc((h->length * 2) + 2);
        for(row = 0; row < ((h->length - 1) >> 4) + 1; row++) {
                memset(tmp_s, 0, (h->length * 2) + 2);

                for(i = 0; i < (16 && i < h->length - (row << 4)); i++) {
                        snprintf(tmp_s + strlen(tmp_s), (h->length * 2)-strlen(tmp_s),
                                 "0x%02x", (h->data)[(row << 4) + i]);
                }
                row_n = dmixml_AddTextChild(dump_n, "Row", "%s", tmp_s);
                dmixml_AddAttribute(row_n, "index", "%i", row);
                row_n = NULL;
        }
        free(tmp_s); tmp_s = NULL;
        dump_n = NULL;

        dump_n = xmlNewChild(node, NULL, (xmlChar *) "Strings", NULL);
        assert( dump_n != NULL );

        if((h->data)[h->length] || (h->data)[h->length + 1]) {
                i = 1;
                while((s = dmi_string(h, i++)) != NULL) {
                        //. FIXME: DUMP
                        /*
                         * opt->flags will need to be transported to the function somehow
                         * when this feature is implemented completely.
                         *
                         * if(opt->flags & FLAG_DUMP) {
                         * int j, l = strlen(s)+1;
                         * for(row=0; row<((l-1)>>4)+1; row++) {
                         * for(j=0; j<16 && j<l-(row<<4); j++)
                         * PyList_Append(data1, PyString_FromFormat("0x%02x", s[(row<<4)+j]));
                         * }
                         * fprintf(stderr, "\"%s\"|", s);
                         * }
                         * else fprintf(stderr, "%s|", s);
                         */
                        row_n = dmixml_AddTextChild(dump_n, "String", "%s", s);
                        dmixml_AddAttribute(row_n, "index", "%i", i);
                        row_n = NULL;
                }
        }
        dump_n = NULL;
}

/*******************************************************************************
** 3.3.1 BIOS Information (Type 0)
*/

void dmi_bios_runtime_size(xmlNode *node, u32 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "RuntimeSize", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code & 0x000003FF) {
                dmixml_AddAttribute(data_n, "unit", "bytes");
                dmixml_AddTextContent(data_n, "%i", code);
        } else {
                dmixml_AddAttribute(data_n, "unit", "KB");
                dmixml_AddTextContent(data_n, "%i", code >> 10);
        }
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

        if(code.l&(1<<3)) {
                dmixml_AddAttribute(node, "unavailable", "1");
                dmixml_AddTextContent(node, characteristics[0]);
        } else {
                int i = 0;
                xmlNode *flags_n = xmlNewChild(node, NULL, (xmlChar *) "flags", NULL);
                assert( flags_n != NULL );

                for(i = 4; i <= 31; i++) {
                        xmlNode *flg_n = dmixml_AddTextChild(flags_n, "flag", characteristics[i - 3]);
                        dmixml_AddAttribute(flg_n, "enabled", "%i", (code.l & (1 << i) ? 1 : 0 ));
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
                xmlNode *chr_n = dmixml_AddTextChild(node, "characteristic", characteristics[i]);
                dmixml_AddAttribute(chr_n, "enabled", "%i", (code & (1 << i) ? 1: 0));
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
                xmlNode *chr_n = dmixml_AddTextChild(node, "characteristic", characteristics[i]);
                dmixml_AddAttribute(chr_n, "enabled", "%i", (code & (1 << i) ? 1: 0));
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

                if( manufacturer == NULL ) {
                        dmixml_AddTextContent(family_n, "Core 2 or K7 (Unkown manufacturer)");
                        return;
                }

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
                dmixml_AddTextContent(family_n, "Core 2 or K7 (Unkown manufacturer)");
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

xmlNode *dmi_processor_id(xmlNode *node, const struct dmi_header *h)
{
        /* Intel AP-485 revision 31, table 3-4 */
        static struct _cpuflags {
                const char *flag;
                const char *descr;
        } flags[] = {
                /* *INDENT-OFF* */
                {"FPU", "FPU (Floating-point unit on-chip)"},    /* 0 */
                {"VME", "VME (Virtual mode extension)"},
                {"DE", "DE (Debugging extension)"},
                {"PSE", "PSE (Page size extension)"},
                {"TSC", "TSC (Time stamp counter)"},
                {"MSR", "MSR (Model specific registers)"},
                {"PAE", "PAE (Physical address extension)"},
                {"MCE", "MCE (Machine check exception)"},
                {"CX8", "CX8 (CMPXCHG8 instruction supported)"},
                {"APIC", "APIC (On-chip APIC hardware supported)"},
                {NULL, NULL},           /* 10 */
                {"SEP", "SEP (Fast system call)"},
                {"MTRR", "MTRR (Memory type range registers)"},
                {"PGE", "PGE (Page global enable)"},
                {"MCA", "MCA (Machine check architecture)"},
                {"CMOV", "CMOV (Conditional move instruction supported)"},
                {"PAT", "PAT (Page attribute table)"},
                {"PSE-36", "PSE-36 (36-bit page size extension)"},
                {"PSN", "PSN (Processor serial number present and enabled)"},
                {"CLFSH", "CLFLUSH (CLFLUSH instruction supported)"},
                {NULL, NULL },           /* 20 */
                {"DS", "DS (Debug store)"},
                {"ACPI", "ACPI (ACPI supported)"},
                {"MMX", "MMX (MMX technology supported)"},
                {"FXSR", "FXSR (Fast floating-point save and restore)"},
                {"SSE", "SSE (Streaming SIMD extensions)"},
                {"SSE2", "SSE2 (Streaming SIMD extensions 2)"},
                {"SS", "SS (Self-snoop)"},
                {"HTT", "HTT (Hyper-threading technology)"},
                {"TM", "TM (Thermal monitor supported)"},
                {"IA64", "IA64 (IA64 capabilities)"},
                {"PBE", "PBE (Pending break enabled)"}   /* 31 */
                /* *INDENT-ON* */
        };
        u8 type, *p = NULL;
        char *version = NULL;

        xmlNode *flags_n = NULL;
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "CPUCore", NULL);
        assert( data_n != NULL );

        assert( h && h->data );
        type = h->data[0x06];
        p = h->data + 8;
        version = dmi_string(h, h->data[0x10]);

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

        } else if(version && (type == 0x01 || type == 0x02)) {
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
                        if( flags[i].flag != NULL ) {
                                xmlNode *flg_n = dmixml_AddTextChild(flags_n, "flag", "%s", flags[i].descr);
                                dmixml_AddAttribute(flg_n, "available", "%i",
                                                    (edx & (1 << i) ? 1 : 0));
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
                xmlNode *v_n = dmixml_AddTextChild(vltg_n, "Voltage", "%.1f", (float)(code & 0x7f) / 10);
                dmixml_AddAttribute(v_n, "unit", "V");
        } else if( code == 0x00 ) {
                dmixml_AddAttribute(vltg_n, "unknown_value", "1");
        } else {
                for(i = 0; i <= 2; i++) {
                        xmlNode *v_n = dmixml_AddTextChild(vltg_n, "Voltage", "%s", voltage[i]);
                        dmixml_AddAttribute(v_n, "key_compound", "%s V", voltage[i]);
                        dmixml_AddAttribute(v_n, "available", "%i", (code & (1 << i) ? 1 : 0));
                        dmixml_AddAttribute(v_n, "unit", "V");
                        v_n = NULL;
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

        dmixml_AddAttribute(cache_n, "ver", "0x%04x", ver);

        if(code == 0xFFFF) {
                dmixml_AddAttribute(cache_n, "flags", "0x%04x", code);
                if(ver >= 0x0203) {
                        dmixml_AddAttribute(cache_n, "provided", "0");
                        dmixml_AddAttribute(cache_n, "available", "1");
                } else {
                        dmixml_AddAttribute(cache_n, "available", "0");
                }
        } else {
                dmixml_AddAttribute(cache_n, "provided", "1");
                dmixml_AddAttribute(cache_n, "available", "1");
                dmixml_AddAttribute(cache_n, "handle", "0x%04x", code);
        }
}

/* 3.3.5.9 */
void dmi_processor_characteristics(xmlNode *node, u16 code)
{
        static const char *characteristics[] = {
                "Unknown",              /* 1 */
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
                                dmixml_AddAttribute(c_n, "index", "%i", i+1);
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
                xmlNode *sl_n = dmixml_AddTextChild(mslts_n, "Slot", "0x%x:", WORD(p + sizeof(u16) * i));
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
                                dmixml_AddAttribute(mt_n, "index", "%i", i+1);
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
                        dmixml_AddTextChild(data_n, "Connection", "%ld", (code >> 4));
                }
                if((code & 0x0F) != 0x0F) {
                        dmixml_AddTextChild(data_n, "Connection", "%ld", (code & 0x0F));
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
                break;
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
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
                                xmlNode *n = dmixml_AddTextChild(data_n, "CacheType", "%s", types[i]);
                                dmixml_AddAttribute(n, "index", "%i", i+1);
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
void inline set_slottype(xmlNode *node, u8 type) {
        switch (type) {
        case 0x04:             /* MCA */
                dmixml_AddAttribute(node, "slottype", "MCA");
                break;
        case 0x05:             /* EISA */
                dmixml_AddAttribute(node, "slottype", "EISA");
                break;
        case 0x06:             /* PCI */
        case 0x0E:             /* PCI */
                dmixml_AddAttribute(node, "slottype", "PCI");
                break;
        case 0x0F:             /* AGP */
        case 0x10:             /* AGP */
        case 0x11:             /* AGP */
        case 0x13:             /* AGP */
                dmixml_AddAttribute(node, "slottype", "");
                break;
        case 0x12:             /* PCI-X */
                dmixml_AddAttribute(node, "slottype", "PCI-X");
                break;
        case 0xA5:             /* PCI Express */
                dmixml_AddAttribute(node, "slottype", "PCI Express");
                break;
        case 0x07:             /* PCMCIA */
                dmixml_AddAttribute(node, "slottype", "PCMCIA");
                break;
        default:
                break;
        }
}

void dmi_slot_id(xmlNode *node, u8 code1, u8 code2, u8 type)
{
        xmlNode *slotid_n = xmlNewChild(node, NULL, (xmlChar *) "SlotID", NULL);
        dmixml_AddAttribute(slotid_n, "dmispec", "3.3.10.5");
        dmixml_AddAttribute(slotid_n, "flags1", "0x%04x", code1);
        dmixml_AddAttribute(slotid_n, "flags2", "0x%04x", code2);
        dmixml_AddAttribute(slotid_n, "type", "0x%04x", type);
        switch (type) {
        case 0x04:             /* MCA */
                dmixml_AddAttribute(slotid_n, "id", "%i", code1);
                break;
        case 0x05:             /* EISA */
                dmixml_AddAttribute(slotid_n, "id", "%i", code1);
                break;
        case 0x06:             /* PCI */
        case 0x0E:             /* PCI */
        case 0x0F:             /* AGP */
        case 0x10:             /* AGP */
        case 0x11:             /* AGP */
        case 0x12:             /* PCI-X */
        case 0x13:             /* AGP */
        case 0xA5:             /* PCI Express */
                dmixml_AddAttribute(slotid_n, "id", "%i", code1);
                break;
        case 0x07:             /* PCMCIA */
                dmixml_AddAttribute(slotid_n, "adapter", "%i", code1);
                dmixml_AddAttribute(slotid_n, "id", "%i", code2);
                break;
        default:
                break;
        }
        set_slottype(slotid_n, type);
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
                                dmixml_AddAttribute(c_n, "index", "%i", i+8);
                                c_n = NULL;
                        }
                }
        }
}

void dmi_slot_segment_bus_func(xmlNode *node, u16 code1, u8 code2, u8 code3)
{
        /* 3.3.10.8 */
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "BusAddress", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.10.8");

        if(!(code1 == 0xFFFF && code2 == 0xFF && code3 == 0xFF)) {
                dmixml_AddTextContent(data_n, "%04x:%02x:%02x.%x", code1, code2, code3 >> 3, code3 & 0x7);
        }
}

/*******************************************************************************
** 3.3.11 On Board Devices Information (Type 10)
*/

void dmi_on_board_devices_type(xmlNode *node, u8 code)
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

void dmi_on_board_devices(xmlNode *node, const char *tagname, const struct dmi_header *h)
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
                dmixml_AddDMIstring(dev_n, "Description", h, p[2 * i + 1]);
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

        dmixml_AddAttribute(node, "count", "%i", count);

        for(i = 1; i <= count; i++) {
                xmlNode *str_n = dmixml_AddDMIstring(node, "Record", h, i);
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
                xmlNode *o_n = dmixml_AddDMIstring(data_n, "Option", h, i);
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
                xmlNode *l_n = dmixml_AddDMIstring(data_n, "Language", h, i);
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

void dmi_memory_array_location(xmlNode *node, u8 code)
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

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Location", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.17.1");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x0A) {
                dmixml_AddTextContent(data_n, location[code - 0x01]);
        } else if(code >= 0xA0 && code <= 0xA4) {
                dmixml_AddTextContent(data_n, location_0xA0[code - 0xA0]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_memory_array_use(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Use", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.17.2");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x07) {
                dmixml_AddTextContent(data_n, use[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_memory_array_ec_type(xmlNode *node, u8 code)
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

        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "ErrorCorrectionType", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.17.3");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x07) {
                dmixml_AddTextContent(data_n, type[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_memory_array_capacity(xmlNode *node, u32 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "MaxCapacity", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0x8000000) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                if((code & 0x000FFFFF) == 0) {
                        dmixml_AddAttribute(data_n, "unit", "GB");
                        dmixml_AddTextContent(data_n, "%i", code >> 20);
                } else if((code & 0x000003FF) == 0) {
                        dmixml_AddAttribute(data_n, "unit", "MB");
                        dmixml_AddTextContent(data_n, "%i", code >> 10);
                } else {
                        dmixml_AddAttribute(data_n, "unit", "KB");
                        dmixml_AddTextContent(data_n, "%i", code);
                }
        }
}

void dmi_memory_array_error_handle(xmlNode *node, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "ErrorInfoHandle", NULL);
        assert( data_n != NULL );

        if(code == 0xFFFE) {
                dmixml_AddAttribute(data_n, "not_provided", "1");
        } else if(code == 0xFFFF) {
                dmixml_AddAttribute(data_n, "no_error", "1");
        } else {
                dmixml_AddTextContent(data_n, "0x%04x", code);
        }
}

/*******************************************************************************
** 3.3.18 Memory Device (Type 17)
*/

void dmi_memory_device_width(xmlNode *node, const char *tagname, u16 code)
{
        /*
         ** If no memory module is present, width may be 0
         */
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );

        if(code == 0xFFFF || code == 0) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddAttribute(data_n, "unit", "bit");
                dmixml_AddTextContent(data_n, "%i", code);
        }
}

void dmi_memory_device_size(xmlNode *node, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Size", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0) {
                dmixml_AddAttribute(data_n, "empty", "1");
        } else if(code == 0xFFFF) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                //. Keeping this as String rather than Int as it has KB and MB representations...
                dmixml_AddAttribute(data_n, "unit", "%s", (code & 0x8000 ? "KB"          : "MB"));
                dmixml_AddTextContent(data_n,       "%d", (code & 0x8000 ? code & 0x7FFF : code));
        }
}

void dmi_memory_device_form_factor(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "FormFactor", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.18.1");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x0F) {
                dmixml_AddTextContent(data_n, "%s", form_factor[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_memory_device_set(xmlNode *node, u8 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Set", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0xFF) {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        } else if( code > 0 ) {
                dmixml_AddTextContent(data_n, "%ld", code);
        }
}

void dmi_memory_device_type(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Type", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.18.2");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x14) {
                dmixml_AddTextContent(data_n, "%s", type[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_memory_device_type_detail(xmlNode *node, u16 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "TypeDetails", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.18.3");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if((code & 0x1FFE) != 0) {
                int i;
                for(i = 1; i <= 12; i++) {
                        if(code & (1 << i)) {
                                xmlNode *td_n = dmixml_AddTextChild(data_n, "flag", "%s", detail[i - 1]);
                                assert( td_n != NULL );
                                dmixml_AddAttribute(td_n, "index", "%i", i);
                        }
                }
        }
}

void dmi_memory_device_speed(xmlNode *node, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Speed", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddAttribute(data_n, "speed_ns", "%.1f", (float) 1000 / code);
                dmixml_AddAttribute(data_n, "unit", "MHz");
                dmixml_AddTextContent(data_n, "%i", code);
        }
}

/*******************************************************************************
* 3.3.19 32-bit Memory Error Information (Type 18)
*/

void dmi_memory_error_type(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Type", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.19.1");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x0E) {
                dmixml_AddTextContent(data_n, "%s", type[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_memory_error_granularity(xmlNode *node, u8 code)
{
        /* 3.3.19.2 */
        static const char *granularity[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Device Level",
                "Memory Partition Level"        /* 0x04 */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Granularity", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.19.2");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x04) {
                dmixml_AddTextContent(data_n, "%s", granularity[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_memory_error_operation(xmlNode *node, u8 code)
{
        /* 3.3.19.3 */
        static const char *operation[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "Read",
                "Write",
                "Partial Write" /* 0x05 */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Operation", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.19.3");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x05) {
                dmixml_AddTextContent(data_n, "%s", operation[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_memory_error_syndrome(xmlNode *node, u32 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "VendorSyndrome", NULL);
        assert( data_n != NULL );

        if(code == 0x00000000) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddTextContent(data_n, "0x%08x", code);
        }
}

void dmi_32bit_memory_error_address(xmlNode *node, char *tagname, u32 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );

        if(code == 0x80000000) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddTextContent(data_n, "0x%08x", code);
        }
}

/*******************************************************************************
** 3.3.20 Memory Array Mapped Address (Type 19)
*/

void dmi_mapped_address_size(xmlNode *node, u32 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "RangeSize", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.19.2");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0) {
                dmixml_AddAttribute(data_n, "invalid", "1");
        } else if((code & 0x000FFFFF) == 0) {
                dmixml_AddAttribute(data_n, "unit", "GB");
                dmixml_AddTextContent(data_n, "%i", code >> 20);
        } else if((code & 0x000003FF) == 0) {
                dmixml_AddAttribute(data_n, "unit", "MB");
                dmixml_AddTextContent(data_n, "%i", code >> 10);
        } else {
                dmixml_AddAttribute(data_n, "unit", "KB");
                dmixml_AddTextContent(data_n, "%i", code);
        }
}

/*******************************************************************************
** 3.3.21 Memory Device Mapped Address (Type 20)
*/

void dmi_mapped_address_row_position(xmlNode *node, u8 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "PartitionRowPosition", NULL);
        assert( data_n != NULL );

        if(code == 0) {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        } else if(code == 0xFF) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddTextContent(data_n, "%ld", code);
        }
}

void dmi_mapped_address_interleave_position(xmlNode *node, u8 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "InterleavePosition", NULL);
        assert( data_n != NULL );

        if( code <= 0xFE ) {
                dmixml_AddTextContent(data_n, "%i", code);
        } else {
                dmixml_AddAttribute(data_n, "unknown", "1");
        }
}

void dmi_mapped_address_interleaved_data_depth(xmlNode *node, u8 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "InterleaveDataDepth", NULL);
        assert( data_n != NULL );

        if( code < 0xFF ) {
                dmixml_AddTextContent(data_n, "%i", code);
        } else {
                dmixml_AddAttribute(data_n, "unknown", "1");
        }
}

/*******************************************************************************
** 3.3.22 Built-in Pointing Device (Type 21)
*/

void dmi_pointing_device_type(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "DeviceType", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.22.1");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x09) {
                dmixml_AddTextContent(data_n, "%s", type[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_pointing_device_interface(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "DeviceInterface", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.22.2");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x08) {
                dmixml_AddTextContent(data_n, interface[code - 0x01]);
        } else if(code >= 0xA0 && code <= 0xA2) {
                dmixml_AddTextContent(data_n, interface_0xA0[code - 0xA0]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

/*******************************************************************************
** 3.3.23 Portable Battery (Type 22)
*/

void dmi_battery_chemistry(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "BatteryChemistry", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.22.2");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x08) {
                dmixml_AddTextContent(data_n, "%s", chemistry[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_battery_capacity(xmlNode *node, u16 code, u8 multiplier)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "DesignCapacity", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "value", "0x%04x", code);
        dmixml_AddAttribute(data_n, "multiplier", "0x%04x", multiplier);

        if(code != 0) {
                dmixml_AddAttribute(data_n, "unit", "mWh");
                dmixml_AddTextContent(data_n, "%i", code * multiplier);
        }
}

void dmi_battery_voltage(xmlNode *node, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "DesignVoltage", NULL);
        assert( data_n != NULL );

        if(code == 0) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddAttribute(data_n, "unit", "mV");
                dmixml_AddTextContent(data_n, "%i", code);
        }
}

void dmi_battery_maximum_error(xmlNode *node, u8 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "MaximumError", NULL);
        assert( data_n != NULL );

        if(code == 0xFF) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddTextContent(data_n, "%i%%", code);
        }
}

/*******************************************************************************
** 3.3.24 System Reset (Type 23)
*/

void dmi_system_reset_boot_option(xmlNode *node, const char *tagname, u8 code)
{
        static const char *option[] = {
                "Operating System",     /* 0x1 */
                "System Utilities",
                "Do Not Reboot" /* 0x3 */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if( (code > 0) && (code < 4) ) {
                dmixml_AddTextContent(data_n, option[code - 0x1]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_system_reset_count(xmlNode *node, const char *tagname, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0xFFFF) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddTextContent(data_n, "%ld", code);
        }
}

void dmi_system_reset_timer(xmlNode *node, const char *tagname, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0xFFFF) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddAttribute(data_n, "unit", "min");
                dmixml_AddTextContent(data_n, "%i", code);
        }
}

/*******************************************************************************
 * 3.3.25 Hardware Security (Type 24)
 */

void dmi_hardware_security_status(xmlNode *node, const char *tagname, u8 code)
{
        static const char *status[] = {
                "Disabled",     /* 0x00 */
                "Enabled",
                "Not Implemented",
                "Unknown"       /* 0x03 */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);
        dmixml_AddTextContent(data_n, "%s", status[code]);
}

/*******************************************************************************
** 3.3.26 System Power Controls (Type 25)
*/

#define DMI_POWER_CTRL_TIME_STR(dest, variant, data)         \
        if( variant ) { snprintf(dest, 3, "%02x", data); }   \
        else { snprintf(dest, 3, "*"); }                     \

void dmi_power_controls_power_on(xmlNode *node, const char *tagname, const u8 * p)
{
        /* 3.3.26.1 */
        char timestr[5][5];
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.26.1");
        dmixml_AddAttribute(data_n, "flags", "0x%08x", p);

        DMI_POWER_CTRL_TIME_STR(timestr[0], dmi_bcd_range(p[0], 0x01, 0x12), p[0])
        DMI_POWER_CTRL_TIME_STR(timestr[1], dmi_bcd_range(p[1], 0x01, 0x31), p[1])
        DMI_POWER_CTRL_TIME_STR(timestr[2], dmi_bcd_range(p[2], 0x01, 0x23), p[2])
        DMI_POWER_CTRL_TIME_STR(timestr[3], dmi_bcd_range(p[3], 0x01, 0x59), p[3])
        DMI_POWER_CTRL_TIME_STR(timestr[4], dmi_bcd_range(p[4], 0x01, 0x59), p[4])

        dmixml_AddTextContent(data_n, "%s-%s %s:%s:%s",
                              timestr[0], timestr[1],
                              timestr[2], timestr[3], timestr[4]);
}

/*******************************************************************************
* 3.3.27 Voltage Probe (Type 26)
*/

void dmi_voltage_probe_location(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Location", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.27.1");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x0B) {
                dmixml_AddTextContent(data_n, "%s", location[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_probe_status(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Status", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.27.1");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x06) {
                dmixml_AddTextContent(data_n, "%s", status[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_voltage_probe_value(xmlNode *node, const char *tagname, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0x8000) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddAttribute(data_n, "unit", "V");
                dmixml_AddTextContent(data_n, "%.3f", (float)(i16) code / 1000);
        }
}

void dmi_voltage_probe_resolution(xmlNode *node, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Resolution", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0x8000) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddAttribute(data_n, "unit", "mV");
                dmixml_AddTextContent(data_n, "%.1f", (float) code / 10);
        }
}

void dmi_probe_accuracy(xmlNode *node, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Accuracy", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0x8000) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddAttribute(data_n, "unit", "%%");
                dmixml_AddTextContent(data_n, "%.2f", (float)code / 100);
        }
}

/*******************************************************************************
** 3.3.28 Cooling Device (Type 27)
*/

void dmi_cooling_device_type(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Type", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.28.1", code);
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x09) {
                dmixml_AddTextContent(data_n, "%s", type[code - 0x01]);
        } else if(code >= 0x10 && code <= 0x11) {
                dmixml_AddTextContent(data_n, "%s", type_0x10[code - 0x10]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_cooling_device_speed(xmlNode *node, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "NominalSpeed", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0x8000) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        }

        dmixml_AddAttribute(data_n, "unit", "rpm");
        dmixml_AddTextContent(data_n, "%i", code);
}

/*******************************************************************************
** 3.3.29 Temperature Probe (Type 28)
*/

void dmi_temperature_probe_location(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Location", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.29.1", code);
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x0F) {
                dmixml_AddTextContent(data_n, "%s", location[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_temperature_probe_value(xmlNode *node, const char *tagname, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0x8000) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddAttribute(data_n, "unit", "C");
                dmixml_AddTextContent(data_n, "%.1f", (float)(i16) code / 10);
        }
}

void dmi_temperature_probe_resolution(xmlNode *node, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Resolution", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0x8000) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddAttribute(data_n, "unit", "C");
                dmixml_AddTextContent(data_n, "%.3f", (float)code / 1000);
        }
}

/*******************************************************************************
** 3.3.30 Electrical Current Probe (Type 29)
*/

void dmi_current_probe_value(xmlNode *node, const char *tagname, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0x8000) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddAttribute(data_n, "unit", "A");
                dmixml_AddTextContent(data_n, "%.3f", (float)(i16) code / 1000);
        }
}

void dmi_current_probe_resolution(xmlNode *node, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Resolution", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0x8000) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddAttribute(data_n, "unit", "mA");
                dmixml_AddTextContent(data_n, "%.1f A", (float)code / 10);
        }
}

/*******************************************************************************
** 3.3.33 System Boot Information (Type 32)
*/

void dmi_system_boot_status(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Status", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code <= 8) {
                dmixml_AddTextContent(data_n, "%s", status[code]);
        } else if(code >= 128 && code <= 191) {
                dmixml_AddTextContent(data_n, "OEM-specific");
        } else if(code >= 192) {
                dmixml_AddTextContent(data_n, "Product-specific");
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

/*******************************************************************************
** 3.3.34 64-bit Memory Error Information (Type 33)
*/

void dmi_64bit_memory_error_address(xmlNode *node, const char *tagname, u64 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) tagname, NULL);
        assert( data_n != NULL );

        if(code.h == 0x80000000 && code.l == 0x00000000) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddTextContent(data_n, "0x%08x%08x", code.h, code.l);
        }
}

/*******************************************************************************
** 3.3.35 Management Device (Type 34)
*/

void dmi_management_device_type(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Type", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.35.1", code);
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x0D) {
                dmixml_AddTextContent(data_n, "%s", type[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_management_device_address_type(xmlNode *node, u8 code)
{
        /* 3.3.35.2 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "I/O Port",
                "Memory",
                "SMBus"         /* 0x05 */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "AddressType", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.35.2", code);
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x05) {
                dmixml_AddTextContent(data_n, "%s", type[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

/*******************************************************************************
** 3.3.38 Memory Channel (Type 37)
*/

void dmi_memory_channel_type(xmlNode *node, u8 code)
{
        /* 3.3.38.1 */
        static const char *type[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "RamBus",
                "SyncLink"      /* 0x04 */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Type", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.38.1", code);
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x04) {
                dmixml_AddTextContent(data_n, "%s", type[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_memory_channel_devices(xmlNode *node, u8 count, const u8 * p)
{
        int i;

        for(i = 1; i <= count; i++) {
                xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Device", NULL);
                assert( data_n != NULL );

                dmixml_AddAttribute(data_n, "Load", "%i", p[3 * i]);
                dmixml_AddAttribute(data_n, "Handle", "0x%04x", WORD(p + 3 * i + 1));
        }
}

/*******************************************************************************
** 3.3.39 IPMI Device Information (Type 38)
*/

void dmi_ipmi_interface_type(xmlNode *node, u8 code)
{
        /* 3.3.39.1 and IPMI 2.0, appendix C1, table C1-2 */
        static const char *type[] = {
                "Unknown",      /* 0x00 */
                "KCS (Keyboard Control Style)",
                "SMIC (Server Management Interface Chip)",
                "BT (Block Transfer)",
                "SSIF (SMBus System Interface)" /* 0x04 */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "InterfaceType", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.39.1", code);
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code <= 0x04) {
                dmixml_AddTextContent(data_n, "%s", type[code]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_ipmi_base_address(xmlNode *node, u8 type, const u8 * p, u8 lsb)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "BaseAddress", NULL);
        assert( data_n != NULL );

        if(type == 0x04) {      /* SSIF */
                dmixml_AddAttribute(data_n, "interface", "SMBus-SSIF");
                dmixml_AddTextContent(data_n, "0x%02x", (*p) >> 1);
        } else {
                u64 address = QWORD(p);
                dmixml_AddAttribute(data_n, "interface", "%s",
                                    address.l & 1 ? "I/O" : "Memory-mapped");
                dmixml_AddTextContent(data_n, "0x%08x%08x",
                                      address.h, (address.l & ~1) | lsb);
        }
}

void dmi_ipmi_register_spacing(xmlNode *node, u8 code)
{
        /* IPMI 2.0, appendix C1, table C1-1 */
        static const char *spacing[] = {
                "Successive Byte Boundaries",   /* 0x00 */
                "32-bit Boundaries",
                "16-byte Boundaries"    /* 0x02 */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "RegisterSpacing", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code <= 0x02) {
                dmixml_AddTextContent(data_n, "%s", spacing[code]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

/*******************************************************************************
** 3.3.40 System Power Supply (Type 39)
*/

void dmi_power_supply_power(xmlNode *node, u16 code)
{
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "MaxPowerCapacity", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code == 0x8000) {
                dmixml_AddAttribute(data_n, "unknown", "1");
        } else {
                dmixml_AddAttribute(data_n, "unit", "W");
                dmixml_AddTextContent(data_n, "%.3f", (float)code / 1000);
        }
}

void dmi_power_supply_type(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Type", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.40.1");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x08) {
                dmixml_AddTextContent(data_n, "%s", type[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_power_supply_status(xmlNode *node, u8 code)
{
        /* 3.3.40.1 */
        static const char *status[] = {
                "Other",        /* 0x01 */
                "Unknown",
                "OK",
                "Non-critical",
                "Critical"      /* 0x05 */
        };
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "Status", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.40.1");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);
        dmixml_AddAttribute(data_n, "present", "1");

        if(code >= 0x01 && code <= 0x05) {
                dmixml_AddTextContent(data_n, "%s", status[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

void dmi_power_supply_range_switching(xmlNode *node, u8 code)
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
        xmlNode *data_n = xmlNewChild(node, NULL, (xmlChar *) "VoltageRangeSwitching", NULL);
        assert( data_n != NULL );
        dmixml_AddAttribute(data_n, "dmispec", "3.3.40.1");
        dmixml_AddAttribute(data_n, "flags", "0x%04x", code);

        if(code >= 0x01 && code <= 0x06) {
                dmixml_AddTextContent(data_n, "%s", switching[code - 0x01]);
        } else {
                dmixml_AddAttribute(data_n, "outofspec", "1");
        }
}

/*
** 3.3.41 Additional Information (Type 40)
**
** Proper support of this entry type would require redesigning a large part of
** the code, so I am waiting to see actual implementations of it to decide
** whether it's worth the effort.
*/

void dmi_additional_info(xmlNode *node, const struct dmi_header *h)
{
        u8 *p = h->data + 4;
        u8 count = *p++;
        u8 length;
        int i, offset = 5;

        assert( node != NULL );

        for(i = 0; i < count; i++) {
                xmlNode *data_n = NULL, *str_n = NULL, *val_n = NULL;

                /* Check for short entries */
                if(h->length < offset + 1) {
                        break;
                }

                length = p[0x00];
                if(length < 0x05 || h->length < offset + length)
                        break;

                data_n = xmlNewChild(node, NULL, (xmlChar *) "Record", NULL);
                assert( data_n != NULL );

                dmixml_AddAttribute(data_n, "index", "%i", i);
                dmixml_AddAttribute(data_n, "ReferenceHandle", "0x%04x", WORD(p + 0x01));
                dmixml_AddAttribute(data_n, "ReferenceOffset", "0x%02x", p[0x03]);

                str_n = dmixml_AddDMIstring(data_n, "String", h, p[0x04]);

                switch (length - 0x05) {
                case 1:
                        dmixml_AddTextChild(data_n, "Value", "0x%02x", p[0x05]);
                        break;
                case 2:
                        dmixml_AddTextChild(data_n, "Value", "0x%04x", WORD(p + 0x05));
                        break;
                case 4:
                        dmixml_AddTextChild(data_n, "Value", "0x%08x", DWORD(p + 0x05));
                        break;
                default:
                        val_n = xmlNewChild(data_n, NULL, (xmlChar *) "Value", NULL);
                        dmixml_AddAttribute(val_n, "unexpected_size", "1");
                        break;
                }

                p += length;
                offset += length;
        }
}

/*******************************************************************************
** Main
*/

xmlNode *dmi_decode(xmlNode *prnt_n, dmi_codes_major *dmiMajor, struct dmi_header * h, u16 ver)
{
        const u8 *data = h->data;
        xmlNode *sect_n = NULL, *sub_n = NULL, *sub2_n = NULL;
        //. 0xF1 --> 0xF100
        //int minor = h->type<<8;

        sect_n = xmlNewChild(prnt_n, NULL, (xmlChar *) dmiMajor->tagname, NULL);
        assert( sect_n != NULL );

        dmixml_AddAttribute(sect_n, "dmispec", "%s", dmiMajor->id);
        dmixml_AddAttribute(sect_n, "type", "%i", h->type);
        dmixml_AddTextChild(sect_n, "DMIdescription", "%s", dmiMajor->desc);

        switch (h->type) {
        case 0:                /* 3.3.1 BIOS Information */
                if(h->length < 0x12) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "Vendor", h, data[0x04]);
                dmixml_AddDMIstring(sect_n, "Version", h, data[0x05]);
                dmixml_AddDMIstring(sect_n, "ReleaseDate", h, data[0x08]);

                /*
                 * On IA-64, the BIOS base address will read 0 because
                 * there is no BIOS. Skip the base address and the
                 * runtime size in this case.
                 */

                if(WORD(data + 0x06) != 0) {
                        dmixml_AddTextChild(sect_n, "Address", "0x%04x0", WORD(data + 0x06));
                        dmi_bios_runtime_size(sect_n, (0x10000 - WORD(data + 0x06)) << 4);
                }

                sub_n = dmixml_AddTextChild(sect_n, "ROMsize", "%i", (data[0x09] + 1) << 6);
                dmixml_AddAttribute(sub_n, "unit", "KB");
                sub_n = NULL;

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Characteristics", NULL);
                assert( sub_n != NULL );

                dmixml_AddAttribute(sub_n, "level", "0");
                dmi_bios_characteristics(sub_n, QWORD(data + 0x0A));
                sub_n = NULL;

                if(h->length < 0x13) {
                        break;
                }

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Characteristics", NULL);
                assert( sub_n != NULL );

                dmixml_AddAttribute(sub_n, "level", "x1");
                dmi_bios_characteristics_x1(sub_n, data[0x12]);
                sub_n = NULL;

                if(h->length < 0x14) {
                        break;
                }

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Characteristics", NULL);
                assert( sub_n != NULL );

                dmixml_AddAttribute(sub_n, "level", "x2");
                dmi_bios_characteristics_x2(sub_n, data[0x13]);
                sub_n = NULL;

                if(h->length < 0x18) {
                        break;
                }

                if(data[0x14] != 0xFF && data[0x15] != 0xFF) {
                        dmixml_AddTextChild(sect_n, "BIOSrevision", "%i.%i", data[0x14], data[0x15]);
                }

                if(data[0x16] != 0xFF && data[0x17] != 0xFF) {
                        dmixml_AddTextChild(sect_n, "FirmwareRevision", "%i.%i", data[0x16], data[0x17]);
                }
                break;

        case 1:                /* 3.3.2 System Information */
                if(h->length < 0x08) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "Manufacturer", h, data[0x04]);
                dmixml_AddDMIstring(sect_n, "ProductName", h, data[0x05]);
                dmixml_AddDMIstring(sect_n, "Version", h, data[0x06]);
                dmixml_AddDMIstring(sect_n, "SerialNumber", h, data[0x07]);

                if(h->length < 0x19) {
                        break;
                }

                dmi_system_uuid(sect_n, data + 0x08, ver);

                dmi_system_wake_up_type(sect_n, data[0x18]);

                if(h->length < 0x1B) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "SKUnumber", h, data[0x19]);
                dmixml_AddDMIstring(sect_n, "Family", h, data[0x1A]);
                break;

        case 2:                /* 3.3.3 Base Board Information */
                if(h->length < 0x08) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "Manufacturer", h, data[0x04]);
                dmixml_AddDMIstring(sect_n, "ProductName", h, data[0x05]);
                dmixml_AddDMIstring(sect_n, "Version", h, data[0x06]);
                dmixml_AddDMIstring(sect_n, "SerialNumber", h, data[0x07]);

                if(h->length < 0x0F) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "AssetTag", h, data[0x08]);

                dmi_base_board_features(sect_n, data[0x09]);

                dmixml_AddDMIstring(sect_n, "ChassisLocation", h, data[0x0A]);
                dmixml_AddTextChild(sect_n, "ChassisHandle", "0x%04x", WORD(data + 0x0B));

                dmi_base_board_type(sect_n, "Type", data[0x0D]);

                if(h->length < 0x0F + data[0x0E] * sizeof(u16)) {
                        break;
                }

                dmi_base_board_handles(sect_n, data[0x0E], data + 0x0F);
                break;

        case 3:                /* 3.3.4 Chassis Information */
                if(h->length < 0x09) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "Manufacturer", h, data[0x04]);
                dmi_chassis_type(sect_n, data[0x05] & 0x7F);
                dmi_chassis_lock(sect_n, data[0x05] >> 7);
                dmixml_AddDMIstring(sect_n, "Version", h, data[0x06]);
                dmixml_AddDMIstring(sect_n, "SerialNumber", h, data[0x07]);
                dmixml_AddDMIstring(sect_n, "AssetTag", h, data[0x08]);

                if(h->length < 0x0D) {
                        break;
                }

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "ChassisStates", NULL);
                assert( sub_n != NULL );

                dmi_chassis_state(sub_n, "BootUp", data[0x09]);
                dmi_chassis_state(sub_n, "PowerSupply", data[0x0A]);
                dmi_chassis_state(sub_n, "Thermal", data[0x0B]);
                sub_n = NULL;

                dmi_chassis_security_status(sect_n, data[0x0C]);

                if(h->length < 0x11) {
                        break;
                }

                dmixml_AddTextChild(sect_n, "OEMinformation", "0x%08x", DWORD(data + 0x0D));

                if(h->length < 0x13) {
                        break;
                }

                dmi_chassis_height(sect_n, data[0x11]);
                dmi_chassis_power_cords(sect_n, data[0x12]);

                if((h->length < 0x15) || (h->length < 0x15 + data[0x13] * data[0x14])){
                        break;
                }

                dmi_chassis_elements(sect_n, data[0x13], data[0x14], data + 0x15);
                break;

        case 4:                /* 3.3.5 Processor Information */
                if(h->length < 0x1A) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "SocketDesignation", h, data[0x04]);
                dmi_processor_type(sect_n, data[0x05]);
                dmi_processor_family(sect_n, h);

                dmi_processor_id(sect_n, h);

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Manufacturer", NULL);
                assert( sub_n != NULL );
                dmixml_AddDMIstring(sub_n, "Vendor", h, data[0x07]);

                dmixml_AddDMIstring(sub_n, "Version", h, data[0x10]);
                sub_n = NULL;

                dmi_processor_voltage(sect_n, data[0x11]);

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Frequencies", NULL);
                assert( sub_n != NULL );

                dmixml_AddTextChild(sub_n, "ExternalClock", "%i", dmi_processor_frequency(data + 0x12));
                dmixml_AddTextChild(sub_n, "MaxSpeed", "%i", dmi_processor_frequency(data + 0x14));
                dmixml_AddTextChild(sub_n, "CurrentSpeed", "%i", dmi_processor_frequency(data + 0x16));
                sub_n = NULL;

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
                        dmixml_AddTextChild(sect_n, "Populated", "No");
                }

                dmi_processor_upgrade(sect_n, data[0x19]);

                if(h->length < 0x20) {
                        break;
                }

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

                if(h->length < 0x23) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "SerialNumber", h, data[0x20]);
                dmixml_AddDMIstring(sect_n, "AssetTag", h, data[0x21]);
                dmixml_AddDMIstring(sect_n, "PartNumber", h, data[0x22]);

                if(h->length < 0x28) {
                        break;
                }

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Cores", NULL);
                assert( sub_n != NULL );

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
                break;

        case 5:                /* 3.3.6 Memory Controller Information */
                if(h->length < 0x0F) {
                        break;
                }

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "ErrorCorrection", NULL);
                assert( sub_n != NULL );

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

                if(h->length < 0x0F + data[0x0E] * sizeof(u16)) {
                        break;
                }

                dmi_memory_controller_slots(sect_n, data[0x0E], data + 0x0F);

                if(h->length < 0x10 + data[0x0E] * sizeof(u16)) {
                        break;
                }

                dmi_memory_controller_ec_capabilities(sect_n, "EnabledErrorCorrection",
                                                      data[0x0F + data[0x0E] * sizeof(u16)]);
                break;

        case 6:                /* 3.3.7 Memory Module Information */
                if(h->length < 0x0C) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "SocketDesignation", h, data[0x04]);
                dmi_memory_module_connections(sect_n, data[0x05]);
                dmi_memory_module_speed(sect_n, "ModuleSpeed", data[0x06]);
                dmi_memory_module_types(sect_n, "Type", WORD(data + 0x07));

                dmi_memory_module_size(sect_n, "InstalledSize", data[0x09]);
                dmi_memory_module_size(sect_n, "EnabledSize",   data[0x0A]);
                dmi_memory_module_error(sect_n, data[0x0B]);
                break;

        case 7:                /* 3.3.8 Cache Information */
                if(h->length < 0x0F) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "SocketDesignation", h, data[0x04]);
                dmixml_AddAttribute(sect_n, "Enabled", "%i", (WORD(data + 0x05) & 0x0080 ? 1 : 0));
                dmixml_AddAttribute(sect_n, "Socketed", "%i", (WORD(data + 0x05) & 0x0008 ? 1 : 0));
                dmixml_AddAttribute(sect_n, "Level", "%ld", ((WORD(data + 0x05) & 0x0007) + 1));

                sub_n = dmixml_AddTextChild(sect_n, "OperationalMode", "%s",
                                            dmi_cache_mode((WORD(data + 0x05) >> 8) & 0x0003));
                dmixml_AddAttribute(sub_n, "flags", "0x%04x", (WORD(data + 0x05) >> 8) & 0x0003);
                sub_n = NULL;

                dmi_cache_location(sect_n, (WORD(data + 0x05) >> 5) & 0x0003);
                dmi_cache_size(sect_n, "InstalledSize", WORD(data + 0x09));
                dmi_cache_size(sect_n, "MaximumSize", WORD(data + 0x07));

                dmi_cache_types(sect_n, "SupportedSRAMtypes", WORD(data + 0x0B));
                dmi_cache_types(sect_n, "InstalledSRAMtypes", WORD(data + 0x0D));

                if(h->length < 0x13) {
                        break;
                }

                dmi_memory_module_speed(sect_n, "Speed", data[0x0F]);
                dmi_cache_ec_type(sect_n, data[0x10]);
                dmi_cache_type(sect_n, data[0x11]);
                dmi_cache_associativity(sect_n, data[0x12]);
                break;

        case 8:                /* 3.3.9 Port Connector Information */
                if(h->length < 0x09) {
                        break;
                }

                sub_n = dmixml_AddDMIstring(sect_n, "DesignatorRef", h, data[0x04]);
                assert( sub_n != NULL );
                dmixml_AddAttribute(sub_n, "type", "internal");
                sub_n = NULL;

                dmi_port_connector_type(sect_n, "internal", data[0x05]);

                sub_n = dmixml_AddDMIstring(sect_n, "DesignatorRef", h, data[0x06]);
                assert( sub_n != NULL );
                dmixml_AddAttribute(sub_n, "type", "external");
                sub_n = NULL;

                dmi_port_connector_type(sect_n, "external", data[0x07]);
                dmi_port_type(sect_n, data[0x08]);
                break;

        case 9:                /* 3.3.10 System Slots */
                if(h->length < 0x0C) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "Designation", h, data[0x04]);

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
                break;

        case 10:               /* 3.3.11 On Board Devices Information */
                dmi_on_board_devices(sect_n, "dmi_on_board_devices", h);
                break;

        case 11:               /* 3.3.12 OEM Strings */
                if(h->length < 0x05) {
                        break;
                }

                dmi_oem_strings(sect_n, h);
                break;

        case 12:               /* 3.3.13 System Configuration Options */
                if(h->length < 0x05) {
                        break;
                }

                dmi_system_configuration_options(sect_n, h);
                break;

        case 13:               /* 3.3.14 BIOS Language Information */
                if(h->length < 0x16) {
                        break;
                }

                dmixml_AddAttribute(sect_n, "installable_languages", "%i", data[0x04]);

                dmi_bios_languages(sect_n, h);
                break;

        case 14:               /* 3.3.15 Group Associations */
                if(h->length < 0x05) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "Name", h, data[0x04]);

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Groups", NULL);
                assert( sub_n != NULL );
                dmi_group_associations_items(sub_n, (h->length - 0x05) / 3, data + 0x05);
                sub_n = NULL;
                break;

        case 15:               /* 3.3.16 System Event Log */
                // SysEventLog - sect_n
                if(h->length < 0x14) {
                        break;
                }

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

                if(h->length < 0x17) {
                        break;
                }

                // SysEventLog/Access/Header/Format - sub2_n
                dmi_event_log_header_type(sub2_n, data[0x14]);

                sub2_n = NULL;
                sub_n = NULL;

                // SysEventLog/LogTypes - resuing sub_n
                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "LogTypes", NULL);
                assert( sub_n != NULL );

                // SysEventLog/LogTypes/@count
                dmixml_AddAttribute(sub_n, "count", "%i", data[0x15]);

                if(h->length < 0x17 + data[0x15] * data[0x16]) {
                        break;
                }

                dmixml_AddAttribute(sub_n, "length", "%i", data[0x16]);

                // SysEventLog/LogTypes/LogType
                dmi_event_log_descriptors(sub_n, data[0x15], data[0x16], data + 0x17);
                sub_n = NULL;
                break;

        case 16:               /* 3.3.17 Physical Memory Array */
                if(h->length < 0x0F) {
                        break;
                }

                dmixml_AddAttribute(sect_n, "NumDevices", "%ld", WORD(data + 0x0D));
                dmi_memory_array_location(sect_n, data[0x04]);
                dmi_memory_array_use(sect_n, data[0x05]);
                dmi_memory_array_ec_type(sect_n, data[0x06]);
                dmi_memory_array_capacity(sect_n, DWORD(data + 0x07));
                dmi_memory_array_error_handle(sect_n, WORD(data + 0x0B));
                break;

        case 17:               /* 3.3.18 Memory Device */
                if(h->length < 0x15) {
                        break;
                }

                dmixml_AddAttribute(sect_n, "ArrayHandle", "0x%04x", WORD(data + 0x04));
                dmi_memory_array_error_handle(sect_n, WORD(data + 0x06));

                dmi_memory_device_width(sect_n, "TotalWidth", WORD(data + 0x08));
                dmi_memory_device_width(sect_n, "DataWidth", WORD(data + 0x0A));
                dmi_memory_device_size(sect_n, WORD(data + 0x0C));
                dmi_memory_device_form_factor(sect_n, data[0x0E]);
                dmi_memory_device_set(sect_n, data[0x0F]);
                dmixml_AddDMIstring(sect_n, "Locator", h, data[0x10]);
                dmixml_AddDMIstring(sect_n, "BankLocator", h, data[0x11]);

                dmi_memory_device_type(sect_n, data[0x12]);
                dmi_memory_device_type_detail(sect_n, WORD(data + 0x13));

                if(h->length < 0x17) {
                        break;
                }

                dmi_memory_device_speed(sect_n, WORD(data + 0x15));

                if(h->length < 0x1B) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "Manufacturer", h, data[0x17]);
                dmixml_AddDMIstring(sect_n, "SerialNumber", h, data[0x18]);
                dmixml_AddDMIstring(sect_n, "AssetTag",     h, data[0x19]);
                dmixml_AddDMIstring(sect_n, "PartNumber",   h, data[0x1A]);
                break;

        case 18:               /* 3.3.19 32-bit Memory Error Information */
        case 33:               /* 3.3.34 64-bit Memory Error Information */
                if( h->type == 18 ) {
                        dmixml_AddAttribute(sect_n, "bits", "32");
                } else {
                        dmixml_AddAttribute(sect_n, "bits", "64");
                }

                if( ((h->type == 18) && (h->length < 0x17))        /* 32-bit */
                    || ((h->type == 33) && (h->length < 0x1F)) )   /* 64-bit */
                        {
                                break;
                        }

                dmi_memory_error_type(sect_n, data[0x04]);
                dmi_memory_error_granularity(sect_n, data[0x05]);
                dmi_memory_error_operation(sect_n, data[0x06]);
                dmi_memory_error_syndrome(sect_n, DWORD(data + 0x07));

                if( h->type == 18 ) {
                        /* 32-bit */
                        dmi_32bit_memory_error_address(sect_n, "MemArrayAddr", DWORD(data + 0x0B));
                        dmi_32bit_memory_error_address(sect_n, "DeviceAddr",   DWORD(data + 0x0F));
                        dmi_32bit_memory_error_address(sect_n, "Resolution",   DWORD(data + 0x13));
                } else if( h->type == 33 ) {
                        /* 64-bit */
                        dmi_64bit_memory_error_address(sect_n, "MemArrayAddr", QWORD(data + 0x0B));
                        dmi_64bit_memory_error_address(sect_n, "DeviceAddr",   QWORD(data + 0x13));
                        dmi_32bit_memory_error_address(sect_n, "Resolution",   DWORD(data + 0x1B));
                }
                break;

        case 19:               /* 3.3.20 Memory Array Mapped Address */
                if(h->length < 0x0F) {
                        break;
                }

                dmixml_AddTextChild(sect_n, "StartAddress", "0x%08x%03x",
                                    (DWORD(data + 0x04) >> 2),
                                    (DWORD(data + 0x04) & 0x3) << 10);
                dmixml_AddTextChild(sect_n, "EndAddress", "0x%08x%03x",
                                    (DWORD(data + 0x08) >> 2),
                                    ((DWORD(data + 0x08) & 0x3) << 10) + 0x3FF);
                dmi_mapped_address_size(sect_n, DWORD(data + 0x08) - DWORD(data + 0x04) + 1);
                dmixml_AddTextChild(sect_n, "PhysicalArrayHandle", "0x%04x", WORD(data + 0x0C));
                dmixml_AddTextChild(sect_n, "PartitionWidth", "%i", data[0x0F]);
                break;

        case 20:               /* 3.3.21 Memory Device Mapped Address */
                if(h->length < 0x13) {
                        break;
                }

                dmixml_AddTextChild(sect_n, "StartAddress", "0x%08x%03x",
                                    (DWORD(data + 0x04) >> 2),
                                    (DWORD(data + 0x04) & 0x3) << 10);

                dmixml_AddTextChild(sect_n, "EndAddress", "0x%08x%03x",
                                    (DWORD(data + 0x08) >> 2),
                                    ((DWORD(data + 0x08) & 0x3) << 10) + 0x3FF);

                dmi_mapped_address_size(sect_n, DWORD(data + 0x08) - DWORD(data + 0x04) + 1);

                dmixml_AddTextChild(sect_n, "PhysicalDeviceHandle", "0x%04x", WORD(data + 0x0C));
                dmixml_AddTextChild(sect_n, "MemArrayMappedAddrHandle", "0x%04x", WORD(data + 0x0E));

                dmi_mapped_address_row_position(sect_n, data[0x10]);

                dmi_mapped_address_interleave_position(sect_n, data[0x11]);
                dmi_mapped_address_interleaved_data_depth(sect_n, data[0x12]);
                break;

        case 21:               /* 3.3.22 Built-in Pointing Device */
                if(h->length < 0x07) {
                        break;
                }

                dmi_pointing_device_type(sect_n, data[0x04]);
                dmi_pointing_device_interface(sect_n, data[0x05]);
                dmixml_AddTextChild(sect_n, "Buttons", "%i", data[0x06]);
                break;

        case 22:               /* 3.3.23 Portable Battery */
                if(h->length < 0x10) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "Location", h, data[0x04]);
                dmixml_AddDMIstring(sect_n, "Manufacturer", h, data[0x05]);

                if(data[0x06] || h->length < 0x1A) {
                        dmixml_AddDMIstring(sect_n, "ManufactureDate", h, data[0x06]);
                }

                if(data[0x07] || h->length < 0x1A) {
                        dmixml_AddDMIstring(sect_n, "SerialNumber", h, data[0x07]);
                }

                dmixml_AddDMIstring(sect_n, "Name", h, data[0x08]);

                if(data[0x09] != 0x02 || h->length < 0x1A) {
                        dmi_battery_chemistry(sect_n, data[0x09]);
                }

                dmi_battery_capacity(sect_n, WORD(data + 0x0A), (h->length < 0x1A ? 1 : data[0x15]));
                dmi_battery_voltage(sect_n, WORD(data + 0x0C));
                dmixml_AddDMIstring(sect_n, "SBDSversion", h, data[0x0E]);

                dmi_battery_maximum_error(sect_n, data[0x0F]);

                if(h->length < 0x1A) {
                        break;
                }

                if(data[0x07] == 0) {
                        dmixml_AddTextChild(sect_n, "SBDSserialNumber", "%04x", WORD(data + 0x10));
                }
                if(data[0x06] == 0) {
                        dmixml_AddTextChild(sect_n, "SBDSmanufactureDate", "%i-%02u-%02u",
                                            1980 + (WORD(data + 0x12) >> 9),
                                            (WORD(data + 0x12) >> 5) & 0x0F,
                                            (WORD(data + 0x12) & 0x1F));
                }
                if(data[0x09] == 0x02) {
                        dmixml_AddDMIstring(sect_n, "SBDSchemistry", h, data[0x14]);
                }

                dmixml_AddTextChild(sect_n, "OEMinformation", "0x%08x", DWORD(data + 0x16));
                break;

        case 23:               /* 3.3.24 System Reset */
                if(h->length < 0x0D) {
                        break;
                }

                sub_n = dmixml_AddTextChild(sect_n, "Status", "%s",
                                            data[0x04] & (1 << 0) ? "Enabled" : "Disabled");
                dmixml_AddAttribute(sub_n, "enabled", "%i", data[0x04] & (1 << 0) ? 1 : 0);
                sub_n = NULL;

                sub_n = dmixml_AddTextChild(sect_n, "WatchdogTimer", "%s",
                                            data[0x04] & (1 << 5) ? "Present" : "Not Present");
                dmixml_AddAttribute(sub_n, "present", "%i", data[0x04] & (1 << 5) ? 1 : 0);
                sub_n = NULL;

                if(!(data[0x04] & (1 << 5))) {
                        break;
                }

                dmi_system_reset_boot_option(sect_n, "BootOption", (data[0x04] >> 1) & 0x3);
                dmi_system_reset_boot_option(sect_n, "BootOptionOnLimit", (data[0x04] >> 3) & 0x3);

                dmi_system_reset_count(sect_n, "ResetCount", WORD(data + 0x05));
                dmi_system_reset_count(sect_n, "ResetLimit", WORD(data + 0x07));

                dmi_system_reset_timer(sect_n, "TimerInterval", WORD(data + 0x09));
                dmi_system_reset_timer(sect_n, "Timeout", WORD(data + 0x0B));
                break;

        case 24:               /* 3.3.25 Hardware Security */
                if(h->length < 0x05) {
                        break;
                }

                dmi_hardware_security_status(sect_n, "PowerOnPassword", data[0x04] >> 6);
                dmi_hardware_security_status(sect_n, "KeyboardPassword", (data[0x04] >> 4) & 0x3);
                dmi_hardware_security_status(sect_n, "AdministratorPassword", (data[0x04] >> 2) & 0x3);
                dmi_hardware_security_status(sect_n, "FronPanelReset", data[0x04] & 0x3);

                break;

        case 25:               /* 3.3.26 System Power Controls */
                if(h->length < 0x09) {
                        break;
                }

                dmi_power_controls_power_on(sect_n, "NextSchedPowerOn", data + 0x04);
                break;

        case 26:               /* 3.3.27 Voltage Probe */
                dmixml_AddAttribute(sect_n, "probetype", "Voltage");

                if(h->length < 0x14) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "Description", h, data[0x04]);

                dmi_voltage_probe_location(sect_n, data[0x05] & 0x1f);
                dmi_probe_status(sect_n, data[0x05] >> 5);

                dmi_voltage_probe_value(sect_n, "MaxValue", WORD(data + 0x06));
                dmi_voltage_probe_value(sect_n, "MinValue", WORD(data + 0x08));
                dmi_voltage_probe_resolution(sect_n, WORD(data + 0x0A));
                dmi_voltage_probe_value(sect_n, "Tolerance", WORD(data + 0x0C));

                dmi_probe_accuracy(sect_n, WORD(data + 0x0E));

                dmixml_AddTextChild(sect_n, "OEMinformation", "0x%08x", DWORD(data + 0x10));

                if(h->length < 0x16) {
                        break;
                }

                dmi_voltage_probe_value(sect_n, "NominalValue", WORD(data + 0x14));
                break;

        case 27:               /* 3.3.28 Cooling Device */
                if(h->length < 0x0C) {
                        break;
                }

                if(WORD(data + 0x04) != 0xFFFF) {
                        dmixml_AddTextContent(sect_n, "TemperatureProbeHandle", "0x%04x", WORD(data + 0x04));
                }

                dmi_cooling_device_type(sect_n, data[0x06] & 0x1f);
                dmi_probe_status(sect_n, data[0x06] >> 5);

                if(data[0x07] != 0x00) {
                        dmixml_AddTextChild(sect_n, "UnitGroup", "%i", data[0x07]);
                }

                dmixml_AddTextChild(sect_n, "OEMinformation", "0x%08x", DWORD(data + 0x08));

                if(h->length < 0x0E) {
                        break;
                }

                dmi_cooling_device_speed(sect_n, WORD(data + 0x0C));
                break;

        case 28:               /* 3.3.29 Temperature Probe */
                dmixml_AddAttribute(sect_n, "probetype", "Temperature");

                if(h->length < 0x14) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "Description", h, data[0x04]);
                dmi_temperature_probe_location(sect_n,data[0x05] & 0x1F);
                dmi_probe_status(sect_n, data[0x05] >> 5);

                dmi_temperature_probe_value(sect_n, "MaxValue", WORD(data + 0x06));
                dmi_temperature_probe_value(sect_n, "MinValue", WORD(data + 0x08));
                dmi_temperature_probe_resolution(sect_n, WORD(data + 0x0A));
                dmi_temperature_probe_value(sect_n, "Tolerance", WORD(data + 0x0C));
                dmi_probe_accuracy(sect_n, WORD(data + 0x0E));

                dmixml_AddTextChild(sect_n, "OEMinformation", "0x%08x", DWORD(data + 0x10));

                if(h->length < 0x16) {
                        break;
                }

                dmi_temperature_probe_value(sect_n, "NominalValue", WORD(data + 0x14));
                break;

        case 29:               /* 3.3.30 Electrical Current Probe */
                dmixml_AddAttribute(sect_n, "probetype", "Electrical Current");

                if(h->length < 0x14) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "Description", h, data[0x04]);
                dmi_voltage_probe_location(sect_n, data[5] & 0x1F);
                dmi_probe_status(sect_n, data[0x05] >> 5);

                dmi_current_probe_value(sect_n, "MaxValue", WORD(data + 0x06));
                dmi_current_probe_value(sect_n, "MinValue", WORD(data + 0x08));
                dmi_current_probe_resolution(sect_n, WORD(data + 0x0A));
                dmi_current_probe_value(sect_n, "Tolerance", WORD(data + 0x0C));

                dmi_probe_accuracy(sect_n, WORD(data + 0x0E));

                dmixml_AddTextChild(sect_n, "OEMinformation", "0x%08x", DWORD(data + 0x10));

                if(h->length < 0x16) {
                        break;
                }

                dmi_current_probe_value(sect_n, "NominalValue", WORD(data + 0x14));
                break;

        case 30:               /* 3.3.31 Out-of-band Remote Access */
                if(h->length < 0x06) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "ManufacturerName", h, data[0x04]);
                dmixml_AddAttribute(sect_n, "InboundConnectionEnabled",  "%i", data[0x05] & (1 << 0) ? 1 : 0);
                dmixml_AddAttribute(sect_n, "OutboundConnectionEnabled", "%i", data[0x05] & (1 << 1) ? 1 : 0);
                break;

        case 31:               /* 3.3.32 Boot Integrity Services Entry Point */
                dmixml_AddAttribute(sect_n, "NOT_IMPLEMENTED", "1");
                break;

        case 32:               /* 3.3.33 System Boot Information */
                if(h->length < 0x0B) {
                        break;
                }

                dmi_system_boot_status(sect_n, data[0x0A]);
                break;

        case 34:               /* 3.3.35 Management Device */
                dmixml_AddAttribute(sect_n, "mgmtype", "");

                if(h->length < 0x0B) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "Description", h, data[0x04]);
                dmi_management_device_type(sect_n, data[0x05]);
                dmixml_AddTextChild(sect_n, "Address", "0x%08x", DWORD(data + 0x06));
                dmi_management_device_address_type(sect_n, data[0x0A]);
                break;

        case 35:               /* 3.3.36 Management Device Component */
                dmixml_AddAttribute(sect_n, "mgmtype", "Component");

                if(h->length < 0x0B) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "Description", h, data[0x04]);
                dmixml_AddTextChild(sect_n, "ManagementDeviceHandle", "0x%04x", WORD(data + 0x05));
                dmixml_AddTextChild(sect_n, "ComponentHandle", "0x%04x", WORD(data + 0x07));

                if(WORD(data + 0x09) != 0xFFFF) {
                        dmixml_AddTextChild(sect_n, "ThresholdHandle", "0x%04x", WORD(data + 0x09));
                }
                break;

        case 36:               /* 3.3.37 Management Device Threshold Data */
                dmixml_AddAttribute(sect_n, "mgmtype", "Threshold Data");

                if(h->length < 0x10) {
                        break;
                }

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Thresholds", NULL);
                assert( sub_n != NULL );
                dmixml_AddAttribute(sub_n, "mode", "non-critical");

                if(WORD(data + 0x04) != 0x8000) {
                        dmixml_AddAttribute(sub_n, "Lower", "%d", (i16) WORD(data + 0x04));
                }
                if(WORD(data + 0x06) != 0x8000) {
                        dmixml_AddAttribute(sub_n, "Upper", "%d", (i16) WORD(data + 0x06));
                }
                sub_n = NULL;

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Thresholds", NULL);
                assert( sub_n != NULL );
                dmixml_AddAttribute(sub_n, "mode", "critical");

                if(WORD(data + 0x08) != 0x8000) {
                        dmixml_AddAttribute(sub_n, "Lower", "%d", (i16) WORD(data + 0x08));
                }
                if(WORD(data + 0x0A) != 0x8000) {
                        dmixml_AddAttribute(sub_n, "Upper", "%d", (i16) WORD(data + 0x0A));

                }
                sub_n = NULL;

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Thresholds", NULL);
                assert( sub_n != NULL );
                dmixml_AddAttribute(sub_n, "mode", "non-recoverable");

                if(WORD(data + 0x0C) != 0x8000) {
                        dmixml_AddAttribute(sub_n, "Lower", "%d", (i16) WORD(data + 0x0C));
                }
                if(WORD(data + 0x0E) != 0x8000) {
                        dmixml_AddAttribute(sub_n, "Upper", "%d", (i16) WORD(data + 0x0E));
                }
                sub_n = NULL;
                break;

        case 37:               /* 3.3.38 Memory Channel */
                if(h->length < 0x07) {
                        break;
                }

                dmi_memory_channel_type(sect_n, data[0x04]);
                dmixml_AddTextChild(sect_n, "MaxLoad", "%i", data[0x05]);

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Devices", NULL);
                assert( sub_n != NULL );
                dmixml_AddAttribute(sub_n, "devices", "%i", data[0x06]);

                if(h->length < 0x07 + 3 * data[0x06]) {
                        sub_n = NULL;
                        break;
                }

                dmi_memory_channel_devices(sub_n, data[0x06], data + 0x07);
                sub_n = NULL;
                break;

        case 38:               /* 3.3.39 IPMI Device Information */
                /*
                 * We use the word "Version" instead of "Revision", conforming to
                 * the IPMI specification.
                 */
                if(h->length < 0x10) {
                        break;
                }

                dmi_ipmi_interface_type(sect_n, data[0x04]);

                dmixml_AddAttribute(sect_n, "spec_version", "%i.%i", data[0x05] >> 4, data[0x05] & 0x0F);
                dmixml_AddAttribute(sect_n, "I2CslaveAddr", "0x%02x", data[0x06] >> 1);


                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "NVstorageDevice", NULL);
                assert( sub_n != NULL );

                if(data[0x07] != 0xFF) {
                        dmixml_AddAttribute(sub_n, "Address", "%i", data[0x07]);
                } else {
                        dmixml_AddAttribute(sub_n, "NotPresent", "1");
                }
                sub_n = NULL;

                dmi_ipmi_base_address(sect_n, data[0x04], data + 0x08,
                                      h->length < 0x12 ? 0 : (data[0x10] >> 5) & 1);

                if(h->length < 0x12) {
                        break;
                }

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Interrupt", NULL);
                assert( sub_n != NULL );

                if(data[0x04] != 0x04) {
                        dmi_ipmi_register_spacing(sect_n, data[0x10] >> 6);

                        if(data[0x10] & (1 << 3)) {
                                sub2_n = dmixml_AddTextChild(sub_n, "Polarity", "%s",
                                                   data[0x10] & (1 << 1) ? "Active High" : "Active Low");
                                assert( sub2_n != NULL );
                                dmixml_AddAttribute(sub2_n, "active_high", "%i", data[0x10] & (1 << 1) ? 1: 0);
                                sub2_n = NULL;

                                dmixml_AddTextChild(sub_n, "TriggerMode", "%s",
                                                    data[0x10] & (1 << 0) ? "Level" : "Edge");
                        }
                }
                if(data[0x11] != 0x00) {
                        dmixml_AddTextChild(sub_n, "InterruptNumber", "%x", data[0x11]);
                }
                sub_n = NULL;
                break;

        case 39:               /* 3.3.40 System Power Supply */
                if(h->length < 0x10) {
                        break;
                }

                if(data[0x04] != 0x00) {
                        dmixml_AddAttribute(sect_n, "UnitGroup", "%i", data[0x04]);
                }

                dmixml_AddDMIstring(sect_n, "Location",        h, data[0x05]);
                dmixml_AddDMIstring(sect_n, "Name",            h, data[0x06]);
                dmixml_AddDMIstring(sect_n, "Manufacturer",    h, data[0x07]);
                dmixml_AddDMIstring(sect_n, "SerialNumber",    h, data[0x08]);
                dmixml_AddDMIstring(sect_n, "AssetTag",        h, data[0x09]);
                dmixml_AddDMIstring(sect_n, "ModelPartNumber", h, data[0x0A]);
                dmixml_AddDMIstring(sect_n, "Revision",        h, data[0x0B]);

                dmi_power_supply_power(sect_n, WORD(data + 0x0C));

                if(WORD(data + 0x0E) & (1 << 1)) {
                        dmi_power_supply_status(sect_n, (WORD(data + 0x0E) >> 7) & 0x07);
                } else {
                        sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Status", NULL);
                        assert( sub_n != NULL );
                        dmixml_AddAttribute(sub_n, "present", "0");
                        sub_n = NULL;
                }

                dmi_power_supply_type(sect_n, (WORD(data + 0x0E) >> 10) & 0x0F);

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "Input", NULL);
                assert( sub_n != NULL );

                dmi_power_supply_range_switching(sub_n, (WORD(data + 0x0E) >> 3) & 0x0F);

                dmixml_AddAttribute(sub_n, "Plugged",       "%i", WORD(data + 0x0E) & (1 << 2) ? 0 : 1);
                dmixml_AddAttribute(sub_n, "HotReplacable", "%i",  WORD(data + 0x0E) & (1 << 0) ? 1 : 0);

                if(h->length < 0x16) {
                        sub_n = NULL;
                        break;
                }

                if(WORD(data + 0x10) != 0xFFFF) {
                        dmixml_AddTextChild(sub_n, "ProbeHandle", "0x%04x", WORD(data + 0x10));
                }

                if(WORD(data + 0x12) != 0xFFFF) {
                        dmixml_AddTextChild(sect_n, "CoolingDeviceHandle", "0x%04x", WORD(data + 0x12));
                }

                if(WORD(data + 0x14) != 0xFFFF) {
                        dmixml_AddTextChild(sub_n, "CurrentProbeHandle", "0x%04x", WORD(data + 0x14));
                }

                sub_n = NULL;
                break;

        case 40:               /* 3.3.41 Additional Information */
                dmixml_AddAttribute(sect_n, "subtype", "AdditionalInformation");

                if(h->length < 0x0B) {
                        break;
                }

                dmi_additional_info(sect_n, h);
                break;

        case 41:               /* 3.3.42 Onboard Device Extended Information */
                dmixml_AddAttribute(sect_n, "subtype", "OnboardDeviceExtendedInformation");

                if(h->length < 0x0B) {
                        break;
                }

                dmixml_AddDMIstring(sect_n, "ReferenceDesignation", h, data[0x04]);

                sub_n = xmlNewChild(sect_n, NULL, (xmlChar *) "OnboardDevice", NULL);
                dmi_on_board_devices_type(sub_n, data[0x05] & 0x7F);

                dmixml_AddAttribute(sub_n, "Enabled", "%i", data[0x05] & 0x80 ? 1 : 0);
                dmixml_AddAttribute(sub_n, "TypeInstance", "%ld", data[0x06]);
                dmi_slot_segment_bus_func(sub_n, WORD(data + 0x07), data[0x09], data[0x0A]);
                sub_n = NULL;
                break;

        case 126:              /* 3.3.43 Inactive */
        case 127:              /* 3.3.44 End Of Table */
                break;

        default:
                if(dmi_decode_oem(h))
                        break;

                sect_n = xmlNewChild(sect_n, NULL, (xmlChar *) "DMIdump", NULL);
                assert( sect_n != NULL );

                dmixml_AddAttribute(sect_n, "Type", "%i", h->type);
                dmixml_AddAttribute(sect_n, "InfoType", "%s", h->type >= 128 ? "OEM-specific" : "Unknown");

                dmi_dump(sect_n, h);
                break;
        }
        return sect_n;
}

void to_dmi_header(struct dmi_header *h, u8 * data)
{
        h->type = data[0];
        h->length = data[1];
        h->handle = WORD(data + 2);
        h->data = data;
}


dmi_codes_major *find_dmiMajor(const struct dmi_header *h)
{
        int i = 0;

        for( i = 0; dmiCodesMajor[i].id != NULL; i++ ) {
                if( h->type == dmiCodesMajor[i].code ) {
                        return (dmi_codes_major *)&dmiCodesMajor[i];
                }
        }
        return NULL;
}

static void dmi_table(Log_t *logp, int type, u32 base, u16 len, u16 num, u16 ver, const char *devmem, xmlNode *xmlnode)
{
        u8 *buf;
        u8 *data;
        int i = 0;
        int decoding_done = 0;

        if( type == -1 ) {
                xmlNode *info_n = NULL;

                info_n = dmixml_AddTextChild(xmlnode, "DMIinfo", "%i structures occupying %i bytes", num, len);
                dmixml_AddAttribute(info_n, "dmi_structures", "%i", num);
                dmixml_AddAttribute(info_n, "dmi_size", "%i", len);

                /* TODO DUMP
                 * if (!(opt->flags & FLAG_FROM_DUMP))
                 * dmixml_AddAttribute(info_n, "dmi_table_base", "0x%08x", base);
                 */

                dmixml_AddAttribute(info_n, "dmi_table_base", "0x%08x", base);
                info_n = NULL;
        }

        if((buf = mem_chunk(logp, base, len, devmem)) == NULL) {
                log_append(logp, LOGFL_NODUPS, LOG_WARNING, "Table is unreachable, sorry."
#ifndef USE_MMAP
                        "Try compiling dmidecode with -DUSE_MMAP."
#endif
                        );
                return;
        }

        data = buf;
        while(i < num && data + 4 <= buf + len) {       /* 4 is the length of an SMBIOS structure header */

                u8 *next;
                struct dmi_header h;

                to_dmi_header(&h, data);

                /*
                 ** If a short entry is found (less than 4 bytes), not only it
                 ** is invalid, but we cannot reliably locate the next entry.
                 ** Better stop at this point, and let the user know his/her
                 ** table is broken.
                 */
                if(h.length < 4) {
                        log_append(logp, LOGFL_NORMAL, LOG_WARNING,
				   "Invalid entry length (%i) for type %i. DMI table is broken! Stop.",
				   (unsigned int)h.length, type);
                        break;
                }

                /* In quiet mode (FLAG_QUIET - removed for python-dmidecode all together),
                 * stop decoding at end of table marker
                 */

                /* assign vendor for vendor-specific decodes later */
                if(h.type == 0 && h.length >= 5) {
                        dmi_set_vendor(&h);
                }

                /* look for the next handle */
                next = data + h.length;
                while(next - buf + 1 < len && (next[0] != 0 || next[1] != 0)) {
                        next++;
                }
                next += 2;

                xmlNode *handle_n = NULL;
                if( h.type == type ) {
                        if(next - buf <= len) {
                                dmi_codes_major *dmiMajor = NULL;
                                /* TODO: ...
                                 * if(opt->flags & FLAG_DUMP) {
                                 * PyDict_SetItem(hDict, PyString_FromString("lookup"), dmi_dump(&h));
                                 * } */

                                dmiMajor = find_dmiMajor(&h);
                                if( dmiMajor != NULL ) {
                                        handle_n = dmi_decode(xmlnode, dmiMajor, &h, ver);
                                } else {
                                        handle_n = xmlNewChild(xmlnode, NULL, (xmlChar *) "DMImessage", NULL);
                                        assert( handle_n != NULL );
                                        dmixml_AddTextContent(handle_n, "DMI/SMBIOS type 0x%02X is not supported "
                                                              "by dmidecode", h.type);
                                        dmixml_AddAttribute(handle_n, "type", "%i", h.type);
                                        dmixml_AddAttribute(handle_n, "unsupported", "1");
                                }
                        } else {
                                handle_n = xmlNewChild(xmlnode, NULL, (xmlChar *) "DMIerror", NULL);
                                assert( handle_n != NULL );
                                dmixml_AddTextContent(handle_n, "Data is truncated %i bytes on type 0x%02X",
                                                      (next - buf - len), h.type);
                                dmixml_AddAttribute(handle_n, "type", "%i", h.type);
                                dmixml_AddAttribute(handle_n, "truncated", "1");
                                dmixml_AddAttribute(handle_n, "length", "%i", (next - buf));
                                dmixml_AddAttribute(handle_n, "expected_length", "%i", len);

                                log_append(logp, LOGFL_NODUPS, LOG_WARNING,
                                           "DMI/SMBIOS type 0x%02X is exceeding the expected buffer "
                                           "size by %i bytes.  Will not decode this entry.",
                                           h.type, (next - buf - len));
                        }
                        dmixml_AddAttribute(handle_n, "handle", "0x%04x", h.handle);
                        dmixml_AddAttribute(handle_n, "size", "%d", h.length);
                        decoding_done = 1;
                }
                data = next;
                i++;
        }

        if( decoding_done == 0 ) {
                xmlNode *handle_n = xmlNewChild(xmlnode, NULL, (xmlChar *) "DMImessage", NULL);
                assert( handle_n != NULL );
                dmixml_AddTextContent(handle_n, "DMI/SMBIOS type 0x%02X is not found on this hardware",
                                      type);
                dmixml_AddAttribute(handle_n, "type", "%i", type);
                dmixml_AddAttribute(handle_n, "notfound", "1");
        }

        if(i != num) {
                log_append(logp, LOGFL_NODUPS, LOG_WARNING,
                           "Wrong DMI structures count: %d announced, only %d decoded.", num, i);
        }

        if(data - buf != len) {
                log_append(logp, LOGFL_NODUPS, LOG_WARNING,
                        "Wrong DMI structures length: %d bytes announced, structures occupy %d bytes.",
                        len, (unsigned int)(data - buf));
        }
        free(buf);
}

int _smbios_decode_check(u8 * buf)
{
        int check = (!checksum(buf, buf[0x05]) || memcmp(buf + 0x10, "_DMI_", 5) != 0 ||
                     !checksum(buf + 0x10, 0x0F)) ? 0 : 1;
        return check;
}

xmlNode *smbios_decode_get_version(u8 * buf, const char *devmem)
{
        int check = _smbios_decode_check(buf);

        xmlNode *data_n = xmlNewNode(NULL, (xmlChar *) "DMIversion");
        assert( data_n != NULL );

        dmixml_AddAttribute(data_n, "type", "SMBIOS");

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
                if(_m || _M) {
                        dmixml_AddTextContent(data_n, "SMBIOS %i.%i present (Version fixup 2.%d -> 2.%d)",
                                              ver >> 8, ver & 0xFF, _m, _M);
                        dmixml_AddAttribute(data_n, "version", "%i.%i", ver >> 8, ver & 0xFF);
                        dmixml_AddAttribute(data_n, "fixup_version", "2.%d_2.%d", _m, _M);
                } else {
                        dmixml_AddTextContent(data_n, "SMBIOS %i.%i present", ver >> 8, ver & 0xFF);
                        dmixml_AddAttribute(data_n, "version", "%i.%i", ver >> 8, ver & 0xFF);
                }
        } else if(check == 0) {
                dmixml_AddTextContent(data_n, "No SMBIOS nor DMI entry point found");
                dmixml_AddAttribute(data_n, "unknown", "1");
        }
        return data_n;
}

int smbios_decode(Log_t *logp, int type, u8 *buf, const char *devmem, xmlNode *xmlnode)
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
                dmi_table(logp, type, DWORD(buf + 0x18), WORD(buf + 0x16), WORD(buf + 0x1C), ver, devmem,
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

xmlNode *legacy_decode_get_version(u8 * buf, const char *devmem)
{
        int check = _legacy_decode_check(buf);

        xmlNode *data_n = xmlNewNode(NULL, (xmlChar *) "DMIversion");
        assert( data_n != NULL );

        dmixml_AddAttribute(data_n, "type", "legacy");

        if(check == 1) {
                dmixml_AddTextContent(data_n, "Legacy DMI %i.%i present",
                                      buf[0x0E] >> 4, buf[0x0E] & 0x0F);
                dmixml_AddAttribute(data_n, "version", "%i.%i",
                                    buf[0x0E] >> 4, buf[0x0E] & 0x0F);
        } else if(check == 0) {
                dmixml_AddTextContent(data_n, "No SMBIOS nor DMI entry point found");
                dmixml_AddAttribute(data_n, "unknown", "1");
        }

        return data_n;
}

int legacy_decode(Log_t *logp, int type, u8 *buf, const char *devmem, xmlNode *xmlnode)
{
        int check = _legacy_decode_check(buf);

        if(check == 1)
                dmi_table(logp, type, DWORD(buf + 0x08), WORD(buf + 0x06), WORD(buf + 0x0C),
                          ((buf[0x0E] & 0xF0) << 4) + (buf[0x0E] & 0x0F), devmem, xmlnode);
        return check;
}

