/*
 * DMI Decode
 *
 *   (C) 2000-2002 Alan Cox <alan@redhat.com>
 *   (C) 2002-2007 Jean Delvare <khali@linux-fr.org>
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
 * Management BIOS Reference Specification, Version 2.5" document,
 * available from http://www.dmtf.org/standards/smbios/.
 *
 * Note to contributors:
 * Please reference every value you add or modify, especially if the
 * information does not come from the above mentioned specification.
 *
 * Additional references:
 *  - Intel AP-485 revision 31
 *    "Intel Processor Identification and the CPUID Instruction"
 *    http://developer.intel.com/design/xeon/applnots/241618.htm
 *  - DMTF Master MIF version 040707
 *    "DMTF approved standard groups"
 *    http://www.dmtf.org/standards/dmi
 *  - IPMI 2.0 revision 1.0
 *    "Intelligent Platform Management Interface Specification"
 *    http://developer.intel.com/design/servers/ipmi/spec.htm
 *  - AMD publication #25481 revision 2.18
 *    "CPUID Specification"
 *    http://www.amd.com/us-en/assets/content_type/white_papers_and_tech_docs/25481.pdf
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

#include "version.h"
#include "config.h"
#include "types.h"
#include "util.h"
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

static PyObject *dmi_string_py(const struct dmi_header *dm, u8 s) {
  char *bp=(char *)dm->data;
  size_t i, len;

  PyObject *data;

  if(s==0) data = PyString_FromString("Not Specified");
  else {
    bp += dm->length;
    while(s>1 && *bp) { bp += strlen(bp); bp++; s--; }

    if(!*bp) data = BAD_INDEX;
    else {
      /* ASCII filtering */
      len=strlen(bp);
      for(i=0; i<len; i++)
        if(bp[i]<32 || bp[i]==127)
          bp[i]='.';
      data = PyString_FromString(bp);
    }
  }
  return data;
}

const char *dmi_string(const struct dmi_header *dm, u8 s) {
  char *bp = (char *)dm->data;
  size_t i, len;

  if(s == 0) return "Not Specified";

  bp += dm->length;
  while(s>1 && *bp) {
    bp+=strlen(bp);
    bp++;
    s--;
  }

  if(!*bp) return bad_index;

  /* ASCII filtering */
  len = strlen(bp);
  for(i=0; i<len; i++)
    if(bp[i]<32 || bp[i]==127)
      bp[i]='.';

  return bp;
}




static const char *dmi_smbios_structure_type(u8 code) {
  static const char *type[] = {
    "BIOS", /* 0 */
    "System",
    "Base Board",
    "Chassis",
    "Processor",
    "Memory Controller",
    "Memory Module",
    "Cache",
    "Port Connector",
    "System Slots",
    "On Board Devices",
    "OEM Strings",
    "System Configuration Options",
    "BIOS Language",
    "Group Associations",
    "System Event Log",
    "Physical Memory Array",
    "Memory Device",
    "32-bit Memory Error",
    "Memory Array Mapped Address",
    "Memory Device Mapped Address",
    "Built-in Pointing Device",
    "Portable Battery",
    "System Reset",
    "Hardware Security",
    "System Power Controls",
    "Voltage Probe",
    "Cooling Device",
    "Temperature Probe",
    "Electrical Current Probe",
    "Out-of-band Remote Access",
    "Boot Integrity Services",
    "System Boot",
    "64-bit Memory Error",
    "Management Device",
    "Management Device Component",
    "Management Device Threshold Data",
    "Memory Channel",
    "IPMI Device",
    "Power Supply" /* 39 */
  };

  if(code<=39) return(type[code]);
  return out_of_spec;
}

static int dmi_bcd_range(u8 value, u8 low, u8 high) {
  if(value>0x99 || (value&0x0F)>0x09) return 0;
  if(value<low || value>high) return 0;
  return 1;
}

PyObject* dmi_dump(struct dmi_header *h) {
  int row, i;
  const char *s;

  PyObject *data = PyDict_New();
  PyObject *data1 = PyList_New(0);
  for(row=0; row<((h->length-1)>>4)+1; row++) {
    for(i=0; i<16 && i<h->length-(row<<4); i++)
      PyList_Append(data1, PyString_FromFormat("0x%02x", (h->data)[(row<<4)+i]));
  }
  PyDict_SetItemString(data, "Header and Data", data1);

  if((h->data)[h->length] || (h->data)[h->length+1]) {
    i=1;
    PyObject *data2 = PyList_New(0);
    while((s=dmi_string(h, i++))!=bad_index) {
      //. FIXME: DUMP
      /*
      if(opt.flags & FLAG_DUMP) {
        int j, l = strlen(s)+1;
        for(row=0; row<((l-1)>>4)+1; row++) {
          for(j=0; j<16 && j<l-(row<<4); j++)
            PyList_Append(data1, PyString_FromFormat("0x%02x", s[(row<<4)+j]));
        }
        fprintf(stderr, "\"%s\"|", s);
      }
      else fprintf(stderr, "%s|", s);
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

static PyObject* dmi_bios_runtime_size(u32 code) {
  if(code&0x000003FF) return PyString_FromFormat("%i bytes", code);
  else return PyString_FromFormat("%i kB", code>>10);
}

/* 3.3.1.1 */
static PyObject* dmi_bios_characteristics(u64 code) {
  static const char *characteristics[] = {
    "BIOS characteristics not supported", /* 3 */
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
    "NEC PC-98" /* 31 */
  };

  PyObject *data;
  if(code.l&(1<<3)) {
    data = PyString_FromString(characteristics[0]);
  } else {
    int i;
    data = PyDict_New();
    for(i=4; i<=31; i++)
      PyDict_SetItemString(data, characteristics[i-3], code.l&(1<<i)?Py_True:Py_False);
  }
  return data;
}

/* 3.3.1.2.1 */
static PyObject* dmi_bios_characteristics_x1(u8 code) {
  static const char *characteristics[] = {
    "ACPI", /* 0 */
    "USB legacy",
    "AGP",
    "I2O boot",
    "LS-120 boot",
    "ATAPI Zip drive boot",
    "IEEE 1394 boot",
    "Smart battery" /* 7 */
  };

  int i;
  PyObject *data = PyDict_New();
  for(i=0; i<=7; i++)
    PyDict_SetItemString(data, characteristics[i], code&(1<<i)?Py_True:Py_False);
  return data;

}

/* 3.3.1.2.2 */
static PyObject* dmi_bios_characteristics_x2(u8 code) {
  static const char *characteristics[]={
    "BIOS boot specification", /* 0 */
    "Function key-initiated network boot",
    "Targeted content distribution" /* 2 */
  };

  int i;
  PyObject *data = PyDict_New();
  for(i=0; i<=2; i++)
    PyDict_SetItemString(data, characteristics[i], code&(1<<i)?Py_True:Py_False);
  return data;
}

/*******************************************************************************
** 3.3.2 System Information (Type 1)
*/

PyObject *dmi_system_uuid_py(const u8 *p, u16 ver) {
  int only0xFF=1, only0x00=1;
  int i;

  for(i=0; i<16 && (only0x00 || only0xFF); i++) {
    if(p[i]!=0x00) only0x00=0;
    if(p[i]!=0xFF) only0xFF=0;
  }

  if(only0xFF)
    return PyString_FromString("Not Present");

  if(only0x00)
    return PyString_FromString("Not Settable");

  /*
    * As off version 2.6 of the SMBIOS specification, the first 3
    * fields of the UUID are supposed to be encoded on little-endian.
    * The specification says that this is the defacto standard,
    * however I've seen systems following RFC 4122 instead and use
    * network byte order, so I am reluctant to apply the byte-swapping
    * for older versions.
    */
  if (ver >= 0x0206)
    return PyString_FromFormat("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
      p[3], p[2], p[1], p[0], p[5], p[4], p[7], p[6],
      p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]
    );
  else
    return PyString_FromFormat("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
      p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]
    );
}

/* 3.3.2.1 */
static PyObject *dmi_system_wake_up_type(u8 code) {
  static const char *type[]={
    "Reserved", /* 0x00 */
    "Other",
    "Unknown",
    "APM Timer",
    "Modem Ring",
    "LAN Remote",
    "Power Switch",
    "PCI PME#",
    "AC Power Restored" /* 0x08 */
  };

  if(code<=0x08) return PyString_FromString(type[code]);
  return OUT_OF_SPEC;
}

/*******************************************************************************
** 3.3.3 Base Board Information (Type 2)
*/

/* 3.3.3.1 */
static PyObject *dmi_base_board_features(u8 code) {
  static const char *features[] = {
    "Board is a hosting board", /* 0 */
    "Board requires at least one daughter board",
    "Board is removable",
    "Board is replaceable",
    "Board is hot swappable" /* 4 */
  };

  PyObject *data;
  if((code&0x1F)==0) data = Py_None;
  else {
    int i;
    data = PyList_New(5);
    for(i=0; i<=4; i++) {
      if(code&(1<<i)) PyList_SET_ITEM(data, i, PyString_FromString(features[i]));
      else PyList_SET_ITEM(data, i, Py_None);
    }
  }
  return data;
}

static PyObject *dmi_base_board_type(u8 code) {
  /* 3.3.3.2 */
  static const char *type[] = {
    "Unknown", /* 0x01 */
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
    "Interconnect Board" /* 0x0D */
  };

  if(code>=0x01 && code<=0x0D)
    return PyString_FromString(type[code-0x01]);
  return OUT_OF_SPEC;
}

static PyObject *dmi_base_board_handles(u8 count, const u8 *p) {
  int i;

  PyObject *dict = PyDict_New();
  PyObject *list = PyList_New(count);

  for(i=0; i<count; i++)
    PyList_SET_ITEM(list, i, PyString_FromFormat("0x%04x", WORD(p+sizeof(u16)*i)));

  PyDict_SetItemString(dict, "Contained Object Handles", list);
  Py_DECREF(list);

  return dict;
}

/*******************************************************************************
** 3.3.4 Chassis Information (Type 3)
*/

/* 3.3.4.1 */
const char *dmi_chassis_type(u8 code) {
  static const char *type[] = {
    "Other", /* 0x01 */
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
    "Main Server Chassis", /* master.mif says System */
    "Expansion Chassis",
    "Sub Chassis",
    "Bus Expansion Chassis",
    "Peripheral Chassis",
    "RAID Chassis",
    "Rack Mount Chassis",
    "Sealed-case PC",
    "Multi-system",
    "CompactPCI",
    "AdvancedTCA", /* 0x1B */
    "Blade",
    "Blade Enclosing" /* 0x1D */
  };

  if(code>=0x01 && code<=0x1B)
    return type[code-0x01];
  return out_of_spec;
}

static PyObject *dmi_chassis_type_py(u8 code) {
  return PyString_FromString(dmi_chassis_type(code));
}

static PyObject *dmi_chassis_lock(u8 code) {
  static const char *lock[] = {
    "Not Present", /* 0x00 */
    "Present" /* 0x01 */
  };

  return PyString_FromString(lock[code]);
}

/* 3.3.4.2 */
static PyObject *dmi_chassis_state(u8 code) {
  static const char *state[]={
    "Other", /* 0x01 */
    "Unknown",
    "Safe", /* master.mif says OK */
    "Warning",
    "Critical",
    "Non-recoverable" /* 0x06 */
  };

  if(code>=0x01 && code<=0x06)
    return PyString_FromString(state[code-0x01]);
  return OUT_OF_SPEC;
}

/* 3.3.4.3 */
static const char *dmi_chassis_security_status(u8 code) {
  static const char *status[]={
    "Other", /* 0x01 */
    "Unknown",
    "None",
    "External Interface Locked Out",
    "External Interface Enabled" /* 0x05 */
  };

  if(code>=0x01 && code<=0x05)
    return(status[code-0x01]);
  return out_of_spec;
}

static PyObject *dmi_chassis_height(u8 code) {
  if(code==0x00) return PyString_FromString("Unspecified");
  else return PyString_FromFormat("%i U", code);
}

static PyObject *dmi_chassis_power_cords(u8 code) {
  if(code==0x00) return PyString_FromString("Unspecified");
  else return PyString_FromFormat("%i", code);
}

static PyObject *dmi_chassis_elements(u8 count, u8 len, const u8 *p) {
  int i;

  PyObject *data = PyDict_New();
  PyDict_SetItemString(data, "Contained Elements", PyInt_FromLong(count));

  PyObject *_key, *_val;
  for(i=0; i<count; i++) {
    if(len>=0x03) {

      _key = PyString_FromFormat("%s",
        p[i*len]&0x80?
        dmi_smbios_structure_type(p[i*len]&0x7F):
        PyString_AS_STRING(dmi_base_board_type(p[i*len]&0x7F))
      );

      if (p[1+i*len]==p[2+i*len]) _val = PyString_FromFormat("%i", p[1+i*len]);
      else _val = PyString_FromFormat("%i-%i", p[1+i*len], p[2+i*len]);

      PyDict_SetItem(data, _key, _val);

      Py_DECREF(_key);
      Py_DECREF(_val);
    }
  }

  return data;
}

/*******************************************************************************
** 3.3.5 Processor Information (Type 4)
*/

static PyObject *dmi_processor_type(u8 code) {
  /* 3.3.5.1 */
  static const char *type[]={
    "Other", /* 0x01 */
    "Unknown",
    "Central Processor",
    "Math Processor",
    "DSP Processor",
    "Video Processor" /* 0x06 */
  };

  if(code>=0x01 && code<=0x06) return PyString_FromString(type[code-0x01]);
  return OUT_OF_SPEC;
}

static const char *dmi_processor_family(u16 code) {
  unsigned int i;

  /* 3.3.5.2 */
  static struct {
    int value;
    const char *name;
  } family2[] = {
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

    { 0x90, "PA-RISC" },
    { 0x91, "PA-RISC 8500" },
    { 0x92, "PA-RISC 8000" },
    { 0x93, "PA-RISC 7300LC" },
    { 0x94, "PA-RISC 7200" },
    { 0x95, "PA-RISC 7100LC" },
    { 0x96, "PA-RISC 7100" },

    { 0xA0, "V30" },

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

    { 0xBF, "Core 2 Duo" },

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
  };

  for(i=0; i<ARRAY_SIZE(family2); i++)
    if (family2[i].value == code)
      return family2[i].name;

  return out_of_spec;
}
static PyObject *dmi_processor_family_py(u16 code) {
  return PyString_FromString(dmi_processor_family(code));
}

static PyObject *dmi_processor_id(u8 type, const u8 *p, const char *version) {
  PyObject *data = PyDict_New();

  /* Intel AP-485 revision 31, table 3-4 */
  static const char *flags[32]={
    "FPU (Floating-point unit on-chip)", /* 0 */
    "VME (Virtual mode extension)",
    "DE (Debugging extension)",
    "PSE (Page size extension)",
    "TSC (Time stamp counter)",
    "MSR (Model specific registers)",
    "PAE (Physical address extension)",
    "MCE (Machine check exception)",
    "CX8 (CMPXCHG8 instruction supported)",
    "APIC (On-chip APIC hardware supported)",
    NULL, /* 10 */
    "SEP (Fast system call)",
    "MTRR (Memory type range registers)",
    "PGE (Page global enable)",
    "MCA (Machine check architecture)",
    "CMOV (Conditional move instruction supported)",
    "PAT (Page attribute table)",
    "PSE-36 (36-bit page size extension)",
    "PSN (Processor serial number present and enabled)",
    "CLFSH (CLFLUSH instruction supported)",
    NULL, /* 20 */
    "DS (Debug store)",
    "ACPI (ACPI supported)",
    "MMX (MMX technology supported)",
    "FXSR (Fast floating-point save and restore)",
    "SSE (Streaming SIMD extensions)",
    "SSE2 (Streaming SIMD extensions 2)",
    "SS (Self-snoop)",
    "HTT (Hyper-threading technology)",
    "TM (Thermal monitor supported)",
    "IA64 (IA64 capabilities)",
    "PBE (Pending break enabled)" /* 31 */
  };
  /*
  ** Extra flags are now returned in the ECX register when one calls
  ** the CPUID instruction. Their meaning is explained in table 3-5, but
  ** DMI doesn't support this yet.
  */
  u32 eax, edx;
  int sig=0;

  /*
  ** This might help learn about new processors supporting the
  ** CPUID instruction or another form of identification.
  */

  //. TODO: PyString_FromFormat does not support %x (yet?)...
  PyDict_SetItemString(data, "ID",
    PyString_FromFormat("%02x %02x %02x %02x %02x %02x %02x %02x",
      p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]
    )
  );

  if(type==0x05) /* 80386 */ {
    u16 dx=WORD(p);
    /*
    ** 80386 have a different signature.
    */
    PyDict_SetItemString(data, "Signature",
      PyString_FromFormat(
        "Type %i, Family %i, Major Stepping %i, Minor Stepping %i",
        dx>>12, (dx>>8)&0xF, (dx>>4)&0xF, dx&0xF
      )
    );
    return data;
  }

  if(type==0x06) /* 80486 */ {
    u16 dx=WORD(p);
    /*
    ** Not all 80486 CPU support the CPUID instruction, we have to find
    ** wether the one we have here does or not. Note that this trick
    ** works only because we know that 80486 must be little-endian.
    */
    if((dx&0x0F00)==0x0400
    &&((dx&0x00F0)==0x0040 || (dx&0x00F0)>=0x0070)
    &&((dx&0x000F)>=0x0003)) sig=1;
    else {
      PyDict_SetItemString(data, "Signature",
        PyString_FromFormat(
          "Type %i, Family %i, Model %i, Stepping %i",
          (dx>>12)&0x3, (dx>>8)&0xF, (dx>>4)&0xF, dx&0xF
        )
      );
      return data;
    }
  } else if((type>=0x0B && type<=0x13) /* Intel, Cyrix */
    || (type>=0xB0 && type<=0xB3) /* Intel */
    || type==0xB5 /* Intel */
    || (type>=0xB9 && type<=0xBC)) /* Intel */
    sig=1;
  else if((type>=0x18 && type<=0x1D) /* AMD */
    || type==0x1F /* AMD */
    || (type>=0xB6 && type<=0xB7) /* AMD */
    || (type>=0x83 && type<=0x88)) /* AMD */
    sig=2;
  else if(type==0x01 || type==0x02) {
    /*
    ** Some X86-class CPU have family "Other" or "Unknown". In this case,
    ** we use the version string to determine if they are known to
    ** support the CPUID instruction.
    */
    if(strncmp(version, "Pentium III MMX", 15)==0) sig=1;
    else if(strncmp(version, "AMD Athlon(TM)", 14)==0 || strncmp(version, "AMD Opteron(tm)", 15)==0) sig=2;
    else return data;
  } else /* not X86-class */ return data;

  eax=DWORD(p);
  edx=DWORD(p+4);
  switch(sig) {
    case 1: /* Intel */
      PyDict_SetItemString(data, "Signature",
        PyString_FromFormat(
          "Type %i, Family %i, Model %i, Stepping %i",
          (eax>>12)&0x3, ((eax>>20)&0xFF)+((eax>>8)&0x0F),
          ((eax>>12)&0xF0)+((eax>>4)&0x0F), eax&0xF
        )
      );
      break;
    case 2: /* AMD */
      PyDict_SetItemString(data, "Signature",
        PyString_FromFormat(
          "Family %i, Model %i, Stepping %i",
          ((eax>>8)&0xF)+(((eax>>8)&0xF)==0xF?(eax>>20)&0xFF:0),
          ((eax>>4)&0xF)|(((eax>>8)&0xF)==0xF?(eax>>12)&0xF0:0),
          eax&0xF
        )
      );
      break;
  }

  edx=DWORD(p+4);
  if((edx&0xFFEFFBFF)==0) PyDict_SetItemString(data, "Flags", Py_None);
  else {
    int i;
    PyObject *subdata = PyDict_New();
    for(i=0; i<=31; i++)
      if(flags[i]!=NULL)
        PyDict_SetItemString(subdata, flags[i], (edx&(1<<i))?Py_True:Py_False);
    PyDict_SetItemString(data, "Flags", subdata);
    Py_DECREF(subdata);
  }

  return data;
}

/* 3.3.5.4 */
static PyObject *dmi_processor_voltage(u8 code) {
  static const char *voltage[]={
    "5.0 V", /* 0 */
    "3.3 V",
    "2.9 V" /* 2 */
  };
  int i;

  PyObject *data;
  if(code&0x80) data = PyString_FromFormat("%.1f V", (float)(code&0x7f)/10);
  else {
    data = PyDict_New();
    for(i=0; i<=2; i++)
      PyDict_SetItemString(data, voltage[i], (code&(1<<i)?Py_True:Py_False));
    if(code==0x00)
      PyDict_SetItemString(data, "VOLTAGE", PyString_FromString("Unknown"));
  }
  return data;
}

int dmi_processor_frequency(const u8 *p) {
  u16 code = WORD(p);

  if(code) return code; //. Value measured in MHz
  else return -1; //. Unknown
}
static PyObject *dmi_processor_frequency_py(const u8 *p) {
  return PyInt_FromLong(dmi_processor_frequency(p));
}

static const char *dmi_processor_status(u8 code) {
  static const char *status[] = {
    "Unknown", /* 0x00 */
    "Enabled",
    "Disabled By User",
    "Disabled By BIOS",
    "Idle", /* 0x04 */
    "Other" /* 0x07 */
  };

  if(code<=0x04) return status[code];
  if(code==0x07) return status[0x05];
  return out_of_spec;
}

static PyObject *dmi_processor_upgrade(u8 code) {
  /* 3.3.5.5 */
  static const char *upgrade[]={
    "Other", /* 0x01 */
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
    "Socket LGA775", /* 0x15 */
    "Socket S1",
    "Socket AM2",
    "Socket F (1207)" /* 0x18 */
  };

  if(code>=0x01 && code<=0x15) return PyString_FromString(upgrade[code-0x01]);
  return OUT_OF_SPEC;
}

static PyObject *dmi_processor_cache(u16 code, const char *level, u16 ver) {
  PyObject *data;
  if(code==0xFFFF) {
    if(ver>=0x0203) data = PyString_FromString("Not Provided");
    else data = PyString_FromFormat("No %s Cache", level);
  } else data = PyString_FromFormat("0x%04x", code);
  return data;
}

/* 3.3.5.9 */
static PyObject *dmi_processor_characteristics(u16 code) {
  static const char *characteristics[]={
    "64-bit capable" /* 2 */
  };

  PyObject *data;
  if((code&0x0004)==0) {
    data = Py_None;
  } else {
    data = PyList_New(1);
    int i;
    for(i=2; i<=2; i++)
      if(code&(1<<i))
         PyList_SET_ITEM(data, 0, PyString_FromString(characteristics[i-2]));
  }
  return data;
}

/*******************************************************************************
** 3.3.6 Memory Controller Information (Type 5)
*/

static PyObject *dmi_memory_controller_ed_method(u8 code) {
  /* 3.3.6.1 */
  static const char *method[]={
    "Other", /* 0x01 */
    "Unknown",
    "None",
    "8-bit Parity",
    "32-bit ECC",
    "64-bit ECC",
    "128-bit ECC",
    "CRC" /* 0x08 */
  };

  if(code>=0x01 && code<=0x08) return(PyString_FromString(method[code-0x01]));
  return OUT_OF_SPEC;
}

/* 3.3.6.2 */
static PyObject *dmi_memory_controller_ec_capabilities(u8 code) {
  static const char *capabilities[]={
    "Other", /* 0 */
    "Unknown",
    "None",
    "Single-bit Error Correcting",
    "Double-bit Error Correcting",
    "Error Scrubbing" /* 5 */
  };

  PyObject *data = Py_None;
  if((code&0x3F)==0) return Py_None;
  else {
    int i;

    data = PyList_New(6);
    for(i=0; i<=5; i++)
      if(code&(1<<i))
        PyList_SET_ITEM(data, i, PyString_FromString(capabilities[i]));
      else
        PyList_SET_ITEM(data, i, Py_None);
  }
  return data;
}

static PyObject *dmi_memory_controller_interleave(u8 code) {
  /* 3.3.6.3 */
  static const char *interleave[]={
    "Other", /* 0x01 */
    "Unknown",
    "One-way Interleave",
    "Two-way Interleave",
    "Four-way Interleave",
    "Eight-way Interleave",
    "Sixteen-way Interleave" /* 0x07 */
  };

  if(code>=0x01 && code<=0x07) return PyString_FromString(interleave[code-0x01]);
  return OUT_OF_SPEC;
}

/* 3.3.6.4 */
static PyObject *dmi_memory_controller_speeds(u16 code) {
  const char *speeds[]={
    "Other", /* 0 */
    "Unknown",
    "70 ns",
    "60 ns",
    "50 ns" /* 4 */
  };

  PyObject *data;
  if((code&0x001F)!=0) data = Py_None;
  else {
    int i;

    data = PyList_New(5);
    for(i=0; i<=4; i++)
      if(code&(1<<i))
        PyList_SET_ITEM(data, i, PyString_FromString(speeds[i]));
      else
        PyList_SET_ITEM(data, i, Py_None);
  }
  return data;
}

static PyObject *dmi_memory_controller_slots(u8 count, const u8 *p) {
  int i;

  PyObject *data = PyList_New(count);
  for(i=0; i<count; i++)
    PyList_SET_ITEM(data, i, PyString_FromFormat("0x%04x:", WORD(p+sizeof(u16)*i)));
  return data;
}

/*******************************************************************************
** 3.3.7 Memory Module Information (Type 6)
*/

/* 3.3.7.1 */
static PyObject *dmi_memory_module_types(u16 code) {
  static const char *types[]={
    "Other", /* 0 */
    "Unknown",
    "Standard",
    "FPM",
    "EDO",
    "Parity",
    "ECC",
    "SIMM",
    "DIMM",
    "Burst EDO",
    "SDRAM" /* 10 */
  };

  PyObject *data;
  if((code&0x07FF)==0) data = Py_None;
  else {
    int i;

    data = PyList_New(11);
    for(i=0; i<=10; i++)
      if(code&(1<<i))
        PyList_SET_ITEM(data, i, PyString_FromString( types[i]));
      else
        PyList_SET_ITEM(data, i, Py_None);
  }
  return data;
}

static PyObject *dmi_memory_module_connections(u8 code) {
  PyObject * data;
  if(code==0xFF) data = Py_None;
  else {
    data = PyList_New(0);
    if((code&0xF0)!=0xF0) PyList_Append(data, PyInt_FromLong(code>>4));
    if((code&0x0F)!=0x0F) PyList_Append(data, PyInt_FromLong(code&0x0F));
  }
  return data;
}

static PyObject *dmi_memory_module_speed(u8 code) {
  if(code==0) return PyString_FromString("Unknown");
  else return PyString_FromFormat("%i ns", code);
}

/* 3.3.7.2 */
static PyObject *dmi_memory_module_size(u8 code) {
  PyObject *data = PyDict_New();
  int check_conn = 1;

  switch(code&0x7F) {
    case 0x7D:
      PyDict_SetItemString(data, "Size", PyString_FromString("Not Determinable"));
      break;
    case 0x7E:
      PyDict_SetItemString(data, "Size", PyString_FromString("Disabled"));
      break;
    case 0x7F:
      PyDict_SetItemString(data, "Size", PyString_FromString("Not Installed"));
      check_conn = 0;
    default:
      PyDict_SetItemString(data, "Size", PyString_FromFormat("%i MB", 1<<(code&0x7F)));
  }

  if(check_conn) {
    if(code&0x80) PyDict_SetItemString(data, "Connection", PyString_FromString("Double-bank"));
    else PyDict_SetItemString(data, "Connection", PyString_FromString("Single-bank"));
  }
  return data;
}

static PyObject *dmi_memory_module_error(u8 code) {
  PyObject *data = NULL;
  if(code&(1<<2)) data = Py_None; //. TODO: sprintf(_, "See Event Log");
  else {
    if((code&0x03)==0) data = Py_True;
    if(code&(1<<0)) data = PyString_FromString("Uncorrectable Errors");
    if(code&(1<<1)) data = PyString_FromString("Correctable Errors");
  }
  return data;
}

/*******************************************************************************
** 3.3.8 Cache Information (Type 7)
*/
static PyObject *dmi_cache_mode(u8 code) {
  static const char *mode[]={
    "Write Through", /* 0x00 */
    "Write Back",
    "Varies With Memory Address",
    "Unknown" /* 0x03 */
  };

  return PyString_FromString(mode[code]);
}

static PyObject *dmi_cache_location(u8 code) {
  static const char *location[4]={
    "Internal", /* 0x00 */
    "External",
    NULL, /* 0x02 */
    "Unknown" /* 0x03 */
  };

  PyObject *data;
  if(location[code]!=NULL) data = PyString_FromString(location[code]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_cache_size(u16 code) {
  PyObject *data;
  if(code&0x8000) data = PyString_FromFormat("%i KB", (code&0x7FFF)<<6);
  else data = PyString_FromFormat("%i KB", code);
  return data;
}

/* 3.3.8.2 */
static PyObject *dmi_cache_types(u16 code) {
  static const char *types[] = {
    "Other", /* 0 */
    "Unknown",
    "Non-burst",
    "Burst",
    "Pipeline Burst",
    "Synchronous",
    "Asynchronous" /* 6 */
  };
  PyObject *data;

  if((code&0x007F)==0) data = Py_None;
  else {
    int i;

    data = PyList_New(7);
    for(i=0; i<=6; i++)
      if(code&(1<<i))
        PyList_SET_ITEM(data, i, PyString_FromString(types[i]));
      else
        PyList_SET_ITEM(data, i, Py_None);
  }
  return data;
}

static PyObject *dmi_cache_ec_type(u8 code) {
  /* 3.3.8.3 */
  static const char *type[]={
    "Other", /* 0x01 */
    "Unknown",
    "None",
    "Parity",
    "Single-bit ECC",
    "Multi-bit ECC" /* 0x06 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x06) data = PyString_FromString(type[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_cache_type(u8 code) {
  /* 3.3.8.4 */
  static const char *type[]={
    "Other", /* 0x01 */
    "Unknown",
    "Instruction",
    "Data",
    "Unified" /* 0x05 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x05) data = PyString_FromString(type[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_cache_associativity(u8 code) {
  /* 3.3.8.5 */
  static const char *type[]={
    "Other", /* 0x01 */
    "Unknown",
    "Direct Mapped",
    "2-way Set-associative",
    "4-way Set-associative",
    "Fully Associative",
    "8-way Set-associative",
    "16-way Set-associative" /* 0x08 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x08) data = PyString_FromString(type[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

/*******************************************************************************
** 3.3.9 Port Connector Information (Type 8)
*/

static PyObject *dmi_port_connector_type(u8 code) {
  /* 3.3.9.2 */
  static const char *type[] = {
    "None", /* 0x00 */
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
       "SAS/SATA Plug Receptacle" /* 0x22 */
  };
  static const char *type_0xA0[]={
    "PC-98", /* 0xA0 */
    "PC-98 Hireso",
    "PC-H98",
    "PC-98 Note",
    "PC-98 Full" /* 0xA4 */
  };

  if(code<=0x22) return PyString_FromString(type[code]);
  if(code>=0xA0 && code<=0xA4) return PyString_FromString(type_0xA0[code-0xA0]);
  if(code==0xFF) return PyString_FromString("Other");
  return OUT_OF_SPEC;
}

static PyObject *dmi_port_type(u8 code) {
  /* 3.3.9.3 */
  static const char *type[] = {
    "None", /* 0x00 */
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
    "SAS" /* 0x21 */
  };
  static const char *type_0xA0[]={
    "8251 Compatible", /* 0xA0 */
    "8251 FIFO Compatible" /* 0xA1 */
  };

  if(code<=0x21) return PyString_FromString(type[code]);
  if(code>=0xA0 && code<=0xA1) return PyString_FromString(type_0xA0[code-0xA0]);
  if(code==0xFF) return PyString_FromString("Other");
  return OUT_OF_SPEC;
}

/*******************************************************************************
** 3.3.10 System Slots (Type 9)
*/

static PyObject *dmi_slot_type(u8 code) {
  /* 3.3.10.1 */
  static const char *type[] = {
    "Other", /* 0x01 */
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
    "AGP 8x" /* 0x13 */
  };
  static const char *type_0xA0[]={
    "PC-98/C20", /* 0xA0 */
    "PC-98/C24",
    "PC-98/E",
    "PC-98/Local Bus",
    "PC-98/Card",
    "PCI Express" /* 0xA5 */
  };

  if(code>=0x01 && code<=0x13) return PyString_FromString(type[code-0x01]);
  if(code>=0xA0 && code<=0xA5) return PyString_FromString(type_0xA0[code-0xA0]);
  return OUT_OF_SPEC;
}

static PyObject *dmi_slot_bus_width(u8 code) {
  /* 3.3.10.2 */
  static const char *width[]={
    "", /* 0x01, "Other" */
    "", /* "Unknown" */
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
    "x32 " /* 0x0E */
  };

  if(code>=0x01 && code<=0x0E) return PyString_FromString(width[code-0x01]);
  return OUT_OF_SPEC;
}

static PyObject *dmi_slot_current_usage(u8 code) {
  /* 3.3.10.3 */
  static const char *usage[]={
    "Other", /* 0x01 */
    "Unknown",
    "Available",
    "In Use" /* 0x04 */
  };

  if(code>=0x01 && code<=0x04) return PyString_FromString(usage[code-0x01]);
  return OUT_OF_SPEC;
}

/* 3.3.1O.4 */
static PyObject *dmi_slot_length(u8 code) {
  static const char *length[]={
    "Other", /* 0x01 */
    "Unknown",
    "Short",
    "Long" /* 0x04 */
  };

  if(code>=0x01 && code<=0x04)
    return PyString_FromString(length[code-0x01]);
  return OUT_OF_SPEC;
}

/* 3.3.10.5 */
static PyObject *dmi_slot_id(u8 code1, u8 code2, u8 type) {
  PyObject *data;
  switch(type) {
    case 0x04: /* MCA */
      data = PyString_FromFormat("%i", code1);
      break;
    case 0x05: /* EISA */
      data = PyString_FromFormat("%i", code1);
      break;
    case 0x06: /* PCI */
    case 0x0E: /* PCI */
    case 0x0F: /* AGP */
    case 0x10: /* AGP */
    case 0x11: /* AGP */
    case 0x12: /* PCI-X */
    case 0x13: /* AGP */
    case 0xA5: /* PCI Express */
      data = PyString_FromFormat("%i", code1);
      break;
    case 0x07: /* PCMCIA */
      data = PyString_FromFormat("Adapter %i, Socket %i", code1, code2);
      break;
    default:
      data = Py_None;
  }
  return data;
}

static PyObject *dmi_slot_characteristics(u8 code1, u8 code2) {
  /* 3.3.10.6 */
  static const char *characteristics1[]={
    "5.0 V is provided", /* 1 */
    "3.3 V is provided",
    "Opening is shared",
    "PC Card-16 is supported",
    "Cardbus is supported",
    "Zoom Video is supported",
    "Modem ring resume is supported" /* 7 */
  };

  /* 3.3.10.7 */
  static const char *characteristics2[]={
    "PME signal is supported", /* 0 */
    "Hot-plug devices are supported",
    "SMBus signal is supported" /* 2 */
  };

  PyObject *data;
  if(code1&(1<<0)) data = PyString_FromString("Unknown");
  else if((code1&0xFE)==0 && (code2&0x07)==0) data = Py_None;
  else {
    int i;

    data = PyList_New(7+3);
    for(i=1; i<=7; i++) {
      if(code1&(1<<i)) PyList_SET_ITEM(data, i-1, PyString_FromString(characteristics1[i-1]));
      else PyList_SET_ITEM(data, i-1, Py_None);
    }
    for(i=0; i<=2; i++) {
      if(code2&(1<<i)) PyList_SET_ITEM(data, 7+i, PyString_FromString(characteristics2[i]));
      else PyList_SET_ITEM(data, 7+i, Py_None);
    }
  }
  return data;
}

/*******************************************************************************
** 3.3.11 On Board Devices Information (Type 10)
*/

static const char *dmi_on_board_devices_type(u8 code) {
  /* 3.3.11.1 */
  static const char *type[]={
    "Other", /* 0x01 */
    "Unknown",
    "Video",
    "SCSI Controller",
    "Ethernet",
    "Token Ring",
    "Sound",
    "PATA Controller",
    "SATA Controller",
    "SAS Controller" /* 0x0A */
  };

  if(code>=0x01 && code<=0x0A) return type[code-0x01];
  return out_of_spec;
}

static PyObject *dmi_on_board_devices(struct dmi_header *h) {
  PyObject *data = NULL;
  u8 *p = h->data+4;
  u8 count = (h->length-0x04)/2;
  int i;

  if((data = PyList_New(count))) {
    PyObject *_pydict;
    PyObject *_val;
    for(i=0; i<count; i++) {
      _pydict = PyDict_New();

      _val = PyString_FromString(dmi_on_board_devices_type(p[2*i]&0x7F));
      PyDict_SetItemString(_pydict, "Type", _val);
      Py_DECREF(_val);

      _val = p[2*i]&0x80?Py_True:Py_False;
      PyDict_SetItemString(_pydict, "Enabled", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, p[2*i+1]);
      PyDict_SetItemString(_pydict, "Description", _val);
      Py_DECREF(_val);

      PyList_SET_ITEM(data, i, _pydict);
    }
  }

  assert(data != NULL);
  Py_INCREF(data);
  return data;
}

/*******************************************************************************
 * 3.3.12 OEM Strings (Type 11)
 */

static PyObject *dmi_oem_strings(struct dmi_header *h) {
  u8 *p=h->data+4;
  u8 count=p[0x00];
  int i;

  PyObject *data = PyDict_New();
  PyObject *val;

  for(i=1; i<=count; i++) {
    val = dmi_string_py(h, i);
    PyDict_SetItem(data, PyInt_FromLong(i), val);
    Py_DECREF(val);
  }

  return data;
}

/*******************************************************************************
** 3.3.13 System Configuration Options (Type 12)
*/

static PyObject *dmi_system_configuration_options(struct dmi_header *h) {
  u8 *p=h->data+4;
  u8 count=p[0x00];
  int i;

  PyObject *data = PyDict_New();
  PyObject *val;
  for(i=1; i<=count; i++) {
    val = dmi_string_py(h, i);
    PyDict_SetItem(data, PyInt_FromLong(i), val);
    Py_DECREF(val);
  }

  return data;
}

/*******************************************************************************
** 3.3.14 BIOS Language Information (Type 13)
*/

static PyObject *dmi_bios_languages(struct dmi_header *h) {
  u8 *p = h->data+4;
  u8 count = p[0x00];
  int i;

  PyObject *data = PyList_New(count + 1);
  for(i=1; i<=count; i++)
    PyList_SET_ITEM(data, i, dmi_string_py(h, i));

  return data;
}

/*******************************************************************************
** 3.3.15 Group Associations (Type 14)
*/

static PyObject *dmi_group_associations_items(u8 count, const u8 *p) {
  int i;

  PyObject *data = PyList_New(count);
  PyObject *val;
  for(i=0; i<count; i++) {
    val = PyString_FromFormat("0x%04x (%s)",
      WORD(p+3*i+1),
      dmi_smbios_structure_type(p[3*i])
    );
    PyList_SET_ITEM(data, i, val);
  }
  return data;
}

/*******************************************************************************
** 3.3.16 System Event Log (Type 15)
*/

static const char *dmi_event_log_method(u8 code) {
  static const char *method[]={
    "Indexed I/O, one 8-bit index port, one 8-bit data port", /* 0x00 */
    "Indexed I/O, two 8-bit index ports, one 8-bit data port",
    "Indexed I/O, one 16-bit index port, one 8-bit data port",
    "Memory-mapped physical 32-bit address",
    "General-purpose non-volatile data functions" /* 0x04 */
  };

  if(code<=0x04) return method[code];
  if(code>=0x80) return "OEM-specific";
  return out_of_spec;
}

static PyObject *dmi_event_log_status_py(u8 code) {
  static const char *valid[]={
    "Invalid", /* 0 */
    "Valid" /* 1 */
  };
  static const char *full[]={
    "Not Full", /* 0 */
    "Full" /* 1 */
  };

  return PyString_FromFormat("%s, %s", valid[(code>>0)&1], full[(code>>1)&1]);
}

static PyObject *dmi_event_log_address_py(u8 method, const u8 *p) {
  /* 3.3.16.3 */
  switch(method) {
    case 0x00:
    case 0x01:
    case 0x02:
      return PyString_FromFormat("Index 0x%04x, Data 0x%04x", WORD(p), WORD(p+2));
      break;
    case 0x03:
      return PyString_FromFormat("0x%08x", DWORD(p));
      break;
    case 0x04:
      return PyString_FromFormat("0x%04x", WORD(p));
      break;
    default:
      return PyString_FromString("Unknown");
  }
}

static const char *dmi_event_log_header_type(u8 code) {
  static const char *type[]={
    "No Header", /* 0x00 */
    "Type 1" /* 0x01 */
  };

  if(code<=0x01) return type[code];
  if(code>=0x80) return "OEM-specific";
  return out_of_spec;
}

static PyObject *dmi_event_log_descriptor_type(u8 code) {
  /* 3.3.16.6.1 */
  static const char *type[]={
    NULL, /* 0x00 */
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
    NULL, /* 0x0F */
    "System limit exceeded",
    "Asynchronous hardware timer expired",
    "System configuration information",
    "Hard disk information",
    "System reconfigured",
    "Uncorrectable CPU-complex error",
    "Log area reset/cleared",
    "System boot" /* 0x17 */
  };

  const char *data;
  if(code<=0x17 && type[code]!=NULL) data = type[code];
  else if(code>=0x80 && code<=0xFE) data = "OEM-specific";
  else if(code==0xFF) data = "End of log";
  else data = out_of_spec;
  return PyString_FromString(data);
}

static PyObject *dmi_event_log_descriptor_format(u8 code) {
  /* 3.3.16.6.2 */
  static const char *format[]={
    "None", /* 0x00 */
    "Handle",
    "Multiple-event",
    "Multiple-event handle",
    "POST results bitmap",
    "System management",
    "Multiple-event system management" /* 0x06 */
  };

  const char *data;
  if(code<=0x06) data = format[code];
  else if(code>=0x80) data = "OEM-specific";
  else data = out_of_spec;
  return PyString_FromString(data);
}

static PyObject *dmi_event_log_descriptors(u8 count, const u8 len, const u8 *p) {
  /* 3.3.16.1 */
  int i;

  PyObject* data;
  data = PyList_New(count);
  for(i=0; i<count; i++) {
    if(len>=0x02) {
      PyObject *subdata = PyDict_New();
      PyDict_SetItemString(subdata, "Descriptor", dmi_event_log_descriptor_type(p[i*len]));
      PyDict_SetItemString(subdata, "Data Format", dmi_event_log_descriptor_format(p[i*len+1]));
      PyList_SET_ITEM(data, i, subdata);
    }
  }
  return data;
}

/*******************************************************************************
** 3.3.17 Physical Memory Array (Type 16)
*/

static PyObject *dmi_memory_array_location(u8 code) {
  /* 3.3.17.1 */
  static const char *location[]={
    "Other", /* 0x01 */
    "Unknown",
    "System Board Or Motherboard",
    "ISA Add-on Card",
    "EISA Add-on Card",
    "PCI Add-on Card",
    "MCA Add-on Card",
    "PCMCIA Add-on Card",
    "Proprietary Add-on Card",
    "NuBus" /* 0x0A, master.mif says 16 */
  };
  static const char *location_0xA0[]={
    "PC-98/C20 Add-on Card", /* 0xA0 */
    "PC-98/C24 Add-on Card",
    "PC-98/E Add-on Card",
    "PC-98/Local Bus Add-on Card",
    "PC-98/Card Slot Add-on Card" /* 0xA4, from master.mif */
  };

  if(code>=0x01 && code<=0x0A) return PyString_FromString(location[code-0x01]);
  if(code>=0xA0 && code<=0xA4) return PyString_FromString(location_0xA0[code-0xA0]);
  return OUT_OF_SPEC;
}

static PyObject *dmi_memory_array_use(u8 code) {
  /* 3.3.17.2 */
  static const char *use[]={
    "Other", /* 0x01 */
    "Unknown",
    "System Memory",
    "Video Memory",
    "Flash Memory",
    "Non-volatile RAM",
    "Cache Memory" /* 0x07 */
  };

  if(code>=0x01 && code<=0x07) return PyString_FromString(use[code-0x01]);
  return OUT_OF_SPEC;
}

static PyObject *dmi_memory_array_ec_type(u8 code) {
  /* 3.3.17.3 */
  static const char *type[]={
    "Other", /* 0x01 */
    "Unknown",
    "None",
    "Parity",
    "Single-bit ECC",
    "Multi-bit ECC",
    "CRC" /* 0x07 */
  };

  if(code>=0x01 && code<=0x07) return PyString_FromString(type[code-0x01]);
  return OUT_OF_SPEC;
}

static PyObject *dmi_memory_array_capacity(u32 code) {
  PyObject *data;
  if(code==0x8000000) data = PyString_FromString("Unknown");
  else {
    if((code&0x000FFFFF)==0) data = PyString_FromFormat("%i GB", code>>20);
    else if((code&0x000003FF)==0) data = PyString_FromFormat("%i MB", code>>10);
    else data = PyString_FromFormat("%i kB", code);
  }
  return data;
}

static PyObject *dmi_memory_array_error_handle(u16 code) {
  PyObject *data;
  if(code==0xFFFE) data = PyString_FromString("Not Provided");
  else if(code==0xFFFF) data = PyString_FromString("No Error");
  else data = PyString_FromFormat("0x%04x", code);
  return data;
}

/*******************************************************************************
** 3.3.18 Memory Device (Type 17)
*/

static PyObject *dmi_memory_device_width(u16 code) {
  /*
  ** If no memory module is present, width may be 0
  */
  PyObject *data;
  if(code==0xFFFF || code==0) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%i bits", code);
  return data;
}

static PyObject *dmi_memory_device_size(u16 code) {
  PyObject *data = NULL;
  if(code==0) data = Py_None; //. No Module Installed
  else if(code==0xFFFF) data = PyString_FromString("Unknown"); //. Unknown
  else {
    //. Keeping this as String rather than Int as it has KB and MB representations...
    if(code&0x8000) data = PyString_FromFormat("%d KB", code&0x7FFF);
    else data = PyString_FromFormat("%d MB", code);
  }
  return data;
}

static PyObject *dmi_memory_device_form_factor(u8 code) {
  /* 3.3.18.1 */
  static const char *form_factor[]={
    "Other", /* 0x01 */
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
    "FB-DIMM" /* 0x0F */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x0F) return data = PyString_FromString(form_factor[code-0x01]);
  return data = OUT_OF_SPEC;
}

static PyObject *dmi_memory_device_set(u8 code) {
  PyObject *data;
  if(code==0) data = Py_None;
  else if(code==0xFF) data = PyString_FromString("Unknown");
  else data = PyInt_FromLong(code);
  return data;
}

static PyObject *dmi_memory_device_type(u8 code) {
  /* 3.3.18.2 */
  static const char *type[]={
    "Other", /* 0x01 */
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
    "DDR2 FB-DIMM" /* 0x14 */
  };

  if(code>=0x01 && code<=0x14) return PyString_FromString(type[code-0x01]);
  return OUT_OF_SPEC;
}

static PyObject *dmi_memory_device_type_detail(u16 code) {
  /* 3.3.18.3 */
  static const char *detail[]={
    "Other", /* 1 */
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
    "Non-Volatile" /* 12 */
  };

  PyObject *data;
  if((code&0x1FFE)==0) data = Py_None;
  else {
    int i;

    data = PyList_New(12);
    for(i=1; i<=12; i++)
      if(code&(1<<i))
        PyList_SET_ITEM(data, i-1, PyString_FromString(detail[i-1]));
      else
        PyList_SET_ITEM(data, i-1, Py_None);
  }
  return data;
}

static PyObject *dmi_memory_device_speed(u16 code) {
  PyObject *data;
  if(code==0) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%i MHz (%.1f ns)", code, (float)1000/code);
  return data;
}

/*******************************************************************************
* 3.3.19 32-bit Memory Error Information (Type 18)
*/

static PyObject *dmi_memory_error_type(u8 code) {
  /* 3.3.19.1 */
  static const char *type[]={
    "Other", /* 0x01 */
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
    "Uncorrectable Error" /* 0x0E */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x0E) data = PyString_FromString(type[code-0x01]);
  data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_memory_error_granularity(u8 code) {
  /* 3.3.19.2 */
  static const char *granularity[]={
    "Other", /* 0x01 */
    "Unknown",
    "Device Level",
    "Memory Partition Level" /* 0x04 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x04) data = PyString_FromString(granularity[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_memory_error_operation(u8 code) {
  /* 3.3.19.3 */
  static const char *operation[]={
    "Other", /* 0x01 */
    "Unknown",
    "Read",
    "Write",
    "Partial Write" /* 0x05 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x05) data = PyString_FromString(operation[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_memory_error_syndrome(u32 code) {
  PyObject *data;
  if(code==0x00000000) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("0x%08x", code);
  return data;
}

static PyObject *dmi_32bit_memory_error_address(u32 code) {
  PyObject *data;
  if(code==0x80000000) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("0x%08x", code);
  return data;
}

/*******************************************************************************
** 3.3.20 Memory Array Mapped Address (Type 19)
*/

static PyObject *dmi_mapped_address_size(u32 code) {
  PyObject *data;
  if(code==0) data = PyString_FromString("Invalid");
  else if((code&0x000FFFFF)==0) data = PyString_FromFormat("%i GB", code>>20);
  else if((code&0x000003FF)==0) data = PyString_FromFormat("%i MB", code>>10);
  else data = PyString_FromFormat("%i kB", code);
  return data;
}

/*******************************************************************************
** 3.3.21 Memory Device Mapped Address (Type 20)
*/

static PyObject *dmi_mapped_address_row_position(u8 code) {
  PyObject *data;
  if(code==0) data = OUT_OF_SPEC;
  else if(code==0xFF) data = PyString_FromString("Unknown");
  else data = PyInt_FromLong(code);
  return data;
}

static PyObject *dmi_mapped_address_interleave_position(u8 code) {
  PyObject *data;
  if(code!=0) {
    data = PyDict_New();
    PyDict_SetItemString(data, "Interleave Position", (code==0xFF)?PyString_FromString("Unknown"):PyInt_FromLong(code));
  } else data = Py_None;
  return data;
}

static PyObject *dmi_mapped_address_interleaved_data_depth(u8 code) {
  PyObject *data;
  if(code!=0) {
    data = PyDict_New();
    PyDict_SetItemString(data, "Interleave Data Depth", (code==0xFF)?PyString_FromString("Unknown"):PyInt_FromLong(code));
  } else data = Py_None;
  return data;
}

/*******************************************************************************
** 3.3.22 Built-in Pointing Device (Type 21)
*/

static PyObject *dmi_pointing_device_type(u8 code) {
  /* 3.3.22.1 */
  static const char *type[]={
    "Other", /* 0x01 */
    "Unknown",
    "Mouse",
    "Track Ball",
    "Track Point",
    "Glide Point",
    "Touch Pad",
    "Touch Screen",
    "Optical Sensor" /* 0x09 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x09) data = PyString_FromString(type[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_pointing_device_interface(u8 code) {
  /* 3.3.22.2 */
  static const char *interface[]={
    "Other", /* 0x01 */
    "Unknown",
    "Serial",
    "PS/2",
    "Infrared",
    "HIP-HIL",
    "Bus Mouse",
    "ADB (Apple Desktop Bus)" /* 0x08 */
  };
  static const char *interface_0xA0[]={
    "Bus Mouse DB-9", /* 0xA0 */
    "Bus Mouse Micro DIN",
    "USB" /* 0xA2 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x08) data = PyString_FromString(interface[code-0x01]);
  else if(code>=0xA0 && code<=0xA2) data = PyString_FromString(interface_0xA0[code-0xA0]);
  else data = OUT_OF_SPEC;
  return data;
}

/*******************************************************************************
** 3.3.23 Portable Battery (Type 22)
*/

static PyObject *dmi_battery_chemistry(u8 code) {
  /* 3.3.23.1 */
  static const char *chemistry[]={
    "Other", /* 0x01 */
    "Unknown",
    "Lead Acid",
    "Nickel Cadmium",
    "Nickel Metal Hydride",
    "Lithium Ion",
    "Zinc Air",
    "Lithium Polymer" /* 0x08 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x08) data = PyString_FromString(chemistry[code-0x01]);
  data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_battery_capacity(u16 code, u8 multiplier) {
  PyObject *data;
  if(code==0) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%i mWh", code*multiplier);
  return data;
}

static PyObject *dmi_battery_voltage(u16 code) {
  PyObject *data;
  if(code==0) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%i mV", code);
  return data;
}

static PyObject *dmi_battery_maximum_error(u8 code) {
  PyObject *data;
  if(code==0xFF) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%i%%", code);
  return data;
}

/*******************************************************************************
** 3.3.24 System Reset (Type 23)
*/

static PyObject *dmi_system_reset_boot_option(u8 code) {
  static const char *option[]={
    "Operating System", /* 0x1 */
    "System Utilities",
    "Do Not Reboot" /* 0x3 */
  };
  PyObject *data;

  if(code>=0x1) data = PyString_FromString(option[code-0x1]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_system_reset_count(u16 code) {
  PyObject *data;
  if(code==0xFFFF) data = PyString_FromString("Unknown");
  else data = PyInt_FromLong(code);
  return data;
}

static PyObject *dmi_system_reset_timer(u16 code) {
  PyObject *data;
  if(code==0xFFFF) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%i min", code);
  return data;
}

/*******************************************************************************
 * 3.3.25 Hardware Security (Type 24)
 */

static PyObject *dmi_hardware_security_status(u8 code) {
  static const char *status[]={
    "Disabled", /* 0x00 */
    "Enabled",
    "Not Implemented",
    "Unknown" /* 0x03 */
  };

  return PyString_FromString(status[code]);
}

/*******************************************************************************
** 3.3.26 System Power Controls (Type 25)
*/

static PyObject *dmi_power_controls_power_on(const u8 *p) {
  /* 3.3.26.1 */
  PyObject *data = PyList_New(5);

  PyList_SET_ITEM(data, 0, dmi_bcd_range(p[0], 0x01, 0x12)?PyString_FromFormat(" %02x", p[0]):PyString_FromString(" *"));
  PyList_SET_ITEM(data, 1, dmi_bcd_range(p[1], 0x01, 0x31)?PyString_FromFormat("-%02x", p[1]):PyString_FromString("-*"));
  PyList_SET_ITEM(data, 2, dmi_bcd_range(p[2], 0x00, 0x23)?PyString_FromFormat(" %02x", p[2]):PyString_FromString(" *"));
  PyList_SET_ITEM(data, 3, dmi_bcd_range(p[3], 0x00, 0x59)?PyString_FromFormat(":%02x", p[3]):PyString_FromString(":*"));
  PyList_SET_ITEM(data, 4, dmi_bcd_range(p[4], 0x00, 0x59)?PyString_FromFormat(":%02x", p[4]):PyString_FromString(":*"));

  return data;
}

/*******************************************************************************
* 3.3.27 Voltage Probe (Type 26)
*/

static PyObject *dmi_voltage_probe_location(u8 code) {
  /* 3.3.27.1 */
  static const char *location[]={
    "Other", /* 0x01 */
    "Unknown",
    "Processor",
    "Disk",
    "Peripheral Bay",
    "System Management Module",
    "Motherboard",
    "Memory Module",
    "Processor Module",
    "Power Unit",
    "Add-in Card" /* 0x0B */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x0B) data = PyString_FromString(location[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_probe_status(u8 code) {
  /* 3.3.27.1 */
  static const char *status[]={
    "Other", /* 0x01 */
    "Unknown",
    "OK",
    "Non-critical",
    "Critical",
    "Non-recoverable" /* 0x06 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x06) data = PyString_FromString(status[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_voltage_probe_value(u16 code) {
  PyObject *data;
  if(code==0x8000) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%.3f V", (float)(i16)code/1000);
  return data;
}

static PyObject *dmi_voltage_probe_resolution(u16 code) {
  PyObject *data;
  if(code==0x8000) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%.1f mV", (float)code/10);
  return data;
}

static PyObject *dmi_probe_accuracy(u16 code) {
  PyObject *data;
  if(code==0x8000) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%.2f%%", (float)code/100);
  return data;
}

/*******************************************************************************
** 3.3.28 Cooling Device (Type 27)
*/

static PyObject *dmi_cooling_device_type(u8 code) {
  /* 3.3.28.1 */
  static const char *type[]={
    "Other", /* 0x01 */
    "Unknown",
    "Fan",
    "Centrifugal Blower",
    "Chip Fan",
    "Cabinet Fan",
    "Power Supply Fan",
    "Heat Pipe",
    "Integrated Refrigeration" /* 0x09 */
  };
  static const char *type_0x10[]={
    "Active Cooling", /* 0x10, master.mif says 32 */
    "Passive Cooling" /* 0x11, master.mif says 33 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x09) data = PyString_FromString(type[code-0x01]);
  else if(code>=0x10 && code<=0x11) data = PyString_FromString(type_0x10[code-0x10]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_cooling_device_speed(u16 code) {
  PyObject *data;
  if(code==0x8000) data = PyString_FromString("Unknown Or Non-rotating");
  else data = PyString_FromFormat("%i rpm", code);
  return data;
}

/*******************************************************************************
** 3.3.29 Temperature Probe (Type 28)
*/

static PyObject *dmi_temperature_probe_location(u8 code) {
  /* 3.3.29.1 */
  static const char *location[]={
    "Other", /* 0x01 */
    "Unknown",
    "Processor",
    "Disk",
    "Peripheral Bay",
    "System Management Module", /* master.mif says SMB Master */
    "Motherboard",
    "Memory Module",
    "Processor Module",
    "Power Unit",
    "Add-in Card",
    "Front Panel Board",
    "Back Panel Board",
    "Power System Board",
    "Drive Back Plane" /* 0x0F */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x0F) data = PyString_FromString(location[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_temperature_probe_value(u16 code) {
  PyObject *data;
  if(code==0x8000) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%.1f deg C", (float)(i16)code/10);
  return data;
}

static PyObject *dmi_temperature_probe_resolution(u16 code) {
  PyObject *data;
  if(code==0x8000) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%.3f deg C", (float)code/1000);
  return data;
}

/*******************************************************************************
** 3.3.30 Electrical Current Probe (Type 29)
*/

static PyObject *dmi_current_probe_value(u16 code) {
  PyObject *data;
  if(code==0x8000) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%.3f A", (float)(i16)code/1000);
  return data;
}

static PyObject *dmi_current_probe_resolution(u16 code) {
  PyObject *data;
  if(code==0x8000) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%.1f mA", (float)code/10);
  return data;
}

/*******************************************************************************
** 3.3.33 System Boot Information (Type 32)
*/

static PyObject *dmi_system_boot_status(u8 code) {
  static const char *status[]={
    "No errors detected", /* 0 */
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

  if(code<=8) data = PyString_FromString(status[code]);
  else if(code>=128 && code<=191) data = PyString_FromString("OEM-specific");
  else if(code>=192) data = PyString_FromString("Product-specific");
  else data = OUT_OF_SPEC;
  return data;
}

/*******************************************************************************
** 3.3.34 64-bit Memory Error Information (Type 33)
*/

static PyObject *dmi_64bit_memory_error_address(u64 code) {
  PyObject *data;
  if(code.h==0x80000000 && code.l==0x00000000) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("0x%08x%08x", code.h, code.l);
  return data;
}

/*******************************************************************************
** 3.3.35 Management Device (Type 34)
*/

static PyObject *dmi_management_device_type(u8 code) {
  /* 3.3.35.1 */
  static const char *type[]={
    "Other", /* 0x01 */
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
    "HT82H791" /* 0x0D */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x0D) data = PyString_FromString(type[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_management_device_address_type(u8 code) {
  /* 3.3.35.2 */
  static const char *type[]={
    "Other", /* 0x01 */
    "Unknown",
    "I/O Port",
    "Memory",
    "SMBus" /* 0x05 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x05) data = PyString_FromString(type[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

/*******************************************************************************
** 3.3.38 Memory Channel (Type 37)
*/

static PyObject *dmi_memory_channel_type(u8 code) {
  /* 3.3.38.1 */
  static const char *type[]={
    "Other", /* 0x01 */
    "Unknown",
    "RamBus",
    "SyncLink" /* 0x04 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x04) data = PyString_FromString(type[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_memory_channel_devices(u8 count, const u8 *p) {
  PyObject *data = PyDict_New();
  PyObject *subdata, *val;
  int i;

  for(i=1; i<=count; i++) {
    subdata = PyList_New(2);

    val = PyString_FromFormat("Load: %i", p[3*i]);
    PyList_SET_ITEM(subdata, 0, val);
    Py_DECREF(val);

    //if(!(opt.flags & FLAG_QUIET))
    val = PyString_FromFormat("Handle: 0x%04x", WORD(p+3*i+1));
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

static PyObject *dmi_ipmi_interface_type(u8 code) {
  /* 3.3.39.1 and IPMI 2.0, appendix C1, table C1-2 */
  static const char *type[]={
    "Unknown", /* 0x00 */
    "KCS (Keyboard Control Style)",
    "SMIC (Server Management Interface Chip)",
    "BT (Block Transfer)",
    "SSIF (SMBus System Interface)" /* 0x04 */
  };
  PyObject *data;

  if(code<=0x04) data = PyString_FromString(type[code]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_ipmi_base_address(u8 type, const u8 *p, u8 lsb) {
  PyObject *data;
  if(type==0x04) /* SSIF */ {
    data = PyString_FromFormat("0x%02x (SMBus)", (*p)>>1);
  } else {
    u64 address=QWORD(p);
    data = PyString_FromFormat("0x%08x%08x (%s)", address.h, (address.l&~1)|lsb, address.l&1?"I/O":"Memory-mapped");
  }
  return data;
}

static PyObject *dmi_ipmi_register_spacing(u8 code) {
  /* IPMI 2.0, appendix C1, table C1-1 */
  static const char *spacing[]={
    "Successive Byte Boundaries", /* 0x00 */
    "32-bit Boundaries",
    "16-byte Boundaries" /* 0x02 */
  };
  PyObject *data;

  if(code<=0x02) return data = PyString_FromString(spacing[code]);
  return data = OUT_OF_SPEC;
}

/*******************************************************************************
** 3.3.40 System Power Supply (Type 39)
*/

static PyObject *dmi_power_supply_power(u16 code) {
  PyObject *data;
  if(code==0x8000) data = PyString_FromString("Unknown");
  else data = PyString_FromFormat("%.3f W", (float)code/1000);
  return data;
}

static PyObject *dmi_power_supply_type(u8 code) {
  /* 3.3.40.1 */
  static const char *type[]={
    "Other", /* 0x01 */
    "Unknown",
    "Linear",
    "Switching",
    "Battery",
    "UPS",
    "Converter",
    "Regulator" /* 0x08 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x08) data = PyString_FromString(type[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_power_supply_status(u8 code) {
  /* 3.3.40.1 */
  static const char *status[]={
    "Other", /* 0x01 */
    "Unknown",
    "OK",
    "Non-critical",
    "Critical" /* 0x05 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x05) data = PyString_FromString(status[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

static PyObject *dmi_power_supply_range_switching(u8 code) {
  /* 3.3.40.1 */
  static const char *switching[]={
    "Other", /* 0x01 */
    "Unknown",
    "Manual",
    "Auto-switch",
    "Wide Range",
    "N/A" /* 0x06 */
  };
  PyObject *data;

  if(code>=0x01 && code<=0x06) data = PyString_FromString(switching[code-0x01]);
  else data = OUT_OF_SPEC;
  return data;
}

/*******************************************************************************
** Main
*/

PyObject* dmi_decode(struct dmi_header *h, u16 ver) {

  const u8 *data = h->data;

  //. 0xF1 --> 0xF100
  //int minor = h->type<<8;
  char _[2048]; bzero(_, 2048);
  dmi_codes_major *dmiMajor = (dmi_codes_major *)&dmiCodesMajor[map_maj[h->type]];
  PyObject *pylist = PyDict_New();
  PyDict_SetItemString(pylist, "id", PyString_FromString(dmiMajor->id));
  PyDict_SetItemString(pylist, "desc", PyString_FromString(dmiMajor->desc));
  PyObject *caseData = NULL;
  PyObject *_val; //. A Temporary pointer (value)
  PyObject *_key; //. Another temporary pointer (key)

  /* TODO: DMI types 37 and 39 are untested */
  //fprintf(stderr, ">>> case %d <<<\n", h->type);

  switch(h->type) {
    case 0: /* 3.3.1 BIOS Information */
      caseData = PyDict_New();

      if(h->length<0x12) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Vendor", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x05]);
      PyDict_SetItemString(caseData, "Version", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x08]);
      PyDict_SetItemString(caseData, "Release Date", _val);
      Py_DECREF(_val);

      /*
      * On IA-64, the BIOS base address will read 0 because
      * there is no BIOS. Skip the base address and the
      * runtime size in this case.
      */

      if(WORD(data+0x06)!=0) {
        _val = PyString_FromFormat("0x%04x0", WORD(data+0x06));
        PyDict_SetItemString(caseData, "Address", _val);
        Py_DECREF(_val);

        _val = dmi_bios_runtime_size((0x10000-WORD(data+0x06))<<4);
        PyDict_SetItemString(caseData, "Runtime Size", _val);
        Py_DECREF(_val);
      }

      _val = PyString_FromFormat("%i kB", (data[0x09]+1)<<6);
      PyDict_SetItemString(caseData, "ROM Size", _val);
      Py_DECREF(_val);

      //. FIXME
      _val = dmi_bios_characteristics(QWORD(data+0x0A));
      PyDict_SetItemString(caseData, "Characteristics", _val);
      Py_DECREF(_val);

      if(h->length<0x13) break;
      _val = dmi_bios_characteristics_x1(data[0x12]);
      PyDict_SetItemString(caseData, "Characteristics x1", _val);
      Py_DECREF(_val);

      if(h->length<0x14) break;
      _val = dmi_bios_characteristics_x2(data[0x13]);
      PyDict_SetItemString(caseData, "Characteristics x2", _val);
      Py_DECREF(_val);

      if(h->length<0x18) break;

      if(data[0x14]!=0xFF && data[0x15]!=0xFF) {
        _val = PyString_FromFormat("%i.%i", data[0x14], data[0x15]);
        PyDict_SetItemString(caseData, "BIOS Revision", _val);
        Py_DECREF(_val);
      }

      if(data[0x16]!=0xFF && data[0x17]!=0xFF) {
        _val = PyString_FromFormat("%i.%i", data[0x16], data[0x17]);
        PyDict_SetItemString(caseData, "Firmware Revision", _val);
        Py_DECREF(_val);
      }

      break;

    case 1: /* 3.3.2 System Information */
      caseData = PyDict_New();

      if(h->length<0x08) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Manufacturer", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x05]);
      PyDict_SetItemString(caseData, "Product Name", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x06]);
      PyDict_SetItemString(caseData, "Version", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x07]);
      PyDict_SetItemString(caseData, "Serial Number", _val);
      Py_DECREF(_val);

      if(h->length<0x19) break;
      _val = dmi_system_uuid_py(data+0x08, ver);
      PyDict_SetItemString(caseData, "UUID", _val);
      Py_DECREF(_val);

      _val = dmi_system_wake_up_type(data[0x18]);
      PyDict_SetItemString(caseData, "Wake-Up Type", _val);
      Py_DECREF(_val);

      if(h->length<0x1B) break;
      _val = dmi_string_py(h, data[0x19]);
      PyDict_SetItemString(caseData, "SKU Number", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x1A]);
      PyDict_SetItemString(caseData, "Family", _val);
      Py_DECREF(_val);
      break;

    case 2: /* 3.3.3 Base Board Information */
      caseData = PyDict_New();

      if(h->length<0x08) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Manufacturer", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x05]);
      PyDict_SetItemString(caseData, "Product Name", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x06]);
      PyDict_SetItemString(caseData, "Version", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x07]);
      PyDict_SetItemString(caseData, "Serial Number", _val);
      Py_DECREF(_val);

      if(h->length<0x0F) break;
      _val = dmi_string_py(h, data[0x08]);
      PyDict_SetItemString(caseData, "Asset Tag", _val);
      Py_DECREF(_val);

      _val = dmi_base_board_features(data[0x09]);
      PyDict_SetItemString(caseData, "Features", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x0A]);
      PyDict_SetItemString(caseData, "Location In Chassis", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%04x", WORD(data+0x0B));
      PyDict_SetItemString(caseData, "Chassis Handle", _val);
      Py_DECREF(_val);

      _val = dmi_base_board_type(data[0x0D]);
      PyDict_SetItemString(caseData, "Type", _val);
      Py_DECREF(_val);

      if(h->length<0x0F+data[0x0E]*sizeof(u16)) break;
      _val = dmi_base_board_handles(data[0x0E], data+0x0F);
      PyDict_SetItemString(caseData, "Type ???", _val);
      Py_DECREF(_val);
      break;

    case 3: /* 3.3.4 Chassis Information */
      caseData = PyDict_New();

      if(h->length<0x09) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Manufacturer", _val);
      Py_DECREF(_val);

      _val = dmi_chassis_type_py(data[0x05]&0x7F);
      PyDict_SetItemString(caseData, "Type", _val);
      Py_DECREF(_val);

      _val = dmi_chassis_lock(data[0x05]>>7);
      PyDict_SetItemString(caseData, "Lock", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x06]);
      PyDict_SetItemString(caseData, "Version", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x07]);
      PyDict_SetItemString(caseData, "Serial Number", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x08]);
      PyDict_SetItemString(caseData, "Asset Tag", _val);
      Py_DECREF(_val);

      if(h->length<0x0D) break;
      _val = dmi_chassis_state(data[0x09]);
      PyDict_SetItemString(caseData, "Boot-Up State", _val);
      Py_DECREF(_val);

      _val = dmi_chassis_state(data[0x0A]);
      PyDict_SetItemString(caseData, "Power Supply State", _val);
      Py_DECREF(_val);

      _val = dmi_chassis_state(data[0x0B]);
      PyDict_SetItemString(caseData, "Thermal State", _val);
      Py_DECREF(_val);

      _val = PyString_FromString(dmi_chassis_security_status(data[0x0C]));
      PyDict_SetItemString(caseData, "Security Status", _val);
      Py_DECREF(_val);

      if(h->length<0x11) break;
      _val = PyString_FromFormat("0x%08x", DWORD(data+0x0D));
      PyDict_SetItemString(caseData, "OEM Information", _val);
      Py_DECREF(_val);

      if(h->length<0x15) break;
      _val = dmi_chassis_height(data[0x11]);
      PyDict_SetItemString(caseData, "Height", _val);
      Py_DECREF(_val);

      _val = dmi_chassis_power_cords(data[0x12]);
      PyDict_SetItemString(caseData, "Number Of Power Cords", _val);
      Py_DECREF(_val);

      if(h->length<0x15+data[0x13]*data[0x14]) break;
      _val = dmi_chassis_elements(data[0x13], data[0x14], data+0x15);
      PyDict_SetItemString(caseData, "Elements", _val);
      Py_DECREF(_val);

      break;


    case 4: /* 3.3.5 Processor Information */
      caseData = PyDict_New();

      if(h->length<0x1A) break;

      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Socket Designation", _val);
      Py_DECREF(_val);

      _val = dmi_processor_type(data[0x05]);
      PyDict_SetItemString(caseData, "Type", _val);
      Py_DECREF(_val);

      _val = (data[0x06] == 0xFE && h->length >= 0x2A)
        ? dmi_processor_family_py(WORD(data+0x28))
        : dmi_processor_family_py(data[0x06]);
      PyDict_SetItemString(caseData, "Family", _val);
      Py_DECREF(_val);

      _val = dmi_processor_id(data[0x06], data+8, dmi_string(h, data[0x10]));
      PyDict_SetItemString(_val, "Manufacturer (Vendor)", dmi_string_py(h, data[0x07]));
      PyDict_SetItemString(caseData, "Manufacturer", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x10]);
      PyDict_SetItemString(caseData, "Version", _val);
      Py_DECREF(_val);

      _val = dmi_processor_voltage(data[0x11]);
      PyDict_SetItemString(caseData, "Voltage", _val);
      Py_DECREF(_val);

      _val = dmi_processor_frequency_py(data+0x12);
      PyDict_SetItemString(caseData, "External Clock", _val);
      Py_DECREF(_val);

      _val = dmi_processor_frequency_py(data+0x14);
      PyDict_SetItemString(caseData, "Max Speed", _val);
      Py_DECREF(_val);

      _val = dmi_processor_frequency_py(data+0x16);
      PyDict_SetItemString(caseData, "Current Speed", _val);
      Py_DECREF(_val);

      if(data[0x18]&(1<<6)) {
        _val = PyString_FromFormat("Populated:%s", dmi_processor_status(data[0x18]&0x07));
        PyDict_SetItemString(caseData, "Status", _val);
        Py_DECREF(_val);
      } else {
        _val = PyString_FromString("Populated:No");
        PyDict_SetItemString(caseData, "Status", _val);
        Py_DECREF(_val);
      }
      _val = dmi_processor_upgrade(data[0x19]);
      PyDict_SetItemString(caseData, "Upgrade", _val);
      Py_DECREF(_val);

      if(h->length<0x20) break;
      _val = dmi_processor_cache(WORD(data+0x1A), "L1", ver);
      PyDict_SetItemString(caseData, "L1 Cache Handle", _val);
      Py_DECREF(_val);

      _val = dmi_processor_cache(WORD(data+0x1C), "L2", ver);
      PyDict_SetItemString(caseData, "L2 Cache Handle", _val);
      Py_DECREF(_val);

      _val = dmi_processor_cache(WORD(data+0x1E), "L3", ver);
      PyDict_SetItemString(caseData, "L3 Cache Handle", _val);
      Py_DECREF(_val);

      if(h->length<0x23) break;
      _val = dmi_string_py(h, data[0x20]);
      PyDict_SetItemString(caseData, "Serial Number", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x21]);
      PyDict_SetItemString(caseData, "Asset Tag", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x22]);
      PyDict_SetItemString(caseData, "Part Number", _val);
      Py_DECREF(_val);

      if(h->length<0x28) break;
      if(data[0x23]!=0) {
        _val = PyString_FromFormat("%i", data[0x23]);
        PyDict_SetItemString(caseData, "Core Count", _val);
        Py_DECREF(_val);
      }

      if(data[0x24]!=0) {
        _val = PyString_FromFormat("%i", data[0x24]);
        PyDict_SetItemString(caseData, "Core Enabled", _val);
        Py_DECREF(_val);
      }

      if(data[0x25]!=0) {
        _val = PyString_FromFormat("%i", data[0x25]);
        PyDict_SetItemString(caseData, "Thread Count", _val);
        Py_DECREF(_val);
      }

      _val = dmi_processor_characteristics(WORD(data+0x26));
      PyDict_SetItemString(caseData, "Characteristics", _val);
      Py_DECREF(_val);
      break;

    case 5: /* 3.3.6 Memory Controller Information */
      caseData = PyDict_New();
      PyDict_SetItemString(caseData, "dmi_on_board_devices", dmi_on_board_devices(h));

      if(h->length<0x0F) break;
      _val = dmi_memory_controller_ed_method(data[0x04]);
      PyDict_SetItemString(caseData, "Error Detecting Method", _val);
      Py_DECREF(_val);

      _val = dmi_memory_controller_ec_capabilities(data[0x05]);
      PyDict_SetItemString(caseData, "Error Correcting Capabilities", _val);
      Py_DECREF(_val);

      _val = dmi_memory_controller_interleave(data[0x06]);
      PyDict_SetItemString(caseData, "Supported Interleave", _val);
      Py_DECREF(_val);

      _val = dmi_memory_controller_interleave(data[0x07]);
      PyDict_SetItemString(caseData, "Current Interleave", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("%i MB", 1<<data[0x08]);
      PyDict_SetItemString(caseData, "Maximum Memory Module Size", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("%i MB", data[0x0E]*(1<<data[0x08]));
      PyDict_SetItemString(caseData, "Maximum Total Memory Size", _val);
      Py_DECREF(_val);

      _val = dmi_memory_controller_speeds(WORD(data+0x09));
      PyDict_SetItemString(caseData, "Supported Speeds", _val);
      Py_DECREF(_val);

      _val = dmi_memory_module_types(WORD(data+0x0B));
      PyDict_SetItemString(caseData, "Supported Memory Types", _val);
      Py_DECREF(_val);

      _val = dmi_processor_voltage(data[0x0D]);
      PyDict_SetItemString(caseData, "Memory Module Voltage", _val);
      Py_DECREF(_val);

      if(h->length<0x0F+data[0x0E]*sizeof(u16)) break;
      _val = dmi_memory_controller_slots(data[0x0E], data+0x0F);
      PyDict_SetItemString(caseData, "Associated Memory Sluts", _val);
      Py_DECREF(_val);

      if(h->length<0x10+data[0x0E]*sizeof(u16)) break;
      _val = dmi_memory_controller_ec_capabilities(data[0x0F+data[0x0E]*sizeof(u16)]);
      PyDict_SetItemString(caseData, "Enabled Error Correcting Capabilities", _val);
      Py_DECREF(_val);
      break;

    case 6: /* 3.3.7 Memory Module Information */
      caseData = PyDict_New();
      PyDict_SetItemString(caseData, "dmi_on_board_devices", dmi_on_board_devices(h));

      if(h->length<0x0C) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Socket Designation", _val);
      Py_DECREF(_val);

      _val = dmi_memory_module_connections(data[0x05]);
      PyDict_SetItemString(caseData, "Bank Connections", _val);
      Py_DECREF(_val);

      _val = dmi_memory_module_speed(data[0x06]);
      PyDict_SetItemString(caseData, "Current Speed", _val);
      Py_DECREF(_val);

      _val = dmi_memory_module_types(WORD(data+0x07));
      PyDict_SetItemString(caseData, "Type", _val);
      Py_DECREF(_val);

      _val = dmi_memory_module_size(data[0x09]);
      PyDict_SetItemString(caseData, "Installed Size", _val);
      Py_DECREF(_val);

      _val = dmi_memory_module_size(data[0x0A]);
      PyDict_SetItemString(caseData, "Enabled Size", _val);
      Py_DECREF(_val);

      _val = dmi_memory_module_error(data[0x0B]);
      PyDict_SetItemString(caseData, "Error Status", _val);
      Py_DECREF(_val);
      break;

    case 7: /* 3.3.8 Cache Information */
      caseData = PyDict_New();
      PyDict_SetItemString(caseData, "dmi_on_board_devices", dmi_on_board_devices(h));

      if(h->length<0x0F) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Socket Designation", _val);
      Py_DECREF(_val);

      _val = PyDict_New();
      PyDict_SetItemString(_val, "Enabled", WORD(data+0x05)&0x0080?Py_True:Py_False);
      PyDict_SetItemString(_val, "Socketed", WORD(data+0x05)&0x0008?Py_True:Py_False);
      PyDict_SetItemString(_val, "Level", PyInt_FromLong((WORD(data+0x05)&0x0007)+1));
      PyDict_SetItemString(caseData, "Configuration" , _val);
      Py_DECREF(_val);

      _val = dmi_cache_mode((WORD(data+0x05)>>8)&0x0003);
      PyDict_SetItemString(caseData, "Operational Mode", _val);
      Py_DECREF(_val);

      _val = dmi_cache_location((WORD(data+0x05)>>5)&0x0003);
      PyDict_SetItemString(caseData, "Location", _val);
      Py_DECREF(_val);

      _val = dmi_cache_size(WORD(data+0x09));
      PyDict_SetItemString(caseData, "Installed Size", _val);
      Py_DECREF(_val);

      _val = dmi_cache_size(WORD(data+0x07));
      PyDict_SetItemString(caseData, "Maximum Size", _val);
      Py_DECREF(_val);

      _val = dmi_cache_types(WORD(data+0x0B));
      PyDict_SetItemString(caseData, "Supported SRAM Types", _val);
      Py_DECREF(_val);

      _val = dmi_cache_types(WORD(data+0x0D));
      PyDict_SetItemString(caseData, "Installed SRAM Type", _val);
      Py_DECREF(_val);

      if(h->length<0x13) break;
      _val = dmi_memory_module_speed(data[0x0F]);
      PyDict_SetItemString(caseData, "Speed", _val);
      Py_DECREF(_val);

      _val = dmi_cache_ec_type(data[0x10]);
      PyDict_SetItemString(caseData, "Error Correction Type", _val);
      Py_DECREF(_val);

      _val = dmi_cache_type(data[0x11]);
      PyDict_SetItemString(caseData, "System Type", _val);
      Py_DECREF(_val);

      _val = dmi_cache_associativity(data[0x12]);
      PyDict_SetItemString(caseData, "Associativity", _val);
      Py_DECREF(_val);

      break;

    case 8: /* 3.3.9 Port Connector Information */
      caseData = PyDict_New();
      PyDict_SetItemString(caseData, "dmi_on_board_devices", dmi_on_board_devices(h));

      if(h->length<0x09) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Internal Reference Designator", _val);
      Py_DECREF(_val);

      _val = dmi_port_connector_type(data[0x05]);
      PyDict_SetItemString(caseData, "Internal Connector Type", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x06]);
      PyDict_SetItemString(caseData, "External Reference Designator", _val);
      Py_DECREF(_val);

      _val = dmi_port_connector_type(data[0x07]);
      PyDict_SetItemString(caseData, "External Connector Type", _val);
      Py_DECREF(_val);

      _val = dmi_port_type(data[0x08]);
      PyDict_SetItemString(caseData, "Port Type", _val);
      Py_DECREF(_val);
      break;

    case 9: /* 3.3.10 System Slots */
      caseData = PyDict_New();
      PyDict_SetItemString(caseData, "dmi_on_board_devices", dmi_on_board_devices(h));

      if(h->length<0x0C) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Designation", _val);
      Py_DECREF(_val);

      _val = dmi_slot_bus_width(data[0x06]);
      PyDict_SetItemString(caseData, "Type:SlotBusWidth", _val);
      Py_DECREF(_val);
      _val = dmi_slot_type(data[0x05]);
      PyDict_SetItemString(caseData, "Type:SlotType", _val);
      Py_DECREF(_val);

      _val = dmi_slot_current_usage(data[0x07]);
      PyDict_SetItemString(caseData, "Current Usage", _val);
      Py_DECREF(_val);

      _val = dmi_slot_length(data[0x08]);
      PyDict_SetItemString(caseData, "SlotLength", _val);
      Py_DECREF(_val);
      _val = dmi_slot_id(data[0x09], data[0x0A], data[0x05]);
      PyDict_SetItemString(caseData, "SlotId", _val);
      Py_DECREF(_val);

      _val = (h->length<0x0D)?dmi_slot_characteristics(data[0x0B], 0x00):dmi_slot_characteristics(data[0x0B], data[0x0C]);
      PyDict_SetItemString(caseData, "Characteristics", _val);
      Py_DECREF(_val);
      break;

    case 10: /* 3.3.11 On Board Devices Information */
      caseData = PyDict_New();
      PyDict_SetItemString(caseData, "dmi_on_board_devices", dmi_on_board_devices(h));

      break;

    case 11: /* 3.3.12 OEM Strings */
      caseData = PyDict_New();
      PyDict_SetItemString(caseData, "dmi_on_board_devices", dmi_on_board_devices(h));

      if(h->length<0x05) break;
      _val = dmi_oem_strings(h);
      PyDict_SetItemString(caseData, "Strings", _val);
      Py_DECREF(_val);

      break;

    case 12: /* 3.3.13 System Configuration Options */
      caseData = PyDict_New();

      if(h->length<0x05) break;
      _val = dmi_system_configuration_options(h);
      PyDict_SetItemString(caseData, "Options", _val);
      Py_DECREF(_val);

      break;

    case 13: /* 3.3.14 BIOS Language Information */
      caseData = PyDict_New();

      if(h->length<0x16) break;
      _val = PyString_FromFormat("%i", data[0x04]);
      PyDict_SetItemString(caseData, "Installable Languages", _val);
      Py_DECREF(_val);

      _val = dmi_bios_languages(h);
      PyList_SET_ITEM(_val, 0, dmi_string_py(h, data[0x15]));
      PyDict_SetItemString(caseData, "Currently Installed Language", _val);
      Py_DECREF(_val);

      break;

    case 14: /* 3.3.15 Group Associations */
      caseData = PyDict_New();

      if(h->length<0x05) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Name", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("%i", (h->length-0x05)/3);
      PyDict_SetItemString(caseData, "Items", _val);
      Py_DECREF(_val);

      _val = dmi_group_associations_items((h->length-0x05)/3, data+0x05);
      PyDict_SetItemString(caseData, "Items2", _val); //. FIXME: Title
      Py_DECREF(_val);
      break;

    case 15: /* 3.3.16 System Event Log */
      caseData = PyDict_New();

      if(h->length<0x14) break;
      _val = PyString_FromFormat("%i bytes", WORD(data+0x04));
      PyDict_SetItemString(caseData, "Area Length", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%04x", WORD(data+0x06));
      PyDict_SetItemString(caseData, "Header Start Offset", _val);
      Py_DECREF(_val);

      if(WORD(data+0x08)-WORD(data+0x06)) {
        _val = PyString_FromFormat("%i byte%s", WORD(data+0x08)-WORD(data+0x06), WORD(data+0x08)-WORD(data+0x06)>1?"s":"");
        PyDict_SetItemString(caseData, "Header Length", _val);
        Py_DECREF(_val);
      }

      _val = PyString_FromFormat("0x%04x", WORD(data+0x08));
      PyDict_SetItemString(caseData, "Data Start Offset", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("%s", dmi_event_log_method(data[0x0A]));
      PyDict_SetItemString(caseData, "Access Method", _val);
      Py_DECREF(_val);

      _val = dmi_event_log_address_py(data[0x0A], data+0x10);
      PyDict_SetItemString(caseData, "Access Address", _val);
      Py_DECREF(_val);

      _val = dmi_event_log_status_py(data[0x0B]);
      PyDict_SetItemString(caseData, "Status", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%08x", DWORD(data+0x0C));
      PyDict_SetItemString(caseData, "Change Token", _val);
      Py_DECREF(_val);

      if(h->length<0x17) break;
      _val = PyString_FromFormat("%s", dmi_event_log_header_type(data[0x14]));
      PyDict_SetItemString(caseData, "Header Format", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("%i", data[0x15]);
      PyDict_SetItemString(caseData, "Supported Log Type Descriptors", _val);
      Py_DECREF(_val);

      if(h->length<0x17+data[0x15]*data[0x16]) break;
      _val = dmi_event_log_descriptors(data[0x15], data[0x16], data+0x17);
      PyDict_SetItemString(caseData, "DMI Event Log Descriptors", _val);
      Py_DECREF(_val);

      break;

    case 16: /* 3.3.17 Physical Memory Array */
      caseData = PyDict_New();

      if(h->length<0x0F) break;
      _val = dmi_memory_array_location(data[0x04]);
      PyDict_SetItemString(caseData, "Location", _val);
      Py_DECREF(_val);

      _val = dmi_memory_array_use(data[0x05]);
      PyDict_SetItemString(caseData, "Use", _val);
      Py_DECREF(_val);

      _val = dmi_memory_array_ec_type(data[0x06]);
      PyDict_SetItemString(caseData, "Error Correction Type", _val);
      Py_DECREF(_val);

      _val = dmi_memory_array_capacity(DWORD(data+0x07));
      PyDict_SetItemString(caseData, "Maximum Capacity", _val);
      Py_DECREF(_val);

      _val = dmi_memory_array_error_handle(WORD(data+0x0B));
      PyDict_SetItemString(caseData, "Error Information Handle", _val);
      Py_DECREF(_val);

      _val = PyInt_FromLong(WORD(data+0x0D));
      PyDict_SetItemString(caseData, "Number Of Devices", _val);
      Py_DECREF(_val);
      break;


    case 17: /* 3.3.18 Memory Device */
      caseData = PyDict_New();

      if(h->length<0x15) break;
      _val = PyString_FromFormat("0x%04x", WORD(data+0x04));
      PyDict_SetItemString(caseData, "Array Handle", _val);
      Py_DECREF(_val);

      _val = dmi_memory_array_error_handle(WORD(data+0x06));
      PyDict_SetItemString(caseData, "Error Information Handle", _val);
      Py_DECREF(_val);

      _val = dmi_memory_device_width(WORD(data+0x08));
      PyDict_SetItemString(caseData, "Total Width", _val);
      Py_DECREF(_val);

      _val = dmi_memory_device_width(WORD(data+0x0A));
      PyDict_SetItemString(caseData, "Data Width", _val);
      Py_DECREF(_val);

      _val = dmi_memory_device_size(WORD(data+0x0C));
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

      _val = dmi_memory_device_type_detail(WORD(data+0x13));
      PyDict_SetItemString(caseData, "Type Detail", _val);
      Py_DECREF(_val);

      if(h->length<0x17) break;
      _val = dmi_memory_device_speed(WORD(data+0x15));
      PyDict_SetItemString(caseData, "Speed", _val);
      Py_DECREF(_val);

      if(h->length<0x1B) break;
      _val = dmi_string_py(h, data[0x17]);
      PyDict_SetItemString(caseData, "Manufacturer", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x18]);
      PyDict_SetItemString(caseData,"Serial Number" , _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x19]);
      PyDict_SetItemString(caseData, "Asset Tag", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x1A]);
      PyDict_SetItemString(caseData, "Part Number", _val);
      Py_DECREF(_val);
      break;

    case 18: /* 3.3.19 32-bit Memory Error Information */
      caseData = PyDict_New();

      if(h->length<0x17) break;
      _val = dmi_memory_error_type(data[0x04]);
      PyDict_SetItemString(caseData, "Type", _val);
      Py_DECREF(_val);

      _val = dmi_memory_error_granularity(data[0x05]);
      PyDict_SetItemString(caseData, "Granularity", _val);
      Py_DECREF(_val);

      _val = dmi_memory_error_operation(data[0x06]);
      PyDict_SetItemString(caseData, "Operation", _val);
      Py_DECREF(_val);

      _val = dmi_memory_error_syndrome(DWORD(data+0x07));
      PyDict_SetItemString(caseData, "Vendor Syndrome", _val);
      Py_DECREF(_val);

      _val = dmi_32bit_memory_error_address(DWORD(data+0x0B));
      PyDict_SetItemString(caseData, "Memory Array Address", _val);
      Py_DECREF(_val);

      _val = dmi_32bit_memory_error_address(DWORD(data+0x0F));
      PyDict_SetItemString(caseData, "Device Address", _val);
      Py_DECREF(_val);

      _val = dmi_32bit_memory_error_address(DWORD(data+0x13));
      PyDict_SetItemString(caseData, "Resolution", _val);
      Py_DECREF(_val);
      break;

    case 19: /* 3.3.20 Memory Array Mapped Address */
      caseData = PyDict_New();

      if(h->length<0x0F) break;
      _val = PyString_FromFormat("0x%08x%03x", DWORD(data+0x04)>>2, (DWORD(data+0x04)&0x3)<<10);
      PyDict_SetItemString(caseData, "Starting Address", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%08x%03x", DWORD(data+0x08)>>2, ((DWORD(data+0x08)&0x3)<<10)+0x3FF);
      PyDict_SetItemString(caseData, "Ending Address", _val);
      Py_DECREF(_val);

      _val = dmi_mapped_address_size(DWORD(data+0x08)-DWORD(data+0x04)+1);
      PyDict_SetItemString(caseData, "Range Size", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%04x", WORD(data+0x0C));
      PyDict_SetItemString(caseData, "Physical Array Handle", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("%i", data[0x0F]);
      PyDict_SetItemString(caseData, "Partition Width", _val);
      Py_DECREF(_val);
      break;

    case 20: /* 3.3.21 Memory Device Mapped Address */
      caseData = PyDict_New();

      if(h->length<0x13) break;
      _val = PyString_FromFormat("0x%08x%03x", DWORD(data+0x04)>>2, (DWORD(data+0x04)&0x3)<<10);
      PyDict_SetItemString(caseData, "Starting Address", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%08x%03x", DWORD(data+0x08)>>2, ((DWORD(data+0x08)&0x3)<<10)+0x3FF);
      PyDict_SetItemString(caseData, "Ending Address", _val);
      Py_DECREF(_val);

      _val = dmi_mapped_address_size(DWORD(data+0x08)-DWORD(data+0x04)+1);
      PyDict_SetItemString(caseData, "Range Size", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%04x", WORD(data+0x0C));
      PyDict_SetItemString(caseData, "Physical Device Handle", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%04x", WORD(data+0x0E));
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

    case 21: /* 3.3.22 Built-in Pointing Device */
      caseData = PyDict_New();

      if(h->length<0x07) break;
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

    case 22: /* 3.3.23 Portable Battery */
      caseData = PyDict_New();

      if(h->length<0x10) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Location", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x05]);
      PyDict_SetItemString(caseData, "Manufacturer", _val);
      Py_DECREF(_val);

      if(data[0x06] || h->length<0x1A) {
        _val = dmi_string_py(h, data[0x06]);
        PyDict_SetItemString(caseData, "Manufacture Date", _val);
        Py_DECREF(_val);
      }

      if(data[0x07] || h->length<0x1A) {
        _val = dmi_string_py(h, data[0x07]);
        PyDict_SetItemString(caseData, "Serial Number", _val);
        Py_DECREF(_val);
      }

      _val = dmi_string_py(h, data[0x08]);
      PyDict_SetItemString(caseData, "Name", _val);
      Py_DECREF(_val);

      if(data[0x09]!=0x02 || h->length<0x1A) {
        _val = dmi_battery_chemistry(data[0x09]);
        PyDict_SetItemString(caseData, "Chemistry", _val);
        Py_DECREF(_val);
      }
      _val = (h->length<0x1A)?dmi_battery_capacity(WORD(data+0x0A), 1):dmi_battery_capacity(WORD(data+0x0A), data[0x15]);
      PyDict_SetItemString(caseData, "Design Capacity", _val);
      Py_DECREF(_val);

      _val = dmi_battery_voltage(WORD(data+0x0C));
      PyDict_SetItemString(caseData, "Design Voltage", _val);
      Py_DECREF(_val);

      _val = dmi_string_py(h, data[0x0E]);
      PyDict_SetItemString(caseData, "SBDS Version", _val);
      Py_DECREF(_val);

      _val = dmi_battery_maximum_error(data[0x0F]);
      PyDict_SetItemString(caseData, "Maximum Error", _val);
      Py_DECREF(_val);

      if(h->length<0x1A) break;
      if(data[0x07]==0) {
        _val = PyString_FromFormat("%04x", WORD(data+0x10));
        PyDict_SetItemString(caseData, "SBDS Serial Number", _val);
        Py_DECREF(_val);
      }
      if(data[0x06]==0) {
        _val = PyString_FromFormat("%i-%02u-%02u", 1980+(WORD(data+0x12)>>9), (WORD(data+0x12)>>5)&0x0F, WORD(data+0x12)&0x1F);
        PyDict_SetItemString(caseData, "SBDS Manufacture Date", _val);
        Py_DECREF(_val);
      }
      if(data[0x09]==0x02) {
        _val = dmi_string_py(h, data[0x14]);
        PyDict_SetItemString(caseData, "SBDS Chemistry", _val);
        Py_DECREF(_val);
      }

      _val = PyString_FromFormat("0x%08x", DWORD(data+0x16));
      PyDict_SetItemString(caseData, "OEM-specific Information", _val);
      Py_DECREF(_val);
      break;

    case 23: /* 3.3.24 System Reset */
      caseData = PyDict_New();

      if(h->length<0x0D) break;
      _val = PyString_FromFormat("%s", data[0x04]&(1<<0)?"Enabled":"Disabled");
      PyDict_SetItemString(caseData, "Status", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("%s", data[0x04]&(1<<5)?"Present":"Not Present");
      PyDict_SetItemString(caseData, "Watchdog Timer", _val);
      Py_DECREF(_val);

      if(!(data[0x04]&(1<<5))) break;
      _val = dmi_system_reset_boot_option((data[0x04]>>1)&0x3);
      PyDict_SetItemString(caseData, "Boot Option", _val);
      Py_DECREF(_val);

      _val = dmi_system_reset_boot_option((data[0x04]>>3)&0x3);
      PyDict_SetItemString(caseData, "Boot Option On Limit", _val);
      Py_DECREF(_val);

      _val = dmi_system_reset_count(WORD(data+0x05));
      PyDict_SetItemString(caseData, "Reset Count", _val);
      Py_DECREF(_val);

      _val = dmi_system_reset_count(WORD(data+0x07));
      PyDict_SetItemString(caseData, "Reset Limit", _val);
      Py_DECREF(_val);

      _val = dmi_system_reset_timer(WORD(data+0x09));
      PyDict_SetItemString(caseData, "Timer Interval", _val);
      Py_DECREF(_val);

      _val = dmi_system_reset_timer(WORD(data+0x0B));
      PyDict_SetItemString(caseData, "Timeout", _val);
      Py_DECREF(_val);

      break;

    case 24: /* 3.3.25 Hardware Security */
      caseData = PyDict_New();

      if(h->length<0x05) break;
      _val = dmi_hardware_security_status(data[0x04]>>6);
      PyDict_SetItemString(caseData, "Power-On Password Status", _val);
      Py_DECREF(_val);

      _val = dmi_hardware_security_status((data[0x04]>>4)&0x3);
      PyDict_SetItemString(caseData, "Keyboard Password Status", _val);
      Py_DECREF(_val);

      _val = dmi_hardware_security_status((data[0x04]>>2)&0x3);
      PyDict_SetItemString(caseData, "Administrator Password Status", _val);
      Py_DECREF(_val);

      _val = dmi_hardware_security_status(data[0x04]&0x3);
      PyDict_SetItemString(caseData, "Front Panel Reset Status", _val);
      Py_DECREF(_val);

      break;

    case 25: /* 3.3.26 System Power Controls */
      caseData = PyDict_New();

      if(h->length<0x09) break;
      _val = dmi_power_controls_power_on(data+0x04);
      PyDict_SetItemString(caseData, "Next Scheduled Power-on", _val);
      Py_DECREF(_val);

      break;

    case 26: /* 3.3.27 Voltage Probe */
      caseData = PyDict_New();

      if(h->length<0x14) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Description", _val);
      Py_DECREF(_val);

      _val = dmi_voltage_probe_location(data[0x05]&0x1f);
      PyDict_SetItemString(caseData, "Location", _val);
      Py_DECREF(_val);

      _val = dmi_probe_status(data[0x05]>>5);
      PyDict_SetItemString(caseData, "Status", _val);
      Py_DECREF(_val);

      _val = dmi_voltage_probe_value(WORD(data+0x06));
      PyDict_SetItemString(caseData, "Maximum Value", _val);
      Py_DECREF(_val);

      _val = dmi_voltage_probe_value(WORD(data+0x08));
      PyDict_SetItemString(caseData, "Minimum Value", _val);
      Py_DECREF(_val);

      _val = dmi_voltage_probe_resolution(WORD(data+0x0A));
      PyDict_SetItemString(caseData, "Resolution", _val);
      Py_DECREF(_val);

      _val = dmi_voltage_probe_value(WORD(data+0x0C));
      PyDict_SetItemString(caseData, "Tolerance", _val);
      Py_DECREF(_val);

      _val = dmi_probe_accuracy(WORD(data+0x0E));
      PyDict_SetItemString(caseData, "Accuracy", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%08x", DWORD(data+0x10));
      PyDict_SetItemString(caseData, "OEM-specific Information", _val);
      Py_DECREF(_val);

      if(h->length<0x16) break;
      _val = dmi_voltage_probe_value(WORD(data+0x14));
      PyDict_SetItemString(caseData, "Nominal Value", _val);
      Py_DECREF(_val);

      break;

    case 27: /* 3.3.28 Cooling Device */
      caseData = PyDict_New();

      if(h->length<0x0C) break;
      if(WORD(data+0x04)!=0xFFFF) {
        _val = PyString_FromFormat("0x%04x", WORD(data+0x04));
        PyDict_SetItemString(caseData, "Temperature Probe Handle", _val);
        Py_DECREF(_val);
      }

      _val = dmi_cooling_device_type(data[0x06]&0x1f);
      PyDict_SetItemString(caseData, "Type", _val);
      Py_DECREF(_val);

      _val = dmi_probe_status(data[0x06]>>5);
      PyDict_SetItemString(caseData, "Status", _val);
      Py_DECREF(_val);

      if(data[0x07]!=0x00) {
        _val = PyString_FromFormat("%i", data[0x07]);
        PyDict_SetItemString(caseData, "Cooling Unit Group", _val);
        Py_DECREF(_val);
      }

      _val = PyString_FromFormat("0x%08x", DWORD(data+0x08));
      PyDict_SetItemString(caseData, "OEM-specific Information", _val);
      Py_DECREF(_val);

      if(h->length<0x0E) break;
      _val = dmi_cooling_device_speed(WORD(data+0x0C));
      PyDict_SetItemString(caseData, "Nominal Speed", _val);
      Py_DECREF(_val);

      break;

    case 28: /* 3.3.29 Temperature Probe */
      caseData = PyDict_New();

      if(h->length<0x14) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Description", _val);
      Py_DECREF(_val);

      _val = dmi_temperature_probe_location(data[0x05]&0x1F);
      PyDict_SetItemString(caseData, "Location", _val);
      Py_DECREF(_val);

      _val = dmi_probe_status(data[0x05]>>5);
      PyDict_SetItemString(caseData, "Status", _val);
      Py_DECREF(_val);

      _val = dmi_temperature_probe_value(WORD(data+0x06));
      PyDict_SetItemString(caseData, "Maximum Value", _val);
      Py_DECREF(_val);

      _val = dmi_temperature_probe_value(WORD(data+0x08));
      PyDict_SetItemString(caseData, "Minimum Value", _val);
      Py_DECREF(_val);

      _val = dmi_temperature_probe_resolution(WORD(data+0x0A));
      PyDict_SetItemString(caseData, "Resolution", _val);
      Py_DECREF(_val);

      _val = dmi_temperature_probe_value(WORD(data+0x0C));
      PyDict_SetItemString(caseData, "Tolerance", _val);
      Py_DECREF(_val);

      _val = dmi_probe_accuracy(WORD(data+0x0E));
      PyDict_SetItemString(caseData, "Accuracy", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%08x", DWORD(data+0x10));
      PyDict_SetItemString(caseData, "OEM-specific Information", _val);
      Py_DECREF(_val);

      if(h->length<0x16) break;
      _val = dmi_temperature_probe_value(WORD(data+0x14));
      PyDict_SetItemString(caseData, "Nominal Value", _val);
      Py_DECREF(_val);

      break;

    case 29: /* 3.3.30 Electrical Current Probe */
      caseData = PyDict_New();

      if(h->length<0x14) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Description", _val);
      Py_DECREF(_val);

      _val = dmi_voltage_probe_location(data[5]&0x1F);
      PyDict_SetItemString(caseData, "Location", _val);
      Py_DECREF(_val);

      _val = dmi_probe_status(data[0x05]>>5);
      PyDict_SetItemString(caseData, "Status", _val);
      Py_DECREF(_val);

      _val = dmi_current_probe_value(WORD(data+0x06));
      PyDict_SetItemString(caseData, "Maximum Value", _val);
      Py_DECREF(_val);

      _val = dmi_current_probe_value(WORD(data+0x08));
      PyDict_SetItemString(caseData, "Minimum Value", _val);
      Py_DECREF(_val);

      _val = dmi_current_probe_resolution(WORD(data+0x0A));
      PyDict_SetItemString(caseData, "Resolution", _val);
      Py_DECREF(_val);

      _val = dmi_current_probe_value(WORD(data+0x0C));
      PyDict_SetItemString(caseData, "Tolerance", _val);
      Py_DECREF(_val);

      _val = dmi_probe_accuracy(WORD(data+0x0E));
      PyDict_SetItemString(caseData, "Accuracy", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%08x", DWORD(data+0x10));
      PyDict_SetItemString(caseData, "OEM-specific Information", _val);
      Py_DECREF(_val);

      if(h->length<0x16) break;
      _val = dmi_current_probe_value(WORD(data+0x14));
      PyDict_SetItemString(caseData, "Nominal Value", _val);
      Py_DECREF(_val);

      break;

    case 30: /* 3.3.31 Out-of-band Remote Access */
      caseData = PyDict_New();

      if(h->length<0x06) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Manufacturer Name", _val);
      Py_DECREF(_val);

      _val = data[0x05]&(1<<0)?Py_True:Py_False;
      PyDict_SetItemString(caseData, "Inbound Connection Enabled", _val);
      Py_DECREF(_val);

      _val = data[0x05]&(1<<1)?Py_True:Py_False;
      PyDict_SetItemString(caseData, "Outbound Connection Enabled", _val);
      Py_DECREF(_val);
      break;

    case 31: /* 3.3.32 Boot Integrity Services Entry Point */
      caseData = PyDict_New();

      break;

    case 32: /* 3.3.33 System Boot Information */
      caseData = PyDict_New();

      if(h->length<0x0B) break;
      _val = dmi_system_boot_status(data[0x0A]);
      PyDict_SetItemString(caseData, "Status", _val);
      Py_DECREF(_val);

      break;

    case 33: /* 3.3.34 64-bit Memory Error Information */
      if(h->length<0x1F) break;
      caseData = PyDict_New();

      _val = dmi_memory_error_type(data[0x04]);
      PyDict_SetItemString(caseData, "Type", _val);
      Py_DECREF(_val);

      _val = dmi_memory_error_granularity(data[0x05]);
      PyDict_SetItemString(caseData, "Granularity", _val);
      Py_DECREF(_val);

      _val = dmi_memory_error_operation(data[0x06]);
      PyDict_SetItemString(caseData, "Operation", _val);
      Py_DECREF(_val);

      _val = dmi_memory_error_syndrome(DWORD(data+0x07));
      PyDict_SetItemString(caseData, "Vendor Syndrome", _val);
      Py_DECREF(_val);

      _val = dmi_64bit_memory_error_address(QWORD(data+0x0B));
      PyDict_SetItemString(caseData, "Memory Array Address", _val);
      Py_DECREF(_val);

      _val = dmi_64bit_memory_error_address(QWORD(data+0x13));
      PyDict_SetItemString(caseData, "Device Address", _val);
      Py_DECREF(_val);

      _val = dmi_32bit_memory_error_address(DWORD(data+0x1B));
      PyDict_SetItemString(caseData, "Resolution", _val);
      Py_DECREF(_val);

      break;

    case 34: /* 3.3.35 Management Device */
      caseData = PyDict_New();

      if(h->length<0x0B) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Description", _val);
      Py_DECREF(_val);

      _val = dmi_management_device_type(data[0x05]);
      PyDict_SetItemString(caseData, "Type", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%08x", DWORD(data+0x06));
      PyDict_SetItemString(caseData, "Address", _val);
      Py_DECREF(_val);

      _val = dmi_management_device_address_type(data[0x0A]);
      PyDict_SetItemString(caseData, "Address Type", _val);
      Py_DECREF(_val);

      break;

    case 35: /* 3.3.36 Management Device Component */
      caseData = PyDict_New();

      if(h->length<0x0B) break;
      _val = dmi_string_py(h, data[0x04]);
      PyDict_SetItemString(caseData, "Description", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%04x", WORD(data+0x05));
      PyDict_SetItemString(caseData, "Management Device Handle", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%04x", WORD(data+0x07));
      PyDict_SetItemString(caseData, "Component Handle", _val);
      Py_DECREF(_val);

      if(WORD(data+0x09)!=0xFFFF) {
        _val = PyString_FromFormat("0x%04x", WORD(data+0x09));
        PyDict_SetItemString(caseData, "Threshold Handle", _val);
        Py_DECREF(_val);
      }

      break;

    case 36: /* 3.3.37 Management Device Threshold Data */
      caseData = PyDict_New();

      if(h->length<0x10) break;
      if(WORD(data+0x04)!=0x8000) {
        _val = PyString_FromFormat("%d", (i16)WORD(data+0x04));
        PyDict_SetItemString(caseData, "Lower Non-critical Threshold", _val);
        Py_DECREF(_val);
      }
      if(WORD(data+0x06)!=0x8000) {
        _val = PyString_FromFormat("%d", (i16)WORD(data+0x06));
        PyDict_SetItemString(caseData, "Upper Non-critical Threshold", _val);
        Py_DECREF(_val);
      }
      if(WORD(data+0x08)!=0x8000) {
        _val = PyString_FromFormat("%d", (i16)WORD(data+0x08));
        PyDict_SetItemString(caseData, "Lower Critical Threshold", _val);
        Py_DECREF(_val);
      }
      if(WORD(data+0x0A)!=0x8000) {
        _val = PyString_FromFormat("%d", (i16)WORD(data+0x0A));
        PyDict_SetItemString(caseData, "Upper Critical Threshold", _val);
        Py_DECREF(_val);
      }
      if(WORD(data+0x0C)!=0x8000) {
        _val = PyString_FromFormat("%d", (i16)WORD(data+0x0C));
        PyDict_SetItemString(caseData, "Lower Non-recoverable Threshold", _val);
        Py_DECREF(_val);
      }
      if(WORD(data+0x0E)!=0x8000) {
        _val = PyString_FromFormat("%d", (i16)WORD(data+0x0E));
        PyDict_SetItemString(caseData, "Upper Non-recoverable Threshold", _val);
        Py_DECREF(_val);
      }

      break;

    case 37: /* 3.3.38 Memory Channel */
      caseData = PyDict_New();

      if(h->length<0x07) break;
      _val = dmi_memory_channel_type(data[0x04]);
      PyDict_SetItemString(caseData, "Type", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("%i", data[0x05]);
      PyDict_SetItemString(caseData, "Maximal Load", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("%i", data[0x06]);
      PyDict_SetItemString(caseData, "Devices", _val);
      Py_DECREF(_val);

      if(h->length<0x07+3*data[0x06]) break;
      _val = dmi_memory_channel_devices(data[0x06], data+0x07);
      PyDict_SetItemString(caseData, ">>>", _val);
      Py_DECREF(_val);

      break;

    case 38: /* 3.3.39 IPMI Device Information */
      /*
       * We use the word "Version" instead of "Revision", conforming to
       * the IPMI specification.
       */
      caseData = PyDict_New();

      if(h->length<0x10) break;
      _val = dmi_ipmi_interface_type(data[0x04]);
      PyDict_SetItemString(caseData, "Interface Type", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("%i.%i", data[0x05]>>4, data[0x05]&0x0F);
      PyDict_SetItemString(caseData, "Specification Version", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("0x%02x", data[0x06]>>1);
      PyDict_SetItemString(caseData, "I2C Slave Address", _val);
      Py_DECREF(_val);

      if(data[0x07]!=0xFF) {
        _val = PyString_FromFormat("%i", data[0x07]);
        PyDict_SetItemString(caseData, "NV Storage Device Address", _val);
        Py_DECREF(_val);
      } else {
        _val = Py_None;
        PyDict_SetItemString(caseData, "NV Storage Device: Not Present", _val);
        Py_DECREF(_val);
      }

      _val = dmi_ipmi_base_address(data[0x04], data+0x08, h->length<0x12?0:(data[0x10]>>5)&1);
      PyDict_SetItemString(caseData, "Base Address", _val);
      Py_DECREF(_val);

      if(h->length<0x12) break;
      if(data[0x04]!=0x04) {
        _val = dmi_ipmi_register_spacing(data[0x10]>>6);
        PyDict_SetItemString(caseData, "Register Spacing", _val);
        Py_DECREF(_val);

        if(data[0x10]&(1<<3)) {
          _val = PyString_FromFormat("%s", data[0x10]&(1<<1)?"Active High":"Active Low");
          PyDict_SetItemString(caseData, "Interrupt Polarity", _val);
          Py_DECREF(_val);

          _val = PyString_FromFormat("%s", data[0x10]&(1<<0)?"Level":"Edge");
          PyDict_SetItemString(caseData, "Interrupt Trigger Mode", _val);
          Py_DECREF(_val);
        }
      }
      if(data[0x11]!=0x00) {
        _val = PyString_FromFormat("%x", data[0x11]);
        PyDict_SetItemString(caseData, "Interrupt Number", _val);
        Py_DECREF(_val);
      }
      break;

    case 39: /* 3.3.40 System Power Supply */
      caseData = PyDict_New();

      if(h->length<0x10) break;
      if(data[0x04]!=0x00) {
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

      _val = dmi_power_supply_power(WORD(data+0x0C));
      PyDict_SetItemString(caseData, "Max Power Capacity", _val);
      Py_DECREF(_val);

      if(WORD(data+0x0E)&(1<<1)) {
        _val = dmi_power_supply_status((WORD(data+0x0E)>>7)&0x07);
        PyDict_SetItemString(caseData, "Status Present", _val);
        Py_DECREF(_val);
      } else {
        _val = PyString_FromString("Not Present");
        PyDict_SetItemString(caseData, "Status", _val);
        Py_DECREF(_val);
      }
      _val = dmi_power_supply_type((WORD(data+0x0E)>>10)&0x0F);
      PyDict_SetItemString(caseData, "Type", _val);
      Py_DECREF(_val);

      _val = dmi_power_supply_range_switching((WORD(data+0x0E)>>3)&0x0F);
      PyDict_SetItemString(caseData, "Input Voltage Range Switching", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("%s", WORD(data+0x0E)&(1<<2)?"No":"Yes");
      PyDict_SetItemString(caseData, "Plugged", _val);
      Py_DECREF(_val);

      _val = PyString_FromFormat("%s", WORD(data+0x0E)&(1<<0)?"Yes":"No");
      PyDict_SetItemString(caseData, "Hot Replaceable", _val);
      Py_DECREF(_val);

      if(h->length<0x16) break;
      if(WORD(data+0x10)!=0xFFFF) {
        _val = PyString_FromFormat("0x%04x", WORD(data+0x10));
        PyDict_SetItemString(caseData, "Input Voltage Probe Handle", _val);
        Py_DECREF(_val);
      }

      if(WORD(data+0x12)!=0xFFFF) {
        _val = PyString_FromFormat("0x%04x", WORD(data+0x12));
        PyDict_SetItemString(caseData, "Cooling Device Handle", _val);
        Py_DECREF(_val);
      }

      if(WORD(data+0x14)!=0xFFFF) {
        _val = PyString_FromFormat("0x%04x", WORD(data+0x14));
        PyDict_SetItemString(caseData, "Input Current Probe Handle", _val);
        Py_DECREF(_val);
      }

      break;

    case 126: /* 3.3.41 Inactive */
      caseData = PyDict_New();

      _val = Py_None;
      PyDict_SetItemString(caseData, "Inactive", _val);
      Py_DECREF(_val);
      break;

    case 127: /* 3.3.42 End Of Table */
      caseData = PyDict_New();

      _val = Py_None;
      PyDict_SetItemString(caseData, "End Of Table", _val);
      Py_DECREF(_val);

      break;

    default:
      if(dmi_decode_oem(h)) break;
      _key = PyString_FromFormat("%s Type", h->type>=128?"OEM-specific":"Unknown");
      _val = dmi_dump(h);
      PyDict_SetItem(caseData, _key, _val);
      Py_DECREF(_key);
      Py_DECREF(_val);
  }

  /*. All the magic of python dict additions happens here...
  PyObject *pydata = PyDict_New();
  _key = PyInt_FromLong(h->type);
  PyObject *_list;
  if(!(_list = PyDict_GetItem(pydata, _key))) {
    _list = PyList_New(0);
    PyDict_SetItem(pydata, _key, _list);
  }
  PyList_Append(_list, caseData);
  Py_DECREF(_key);

  return pydata;
  */

  assert(caseData != NULL);
  Py_INCREF(caseData);
  return caseData;
}

void to_dmi_header(struct dmi_header *h, u8 *data) {
  h->type=data[0];
  h->length=data[1];
  h->handle=WORD(data+2);
  h->data=data;
}

static void dmi_table_string_py(const struct dmi_header *h, const u8 *data, PyObject *hDict, u16 ver) {
  int key;
  u8 offset = opt.string->offset;

  if (offset >= h->length) return;

  //. TODO: These should have more meaningful dictionary names
  key = (opt.string->type << 8) | offset;
  PyObject *_val;
  switch(key) {
    case 0x108:
      _val = dmi_system_uuid_py(data+offset, ver);
      PyDict_SetItemString(hDict, "0x108", _val);
      break;
    case 0x305:
      _val = dmi_chassis_type_py(data[offset]);
      PyDict_SetItemString(hDict, "0x305", _val);
    case 0x406:
      _val = PyString_FromFormat("%s",
        data[0x06] == 0xFE && h->length >= 0x2A ?
        dmi_processor_family(WORD(data + 0x28)) :
        dmi_processor_family(data[offset])
      );
      PyDict_SetItemString(hDict, "0x406", _val);
      break;
    case 0x416:
      _val = dmi_processor_frequency_py((u8 *)data + offset);
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
static void overwrite_dmi_address(u8 *buf) {
  buf[0x05] += buf[0x08] + buf[0x09] + buf[0x0A] + buf[0x0B] - 32;
  buf[0x08] = 32;
  buf[0x09] = 0;
  buf[0x0A] = 0;
  buf[0x0B] = 0;
}


#define NON_LEGACY 0
#define LEGACY 1
int dumpling(u8 *buf, const char *dumpfile, u8 mode) {
  u32 base;
  u16 len;
  if(mode == NON_LEGACY) {
    if(!checksum(buf, buf[0x05]) || !memcmp(buf+0x10, "_DMI_", 5)==0 || !checksum(buf+0x10, 0x0F)) return 0;
    base = DWORD(buf+0x18);
    len = WORD(buf+0x16);
  } else {
    if(!checksum(buf, 0x0F)) return 0;
    base = DWORD(buf+0x08);
    len = WORD(buf+0x06);
  }

  u8 *buff;
  if((buff = mem_chunk(base, len, DEFAULT_MEM_DEV)) != NULL) {
    //. Part 1.
    printf("# Writing %d bytes to %s.\n", len, dumpfile);
    write_dump(32, len, buf, dumpfile, 0);
    free(buff);

    //. Part 2.
    if(mode != LEGACY) {
      u8 crafted[32];
      memcpy(crafted, buf, 32);
      overwrite_dmi_address(crafted+0x10);
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

int dump(const char *dumpfile) {
  /* On success, return found, otherwise return -1 */
  int ret=0;
  int found=0;
  size_t fp;
  int efi;
  u8 *buf;

  /* First try EFI (ia64, Intel-based Mac) */
  efi = address_from_efi(&fp);
  if(efi == EFI_NOT_FOUND) {
    /* Fallback to memory scan (x86, x86_64) */
    if((buf=mem_chunk(0xF0000, 0x10000, DEFAULT_MEM_DEV))!=NULL) {
      for(fp=0; fp<=0xFFF0; fp+=16) {
        if(memcmp(buf+fp, "_SM_", 4)==0 && fp<=0xFFE0) {
          if(dumpling(buf+fp, dumpfile, NON_LEGACY)) found++;
          fp+=16;
        } else if(memcmp(buf+fp, "_DMI_", 5)==0) {
          if(dumpling(buf+fp, dumpfile, LEGACY)) found++;
        }
      }
    } else ret = -1;
  } else if(efi == EFI_NO_SMBIOS) {
    ret = -1;
  } else {
    if((buf=mem_chunk(fp, 0x20, DEFAULT_MEM_DEV))==NULL) ret = -1;
    else if(dumpling(buf, dumpfile, NON_LEGACY)) found++;
  }

  if(ret==0) {
    free(buf);

    //. TODO: Exception
    //dmiSetItem(pydata, "detect", "No SMBIOS nor DMI entry point found, sorry G.");
    if(!found) ret = -1;
  }

  return ret==0?found:ret;
}



static void dmi_table(u32 base, u16 len, u16 num, u16 ver, const char *devmem, PyObject *pydata) {
  u8 *buf;
  u8 *data;
  int i=0;

  /* TODO: DUMP
  if (opt.flags & FLAG_DUMP_BIN) {
    dmi_table_dump(base, len, devmem);
    return;
  }
  */

  if(opt.type==NULL) {
    dmiSetItem(pydata, "dmi_table_size", "%i structures occupying %i bytes", num, len);
    /* TODO DUMP
    if (!(opt.flags & FLAG_FROM_DUMP))
      dmiSetItem(pydata, "dmi_table_base", "Table at 0x%08x", base);
    */
    dmiSetItem(pydata, "dmi_table_base", "Table at 0x%08x", base);
  }

  if((buf=mem_chunk(base, len, devmem))==NULL) {
    fprintf(stderr, "Table is unreachable, sorry."
#ifndef USE_MMAP
    "Try compiling dmidecode with -DUSE_MMAP.";
#endif
    "\n");
    return;
  }

  data=buf;
  while(i<num && data+4<=buf+len) /* 4 is the length of an SMBIOS structure header */ {
    u8 *next;
    struct dmi_header h;
    int display;

    int _FLAG_QUIET = 0;
    to_dmi_header(&h, data);
    display=((opt.type==NULL || opt.type[h.type])
      && !((opt.flags & _FLAG_QUIET) && (h.type>39 && h.type<=127))
      && !opt.string);

    /*
    ** If a short entry is found (less than 4 bytes), not only it
    ** is invalid, but we cannot reliably locate the next entry.
    ** Better stop at this point, and let the user know his/her
    ** table is broken.
    */
    if(h.length<4) {
      fprintf(stderr, "Invalid entry length (%i). DMI table is broken! Stop.", (unsigned int)h.length);
      break;
    }

    /* In quiet mode, stop decoding at end of table marker */
    //if((opt.flags & FLAG_QUIET) && h.type==127)
    //  break;

    //if(display && !(opt.flags & FLAG_QUIET)) {
    char hid[7];
    sprintf(hid, "0x%04x", h.handle);
    PyObject *hDict = PyDict_New();
    dmiSetItem(hDict, "dmi_handle", "0x%04x", h.handle);
    dmiSetItem(hDict, "dmi_type", "%d", h.type);
    dmiSetItem(hDict, "dmi_size", "%d", h.length);
    //fprintf(stderr, "Handle 0x%04x, DMI type %d, %d bytes", h.handle, h.type, h.length);
    //}

    /* assign vendor for vendor-specific decodes later */
    if(h.type==0 && h.length>=5)
      dmi_set_vendor(dmi_string(&h, data[0x04]));

    /* look for the next handle */
    next=data+h.length;
    while(next-buf+1<len && (next[0]!=0 || next[1]!=0))
      next++;

    next+=2;

    if(display) {
      if(next-buf<=len) {
        /* TODO: ...
        if(opt.flags & FLAG_DUMP) {
          PyDict_SetItem(hDict, PyString_FromString("lookup"), dmi_dump(&h));
        } else {
          //. TODO: //. Is the value of `i' important?...
          //. TODO: PyDict_SetItem(hDict, PyInt_FromLong(i), dmi_decode(&h, ver));
          //. TODO: ...removed and replaced with `data'...
          PyDict_SetItem(hDict, PyString_FromString("data"), dmi_decode(&h, ver));
          PyDict_SetItem(pydata, PyString_FromString(hid), hDict);
        }*/
        PyDict_SetItem(hDict, PyString_FromString("data"), dmi_decode(&h, ver));
        PyDict_SetItem(pydata, PyString_FromString(hid), hDict);
      } else fprintf(stderr, "<TRUNCATED>");
    } else if(opt.string!=NULL && opt.string->type==h.type) {
      dmi_table_string_py(&h, data, hDict, ver);
    }

    data=next;
    i++;
  }

  if(i!=num)
    fprintf(stderr, "Wrong DMI structures count: %d announced, only %d decoded.\n", num, i);
  if(data-buf!=len)
    fprintf(stderr, "Wrong DMI structures length: %d bytes announced, structures occupy %d bytes.\n",
      len, (unsigned int)(data-buf));

  free(buf);
}


int smbios_decode(u8 *buf, const char *devmem, PyObject* pydata) {
  if(pydata == NULL) return 1;
  if(!checksum(buf, buf[0x05]) || !memcmp(buf+0x10, "_DMI_", 5)==0 || !checksum(buf+0x10, 0x0F)) return 0;
  u16 ver = (buf[0x06] << 8) + buf[0x07];
  /* Some BIOS attempt to encode version 2.3.1 as 2.31, fix it up */
  if(ver == 0x021F) {
    printf("SMBIOS version fixup (2.31 -> 2.3).\n");
    ver = 0x0203;
  }
  dmiSetItem(pydata, "detected", "SMBIOS  %i.%i present.", ver>>8, ver&0xFF);
  dmi_table(DWORD(buf+0x18), WORD(buf+0x16), WORD(buf+0x1C), ver, devmem, pydata);
  //. XXX dmiSetItem(pydata, "table", dmi_string(&h, data[opt.string->offset]));

  //. TODO: DUMP
  /*
  if (opt.flags & FLAG_DUMP_BIN) {
    u8 crafted[32];

    memcpy(crafted, buf, 32);
    overwrite_dmi_address(crafted + 0x10);

    printf("# Writing %d bytes to %s.\n", crafted[0x05], opt.dumpfile);
    write_dump(0, crafted[0x05], crafted, opt.dumpfile, 1);
  }
  */

  return 1;
}


int legacy_decode(u8 *buf, const char *devmem, PyObject* pydata) {
  if(pydata == NULL) return 1;
  if(!checksum(buf, 0x0F)) return 0;

  printf("Legacy DMI %u.%u present.\n", buf[0x0E]>>4, buf[0x0E]&0x0F);
  dmiSetItem(pydata, "detected", "Legacy DMI %i.%i present.", buf[0x0E]>>4, buf[0x0E]&0x0F);
  dmi_table(DWORD(buf+0x08), WORD(buf+0x06), WORD(buf+0x0C), ((buf[0x0E]&0xF0)<<4)+(buf[0x0E]&0x0F), devmem, pydata);

  //. TODO: DUMP
  /*
  u8 crafted[16];
  memcpy(crafted, buf, 16);
  overwrite_dmi_address(crafted);
  printf("# Writing %d bytes to %s.\n", 0x0F, opt.dumpfile);
  write_dump(0, 0x0F, crafted, PyString_AS_STRING(opt.dumpfile), 1);
  */

  return 1;
}

/*******************************************************************************
** Probe for EFI interface
*/
int address_from_efi(size_t *address) {
  FILE *efi_systab;
  const char *filename;
  char linebuf[64];
  int ret;

  *address = 0; /* Prevent compiler warning */

  /*
  ** Linux <= 2.6.6: /proc/efi/systab
  ** Linux >= 2.6.7: /sys/firmware/efi/systab
  */
  if((efi_systab=fopen(filename="/sys/firmware/efi/systab", "r"))==NULL
  && (efi_systab=fopen(filename="/proc/efi/systab", "r"))==NULL) {
    /* No EFI interface, fallback to memory scan */
    return EFI_NOT_FOUND;
  }
  ret=EFI_NO_SMBIOS;
  while((fgets(linebuf, sizeof(linebuf)-1, efi_systab))!=NULL) {
    char *addrp=strchr(linebuf, '=');
    *(addrp++)='\0';
    if(strcmp(linebuf, "SMBIOS")==0) {
      *address=strtoul(addrp, NULL, 0);
      printf("# SMBIOS entry point at 0x%08lx\n", (unsigned long)*address);
      ret=0;
      break;
    }
  }
  if(fclose(efi_systab)!=0)
    perror(filename);

  if(ret==EFI_NO_SMBIOS)
    fprintf(stderr, "%s: SMBIOS entry point missing\n", filename);

  return ret;
}

/*
int submain(int argc, char * const argv[])
{
	int ret=0;                  / * Returned value * /
	int found=0;
	size_t fp;
	int efi;
	u8 *buf;

  char _[2048]; bzero(_, 2048);

	if(sizeof(u8)!=1 || sizeof(u16)!=2 || sizeof(u32)!=4 || '\0'!=0)
	{
		fprintf(stderr, "%s: compiler incompatibility\n", argv[0]);
		exit(255);
	}

	/ * Set default option values * /
	//. opt.devmem=DEFAULT_MEM_DEV;
	//. opt.flags=0;

	if(parse_command_line(argc, argv)<0)
	{
		ret=2;
		goto exit_free;
	}

	if(opt.flags & FLAG_HELP)
	{
		print_help();
		goto exit_free;
	}

	if(opt.flags & FLAG_VERSION)
	{
		sprintf(_, "%s\n", VERSION);
		goto exit_free;
	}
	
	if(!(opt.flags & FLAG_QUIET))
		sprintf(_, "# dmidecode %s\n", VERSION);
	

        / * Read from dump if so instructed * /
        if (opt.flags & FLAG_FROM_DUMP)
        {
                if (!(opt.flags & FLAG_QUIET))
                        printf("Reading SMBIOS/DMI data from file %s.\n",
                               opt.dumpfile);
                if ((buf = mem_chunk(0, 0x20, opt.dumpfile)) == NULL)
                {
                        ret = 1;
                        goto exit_free;
                }

                if (memcmp(buf, "_SM_", 4)==0)
                {
                        if (smbios_decode(buf, opt.dumpfile, NULL))
                                found++;
                }
                else if (memcmp(buf, "_DMI_", 5)==0)
                {
                        if (legacy_decode(buf, opt.dumpfile, NULL))
                                found++;
                }
                goto done;
        }


	/ * First try EFI (ia64, Intel-based Mac) * /
	efi=address_from_efi(&fp, _);
	switch(efi)
	{
		case EFI_NOT_FOUND:
			goto memory_scan;
		case EFI_NO_SMBIOS:
			ret=1;
			goto exit_free;
	}

	if((buf=mem_chunk(fp, 0x20, opt.devmem))==NULL)
	{
		ret=1;
		goto exit_free;
	}
	
	if(smbios_decode(buf, opt.devmem, NULL))
		found++;
	goto done;

memory_scan:
	/ * Fallback to memory scan (x86, x86_64) * /
	if((buf=mem_chunk(0xF0000, 0x10000, opt.devmem))==NULL)
	{
		ret=1;
		goto exit_free;
	}
	
	for(fp=0; fp<=0xFFF0; fp+=16)
	{
		if(memcmp(buf+fp, "_SM_", 4)==0 && fp<=0xFFE0)
		{
			if(smbios_decode(buf+fp, opt.devmem, NULL))
				found++;
			fp+=16;
		}
		else if(memcmp(buf+fp, "_DMI_", 5)==0)
		{
			if (legacy_decode(buf+fp, opt.devmem, NULL))
				found++;
		}
	}
	
done:
	free(buf);
	
	if(!found && !(opt.flags & FLAG_QUIET))
		fprintf(stderr, "# No SMBIOS nor DMI entry point found, sorry.\n");

exit_free:
	//. free(opt.type);

	return ret;
}
*/
