/*. ******* coding:utf-8 AUTOHEADER START v1.1 *******
 *. vim: fileencoding=utf-8 syntax=c sw=8 ts=8 et
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
#include "dmilog.h"

#define MAXVAL 1024

typedef struct _dmi_codes_major {
        const unsigned short code;
        const char *id;
        const char *desc;
        const char *tagname;
} dmi_codes_major;

static const dmi_codes_major dmiCodesMajor[] = {
        {0, "7.1", "BIOS Information", "BIOSinfo"},
        {1, "7.2", "System Information", "SystemInfo"},
        {2, "7.3", "Base Board Information", "BaseBoardInfo"},
        {3, "7.4", "Chassis Information", "ChassisInfo"},
        {4, "7.5", "Processor Information", "ProcessorInfo"},
        {5, "7.6", "Memory Controller Information", "MemoryCtrlInfo"},
        {6, "7.7", "Memory Module Information", "MemoryModuleInfo"},
        {7, "7.8", "Cache Information", "CacheInfo"},
        {8, "7.9", "Port Connector Information", "PortConnectorInfo"},
        {9, "7.10", "System Slots", "SystemSlots"},
        {10, "7.11", "On Board Devices Information", "OnBoardDevicesInfo"},
        {11, "7.12", "OEM Strings", "OEMstrings"},
        {12, "7.13", "System Configuration Options", "SysConfigOptions"},
        {13, "7.14", "BIOS Language Information", "BIOSlanguage"},
        {14, "7.15", "Group Associations", "GroupAssoc"},
        {15, "7.16", "System Event Log", "SysEventLog"},
        {16, "7.17", "Physical Memory Array", "PhysicalMemoryArray"},
        {17, "7.18", "Memory Device", "MemoryDevice"},
        {18, "7.19", "32-bit Memory Error Information", "MemoryErrorInfo"},
        {19, "7.20", "Memory Array Mapped Address", "MemoryArrayMappedAddress"},
        {20, "7.21", "Memory Device Mapped Address", "MemoryDeviceMappedAddress"},
        {21, "7.22", "Built-in Pointing Device", "BuiltIntPointingDevice"},
        {22, "7.23", "Portable Battery", "PortableBattery"},
        {23, "7.24", "System Reset", "SystemReset"},
        {24, "7.25", "Hardware Security", "HardwareSecurity"},
        {25, "7.26", "System Power Controls", "SystemPowerCtrls"},
        {26, "7.27", "Voltage Probe", "Probe"},
        {27, "7.28", "Cooling Device", "CoolingDevice"},
        {28, "7.29", "Temperature Probe", "Probe"},
        {29, "7.30", "Electrical Current Probe", "Probe"},
        {30, "7.31", "Out-of-band Remote Access", "RemoteAccess"},
        {31, "7.32", "Boot Integrity Services Entry Point", "BootIntegrity"},
        {32, "7.33", "System Boot Information", "SystemBootInfo"},
        {33, "7.34", "64-bit Memory Error Information", "MemoryErrorInfo"},
        {34, "7.35", "Management Device", "ManagementDevice"},
        {35, "7.36", "Management Device Component", "ManagementDevice"},
        {36, "7.37", "Management Device Threshold Data", "ManagementDevice"},
        {37, "7.38", "Memory Channel", "MemoryChannel"},
        {38, "7.39", "IPMI Device Information", "IPMIdeviceInfo"},
        {39, "7.40", "System Power Supply", "SystemPowerSupply"},
        {40, "7.41", "-------------------", "Unknown"},
        {41, "7.42", "Onboard Device Extended Information", "OnBoardDevicesExtendedInfo"},
        {41, "7.43", "Management Controller Host Interface", "MgmntCtrltHostIntf"},
        {126, "7.44", "Inactive", "Inactive"},
        {127, "7.45", "End Of Table", "EndOfTable"},

        {-1, NULL, NULL, NULL}
};

/*** dmiopt.h ***/
typedef struct _options {
        const char *devmem;
        unsigned int flags;
        int type;
        xmlDoc *mappingxml;
        char *python_xml_map;
        xmlNode *dmiversion_n;
        char *dumpfile;
        Log_t *logdata;
} options;

#endif
