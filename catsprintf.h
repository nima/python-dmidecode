#ifndef CAT
#define CAT 1

#include <Python.h>

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define MAXVAL 1024

static const int map_maj[] = {
  0,   1,  2,  3,  4,  5,  6,  7,  8,  9,
  10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
  20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
  30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
  126, 127
};

typedef struct _dmi_codes_major {
  const unsigned short code;
  const char *id;
  const char *desc;
} dmi_codes_major;

static const dmi_codes_major dmiCodesMajor[] = {
  { 0,   "3.3.1",  "BIOS Information" },
  { 1,   "3.3.2",  "System Information" },
  { 2,   "3.3.3",  "Base Board Information" },
  { 3,   "3.3.4",  "Chassis Information" },
  { 4,   "3.3.5",  "Processor Information" },
  { 5,   "3.3.6",  "Memory Controller Information" },
  { 6,   "3.3.7",  "Memory Module Information" },
  { 7,   "3.3.8",  "Cache Information" },
  { 8,   "3.3.9",  "Port Connector Information" },
  { 9,   "3.3.10", "System Slots" },
  { 10,  "3.3.11", "On Board Devices Information" },
  { 11,  "3.3.12", "OEM Strings" },
  { 12,  "3.3.13", "System Configuration Options" },
  { 13,  "3.3.14", "BIOS Language Information" },
  { 14,  "3.3.15", "Group Associations" },
  { 15,  "3.3.16", "System Event Log" },
  { 16,  "3.3.17", "Physical Memory Array" },
  { 17,  "3.3.18", "Memory Device" },
  { 18,  "3.3.19", "32-bit Memory Error Information" },
  { 19,  "3.3.20", "Memory Array Mapped Address" },
  { 20,  "3.3.21", "Memory Device Mapped Address" },
  { 21,  "3.3.22", "Built-in Pointing Device" },
  { 22,  "3.3.23", "Portable Battery" },
  { 23,  "3.3.24", "System Reset" },
  { 24,  "3.3.25", "Hardware Security" },
  { 25,  "3.3.26", "System Power Controls" },
  { 26,  "3.3.27", "Voltage Probe" },
  { 27,  "3.3.28", "Cooling Device" },
  { 28,  "3.3.29", "Temperature Probe" },
  { 29,  "3.3.30", "Electrical Current Probe" },
  { 30,  "3.3.31", "Out-of-band Remote Access" },
  { 31,  "3.3.32", "Boot Integrity Services Entry Point" },
  { 32,  "3.3.33", "System Boot Information" },
  { 33,  "3.3.34", "64-bit Memory Error Information" },
  { 34,  "3.3.35", "Management Device" },
  { 35,  "3.3.36", "Management Device Component" },
  { 36,  "3.3.37", "Management Device Threshold Data" },
  { 37,  "3.3.38", "Memory Channel" },
  { 38,  "3.3.39", "IPMI Device Information" },
  { 39,  "3.3.40", "System Power Supply" },
  { 126, "3.3.41", "Inactive" },
  { 127, "3.3.42", "End Of Table" },
};

typedef struct _dmi_minor {
  long id;
  dmi_codes_major* major;
  char *key;
  char value[MAXVAL];
  struct _dmi_minor* next;
} dmi_minor;

int catsprintf(char *buf, const char *format, ...);
void dmiAppendData(PyObject *pydata, const int count);
dmi_minor* dmiAppendObject(long code, char const *key, const char *format, ...);
int dmiSetItem(PyObject* dict, const char *key, const char *format, ...);

#endif
