#include "catsprintf.h"

static const int map_maj[] = {
  0,   1,  2,  3,  4,  5,  6,  7,  8,  9,
  10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
  20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
  30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
  126, 127
};

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

dmi_minor* dmiAppendObject(long code, char const *key, const char *format, ...) {
  static dmi_minor* last = NULL;

  //. int minor = code&0x00FF;
  //. int major = code>>8;
  va_list arg;
  va_start(arg, format);

  dmi_minor *o = (dmi_minor *)malloc(sizeof(dmi_minor));
  o->id = code;
  o->major = (dmi_codes_major*)&dmiCodesMajor[map_maj[code>>8]];
  o->key = (char *)key;
  vsprintf(o->value, format, arg);
  o->next = last;

  va_end(arg); /* cleanup */
  last = o;

  return o;
}

int dmiSetItem(PyObject* dict, const char *key, const char *format, ...) {
  va_list arg;
  va_start(arg, format);
  char buffer[2048];
  vsprintf(buffer, format, arg);
  va_end(arg);
  //printf("DEBUG: Setting k:%s, f:%s s:%s...", key, format, buffer);
  PyDict_SetItem(dict, Py_BuildValue("s", key), Py_BuildValue("s", buffer));
  //printf("Done.\n");
  return 0;
}

int catsprintf(char *buf, const char *format, ...) {
  if(format == NULL) {
    bzero(buf, strlen(buf));
    return 0;
  }

  va_list arg; /* will point to each unnamed argument in turn */
  va_start(arg, format); /* point to first element after fmt */

  char b[8192];
  int c = vsprintf (b, format, arg);

  strcat(buf, b);
  va_end(arg); /* cleanup */

  return c;
}
