#!/usr/bin/env python
#.awk '$0 ~ /case [0-9]+: .. 3/ { print $2 }' src/dmidecode.c|tr ':\n' ', '

from pprint import pprint
import os, sys

print "Importing module...",
import dmidecode
print "Done"

#. Test all functions using /dev/mem...
print "Testing bios...",      len(dmidecode.bios()) and "Good" or "Failed"
print "Testing system...",    dmidecode.system() and "Good" or "Failed"
print "Testing baseboard...", dmidecode.baseboard() and "Good" or "Failed"
print "Testing chassis...",   dmidecode.chassis() and "Good" or "Failed"
print "Testing processor...", dmidecode.processor() and "Good" or "Failed"
print "Testing memory...",    dmidecode.memory() and "Good" or "Failed"
print "Testing cache...",     dmidecode.cache() and "Good" or "Failed"
print "Testing connector...", dmidecode.connector() and "Good" or "Failed"
print "Testing slot...",      dmidecode.slot() and "Good" or "Failed"

if os.path.exists("/tmp/foo"):
  print "Removing old file..."
  os.unlink("/tmp/foo")

print "Testing check for write permission on dump...",
print not dmidecode.dump() and "Good" or "Bad"

print "Testing that default device is /dev/mem",
print dmidecode.get_dev() == "/dev/mem" and "Good" or "Bad"

print "Testing ability to change device to /tmp/foo...",
print dmidecode.set_dev("/tmp/foo") and "Good" or "Bad"

print "Testing that device has changed to /tmp/foo...",
print dmidecode.get_dev() == "/tmp/foo" and "Good" or "Bad"

print "Testing that write on new file is ok...",
print dmidecode.dump() and "Good" or "Bad"

print "Testing that file was actually written...",
print os.path.exists("/tmp/foo") and "Yes" or "No"

#print os.stat("/tmp/foo")

#. Now test get/set of memory device file...
#print dmidecode.get_dev()
#print dmidecode.set_dev("private/mem-XXX");
#print dmidecode.get_dev()

#. Test taking a dump...
dmidecode.dump()

for i in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 126, 127):
  print "Testing...", i, len(dmidecode.type(i)), "Done"

sys.exit(0)

#. Test reading the dump...
print "*** bios ***\n";      pprint(dmidecode.bios())
print "*** system ***\n";    pprint(dmidecode.system())
print "*** system ***\n";    pprint(dmidecode.system())
print "*** baseboard ***\n"; pprint(dmidecode.baseboard())
print "*** chassis ***\n";   pprint(dmidecode.chassis())
print "*** processor ***\n"; pprint(dmidecode.processor())
print "*** memory ***\n";    pprint(dmidecode.memory())
print "*** cache ***\n";     pprint(dmidecode.cache())
print "*** connector ***\n"; pprint(dmidecode.connector())
print "*** slot ***\n";      pprint(dmidecode.slot())

print "*** bios ***\n";      pprint(dmidecode.bios())
print "*** system ***\n";    pprint(dmidecode.system())
print "*** baseboard ***\n"; pprint(dmidecode.baseboard())
print "*** chassis ***\n";   pprint(dmidecode.chassis())
print "*** processor ***\n"; pprint(dmidecode.processor())
print "*** memory ***\n";    pprint(dmidecode.memory())
print "*** cache ***\n";     pprint(dmidecode.cache())
print "*** connector ***\n"; pprint(dmidecode.connector())
print "*** slot ***\n";      pprint(dmidecode.slot())


