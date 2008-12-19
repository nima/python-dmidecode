#!/usr/bin/env python
#.awk '$0 ~ /case [0-9]+: .. 3/ { print $2 }' src/dmidecode.c|tr ':\n' ', '

from pprint import pprint
import os, sys

print "Importing module...",
import dmidecode
print "Done"

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

dmidecode.dump()
os.unlink("/tmp/foo")

#print os.stat("/tmp/foo")

#. Now test get/set of memory device file...
#print dmidecode.get_dev()
#print dmidecode.set_dev("private/mem-XXX");
#print dmidecode.get_dev()

#. Test taking a dump...

#. Test all functions using /dev/mem...

devices = [os.path.join("private", _) for _ in os.listdir("private")]
devices.remove('private/.svn')
devices.append("/dev/mem")
for dev in devices:
  sys.stdout.write(" * Testing %s..."%dmidecode.get_dev())
  if dmidecode.set_dev(dev):
    sys.stdout.write("...\n")
    for section in ["bios", "system", "baseboard", "chassis", "processor", "memory", "cache", "connector", "slot"]:
      sys.stdout.write("   * Testing %s..."%section)
      output = getattr(dmidecode, section)
      sys.stdout.write(output and "Done\n" or "FAILED\n")
    for i in tuple(range(0, 42))+tuple(range(126, 128)):
      sys.stdout.write("   * Testing...")
      output = len(dmidecode.type(i))
      sys.stdout.write(output and "Done (%d)\n"%i or "FAILED\n")
  else:
    sys.stdout.write("FAILED\n")
