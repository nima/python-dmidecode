#!/usr/bin/env python
#.awk '$0 ~ /case [0-9]+: .. 3/ { print $2 }' src/dmidecode.c|tr ':\n' ', '

from pprint import pprint
import os, sys, random

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
if os.path.exists("/tmp/foo"):
  sys.stdout.write("Good\n")
  os.unlink("/tmp/foo")
else:
  sys.stdout.write("FAILED\n")

types = range(0, 42)+range(126, 128)
types = range(0, 42)+[126, 127]
sections = ["bios", "system", "baseboard", "chassis", "processor", "memory", "cache", "connector", "slot"]
devices = [os.path.join("private", _) for _ in os.listdir("private")]
devices.remove('private/.svn')
devices.append("/dev/mem")
random.shuffle(types)
random.shuffle(devices)
random.shuffle(sections)

total = 0
success = 0
for dev in devices:
  sys.stdout.write(" * Testing %s..."%dmidecode.get_dev()); sys.stdout.flush()
  total += 1
  if dmidecode.set_dev(dev):
    success += 1
    sys.stdout.write("...\n")
    for i in types:
      sys.stdout.write("   * Testing type %i..."%i); sys.stdout.flush()
      output = len(dmidecode.type(i))
      total += 1
      if output:
        sys.stdout.write("Done\n")
        success += 1
      else:
        sys.stdout.write("FAILED\n")
    for section in sections:
      total += 1
      sys.stdout.write("   * Testing %s..."%section); sys.stdout.flush()
      output = getattr(dmidecode, section)
      if output:
        sys.stdout.write("Done\n")
        success += 1
      else:
        sys.stdout.write("FAILED\n")
  else:
    sys.stdout.write("FAILED\n")

print "Score: %d/%d"%(success, total)
