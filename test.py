#!/usr/bin/env python
#.awk '$0 ~ /case [0-9]+: .. 3/ { sys.stdout.write($2 }' src/dmidecode.c|tr ':\n' ', '

from pprint import pprint
import os, sys, random, tempfile, time

FH, DUMP = tempfile.mkstemp()
os.unlink(DUMP)
os.close(FH)

total = 0
success = 0

def test(r):
  global total
  global success

  total += 1
  if r:
    sys.stdout.write("Good\n")
    success += 1
  else:
    sys.stdout.write("Bad\n")

total += 1
sys.stdout.write("Importing module...")
try:
  import dmidecode
  sys.stdout.write("Done\n")
  success += 1
  sys.stdout.write(" * Version: %s\n"%dmidecode.version)
  sys.stdout.write(" * DMI Version String: %s\n"%dmidecode.dmi)

  sys.stdout.write("Testing that default device is /dev/mem...")
  test(dmidecode.get_dev() == "/dev/mem")

  sys.stdout.write("Testing that write-lock will not break on dump()...")
  test(not dmidecode.dump())

  sys.stdout.write("Testing ability to change device to %s..."%DUMP)
  test(dmidecode.set_dev(DUMP))

  sys.stdout.write("Testing that device has changed to %s..."%DUMP)
  test(dmidecode.get_dev() == DUMP)

  sys.stdout.write("Testing that write on new file is ok...")
  test(dmidecode.dump())

  sys.stdout.write("Testing that file was actually written...")
  time.sleep(0.1)
  test(os.path.exists(DUMP))
  os.unlink(DUMP)

  types = range(0, 42)+range(126, 128)
  types = range(0, 42)+[126, 127]
  sections = ["bios", "system", "baseboard", "chassis", "processor", "memory", "cache", "connector", "slot"]
  devices = [os.path.join("private", _) for _ in os.listdir("private")]
  devices.remove('private/.svn')
  devices.append("/dev/mem")
  random.shuffle(types)
  random.shuffle(devices)
  random.shuffle(sections)

  for dev in devices:
    sys.stdout.write(" * Testing %s..."%dev); sys.stdout.flush()
    total += 1
    if dmidecode.set_dev(dev) and dmidecode.get_dev() == dev:
      success += 1
      sys.stdout.write("...\n")
      for i in types:
        total += 1
        sys.stdout.write("   * Testing type %i..."%i); sys.stdout.flush()
        output = dmidecode.type(i).keys()
        sys.stdout.write("Done (%s)\n"%output)
        success += 1
      for section in sections:
        total += 1
        sys.stdout.write("   * Testing %s..."%section); sys.stdout.flush()
        output = getattr(dmidecode, section)().keys()
        sys.stdout.write("Done (%s)\n"%output)
        success += 1
    else:
      sys.stdout.write("FAILED\n")

except ImportError:
  sys.stdout.write("FAILED\n")

sys.stdout.write("Score: %d/%d\n"%(success, total))
