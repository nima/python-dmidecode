#!/usr/bin/env python
#.awk '$0 ~ /case [0-9]+: .. 3/ { sys.stdout.write($2 }' src/dmidecode.c|tr ':\n' ', '

from pprint import pprint
import os, sys, random, tempfile, time
import commands

DUMPS_D = "private"

def ascii(s, i): return "\033[%d;1m%s\033[0m"%(30+i, str(s))
def black(s): return "\033[30;1m%s\033[0m"%(str(s))
def red(s): return "\033[31;1m%s\033[0m"%(str(s))
def green(s): return "\033[32;1m%s\033[0m"%(str(s))
def yellow(s): return "\033[33;1m%s\033[0m"%(str(s))
def blue(s): return "\033[34;1m%s\033[0m"%(str(s))
def magenta(s): return "\033[35;1m%s\033[0m"%(str(s))
def cyan(s): return "\033[36;1m%s\033[0m"%(str(s))
def white(s): return "\033[37;1m%s\033[0m"%(str(s))

DISPATCH = {
  1 : red,
  2 : green,
  3 : yellow,
  4 : blue,
  5 : magenta,
  6 : cyan,
  7 : white,
}

LINE = "%s\n"%(magenta("="*80))

score = {
  "total"   : 0,
  "skipped" : 0,
  "passed"  : 0,
  "failed"  : 0,
}

def passed(msg=None, indent=1):
  global score
  score["total"] += 1
  score["passed"] += 1
  sys.stdout.write("%s\n"%green("PASS"))
  if msg: sys.stdout.write("%s %s %s\n"%("  "*indent, green("P"), msg))
def skipped(msg=None, indent=1):
  global score
  score["total"] += 1
  score["skipped"] += 1
  sys.stdout.write("%s\n"%yellow("SKIP"))
  if msg: sys.stdout.write("%s %s %s\n"%("  "*indent, yellow("S"), msg))
def failed(msg=None, indent=1):
  global score
  score["total"] += 1
  score["failed"] += 1
  sys.stdout.write("%s\n"%red("FAIL"))
  if msg: sys.stdout.write("%s %s %s\n"%("  "*indent, red("F"), msg))
def test(r, msg=None, indent=1):
  if r:
    passed(msg, indent)
    return True
  else:
    failed(msg, indent)
    return False

sys.stdout.write(LINE)
sys.stdout.write(" * Testing for access to /dev/mem...")
d = True in [os.path.exists(os.path.join(_, "dmidecode")) for _ in os.getenv("PATH").split(':')]
test(d, "Please install `dmidecode' (the binary) for complete testing.", 1)

sys.stdout.write(" * Creation of temporary files...")
try:
  FH, DUMP = tempfile.mkstemp()
  os.unlink(DUMP)
  os.close(FH)
  passed()
except:
  failed()

sys.stdout.write(LINE)
sys.stdout.write(" * Importing module...")
try:
  import dmidecode
  passed()
  sys.stdout.write("   * Version: %s\n"%blue(dmidecode.version))
  sys.stdout.write("   * DMI Version String: %s\n"%blue(dmidecode.dmi))

  sys.stdout.write(" * Testing that default device is /dev/mem...")
  test(dmidecode.get_dev() == "/dev/mem")

  sys.stdout.write(" * Testing that write-lock will not break on dump()...")
  test(not dmidecode.dump())

  sys.stdout.write(" * Testing ability to change device to %s..."%DUMP)
  test(dmidecode.set_dev(DUMP))

  sys.stdout.write(" * Testing that device has changed to %s..."%DUMP)
  test(dmidecode.get_dev() == DUMP)

  sys.stdout.write(" * Testing that write on new file is ok...")
  test(dmidecode.dump())

  sys.stdout.write(" * Testing that file was actually written...")
  time.sleep(0.1)
  if test(os.path.exists(DUMP)):
    os.unlink(DUMP)

  types = range(0, 42)+range(126, 128)
  bad_types = [-1, -1000, 256]
  sections = ["bios", "system", "baseboard", "chassis", "processor", "memory", "cache", "connector", "slot"]
  devices = []
  if os.path.exists(DUMPS_D):
    devices.extend([os.path.join(DUMPS_D, _) for _ in os.listdir(DUMPS_D)])
  else:
    sys.stdout.write(" * If you have memory dumps to test, create a directory called `%s' and drop them in there.\n"%(DUMPS_D))
  devices.append("/dev/mem")
  random.shuffle(types)
  random.shuffle(devices)
  random.shuffle(sections)

  for dev in devices:
    sys.stdout.write(LINE)
    sys.stdout.write(" * Testing %s..."%yellow(dev)); sys.stdout.flush()
    if test(dmidecode.set_dev(dev) and dmidecode.get_dev() == dev):
      i = 0
      for section in sections:
        i += 1
        sys.stdout.write("   * Testing %s (%d/%d)..."%(cyan(section), i, len(sections))); sys.stdout.flush()
        try:
          output = getattr(dmidecode, section)()
          test(output is not False)
          if output:
            sys.stdout.write("     * %s\n"%black(output.keys()))
        except LookupError, e:
          failed(e, 2)
        except IOError:
          skipped("Permission denied", 2)

      for i in bad_types:
        sys.stdout.write("   * Testing bad type %s..."%red(i)); sys.stdout.flush()
        try:
          output = dmidecode.type(i)
          test(output is False)
        except SystemError:
          failed()

      for i in types:
        sys.stdout.write("   * Testing type %s..."%red(i)); sys.stdout.flush()
        try:
          output = dmidecode.type(i)
          if dmidecode:
            _output = commands.getoutput("dmidecode -t %d"%i).strip().split('\n')
            test(len(_output) == 1 and len(output) == 0 or True)
          else:
            test(output is not False)
          if output:
            sys.stdout.write("     * %s\n"%output.keys())
        except:
          failed()

except ImportError:
  failed()

sys.stdout.write(LINE)
sys.stdout.write("Total   : %s\n"%blue(score["total"]))
sys.stdout.write("Skipped : %s\n"%yellow(score["skipped"]))
sys.stdout.write("Passed  : %s\n"%green(score["passed"]))
sys.stdout.write("Failed  : %s\n"%red(score["failed"]))
