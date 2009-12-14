#!/usr/bin/env python
import dmidecode
import sys
from pprint import pprint

#. Test all functions using /dev/mem...
print "*** bios ***\n";      dmidecode.bios()
print "*** system ***\n";    dmidecode.system()
print "*** system ***\n";    dmidecode.system()
print "*** baseboard ***\n"; dmidecode.baseboard()
print "*** chassis ***\n";   dmidecode.chassis()
print "*** processor ***\n"; dmidecode.processor()
print "*** memory ***\n";    dmidecode.memory()
print "*** cache ***\n";     dmidecode.cache()
print "*** connector ***\n"; dmidecode.connector()
print "*** slot ***\n";      dmidecode.slot()

#. Now test get/set of memory device file...
print dmidecode.get_dev()
print dmidecode.set_dev("private/mem-XXX");
print dmidecode.get_dev()

#. Test taking a dump...
print dmidecode.dump()

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

sys.exit(0)
print "*** bios ***\n";      pprint(dmidecode.bios())
print "*** system ***\n";    pprint(dmidecode.system())
print "*** baseboard ***\n"; pprint(dmidecode.baseboard())
print "*** chassis ***\n";   pprint(dmidecode.chassis())
print "*** processor ***\n"; pprint(dmidecode.processor())
print "*** memory ***\n";    pprint(dmidecode.memory())
print "*** cache ***\n";     pprint(dmidecode.cache())
print "*** connector ***\n"; pprint(dmidecode.connector())
print "*** slot ***\n";      pprint(dmidecode.slot())

for v in dmidecode.memory().values():
  if type(v) == dict and v['dmi_type'] == 17:
    pprint(v['data']['Size']),

pprint(dmidecode.type('3'))
pprint(dmidecode.type('bios'))
