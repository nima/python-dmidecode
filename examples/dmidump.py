#!/usr/bin/env python2.4
import dmidecode
import sys
from pprint import pprint

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

_=[dmidecode.type(_) and pprint(dmidecode.type(_)) for _ in range(1,128)]
