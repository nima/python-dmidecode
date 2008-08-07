#!/usr/bin/python
import dmidecode
import sys
from pprint import pprint

print "*** cache ***\n", dmidecode.cache()

#sys.exit(0)

#print "*** bios ***\n", pprint(dmidecode.bios())
#print "*** system ***\n", pprint(dmidecode.system())
#print "*** baseboard ***\n", pprint(dmidecode.baseboard())
#print "*** chassis ***\n", pprint(dmidecode.chassis())
#print "*** processor ***\n", pprint(dmidecode.processor())
#print "*** memory ***\n", pprint(dmidecode.memory())
#print "*** cache ***\n", pprint(dmidecode.cache())
#print "*** connector ***\n", pprint(dmidecode.connector())
#print "*** slot ***\n", pprint(dmidecode.slot())
