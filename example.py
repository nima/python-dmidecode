#!/usr/bin/python

def l(x):
  return x

  for k in x.keys():
    print "  %x"%k, "==>", len(x[k])
  return len(x)

import dmidecode, time

#print "*** bios ***\n", l(dmidecode.bios())
#print "*** system ***\n", l(dmidecode.system())
#print "*** baseboard ***\n", l(dmidecode.baseboard())
#print "*** chassis ***\n", l(dmidecode.chassis())
#print "*** processor ***\n", l(dmidecode.processor())
#print "*** memory ***\n", l(dmidecode.memory())
print "*** cache ***\n", l(dmidecode.cache())
print "*** connector ***\n", l(dmidecode.connector())
print "*** slot ***\n", l(dmidecode.slot())
