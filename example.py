#!/usr/bin/python

def l(x):
  return x

  for k in x.keys():
    print "  %x"%k, "==>", len(x[k])
  return len(x)

import dmidecode, time
#print(dir(dmidecode))

print "bios\n", l(dmidecode.bios())
#print "proc\n", l(dmidecode.processor())
#print "sys\n",  l(dmidecode.system())
#print "bios\n", l(dmidecode.bios())

#print "proc\n", l(dmidecode.processor())
#print "sys\n",  l(dmidecode.system())
#print "bios\n", l(dmidecode.bios())
