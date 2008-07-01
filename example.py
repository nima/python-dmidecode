#!/usr/bin/python

def l(x):
  return len(x)

import dmidecode, time
print(dir(dmidecode))

print "proc", l(dmidecode.processor())
print "sys",  l(dmidecode.system())
print "bios", l(dmidecode.bios())
print "proc", l(dmidecode.processor())
print "sys",  l(dmidecode.system())
print "bios", l(dmidecode.bios())
