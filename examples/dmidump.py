#!/usr/bin/env python
#
#   Examples which makes use of the different python-dmidecode features
#   This script should be run as root, or else expect permission warnings
#
#   Copyright 2008-2009 Nima Talebi <nima@autonomy.net.au>
#   Copyright 2010      David Sommerseth <davids@redhat.com>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
#
#   For the avoidance of doubt the "preferred form" of this code is one which
#   is in an open unpatent encumbered format. Where cryptographic key signing
#   forms part of the process of creating an executable the information
#   including keys needed to generate an equivalently functional executable
#   are deemed to be part of the source code.
#

import dmidecode
import sys, os
from pprint import pprint

def print_warnings():
        "Simple function, dumping out warnings with a prefix if warnings are found and clearing warning buffer"
        warn = dmidecode.get_warnings()
        if warn:
              print("### WARNING: %s" % warn)
              dmidecode.clear_warnings()


# Check if running as root .... provide a warning if not
root_user = (os.getuid() == 0 and True or False)
if not root_user:
        print("####")
        print("####  NOT RUNNING AS ROOT")
        print("####")
        print("#### The first run must always be done as root for this example to work.")
        print("#### When not run as root, quite some permission errors might appear")
        print("####")
        print("#### If this script is first run as root, it should be possible to run this script")
        print("#### as an unprivileged user afterwards, with less warnings.")
        print("####")
        print()
        print()


#. Test for presence of important functions using /dev/mem...  Using the legacy API
#. This does not print any decoded info.  If the call fails, either a warning will
#. be issued or an exception will be raised.  This test is now only used to check
#. for presence of the legacy API, which "under the hood" uses
#. dmidecode.QuerySection(name), where name can be 'bios', 'system', etc.
if root_user:
        print("*** bios ***\n");      dmidecode.bios()
        print_warnings()
        print("*** system ***\n");    dmidecode.system()
        print_warnings()
        print("*** baseboard ***\n"); dmidecode.baseboard()
        print_warnings()
        print("*** chassis ***\n");   dmidecode.chassis()
        print_warnings()
        print("*** processor ***\n"); dmidecode.processor()
        print_warnings()
        print("*** memory ***\n");    dmidecode.memory()
        print_warnings()
        print("*** cache ***\n");     dmidecode.cache()
        print_warnings()
        print("*** connector ***\n"); dmidecode.connector()
        print_warnings()
        print("*** slot ***\n");      dmidecode.slot()
        print_warnings()


#. Now test get/set of memory device file...
print("*** get_dev()")
print(dmidecode.get_dev())
print_warnings()
print("*** set_dev('dmidata.dump')")
print(dmidecode.set_dev("dmidata.dump"));
print_warnings()
print("*** get_dev()")
print(dmidecode.get_dev())
print_warnings()

#. Test taking a dump...
if root_user:
        print("*** Dumping DMI data to dump file")
        print(dmidecode.dump())
        print_warnings()

#. Test reading the dump...  Using the preferred API
print("*** bios ***\n");      pprint(dmidecode.QuerySection('bios'))
print_warnings()
print("*** system ***\n");    pprint(dmidecode.QuerySection('system'))
print_warnings()
print("*** baseboard ***\n"); pprint(dmidecode.QuerySection('baseboard'))
print_warnings()
print("*** chassis ***\n");   pprint(dmidecode.QuerySection('chassis'))
print_warnings()
print("*** processor ***\n"); pprint(dmidecode.QuerySection('processor'))
print_warnings()
print("*** memory ***\n");    pprint(dmidecode.QuerySection('memory'))
print_warnings()
print("*** cache ***\n");     pprint(dmidecode.QuerySection('cache'))
print_warnings()
print("*** connector ***\n"); pprint(dmidecode.QuerySection('connector'))
print_warnings()
print("*** slot ***\n");      pprint(dmidecode.QuerySection('slot'))
print_warnings()

print("*** Extracting memory information")
for v in dmidecode.memory().values():
  if type(v) == dict and v['dmi_type'] == 17:
    pprint(v['data']['Size']),

print("*** Querying for DMI type 3 and 7")
pprint(dmidecode.type(3))        # <-- Legacy API
pprint(dmidecode.QueryTypeId(7)) # <-- preferred API
print_warnings()

print("*** Querying for the BIOS section")
pprint(dmidecode.QuerySection('bios'))
print_warnings()

#
# Test XML stuff
#
print()
print()
print()
print("---------------------------------------")
print("*** *** *** Testing XML API *** *** ***")
print("---------------------------------------")
print()
print()
dmixml = dmidecode.dmidecodeXML()

# Fetch all DMI data into a libxml2.xmlDoc object
print("*** Getting all DMI data into a XML document variable")
dmixml.SetResultType(dmidecode.DMIXML_DOC)  # Valid values: dmidecode.DMIXML_DOC, dmidecode.DMIXML_NODE
xmldoc = dmixml.QuerySection('all')

# Dump the XML to dmidump.xml - formated in UTF-8 decoding
print("*** Dumping XML document to dmidump.xml")
xmldoc.saveFormatFileEnc('dmidump.xml','UTF-8',1)

# Do some XPath queries on the XML document
print("*** Doing some XPath queries against the XML document")
dmixp = xmldoc.xpathNewContext()

# What to look for - XPath expressions
keys = ['/dmidecode/SystemInfo/Manufacturer',
	'/dmidecode/SystemInfo/ProductName',
	'/dmidecode/SystemInfo/SerialNumber',
	'/dmidecode/SystemInfo/SystemUUID']

# Extract data and print it
for k in keys:
	data = dmixp.xpathEval(k)
	for d in data:
		print("%s: %s" % (k, d.get_content()))

del dmixp
del xmldoc

# Query for only a particular DMI TypeID - 0x04 - Processor
print("*** Quering for Type ID 0x04 - Processor - dumping XML document to stdout")
dmixml.QueryTypeId(0x04).saveFormatFileEnc('-','UTF-8',1)
print_warnings()
