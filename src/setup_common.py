#
#   setup-common.py
#   Helper functions for retrieving libxml2 arguments needed for compilation
#   and other functions which is used in both setup.py and setup-dbg.py
#
#   Copyright 2009      David Sommerseth <davids@redhat.com>
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

import commands, sys
from os import path as os_path
from distutils.sysconfig import get_python_lib

# libxml2 - C flags
def libxml2_include(incdir):
    (res, libxml2_cflags) = commands.getstatusoutput("xml2-config --cflags")
    if res != 0:
        print "Could not build python-dmidecode."
        print "Could not run xml2-config, is libxml2 installed?"
        print "Also the development libraries?"
        sys.exit(1)

    # Parse the xml2-config --cflags response
    for l in libxml2_cflags.split(" "):
        if l.find('-I') == 0:
            incdir.append(l.replace("-I", "", 1))



# libxml2 - library flags
def libxml2_lib(libdir, libs):
    libdir.append(get_python_lib(1))
    if os_path.exists("/etc/debian_version"): #. XXX: Debian Workaround...
        libdir.append("/usr/lib/pymodules/python%d.%d"%sys.version_info[0:2])

    (res, libxml2_libs) = commands.getstatusoutput("xml2-config --libs")
    if res != 0:
        print "Could not build python-dmidecode."
        print "Could not run xml2-config, is libxml2 installed?"
        print "Also the development libraries?"
        sys.exit(1)

    # Parse the xml2-config --libs response
    for l in libxml2_libs.split(" "):
        if l.find('-L') == 0:
            libdir.append(l.replace("-L", "", 1))
        elif l.find('-l') == 0:
            libs.append(l.replace("-l", "", 1))

    # this library is not reported and we need it anyway
    libs.append('xml2mod')



# Get version from src/version.h
def get_version():
    version = "0.0.0"
    try:
        f = open("src/version.h")
    except:
        f = open("version.h")

    try:
        for line in f:
            part = line.split(" ")
            if part[0] == "#define":
                if part[1] == "VERSION":
                    version = part[2].strip().strip('"')
                    break
    finally:
        f.close()

    return version

def get_macros():
    "Sets macros which is relevant for all setup*.py files"

    macros = []
    if sys.byteorder == 'big':
        macros.append(("ALIGNMENT_WORKAROUND", None))
    return macros

