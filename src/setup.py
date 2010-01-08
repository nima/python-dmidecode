#
#   setup.py
#   Python distutil package setup
#
#   Copyright 2009      David Sommerseth <davids@redhat.com>
#   Copyright 2007-2009 Nima Talebi <nima@autonomy.net.au>
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

from distutils.core import setup, Extension
from setup_common import *

#
#  Some default values
#
incdir = []
libdir = []
libs = []

# Get libxml2 info
libxml2_include(incdir)
libxml2_lib(libdir, libs)

# misc info
dmidec_version = get_version()
macros = get_macros()

#
#  Python setup
#

setup(
  name = "python-dmidecode",
  version = dmidec_version,
  license='GPL-2',
  description = "Python extension module for dmidecode",
  author = "Nima Talebi & David Sommerseth",
  author_email = "nima@it.net.au, davids@redhat.com",
  url = "http://projects.autonomy.net.au/python-dmidecode/",
  data_files = [ ('share/python-dmidecode', ['src/pymap.xml']) ],
  ext_modules = [
    Extension(
      "dmidecodemod",
      sources      = [
        "src/dmidecodemodule.c",
        "src/util.c",
        "src/dmioem.c",
        "src/dmidecode.c",
        "src/dmixml.c",
        "src/dmierror.c",
        "src/dmilog.c",
        "src/xmlpythonizer.c",
        "src/efi.c",
        "src/dmidump.c"
      ],
      include_dirs = incdir,
      library_dirs = libdir,
      libraries    = libs,
      undef_macros = [ "NDEBUG" ],
      define_macros = macros
    )
  ],
  py_modules = [ "dmidecode" ]
)
