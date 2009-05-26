from distutils.core import setup, Extension

setup(
  name = "python-dmidecode",
  version = "3.10.6",
  license='GPL-2',
  description = "Python extension module for dmidecode",
  author = "Nima Talebi & David Sommerseth",
  author_email = "nima@it.net.au, davids@redhat.com",
  url = "http://projects.autonomy.net.au/python-dmidecode/",
  data_files = [ ('share/python-dmidecode', ['src/pymap.xml']) ],
  ext_modules = [
    Extension(
      "dmidecode",
      sources      = [
        "src/dmidecodemodule.c",
        "src/dmihelper.c",
        "src/util.c",
        "src/dmioem.c",
        "src/dmidecode.c",
        "src/dmixml.c",
        "src/xmlpythonizer.c"
      ],
      include_dirs = [ "/usr/include/libxml2" ],
      library_dirs = [ "/home/nima/dev-room/projects/dmidecode" ],
      libraries    = [ "util", "xml2" ]
    )
  ]
)
