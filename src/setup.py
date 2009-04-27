from distutils.core import setup, Extension

setup(
  name = "python-dmidecode",
  version = "2.10.5",
  description = "Python extension module for dmidecode",
  author = "Nima Talebi",
  author_email = "nima@autonomy.net.au",
  url = "http://projects.autonomy.net.au/dmidecode/",
  ext_modules = [
    Extension(
      "dmidecode",
      sources      = [
        "src/dmidecodemodule.c",
        "src/dmihelper.c",
        "src/util.c",
        "src/dmioem.c",
        "src/dmidecode.c"
      ],
      library_dirs = [ "/home/nima/dev-room/projects/dmidecode" ],
      libraries    = [ "util" ],
      #libraries    = [ "util", "efence" ],
    )
  ]
)
