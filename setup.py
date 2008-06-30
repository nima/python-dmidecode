from distutils.core import setup, Extension

setup(name = "DMIDecode",
      version = "1.0",
      ext_modules = [Extension("dmidecode", ["dmidecodemodule.c"])])
