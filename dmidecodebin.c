//. This file now produces the executable `dmidecode', and dynamically links
//. against libdmidecode.so.
#include <Python.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "version.h"
#include "config.h"
#include "types.h"
#include "util.h"
#include "dmidecode.h"
#include "dmiopt.h"
#include "dmioem.h"

#define EFI_NOT_FOUND   (-1)
#define EFI_NO_SMBIOS   (-2)

#include "global.h"
#include "catsprintf.h"

extern const char *dmi_dump(struct dmi_header *h, char *_);
extern void dmi_decode(struct dmi_header *h, u16 ver);
extern int address_from_efi(size_t *address, char *_);
extern void to_dmi_header(struct dmi_header *h, u8 *data);
extern void dmi_table(u32 base, u16 len, u16 num, u16 ver, const char *devmem);
extern int smbios_decode(u8 *buf, const char *devmem, PyObject* pydata);
extern int legacy_decode(u8 *buf, const char *devmem, PyObject* pydata);
extern int submain(int argc, char * const argv[]);

int main(int argc, char * const argv[]) {
  bzero(buffer, 50000);
  int r = submain(argc, argv);
  printf("%s", buffer);
  return r;
}
