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

extern void dmi_dump(struct dmi_header *h, const char *prefix);
extern void dmi_decode(struct dmi_header *h, u16 ver);
extern int address_from_efi(size_t *address);
extern void to_dmi_header(struct dmi_header *h, u8 *data);
extern void dmi_table(u32 base, u16 len, u16 num, u16 ver, const char *devmem);
extern int smbios_decode(u8 *buf, const char *devmem);
extern int legacy_decode(u8 *buf, const char *devmem);
extern void *mem_chunk(size_t base, size_t len, const char *devmem);
extern u8 *parse_opt_type(u8 *p, const char *arg);
