#include <Python.h>
#include <structmember.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "compat.h"
#include "version.h"
#include "config.h"
#include "types.h"
#include "util.h"
#include "dmidecode.h"
#include "dmioem.h"

#define EFI_NOT_FOUND   (-1)
#define EFI_NO_SMBIOS   (-2)

#include "dmihelper.h"

xmlNode *dmidecode_get_version(options *);

extern void dmi_dump(xmlNode *node, struct dmi_header *h);
extern int address_from_efi(size_t * address);
extern void to_dmi_header(struct dmi_header *h, u8 * data);
extern int smbios_decode(int type, u8 *buf, const char *devmem, xmlNode *node);
extern int legacy_decode(int type, u8 *buf, const char *devmem, xmlNode *node);
extern xmlNode *smbios_decode_get_version(u8 * buf, const char *devmem);
extern xmlNode *legacy_decode_get_version(u8 * buf, const char *devmem);
extern void *mem_chunk(size_t base, size_t len, const char *devmem);

PyMODINIT_FUNC initdmidecode(void);
