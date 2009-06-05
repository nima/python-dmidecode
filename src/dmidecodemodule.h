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

//extern void dmi_decode(struct dmi_header *h, u16 ver, PyObject* pydata);
extern PyObject *dmi_dump(struct dmi_header *h);
extern PyObject* dmi_decode(struct dmi_header *h, u16 ver);
extern int address_from_efi(size_t *address);
extern void to_dmi_header(struct dmi_header *h, u8 *data);
extern void dmi_table(u32 base, u16 len, u16 num, u16 ver, const char *devmem);
extern int smbios_decode(u8 *buf, const char *devmem, PyObject* pydata);
extern int legacy_decode(u8 *buf, const char *devmem, PyObject* pydata);
extern int smbios_decode_set_version(u8 *buf, const char *devmem, PyObject** pydata);
extern int legacy_decode_set_version(u8 *buf, const char *devmem, PyObject** pydata);
extern void *mem_chunk(size_t base, size_t len, const char *devmem);

extern u8 *parse_opt_type(u8 *p, const char *arg);
static const u8 opt_type_bios[] = { 0, 13, 255 };
static const u8 opt_type_system[] = { 1, 12, 15, 23, 32, 255 };
static const u8 opt_type_baseboard[] = { 2, 10, 255 };
static const u8 opt_type_chassis[] = { 3, 255 };
static const u8 opt_type_processor[] = { 4, 255 };
static const u8 opt_type_memory[] = { 5, 6, 16, 17, 255 };
static const u8 opt_type_cache[] = { 7, 255 };
static const u8 opt_type_connector[] = { 8, 255 };
static const u8 opt_type_slot[] = { 9, 255 };
struct type_keyword {
  const char *keyword;
  const u8 *type;
};

static const struct type_keyword opt_type_keyword[] = {
  { "bios", opt_type_bios },
  { "system", opt_type_system },
  { "baseboard", opt_type_baseboard },
  { "chassis", opt_type_chassis },
  { "processor", opt_type_processor },
  { "memory", opt_type_memory },
  { "cache", opt_type_cache },
  { "connector", opt_type_connector },
  { "slot", opt_type_slot },
};

PyMODINIT_FUNC initdmidecode(void);
