/*
 * This file is part of the dmidecode project.
 *
 *   Copyright (C) 2005-2008 Jean Delvare <jdelvare@suse.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <libxml/tree.h>
#include "dmihelper.h"
#include "dmierror.h"

struct dmi_header {
        u8 type;
        u8 length;
        u16 handle;
        u8 *data;
};

void dmi_dump(xmlNode *node, struct dmi_header * h);
xmlNode *dmi_decode(xmlNode *parent_n, dmi_codes_major *dmiMajor, struct dmi_header * h, u16 ver);
void to_dmi_header(struct dmi_header *h, u8 * data);

xmlNode *smbios_decode_get_version(u8 * buf, const char *devmem);
xmlNode *legacy_decode_get_version(u8 * buf, const char *devmem);
int smbios_decode(Log_t *logp, int type, u8 *buf, const char *devmem, xmlNode *xmlnode);
int legacy_decode(Log_t *logp, int type, u8 *buf, const char *devmem, xmlNode *xmlnode);

int is_printable(const u8 *data, int len);
const char *dmi_string(const struct dmi_header *dm, u8 s);
void dmi_system_uuid(xmlNode *node, const u8 * p, u16 ver);
void dmi_chassis_type(xmlNode *node, u8 code);
int dmi_processor_frequency(const u8 * p);
