/*
 * This file is part of the dmidecode project.
 *
 *   (C) 2005-2007 Jean Delvare <khali@linux-fr.org>
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

struct dmi_header {
  u8 type;
  u8 length;
  u16 handle;
  u8 *data;
};

const char *dmi_dump(struct dmi_header *h, char *_);
void dmi_decode(struct dmi_header *h, u16 ver);
int address_from_efi(size_t *address);
void to_dmi_header(struct dmi_header *h, u8 *data);
int smbios_decode(u8 *buf, const char *devmem, char *_);
int legacy_decode(u8 *buf, const char *devmem, char *_);

const char *dmi_string(struct dmi_header *dm, u8 s);
const char *dmi_system_uuid(u8 *p, char *_);
const char *dmi_chassis_type(u8 code);
const char *dmi_processor_family(u8 code);
const char *dmi_processor_frequency(u8 *p, char *_);

int submain(int argc, char * const argv[]);
