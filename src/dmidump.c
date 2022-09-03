/*  Simple program for dumping DMI/SMBIOS data
 *  Based on code from python-dmidecode/dmidecode.c
 *
 *   Copyright 2009      David Sommerseth <davids@redhat.com>
 *   Copyright 2002-2008 Jean Delvare <khali@linux-fr.org>
 *   Copyright 2000-2002 Alan Cox <alan@redhat.com>
 *
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
 *
 *   For the avoidance of doubt the "preferred form" of this code is one which
 *   is in an open unpatent encumbered format. Where cryptographic key signing
 *   forms part of the process of creating an executable the information
 *   including keys needed to generate an equivalently functional executable
 *   are deemed to be part of the source code.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"
#include "util.h"

#include "dmidump.h"
#include "efi.h"

/*
 * Build a crafted entry point with table address hard-coded to 32,
 * as this is where we will put it in the output file. We adjust the
 * DMI checksum appropriately. The SMBIOS checksum needs no adjustment.
 */
static void overwrite_dmi_address(u8 * buf)
{
        buf[0x05] += buf[0x08] + buf[0x09] + buf[0x0A] + buf[0x0B] - 32;
        buf[0x08] = 32;
        buf[0x09] = 0;
        buf[0x0A] = 0;
        buf[0x0B] = 0;
}

/* Same thing for SMBIOS3 entry points */
static void overwrite_smbios3_address(u8 *buf)
{
        buf[0x05] += buf[0x10] + buf[0x11] + buf[0x12] + buf[0x13]
                        + buf[0x14] + buf[0x15] + buf[0x16] + buf[0x17] - 32;
        buf[0x10] = 32;
        buf[0x11] = 0;
        buf[0x12] = 0;
        buf[0x13] = 0;
        buf[0x14] = 0;
        buf[0x15] = 0;
        buf[0x16] = 0;
        buf[0x17] = 0;
}

void dmi_table_dump(const u8 *buf, u32 len, const char *dumpfile)
{
        write_dump(32, len, buf, dumpfile, 0);
}

void dmi_table(off_t base, u32 len, u16 num, u32 ver, const char *devmem,
                      u32 flags, const char *dumpfile)
{
        u8 *buf;
        size_t size = len;

        buf = read_file(NULL, flags & FLAG_NO_FILE_OFFSET ? 0 : base,
                        &size, devmem);
        len = size;

        if (buf == NULL)
        {
                printf("read failed\n");
        }
        dmi_table_dump(buf, len, dumpfile);
        free(buf);
}

static int smbios3_decode(u8 *buf, const char *devmem, u32 flags, const char *dumpfile)
{
        u32 ver;
        u64 offset;
        offset = QWORD(buf + 0x10);
        ver = (buf[0x07] << 16) + (buf[0x08] << 8) + buf[0x09];

        dmi_table(((off_t)offset.h << 32) | offset.l,DWORD(buf + 0x0C), 0, ver, devmem, flags | FLAG_STOP_AT_EOT, dumpfile);

        if (!checksum(buf, buf[0x05]))
                return 0;

        u8 crafted[32];
        memcpy(crafted, buf, 32);
        overwrite_smbios3_address(crafted);
        //overwrite_dmi_address(crafted);
        //printf("Writing %d bytes to %s.",crafted[0x06], dumpfile);
        write_dump(0, crafted[0x06], crafted, dumpfile, 1);
        return 1;
}

static int smbios_decode(u8 *buf, const char *devmem, u32 flags, const char *dumpfile)
{
        u16 ver;
        if (!checksum(buf, buf[0x05])
         || memcmp(buf + 0x10, "_DMI_", 5) != 0
         || !checksum(buf + 0x10, 0x0F))
                return 0;

        ver = (buf[0x06] << 8) + buf[0x07];
        switch (ver)
        {
                case 0x021F:
                case 0x0221:
                        ver = 0x0203;
                        break;
                case 0x0233:
                        ver = 0x0206;
                        break;
        }


        dmi_table(DWORD(buf + 0x18), WORD(buf + 0x16), WORD(buf + 0x1C),
                ver << 8, devmem, flags, dumpfile);

        u8 crafted[32];
        memcpy(crafted, buf, 32);
        overwrite_dmi_address(crafted + 0x10);
        write_dump(0, crafted[0x05], crafted, dumpfile, 1);

        return 1;
}

static int legacy_decode(u8 *buf, const char *devmem, u32 flags,  const char *dumpfile)
{
        u8 crafted[16];

        //dmi_table();
        dmi_table(DWORD(buf + 0x08), WORD(buf + 0x06), WORD(buf + 0x0C),
                ((buf[0x0E] & 0xF0) << 12) + ((buf[0x0E] & 0x0F) << 8),
                devmem, flags, dumpfile);

        memcpy(crafted, buf, 16);
        overwrite_smbios3_address(crafted);
        write_dump(0, 0x0F, crafted, dumpfile, 1);
}

int dump(const char *memdev, const char *dumpfile)
{
        /* On success, return found, otherwise return 0 */
        int ret = 0;
        int found = 0;
        size_t fp;
        int efi;
        u8 *buf;
        size_t size;

        /*
         * First try reading from sysfs tables.  The entry point file could
         * contain one of several types of entry points, so read enough for
         * the largest one, then determine what type it contains.
         */
        size = 0x20;
        if ( (buf = read_file(NULL, 0, &size, SYS_ENTRY_FILE)) != NULL){
                if (size >= 24 && memcmp(buf, "_SM3_", 5) == 0){
                        if (smbios3_decode(buf, SYS_TABLE_FILE, FLAG_NO_FILE_OFFSET, dumpfile))
                                found++;
                } else if (size >= 31 && memcmp(buf, "_SM_", 4) == 0) {
                        if (smbios_decode(buf, SYS_TABLE_FILE, FLAG_NO_FILE_OFFSET, dumpfile))
                                found++;
                } else if (size >= 15 && memcmp(buf, "_DMI_", 5) == 0){
                        if (legacy_decode(buf, SYS_TABLE_FILE, FLAG_NO_FILE_OFFSET, dumpfile))
                                found++;
                }
                if (found){
                        ret = 1;
                        goto exit_free;
                }
        }

        /* First try EFI (ia64, Intel-based Mac) */
        efi = address_from_efi(NULL, &fp);
        switch(efi)
        {
                case EFI_NOT_FOUND:
                        goto memory_scan;
                case EFI_NO_SMBIOS:
                        ret = 1;
                        goto exit_free;
        }

        if ((buf = mem_chunk(NULL, fp, 0x20, memdev )) == NULL){
                ret = 1;
                goto exit_free;
        }

        if (memcmp(buf, "_SM3_", 5) == 0){
                if(smbios3_decode(buf, memdev, 0, dumpfile))
                        found++;
        } else if (memcmp(buf, "_SM_", 4) == 0){
                if(smbios_decode(buf, memdev, 0, dumpfile))
                        found++;
        }
        goto done;

memory_scan:
#if defined __i386__ || defined __x86_64__
        /* Fallback to memory scan (x86, x86_64) */
        if((buf = mem_chunk(NULL, 0xF0000, 0x10000, memdev)) == NULL) {
                ret = 1;
                goto exit_free;
        }

        /* Look for a 64-bit entry point first */
        for(fp = 0; fp <= 0xFFF0; fp += 16){
                if(memcmp(buf + fp, "_SM3_", 5) == 0 && fp <= 0xFFE0){
                        if(smbios3_decode(buf + fp, memdev, 0, dumpfile)){
                                found++;
                                goto done;
                        }
                }
        }

        /* If none found, look for a 32-bit entry point */
        for(fp = 0; fp <= 0xFFF0; fp += 16) {
                if(memcmp(buf + fp, "_SM_", 4) == 0 && fp <= 0xFFE0) {
                        if(smbios_decode(buf + fp, memdev, 0, dumpfile)){
                                found++;
                                goto done;
                        }
                } else if (memcmp(buf+fp, "_DMI_", 5) == 0){
                        if(legacy_decode(buf+fp, memdev, 0, dumpfile)){
                                found++;
                                goto done;
                        }
                }
        }
#endif

done:
        if(!found){
                printf("No SMBIOS nor DMI entry point found, sorry.\n");
        }
        free(buf);

exit_free:
        if (!found)
                free(buf);

        return ret;
}


#ifdef _DMIDUMP_MAIN_
int main(int argc, char **argv)
{
        if( argc != 3 ) {
                fprintf(stderr, "Usage:   %s </dev/mem device> <destfile>\n", argv[0]);
                return 1;
        }
        dump(argv[1], argv[2]);

        return 0;
}
#endif
