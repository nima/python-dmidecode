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


int write_dump(size_t base, size_t len, const void *data, const char *dumpfile, int add)
{
        FILE *f;

        f = fopen(dumpfile, add ? "r+b" : "wb");
        if(!f) {
                fprintf(stderr, "%s: ", dumpfile);
                perror("fopen");
                return -1;
        }

        if(fseek(f, base, SEEK_SET) != 0) {
                fprintf(stderr, "%s: ", dumpfile);
                perror("fseek");
                goto err_close;
        }

        if(fwrite(data, len, 1, f) != 1) {
                fprintf(stderr, "%s: ", dumpfile);
                perror("fwrite");
                goto err_close;
        }

        if(fclose(f)) {
                fprintf(stderr, "%s: ", dumpfile);
                perror("fclose");
                return -1;
        }

        return 0;

      err_close:
        fclose(f);
        return -1;
}


int dumpling(u8 * buf, const char *dumpfile, u8 mode)
{
        u32 base;
        u16 len;

        if(mode == NON_LEGACY) {
                if(!checksum(buf, buf[0x05]) || !memcmp(buf + 0x10, "_DMI_", 5) == 0 ||
                   !checksum(buf + 0x10, 0x0F))
                        return 0;
                base = DWORD(buf + 0x18);
                len = WORD(buf + 0x16);
        } else {
                if(!checksum(buf, 0x0F))
                        return 0;
                base = DWORD(buf + 0x08);
                len = WORD(buf + 0x06);
        }

        u8 *buff;

        if((buff = mem_chunk(NULL, base, len, DEFAULT_MEM_DEV)) != NULL) {
                //. Part 1.
#ifdef NDEBUG
                printf("# Writing %d bytes to %s.\n", len, dumpfile);
#endif
                write_dump(32, len, buff, dumpfile, 0);
                free(buff);

                //. Part 2.
                if(mode != LEGACY) {
                        u8 crafted[32];

                        memcpy(crafted, buf, 32);
                        overwrite_dmi_address(crafted + 0x10);
#ifdef NDEBUG
                        printf("# Writing %d bytes to %s.\n", crafted[0x05], dumpfile);
#endif
                        write_dump(0, crafted[0x05], crafted, dumpfile, 1);
                } else {
                        u8 crafted[16];

                        memcpy(crafted, buf, 16);
                        overwrite_dmi_address(crafted);
#ifdef NDEBUG
                        printf("# Writing %d bytes to %s.\n", 0x0F, dumpfile);
#endif
                        write_dump(0, 0x0F, crafted, dumpfile, 1);
                }
        } else {
                fprintf(stderr, "Failed to read table, sorry.\n");
        }

        //. TODO: Cleanup
        return 1;
}


int dump(const char *memdev, const char *dumpfile)
{
        /* On success, return found, otherwise return -1 */
        int ret = 0;
        int found = 0;
        size_t fp;
        int efi;
        u8 *buf;

        /* First try EFI (ia64, Intel-based Mac) */
        efi = address_from_efi(NULL, &fp);
        if(efi == EFI_NOT_FOUND) {
                /* Fallback to memory scan (x86, x86_64) */
                if((buf = mem_chunk(NULL, 0xF0000, 0x10000, memdev)) != NULL) {
                        for(fp = 0; fp <= 0xFFF0; fp += 16) {
                                if(memcmp(buf + fp, "_SM_", 4) == 0 && fp <= 0xFFE0) {
                                        if(dumpling(buf + fp, dumpfile, NON_LEGACY))
                                                found++;
                                        fp += 16;
                                } else if(memcmp(buf + fp, "_DMI_", 5) == 0) {
                                        if(dumpling(buf + fp, dumpfile, LEGACY))
                                                found++;
                                }
                        }
                } else
                        ret = -1;
        } else if(efi == EFI_NO_SMBIOS) {
                ret = -1;
        } else {
                if((buf = mem_chunk(NULL, fp, 0x20, memdev)) == NULL)
                        ret = -1;
                else if(dumpling(buf, dumpfile, NON_LEGACY))
                        found++;
        }

        if(ret == 0) {
                free(buf);
                if(!found) {
                        ret = -1;
                }
        }

        return ret == 0 ? found : ret;
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
