/*
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

#include "dmilog.h"
#include "efi.h"

/**
 * @file xmlpythonizer.c
 * @brief Helper function for EFI support
 * @author Jean Delvare <khali@linux-fr.org>
 * @author Alan Cox <alan@redhat.com>
 */

/**
 * Probe for EFI interface
 * @param size_t*
 * @return returns EFI_NOT_FOUND or EFI_NO_SMBIOS
 */
int address_from_efi(Log_t *logp, size_t * address)
{
        FILE *efi_systab;
        const char *filename = NULL;
        char linebuf[64];
        int ret;

        *address = 0;           /* Prevent compiler warning */

        /*
         ** Linux <= 2.6.6: /proc/efi/systab
         ** Linux >= 2.6.7: /sys/firmware/efi/systab
         */
        if((efi_systab = fopen(filename = "/sys/firmware/efi/systab", "r")) == NULL
           && (efi_systab = fopen(filename = "/proc/efi/systab", "r")) == NULL) {
                /* No EFI interface, fallback to memory scan */
                return EFI_NOT_FOUND;
        }
        ret = EFI_NO_SMBIOS;
        while((fgets(linebuf, sizeof(linebuf) - 1, efi_systab)) != NULL) {
                char *addrp = strchr(linebuf, '=');

                *(addrp++) = '\0';
                if(strcmp(linebuf, "SMBIOS") == 0) {
                        *address = strtoul(addrp, NULL, 0);
                        ret = 0;
                        break;
                }
        }
        if(fclose(efi_systab) != 0)
                perror(filename);

        if(ret == EFI_NO_SMBIOS) {
                log_append(logp, LOGFL_NODUPS, LOG_WARNING, "%s: SMBIOS entry point missing", filename);
        }

        return ret;
}

