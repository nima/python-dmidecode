/*
 *   This file is part of the dmidecode project.
 *
 *   Copyright (C) 2002-2008 Jean Delvare <khali@linux-fr>
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

#ifndef TYPES_H
#define TYPES_H

#include "config.h"

typedef unsigned char u8;
typedef unsigned short u16;
typedef signed short i16;
typedef unsigned int u32;

/*
 * You may use the following defines to adjust the type definitions
 * depending on the architecture:
 * - Define BIGENDIAN on big-endian systems. Untested, as all target
 *   systems to date are little-endian.
 * - Define ALIGNMENT_WORKAROUND if your system doesn't support
 *   non-aligned memory access. In this case, we use a slower, but safer,
 *   memory access method. This should be done automatically in config.h
 *   for architectures which need it.
 */

#ifdef BIGENDIAN
typedef struct {
        u32 h;
        u32 l;
} u64;
#else
typedef struct {
        u32 l;
        u32 h;
} u64;
#endif

#if defined(ALIGNMENT_WORKAROUND) || defined(BIGENDIAN)
static inline u64 U64(u32 low, u32 high)
{
        u64 self;

        self.l = low;
        self.h = high;

        return self;
}
#endif

/*
 * Per SMBIOS v2.8.0 and later, all structures assume a little-endian
 * ordering convention.
 */
#if defined(ALIGNMENT_WORKAROUND) || defined(BIGENDIAN)
#define WORD(x) (u16)((x)[0] + ((x)[1] << 8))
#define DWORD(x) (u32)((x)[0] + ((x)[1] << 8) + ((x)[2] << 16) + ((x)[3] << 24))
#define QWORD(x) (U64(DWORD(x), DWORD(x + 4)))
#else /* ALIGNMENT_WORKAROUND || BIGENDIAN */
#define WORD(x) (u16)(*(const u16 *)(x))
#define DWORD(x) (u32)(*(const u32 *)(x))
#define QWORD(x) (*(const u64 *)(x))
#endif /* ALIGNMENT_WORKAROUND || BIGENDIAN */

#endif
