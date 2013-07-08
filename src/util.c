
/*
 * Common "util" functions
 * This file is part of the dmidecode project.
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

#include <sys/types.h>
#include <sys/stat.h>

#include "config.h"

#ifdef USE_MMAP
#include <sys/mman.h>
#ifndef MAP_FAILED
#define MAP_FAILED ((void *) -1)
#endif /* !MAP_FAILED */
#endif /* USE MMAP */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include "types.h"
#include "util.h"
#include "dmilog.h"

#ifndef USE_MMAP
static int myread(Log_t *logp, int fd, u8 * buf, size_t count, const char *prefix)
{
        ssize_t r = 1;
        size_t r2 = 0;

        while(r2 != count && r != 0) {
                r = read(fd, buf + r2, count - r2);
                if(r == -1) {
                        if(errno != EINTR) {
                                close(fd);
                                perror(prefix);
                                return -1;
                        }
                } else
                        r2 += r;
        }

        if(r2 != count) {
                close(fd);
                log_append(logp, LOGFL_NORMAL, LOG_WARNING, "%s: Unexpected end of file", prefix);
                return -1;
        }

        return 0;
}
#endif

int checksum(const u8 * buf, size_t len)
{
        u8 sum = 0;
        size_t a;

        for(a = 0; a < len; a++)
                sum += buf[a];
        return (sum == 0);
}

/* Static global variables which should only
 * be used by the sigill_handler()
 */
static int sigill_error = 0;
static Log_t *sigill_logobj = NULL;

void sigill_handler(int ignore_this) {
        sigill_error = 1;
        if( sigill_logobj ) {
                log_append(sigill_logobj, LOGFL_NODUPS, LOG_WARNING,
                           "SIGILL signal caught in mem_chunk()");
        } else {
                fprintf(stderr,
                        "** WARNING ** SIGILL signal caught in mem_chunk()\n");
        }
}

/*
 * Copy a physical memory chunk into a memory buffer.
 * This function allocates memory.
 */
void *mem_chunk(Log_t *logp, size_t base, size_t len, const char *devmem)
{
        void *p;
        int fd;

#ifdef USE_MMAP
        size_t mmoffset;
        void *mmp;
#endif
        sigill_logobj = logp;
        signal(SIGILL, sigill_handler);
        if(sigill_error || (fd = open(devmem, O_RDONLY)) == -1) {
                log_append(logp, LOGFL_NORMAL, LOG_WARNING,
                           "Failed to open memory buffer (%s): %s",
                           devmem, strerror(errno));
                p = NULL;
                goto exit;
        }

        if(sigill_error || (p = malloc(len)) == NULL) {
                log_append(logp, LOGFL_NORMAL, LOG_WARNING,"malloc: %s", strerror(errno));
                p = NULL;
                goto exit;
        }
#ifdef USE_MMAP
#ifdef _SC_PAGESIZE
        mmoffset = base % sysconf(_SC_PAGESIZE);
#else
        mmoffset = base % getpagesize();
#endif /* _SC_PAGESIZE */
        /*
         * Please note that we don't use mmap() for performance reasons here,
         * but to workaround problems many people encountered when trying
         * to read from /dev/mem using regular read() calls.
         */
        mmp = mmap(0, mmoffset + len, PROT_READ, MAP_SHARED, fd, base - mmoffset);
        if(sigill_error || (mmp == MAP_FAILED)) {
                log_append(logp, LOGFL_NORMAL, LOG_WARNING, "%s (mmap): %s", devmem, strerror(errno));
                free(p);
                p = NULL;
                goto exit;
        }

        memcpy(p, (u8 *) mmp + mmoffset, len);
        if (sigill_error) {
                log_append(logp, LOGFL_NODUPS, LOG_WARNING,
                           "Failed to do memcpy() due to SIGILL signal");
                free(p);
                p = NULL;
                goto exit;
        }

        if(sigill_error || (munmap(mmp, mmoffset + len) == -1)) {
                log_append(logp, LOGFL_NORMAL, LOG_WARNING, "%s (munmap): %s", devmem, strerror(errno));
                free(p);
                p = NULL;
                goto exit;
        }
#else /* USE_MMAP */
        if(sigill_error || (lseek(fd, base, SEEK_SET) == -1)) {
                log_append(logp, LOGFL_NORMAL, LOG_WARNING, "%s (lseek): %s", devmem, strerror(errno));
                free(p);
                p = NULL;
                goto exit;
        }

        if(sigill_error || (myread(logp, fd, p, len, devmem) == -1)) {
                free(p);
                p = NULL;
                goto exit;
        }
#endif /* USE_MMAP */

        if(close(fd) == -1)
                perror(devmem);

 exit:
        signal(SIGILL, SIG_DFL);
        sigill_logobj = NULL;
        return p;
}

/* Returns end - start + 1, assuming start < end */
u64 u64_range(u64 start, u64 end)
{
	u64 res;

	res.h = end.h - start.h;
	res.l = end.l - start.l;

	if (end.l < start.l)
		res.h--;
	if (++res.l == 0)
		res.h++;

	return res;
}
