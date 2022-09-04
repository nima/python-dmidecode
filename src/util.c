
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

int checksum(const u8 * buf, size_t len)
{
        u8 sum = 0;
        size_t a;

        for(a = 0; a < len; a++)
                sum += buf[a];
        return (sum == 0);
}

/*
 * Reads all of file from given offset, up to max_len bytes.
 * A buffer of at most max_len bytes is allocated by this function, and
 * needs to be freed by the caller.
 * This provides a similar usage model to mem_chunk()
 *
 * Returns a pointer to the allocated buffer, or NULL on error, and
 * sets max_len to the length actually read.
 */
void *read_file(Log_t *logp, off_t base, size_t *max_len, const char *filename)
{
        struct stat statbuf;
        int fd;
        u8 *p;
        /*
         * Don't print error message on missing file, as we will try to read
         * files that may or may not be present.
         */
        if ((fd = open(filename, O_RDONLY)) == -1)
        {
                if (errno != ENOENT)
                        perror(filename);
                return NULL;
        }

        /*
         * Check file size, don't allocate more than can be read.
         */
        if (fstat(fd, &statbuf) == 0)
        {
                if (base >= statbuf.st_size)
                {
                        fprintf(stderr, "%s: Can't read data beyond EOF\n",
                                filename);
                        p = NULL;
                        goto out;
                }
                if (*max_len > (size_t)statbuf.st_size - base)
                        *max_len = statbuf.st_size - base;
        }

        if ((p = malloc(*max_len)) == NULL)
        {
                perror("malloc");
                goto out;
        }

        if (lseek(fd, base, SEEK_SET) == -1)
        {
                fprintf(stderr, "%s: ", filename);
                perror("lseek");
                goto err_free;
        }
        if (myread(logp, fd, p, *max_len, filename) == 0)
                goto out;

err_free:
        free(p);
        p = NULL;

out:
        if (close(fd) == -1)
                perror(filename);

        return p;
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

static void safe_memcpy(void *dest, const void *src, size_t n)
{
#ifdef USE_SLOW_MEMCPY
        size_t i;

        for (i = 0; i < n; i++)
                *((u8 *)dest + i) = *((const u8 *)src + i);
#else
        memcpy(dest, src, n);
#endif
}

/*
 * Copy a physical memory chunk into a memory buffer.
 * This function allocates memory.
 */
void *mem_chunk(Log_t *logp, size_t base, size_t len, const char *devmem)
{
        void *p;
        int fd = -1;

#ifdef USE_MMAP
        struct stat statbuf;
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
        if (sigill_error || fstat(fd, &statbuf) == -1 )
        {
                log_append(logp, LOGFL_NORMAL, LOG_WARNING,"fstat: %s", strerror(errno));
                goto err_free;
        }

        /*
         * mmap() will fail with SIGBUS if trying to map beyond the end of
         * the file.
         */
        if (sigill_error ||  S_ISREG(statbuf.st_mode) && base + (off_t)len > statbuf.st_size )
        {
                log_append(logp, LOGFL_NORMAL, LOG_WARNING,
                                "mmap: Can't map beyond end of file %s: %s",
                                devmem, strerror(errno));
                goto err_free;
        }
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
        mmp = mmap(NULL, mmoffset + len, PROT_READ, MAP_SHARED, fd, base - mmoffset);
        if(sigill_error || (mmp == MAP_FAILED)) {
                log_append(logp, LOGFL_NORMAL, LOG_WARNING, "%s (mmap): %s", devmem, strerror(errno));
 		goto try_read;
        }

        safe_memcpy(p, (u8 *) mmp + mmoffset, len);

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
	goto exit;

try_read:
#endif /* USE_MMAP */
        if (lseek(fd, base, SEEK_SET) == -1 )
        {
                log_append(logp, LOGFL_NORMAL, LOG_WARNING, "%s (lseek): %s", devmem, strerror(errno));
                goto err_free;
        }

        if(sigill_error || (myread(logp, fd, p, len, devmem) == 0)) {
                free(p);
                p = NULL;
                goto exit;
        }

err_free:
        free(p);
        p = NULL;

exit:
        if (fd >= 0) {
            if(close(fd) == -1)
                perror(devmem);
        }
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

int write_dump(size_t base, size_t len, const void *data, const char *dumpfile, int add)
{
        FILE *f;
        f = fopen(dumpfile, add ? "r+b" : "wb");
        if (!f)
        {
                fprintf(stderr, "%s: ", dumpfile);
                perror("fopen");
                return -1;
        }

        if (fseek(f, base, SEEK_SET) != 0)
        {
                fprintf(stderr, "%s: ", dumpfile);
                perror("fseek");
                goto err_close;
        }

        if (fwrite(data, len, 1, f) != 1)
        {
                fprintf(stderr, "%s: ", dumpfile);
                perror("fwrite");
                goto err_close;
        }

        if (fclose(f))
        {
                fprintf(stderr, "%s: ", dumpfile);
                perror("fclose");
                return -1;
        }

        return 0;

err_close:
        fclose(f);
        return -1;
}
