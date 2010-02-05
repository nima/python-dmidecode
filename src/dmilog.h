/*
 *   2009 (C) David Sommerseth <davids@redhat.com>
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

/**
 *  @file dmilog.h
 *  @brief A simple log module
 *  @author David Sommerseth <davids@redhat.com>
 */


#ifndef DMILOG_H
#define DMILOG_H

#include <stdarg.h>
#include <syslog.h>

/**
 *  Struct defining log records.  Organised as a pointer chain.
 */
struct _Log_t {
	int level;		/**< Log type, based on syslog levels (LOG_ERR|LOG_WARNING) */
	char *message;		/**< Formated log text */
	unsigned int read;	/**< Number of times this log entry has been read */
	struct _Log_t *next;	/**< Next log entry */
};
typedef struct _Log_t Log_t;

/**
 *  Log flags.  These flags can be OR'ed together
 */
typedef enum { LOGFL_NORMAL   = 1, /**< Normal behaviour, log everything and use stderr on errors */
               LOGFL_NODUPS   = 2, /**< Don't log messages we already have logged */
               LOGFL_NOSTDERR = 4  /**< Don't use stderr even if log functions fails */
} Log_f;

Log_t * log_init();
int log_append(Log_t *logp, Log_f flags, int level, const char *fmt, ...);
char * log_retrieve(Log_t *logp, int level);
size_t log_clear_partial(Log_t *logp, int level, int unread);
void log_close(Log_t *logp);

#endif
