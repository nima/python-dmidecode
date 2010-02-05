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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "dmilog.h"

/**
 * Allocates memory for a new Log_t record
 *
 * @return Returns a pointer to a new Log_t record, otherwise NULL on error
 */
Log_t * log_init()
{
	Log_t *ret = NULL;

	ret = (Log_t *) calloc(1, sizeof(Log_t)+2);
	if( !ret ) {
		fprintf(stderr, "** ERROR **  Could not allocate memory for log data\n");
	}
	ret->level = -1; // Initialised - chain header pointer always have -1.
	return ret;
}




/**
 * Registers a new log entry
 *
 * @param logp   Pointer to an allocated Log_t record.  New records will be appended to the end
 * @param flags  Log flags, to specify logging behaviour
 * @param level  syslog log level values.  LOG_ERR and LOG_WARNING are allowed
 * @param fmt    stdarg based string with the log contents
 *
 * @return Returns 1 on successful registration of log entry, otherwise -1 and error is printed to stderr
 *         unless LOGFL_NOSTDERR is set in flags.
 */
int log_append(Log_t *logp, Log_f flags, int level, const char *fmt, ...)
{
        Log_t *ptr = NULL;
        va_list ap;
        char logmsg[4098];

        // Prepare log message
        memset(&logmsg, 0, 4098);
        va_start(ap, fmt);
        vsnprintf(logmsg, 4096, fmt, ap);
        va_end(ap);

        // Go the end of the record chain
        ptr = logp;
        while( ptr && ptr->next ) {
                // Ignore duplicated messages if LOGFL_NODUPS is set
                if( (flags & LOGFL_NODUPS) && ptr->next && ptr->next->message
                    && (strcmp(ptr->next->message, logmsg) == 0) ) {
                        return 1;
                }
                ptr = ptr->next;
        }

        if( ptr && ((level == LOG_ERR) || (level == LOG_WARNING)) ) {
                ptr->next = log_init();
                if( ptr->next ) {
                        ptr->next->level = level;
                        ptr->next->message = strdup(logmsg);
                        return 1;
                }
        }

        if( !(flags & LOGFL_NOSTDERR) ) {
                if( logp ) {
                        // Only print this if we logp is pointing somewhere.
                        // If it is NULL, the caller did not establish a log
                        // buffer on purpose (like dmidump.c) - thus this is
                        // not an error with saving the log entry.
                        fprintf(stderr, "** ERROR **  Failed to save log entry\n");
                }
                fprintf(stderr, "%s\n", logmsg);
        }
        return -1;
}


/**
 * Retrieve all log entries in the Log_t record chain with the corresponding log level.
 * One string will be returned, with all log entries separated with newline.
 *
 * @param logp  Pointer to Log_t record chain with log data
 * @param level Log entries to retrieve
 *
 * @return Returns a pointer to a buffer with all log lines.  This must be freed after usage.
 */
char * log_retrieve(Log_t *logp, int level)
{
	char *ret = NULL;
	size_t len = 0;
	Log_t *ptr = NULL;

	if( !logp ) {
		return NULL;
	}

	for( ptr = logp; ptr != NULL; ptr = ptr->next ) {
		if( ptr && ptr->level == level ) {
			if( ret ) {
				ret = realloc(ret, strlen(ptr->message)+len+3);
			} else {
				ret = calloc(1, strlen(ptr->message)+2);
			}

			if( !ret ) {
				fprintf(stderr,
					"** ERROR ** Could not allocate log retrieval memory buffer\n");
				return NULL;
			}
			strcat(ret, ptr->message);
			strcat(ret, "\n");
			ptr->read++;
			len = strlen(ret);
		}
	}
	return ret;
}


/**
 * Remove only log records of a particular log level from the log chain.  Only
 * records that have been read (by using log_retrieve()) will be removed unless
 * the unread argument == 1.
 *
 * @param logp   Pointer to log chain to work on
 * @param level  Log level to remove
 * @param unread Set to 1 to also clear unread log entriesz
 *
 * @return Returns number of removed elements.
 */
size_t log_clear_partial(Log_t *logp, int level, int unread)
{
	Log_t *ptr = NULL, *prev = NULL;
	size_t elmnt = 0;

	if( !logp ) {
		return 0;
	}

	prev = logp;
	for( ptr = logp->next; ptr != NULL; ptr = ptr->next ) {
		if( !ptr ) {
			break;
		}

		// Only remove log entries which is of the expected log level
		// and that have been read.
		if( (ptr->level == level) && ((unread == 1) || (ptr->read > 0)) ) {
			prev->next = ptr->next;
			if( ptr->message ) {
				free(ptr->message);
				ptr->message = NULL;
			}
			free(ptr);
			ptr = prev;
			elmnt++;
		}
		prev = ptr;
	}

	return elmnt;
}


/**
 * Free all memory used by a Log_t pointer chain.
 *
 * @param logp Pointer to log entries to free up.
 */
void log_close(Log_t *logp)
{
	Log_t *ptr = NULL, *next = NULL;

	ptr = logp;
	while( ptr ) {
		next = ptr->next;
		ptr->next = NULL;
		if( ptr->message ) {
			free(ptr->message);
			ptr->message = NULL;
		}
		free(ptr);
		ptr = next;
	}
}
