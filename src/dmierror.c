/*   Simpilfied and improved Python Error/Exception functions
 *
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
 *  @file dmierror.h
 *  @brief Simpilfied and improved Python Error/Exception functions
 *  @author David Sommerseth <davids@redhat.com>
 */

#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

// #define PRINT_ERRORS  // Enable for copy of error messages to stderr

/**
 *  A more flexible function for setting error messages.  This function
 *  is called via PyReturnError(...) macro which also returns NULL.
 *  @author David Sommerseth <davids@redhat.com>
 *  @param  PyObject*    A Python Exception object
 *  @param  const char*  Error message to follow the exception, may be string formated
 *
 */
void _pyReturnError(void *exception, const char *fname, int line, const char *fmt, ...)
{
        va_list ap;
        char *buf = NULL;

        va_start(ap, fmt);
        buf = (char *) malloc(4098);
        memset(buf, 0, 4098);

        if( buf == NULL ) {
                // Backup routine if we can't get the needed memory
                fprintf(stderr, "\n\n** ERROR ALLOCATING ERROR MESSAGE BUFFER\n\n");
                fprintf(stderr, "** ERROR: [%s:%i] ", fname, line);
                vfprintf(stderr, fmt, ap);
                fprintf(stderr, "\n");
                va_end(ap);
                return;
        }

        // Set the error state and message
        snprintf(buf, 4096, "[%s:%i] %s", fname, line, fmt);
        PyErr_Format(exception, buf, ap);

#ifdef PRINT_ERRORS
        fprintf(stderr, "\n**\n** ERROR: ");
        vfprintf(stderr, buf, ap);
        fprintf(stderr, "\n**\n\n");
#endif
        va_end(ap);
        free(buf); buf = NULL;
}

