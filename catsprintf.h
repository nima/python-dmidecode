#ifndef CAT
#define CAT 1

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
int catsprintf(char *buf, const char *format, ...);
/* sed -i -e 's/\<printf(/catsprintf(buffer, /g' dmidecode.c */

#endif
