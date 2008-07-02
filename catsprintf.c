#include "catsprintf.h"

int catsprintf(char *buf, int major, const char *format, ...) {
  static int i = 0;

  va_list arg; /*will point to each unnamed argument in turn*/
  va_start(arg, format); /* point to first element after fmt*/


  char b[8192];
  int c = vsprintf (b, format, arg);
  i += strlen(b);
  //printf("%d %s (%d)\n", i, b, strlen(b));

  strcat(buf, b);

  va_end(arg); /*cleanup*/

  return c;
}
