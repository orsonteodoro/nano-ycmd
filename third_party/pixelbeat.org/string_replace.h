/* Copyright: Pádraig Brady 2008
 * Summary: String search & replace function
 * Keywords:string interpolation substitution search replace gsub
 * License: LGPL
 * History:
 *     30 Apr 2008 : Initial version
 */

#ifndef STRING_REPLACE_H
#define STRING_REPLACE_H

#include <sys/types.h>

/* Returned string must be free()
 * Returns NULL if out of memory
 * Does not recursively interpolate
 * Replacement string can be empty ("") to delete occurances
 */
extern char* string_replace (const char* src, const char* find, const char* replacement);
extern char* string_replace_n (const char* src, const char* find, const char* replacement, size_t n);

#endif

