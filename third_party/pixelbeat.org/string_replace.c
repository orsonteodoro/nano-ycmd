/* Copyright: Pádraig Brady 2008
 * Summary: String search & replace function
 * Keywords:string interpolation substitution search replace gsub str_replace
 * License: LGPL
 * History:
 *     30 Apr 2008 : Initial version
 */

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include "string_replace.h"

/* Returned string must be free()
 * Returns NULL if out of memory
 * Does not recursively interpolate
 * Replacement string can be empty ("") to delete occurances
 */
char*
string_replace (const char* src, const char* find, const char* replacement) {
    //fprintf (stderr, "string_replace: replacing all [%s] with [%s] in [%s]\n", find, replacement, src);
    return string_replace_n (src, find, replacement, (size_t)-1);
}

char*
string_replace_n (const char* src, const char* find, const char* replacement, size_t n)
{
    //fprintf(stderr, "string_replace_n: replacing first [%zu] [%s] with [%s] in [%s]\n", n, find, replacement, src);

    const char* srcp=src;
    const char* needle=NULL;
    size_t str_len=strlen(src);
    size_t replace_len=strlen(replacement);
    size_t search_len=strlen(find);
    size_t newl=0;

    char* new=malloc(str_len+1);
    if (!new) {
        fprintf(stderr, "Error: string_replace: Out of memory\n");
        return NULL;
    }
    while (n-- && (needle=strstr(srcp,find))) {
        str_len+=replace_len-search_len;
        char* rp=realloc(new, str_len+1);
        if (!rp) {
            fprintf(stderr, "Error: string_replace: Out of memory\n");
            free(new);
            return NULL;
        } else {
            new = rp;
        }
        size_t skip_len=needle-srcp;
        memcpy(new+newl, srcp, skip_len);
        memcpy(new+newl+skip_len, replacement, replace_len);
        newl+=skip_len+replace_len;
        srcp=needle+search_len;
    }
    strcpy(new+newl, srcp);

    return new;
}

#if 0
int main(void)
{
    char* rpl=NULL;

    rpl=string_replace("hello cruel world", "cruel ", "");
    if (rpl) {
        puts(rpl);
        free(rpl);
    }

    rpl=string_replace("echo $PATH", "$PATH", "/bin:/sbin");
    if (rpl) {
        puts(rpl);
        free(rpl);
    }

    return 0;
}
#endif

/*
 Note with glib >= 2.14 the following can be used to replace _all_ occurances of a _pattern_

 GRegex* regex = g_regex_new (find, 0, 0, NULL);
 char* new = g_regex_replace_literal (regex, src, -1, 0, replacement, 0, NULL);
 g_regex_unref (regex);
*/

