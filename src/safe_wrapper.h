/*
 * Copyright (c) 2025 多彩
 * Copyright (c) 2025 Orson Teodoro
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef SAFE_WRAPPER_H
#define SAFE_WRAPPER_H

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <pthread.h>
#if USE_SAFECLIB
#include <safeclib/safe_types.h>
#else
typedef int errno_t;
#endif

/*
 * CE = Code Execution
 * PE = Privilege Escalation
 * ID = Information Disclosure
 * DoS = Denial Of Service
 * DT = Data Tampering
 * DP = Dangling Pointer
 * HO = Heap Overflow
 * NPD = Null Pointer Dereference
 * OOBA = Out Of Bounds Access
 * OOBR = Out Of Bounds Read
 * OOBW = Out Of Bounds Write
 * PF = Poison Free
 * SO = Stack Overflow
 * TC = Type Confusion
 * UAF = Use After Free
 * UAR = Use After Return
 * ZF = Zero Free
 */
#if defined(USE_SAFECLIB)
/* LibsafeC secure functions */
/* Mitigations (opinion 1):  DF, DoS, DT, ID, NPD, OOBA, OOBR, OOBW, SF */
/* Mitigations (opinion 2):  DF, DP, HO, NPD, OOBA, OOBW, PF, SO, UAF, ZF */
#else
/* libc standard functions */
/* Mitigations (glibc):  DoS */
/* Mitigations (musl):  NPD */
#endif

/* Wrapper function declarations */
char* wrap_strchr(const char *str, int c);
char *wrap_strcpy(char *dest, const char *src);
char *wrap_strdup(const char* str);
char *wrap_strncat(char *dest, const char *src, size_t n);
char *wrap_strncpy(char *dest, const char *src, size_t n);
char *wrap_strpbrk(const char *str1, const char *str2);
char *wrap_strstr(const char *haystack, const char *needle);
errno_t wrap_secure_zero(void *dest, size_t n);
int wrap_snprintf(char *str, size_t size, const char *format, ...);
int wrap_strcmp(const char *s1, const char *s2);
int wrap_strncasecmp(const char *s1, const char *s2, size_t n);
int wrap_strncmp(const char *s1, const char *s2, size_t n);
int wrap_vsnprintf(char *str, size_t size, const char *format, va_list ap);
size_t wrap_strlen(const char *s);
size_t wrap_strnlen(const char *s, size_t maxlen);
void *wrap_memcpy(void *dest, const void *src, size_t n);
void *wrap_malloc(size_t size);
void wrap_free(void **ptr);

/* Initialize fork handlers */
void init_wrapper(void);

size_t get_smax(void);

#endif /* SAFE_WRAPPER_H */

