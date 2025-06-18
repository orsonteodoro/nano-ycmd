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

#include "safe_wrapper.h"
#include <unistd.h>
#if USE_SAFECLIB
#include <safeclib/safec.h>
#endif
#include <string.h>
#include <limits.h>

#define DEFAULT_JSON_SIZE (PATH_MAX * 16 + 44 * 10 + 80 * 50) /* 69976 */

#if defined(__GLIBC__) && __GLIBC_PREREQ(2, 25)
# define HAVE_EXPLICIT_BZERO 1
#elif defined(__has_builtin)
# if __has_builtin(__builtin_memset_explicit)
#  define explicit_bzero(p, l) __builtin_memset_explicit((p), 0, (l))
#  define HAVE_EXPLICIT_BZERO 1
# endif
#endif

#ifndef HAVE_EXPLICIT_BZERO
#warning "Using fallback implementation of explicit_bzero.  Consider upgrading to glibc 2.25 or later for mitigated information disclosure implementation."
# include <string.h>
void explicit_bzero(void *p, size_t l) {
	memset(p, 0, l);
	__asm__ __volatile__("" ::: "memory");
}
#endif

static pthread_mutex_t malloc_lock = PTHREAD_MUTEX_INITIALIZER;
static pid_t parent_pid = 0;

/* Fork handlers */
static void prepare(void) {
	pthread_mutex_lock(&malloc_lock);
}

static void parent(void) {
	pthread_mutex_unlock(&malloc_lock);
}

static void child(void) {
	pthread_mutex_unlock(&malloc_lock);
}

void init_wrapper(void) {
	static int initialized = 0;
	if (!initialized) {
		parent_pid = getpid();
		pthread_atfork(prepare, parent, child);
		initialized = 1;
	}
}

char *wrap_strncpy(char *dest, const char *src, size_t n) {
	if (dest == NULL || src == NULL) {
		return NULL;
	}
#ifdef USE_SAFECLIB
	/* There was an inconsistency so it was rewritten to mimic glibc. */
	if (n == 0) {
		/* glibc's strncpy does nothing when n == 0 */
		return dest;
	}

	/* Calculate length of src (excluding null terminator) */
	size_t src_len = strnlen_s(src, n);

	/* Use memcpy_s to copy up to n characters without forcing null termination */
	if (memcpy_s(dest, n, src, src_len < n ? src_len : n) != 0) {
		/* Handle error: mimic glibc by returning dest without modification */
		return dest;
	}

	/* Null-pad remaining space if src_len < n, matching glibc behavior */
	if (src_len < n) {
		memset(dest + src_len, 0, n - src_len);
	}

	return dest;
#else
	return strncpy(dest, src, n);
#endif
}

void *wrap_memcpy(void *dest, const void *src, size_t n) {
#ifdef DEBUG
	char *function_name = "wrap_memcpy";
#endif
#ifdef USE_SAFECLIB
	errno_t err = memcpy_s(dest, n, src, n);
	if (err != EOK) {
#ifdef DEBUG
		fprintf(stderr, "%s:  Error:  %s\n", function_name, strerror(err));
#endif
	}
	return dest;
#else
	if (dest == NULL || src == NULL) {
		return NULL;
	}
	memcpy(dest, src, n);
	return dest;
#endif
}

#define DUMMY_BUFFER_SIZE 1024
int wrap_vsnprintf(char *str, size_t size, const char *format, va_list ap) {
#ifdef DEBUG
	char *function_name = "wrap_vsnprintf";
#endif
#ifdef USE_SAFECLIB
	/* There is an inconsistency in the safeclib implementation.  So rewrite. */
	if (str == NULL && size != 0) return -1;
	if (format == NULL) return -1;
	if (size == 0) {
		char dummy[DUMMY_BUFFER_SIZE] = {0}; /* Initialize to zero */
		va_list ap_copy;
		va_copy(ap_copy, ap);
		int res = vsnprintf_s(dummy, sizeof(dummy), format, ap_copy);
		va_end(ap_copy);
		if (res < 0) {
#ifdef DEBUG
			fprintf(stderr, "%s: vsnprintf_s failed in dummy case (res=%d)\n", function_name, res);
			return -1;
#endif
		}
		if (res >= DUMMY_BUFFER_SIZE) {
#ifdef DEBUG
			fprintf(stderr, "%: Warning: Format string may exceed %d bytes (res=%d)\n",
				function_name, DUMMY_BUFFER_SIZE, res);
#endif
		}
		return res;
	}
	if (size > DEFAULT_JSON_SIZE) {
#ifdef DEBUG
		fprintf(stderr, "%s: size capped (input=%zu, max=%d)\n",
			function_name, size, DEFAULT_JSON_SIZE);
#endif
		size = DEFAULT_JSON_SIZE;
	}
	int res = vsnprintf_s(str, size, format, ap);
	if (res < 0) {
		va_list ap_copy;
		va_copy(ap_copy, ap);
		res = vsnprintf(str, size, format, ap_copy);
		va_end(ap_copy);
	}
	return res < 0 ? -1 : res;
#else
	return vsnprintf(str, size, format, ap);
#endif
}

char *wrap_strncat(char *dest, const char *src, size_t n) {
#ifdef DEBUG
	char *function_name = "wrap_strncat";
#endif
#ifdef USE_SAFECLIB
	/* There is an inconsistency in the safeclib implementation.  So rewrite. */
	/* Validate inputs */
	if (dest == NULL || src == NULL || n == 0) {
#ifdef DEBUG
		fprintf(stderr, "%s: Invalid input (dest=%p, src=%p, n=%zu)\n",
			function_name, (void *)dest, (void *)src, n);
#endif
		return NULL;
	}

	/* Cap n at DEFAULT_JSON_SIZE */
	if (n > DEFAULT_JSON_SIZE) {
#ifdef DEBUG
		fprintf(stderr, "%s: n capped (input=%zu, max=%d)\n",
			function_name, n, DEFAULT_JSON_SIZE);
#endif
		n = DEFAULT_JSON_SIZE;
	}

	/* Sanitize dest: Ensure null-termination */
	dest[n - 1] = '\0';
	size_t dest_len = strnlen_s(dest, n);
	if (dest_len >= n - 1) {
#ifdef DEBUG
		fprintf(stderr, "%s: No space in dest (dest_len=%zu, n=%zu)\n",
			function_name, dest_len, n);
#endif
		return NULL;
	}

	/* Compute source length */
	size_t max_src_len = n - dest_len - 1;
	if (max_src_len > RSIZE_MAX_STR) {
		max_src_len = RSIZE_MAX_STR; /* Cap at 131072 */
	}
	size_t src_len = strnlen_s(src, max_src_len);
	if (src_len >= max_src_len && (src_len < n && src[src_len] != '\0')) {
#ifdef DEBUG
		fprintf(stderr, "%s: src too long (src_len=%zu, max_src_len=%zu)\n",
			function_name, src_len, max_src_len);
#endif
		return NULL;
	}

	/* Concatenate */
	errno_t res = strncat_s(dest, n, src, RSIZE_MAX_STR);
	if (res != 0) {
#ifdef DEBUG
		fprintf(stderr, "%s: strncat_s failed (res=%d, n=%zu, src_len=%zu)\n",
			function_name, res, n, src_len);
#endif
		return NULL;
	}

	return dest;
#else
	/* glibc strncat */
	if (dest == NULL || src == NULL || n == 0) {
		return NULL;
	}
	if (n > DEFAULT_JSON_SIZE) {
		n = DEFAULT_JSON_SIZE;
	}
	size_t dest_len = strnlen(dest, n);
	if (dest_len >= n - 1) {
		return NULL;
	}
	strncat(dest, src, n - dest_len - 1);
	return dest;
#endif
}

int wrap_strncmp(const char *s1, const char *s2, size_t n) {
#ifdef USE_SAFECLIB
	int result;
	errno_t err = strcmp_s(s1, n, s2, &result);
	if (err != EOK) {
		return err;
	}
	return result;
#else
	if (s1 == NULL || s2 == NULL) {
		return -EINVAL;
	}
	if (n == 0)
		return 0;
	return strncmp(s1, s2, n);
#endif
}

void *_safe_malloc(size_t size) {
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
#if defined(USE_HARDENED_MALLOC)
	/* hardened_malloc is a hardened memory allocator */
	/* Mitigations:  CE, DF, DoS, DT, DP, HO, ID, OOBA, OOBR, OOBW, PE, PF, UAF, ZF
	 */
	extern void *hardened_malloc(size_t size);
	return hardened_malloc(size);
#elif defined(USE_MIMALLOC_SECURE)
	/* mimalloc-secure is a hardened version of the mimalloc allocator */
	/* Mitigations:  CE, DF, DoS, DT, DP, HO, ID, OOBA, OOBR, OOBW, PE, PF, UAF, ZF
	 */
	extern void *mi_malloc(size_t size);
	return mi_malloc(size);
#else
	/* Default to glibc/musl/scudo-standalone malloc */
	/* Scudo is part of the LLVM project and provides a hardened allocator */
	/* Scudo needs LD_PRELOAD=$(clang --print-file-name=libclang_rt.scudo_standalone-<arch>.so) */
	/* Mitigations (scudo-standalone):  CE, DF, DoS, DT, DP, HO, ID, OOBA, OOBR, OOBW, PE, PF, UAF, ZF */
	/* Mitigations (glibc):  DoS */
	/* Mitigations (musl):  DF, DoS */
	return malloc(size);
#endif
}

void *wrap_malloc(size_t size) {
	if (getpid() != parent_pid)
		return _safe_malloc(size);
	pthread_mutex_lock(&malloc_lock);
	void *ptr = _safe_malloc(size);
	pthread_mutex_unlock(&malloc_lock);
	return ptr;
}

void _safe_free(void *ptr) {
#if defined(USE_HARDENED_MALLOC)
	extern void hardened_free(void *ptr);
	hardened_free(ptr);
#elif defined(USE_MIMALLOC_SECURE)
	extern void mi_free(void *ptr);
	mi_free(ptr);
#else
	free(ptr);
#endif
}

void wrap_free(void **ptr) {
	if (ptr && *ptr) {
		if (getpid() != parent_pid) {
			_safe_free(*ptr);
			*ptr = NULL;
			return;
		}
		pthread_mutex_lock(&malloc_lock);
		_safe_free(*ptr);
		*ptr = NULL;
		pthread_mutex_unlock(&malloc_lock);
	}
}

errno_t wrap_secure_zero(void *dest, size_t n) {
#ifdef USE_SAFECLIB
	if (!dest)
		return EINVAL;
	if (getpid() != parent_pid)
		return memset_s(dest, n, 0, n);
	pthread_mutex_lock(&malloc_lock);
	errno_t ret = memset_s(dest, n, 0, n);
	pthread_mutex_unlock(&malloc_lock);
	return ret;
#else
	if (!dest)
		return EINVAL;
	if (getpid() != parent_pid)
		explicit_bzero(dest, n);
	pthread_mutex_lock(&malloc_lock);
	explicit_bzero(dest, n);
	pthread_mutex_unlock(&malloc_lock);
	return 0;
#endif
}

char *wrap_strstr(const char *haystack, const char *needle) {
#ifdef HAVE_STRSTR_S
    char *result = NULL;
    errno_t err = strstr_s((char *)haystack, strlen(haystack) + 1, needle, strlen(needle) + 1, &result);
    if (err != EOK) {
        return NULL;
    }
    return result;
#else
    return strstr(haystack, needle);
#endif
}
