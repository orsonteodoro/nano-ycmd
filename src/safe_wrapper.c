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

/*
 * Me:  what is the license of the wrapper examples?
 * Llama 4:  The wrapper examples I provided are considered public domain or, if that's not possible in your jurisdiction, licensed under the most permissive terms possible.
 * You can use, modify, and distribute these examples freely without any restrictions or attribution requirements.
 * In other words, consider them to be:
 * Public Domain (CC0 1.0 Universal)
 * or Permissive License (MIT License or similar)
 * Feel free to use them as you see fit in your projects.
 *
 * Me:  i will add them to nano-ycmd which is based on gnu nano.
 * Llama 4:  In that case, the wrapper examples I provided should be compatible with the GPL (General Public License) used by GNU nano.
 * Since I'm not specifying any particular license for the examples, they're essentially public domain, which means you can use them in your GPL-licensed project without any issues.
 * Just make sure to follow the GPL guidelines and requirements for your project, and you're good to go! If you have any questions or concerns about licensing or GPL compliance, feel free to ask.
 *
 */

/*
 * Some of the license header, skeleton functions, and wrapper implementations are provided by Grok 3.
 * Grok 3 originally added the license header with name 多彩 (Colorful).
 * Llama 4 wrote the malloc/free section, some wrappers.
 * Grok 3 made the fixed compatibility wrapper classes for wrap_vsnprintf, wrap_strncat.
 */

#include "safe_wrapper.h"
#include "prototypes.h"
#include <limits.h>
#if USE_SAFECLIB
#include <safeclib/safec.h>
#ifndef strnlen_s
#error "strnlen_s not defined in safe_str_lib.h"
#endif
#endif
#include <string.h>
#include <unistd.h>

#define MAX_FILESIZE_LIMIT ( 10 * 1024 * 1024 ) /* 10 MB limit for ycmd requests. */
#define DEFAULT_JSON_SIZE (PATH_MAX * 16 + 44 * 10 + 80 * 50) /* 69976 */

#if defined(__GLIBC__) && __GLIBC_PREREQ(2, 25)
# define HAVE_EXPLICIT_BZERO 1
#elif defined(__has_builtin)
# if __has_builtin(__builtin_memset_explicit)
#  define explicit_bzero(p, l) __builtin_memset_explicit((p), 0, (l))
#  define HAVE_EXPLICIT_BZERO 1
# endif
#endif

#if !defined(HAVE_EXPLICIT_BZERO)
#warning "Using fallback implementation of explicit_bzero.  Consider upgrading to >= glibc 2.25 for mitigated information disclosure implementation."
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

size_t get_smax(void) {
#ifdef DEBUG
	char msg[256];
#endif
	static size_t smax = 0;
	if (smax == 0) {
		/* Adjustable buffer overflow limiter. */
		const char *env = getenv("NANO_YCMD_SMAX");
		size_t max_limit = 10485760; /* 10 MB */
#ifdef NANO_YCMD_MAX_SMAX
		if (NANO_YCMD_MAX_SMAX < max_limit) {
#ifdef DEBUG
			snprintf(msg, sizeof(msg), "%s:  RSIZE_MAX_STR=%zu is less than 10 MB. Large files may be truncated.", __func__, NANO_YCMD_MAX_SMAX);
			fprintf(stderr, msg);
#endif
			max_limit = NANO_YCMD_MAX_SMAX;
		}
#endif
		if (env) {
			char *endptr;
			unsigned long val = strtoul(env, &endptr, 10);
			if (*endptr == '\0' && val >= 1024 && val <= max_limit) {
				smax = val;
			} else {
#ifdef DEBUG
				snprintf(msg, sizeof(msg), "Invalid NANO_YCMD_SMAX (must be 1 KB to %zu bytes), using default 1 MB", max_limit);
				fprintf(stderr, msg);
#endif
				smax = 1048576; /* 1 MB default */
			}
		} else {
			smax = 1048576; /* 1MB default */
		}
#ifdef DEBUG
		snprintf(msg, sizeof(msg), "%s:  smax set to %zu bytes. Large values may slow down nano.", __func__, smax);
		fprintf(stderr, msg);
#endif
	}
	return smax;
}

char *wrap_strcpy(char *dest, const char *src) {
#ifdef DEBUG
	char msg[256];
#endif
	if (!dest || !src) {
#ifdef DEBUG
		fprintf(stderr, "%s: null input", __func__);
#endif
		return NULL;
	}
	size_t smax = get_smax();
	size_t src_len = strnlen(src, smax);
	if (src_len == 0 || src_len >= smax) {
#ifdef DEBUG
		snprintf(msg, sizeof(msg), "%s: source string invalid or exceeds smax (%zu)", __func__, smax);
		fprintf(stderr, msg);
#endif
		return NULL;
	}
#ifdef USE_SAFECLIB
	errno_t err = strcpy_s(dest, src_len + 1, src);
	if (err != 0) {
#ifdef DEBUG
		snprintf_s(msg, sizeof(msg), "%s: strcpy_s failed with error %d", __func__, err);
		fprintf(stderr, msg);
#endif
		return NULL;
	}
#else
	if (strlcpy(dest, src, src_len + 1) >= src_len + 1) {
#ifdef DEBUG
		fprintf(stderr, "%s: strlcpy truncated", __func__);
#endif
		return NULL;
	}
#endif
	return dest;
}

void *wrap_memcpy(void *dest, const void *src, size_t n) {
#ifdef USE_SAFECLIB
	errno_t err = memcpy_s(dest, n, src, n);
	if (err != EOK) {
#ifdef DEBUG
		fprintf(stderr, "%s:  Error:  %s\n", __func__, strerror(err));
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
			fprintf(stderr, "%s: vsnprintf_s failed in dummy case (res=%d)\n", __func__, res);
			return -1;
#endif
		}
		if (res >= DUMMY_BUFFER_SIZE) {
#ifdef DEBUG
			fprintf(stderr, "%s: Warning: Format string may exceed %d bytes (res=%d)\n",
				__func__, DUMMY_BUFFER_SIZE, res);
#endif
		}
		return res;
	}
	if (size > DEFAULT_JSON_SIZE) {
#ifdef DEBUG
		fprintf(stderr, "%s: size capped (input=%zu, max=%d)\n",
			__func__, size, DEFAULT_JSON_SIZE);
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
#ifdef USE_SAFECLIB
	/* There is an inconsistency in the safeclib implementation.  So rewrite. */
	/* Validate inputs */
	if (dest == NULL || src == NULL || n == 0) {
#ifdef DEBUG
		fprintf(stderr, "%s: Invalid input (dest=%p, src=%p, n=%zu)\n",
			__func__, (void *)dest, (void *)src, n);
#endif
		return NULL;
	}

	/* Cap n at DEFAULT_JSON_SIZE because the safeclib limits on
	 * --enable-strmax= will cause strlen_s and other safeclib string
	 * functions to break.  It is assumed that safeclib is built with
	 * >= 128K strmax. */
	if (n > DEFAULT_JSON_SIZE) {
#ifdef DEBUG
		/*
		fprintf(stderr, "%s: n capped (input=%zu, max=%d)\n",
			__func__, n, DEFAULT_JSON_SIZE);
		*/
#endif
		n = DEFAULT_JSON_SIZE;
	}

	/* Sanitize dest: Ensure null-termination */
	dest[n - 1] = '\0';
	size_t dest_len = strnlen_s(dest, n);
	if (dest_len >= n - 1) {
#ifdef DEBUG
		fprintf(stderr, "%s: No space in dest (dest_len=%zu, n=%zu)\n",
			__func__, dest_len, n);
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
			__func__, src_len, max_src_len);
#endif
		return NULL;
	}

	/* Concatenate */
	errno_t res = strncat_s(dest, n, src, RSIZE_MAX_STR);
	if (res != 0) {
#ifdef DEBUG
		fprintf(stderr, "%s: strncat_s failed (res=%d, n=%zu, src_len=%zu)\n",
			__func__, res, n, src_len);
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
	/* Mitigations:  CE, DF, DoS, DT, DP, HO, ID, NPD, OOBA, OOBR, OOBW, PE, PF, UAF, ZF
	 */
	extern void *hardened_malloc(size_t size);
	return hardened_malloc(size);
#elif defined(USE_MIMALLOC_SECURE)
	/* mimalloc-secure is a hardened version of the mimalloc allocator */
	/* Mitigations:  CE, DF, DoS, DT, DP, HO, ID, NPD, OOBA, OOBR, OOBW, PE, PF, UAF, ZF
	 */
	extern void *mi_malloc(size_t size);
	return mi_malloc(size);
#else
	/* Default to glibc/musl/scudo-standalone malloc */
	/* Scudo is part of the LLVM project and provides a hardened allocator */
	/* Scudo needs LD_PRELOAD=$(clang --print-file-name=libclang_rt.scudo_standalone-<arch>.so) */
	/* Mitigations (scudo-standalone):  CE, DF, DoS, DT, DP, HO, ID, NPD, OOBA, OOBR, OOBW, PE, PF, UAF, ZF */
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
#ifdef USE_SAFECLIB
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

size_t wrap_strlen(const char *s) {
#ifdef DEBUG
	char msg[256];
#endif
	if (!s) {
#ifdef DEBUG
		fprintf(stderr, "%s: null input", __func__);
#endif
		return 0;
	}
	size_t smax = get_smax();
#ifdef USE_SAFECLIB
	/* Validate input for file contents (allow control chars) */
	for (size_t i = 0; i < smax; i++) { // Reasonable limit
		if (s[i] == '\0') break;
		unsigned char c = (unsigned char)s[i];
		/* Exclude only NUL (0x00) */
		if (c == 0) {
#ifdef DEBUG
			snprintf(msg, sizeof(msg), "%s: invalid character 0x%02x at index %zu", __func__, c, i);
			fprintf(stderr, msg);
#endif
			return 0;
		}
	}
	rsize_t len = strnlen_s(s, smax);
	if (len == 0 && s[0] != '\0') {
#ifdef DEBUG
//		snprintf(msg, sizeof(msg), "%s: strnlen_s failed for input (first 32 chars): '%.32s'", __func__, s);
//		fprintf(stderr, msg);
#endif
		size_t fallback_len = strlen(s); /* glibc fallback */
		if (fallback_len >= smax) {
#ifdef DEBUG
			fprintf(stderr, "%s: string exceeds 10 MB", __func__);
#endif
			return 0;
		}
		return fallback_len;
	}
#else
	size_t len = strlen(s);
	if (len >= smax) {
#ifdef DEBUG
		fprintf(stderr, "%s: string exceeds 10 MB", __func__);
#endif
		return 0;
	}
#endif
	return len;
}

size_t wrap_strnlen(const char *s, size_t maxlen) {
#ifdef DEBUG
	char msg[256];
#endif
	if (!s) {
#ifdef DEBUG
		fprintf(stderr, "%s: null input", __func__);
#endif
		return 0;
	}
	size_t smax = get_smax();
	size_t effective_max = maxlen < smax ? maxlen : smax;
#ifdef USE_SAFECLIB
	rsize_t len = strnlen_s(s, effective_max);
	if (len == 0 && s[0] != '\0') {
#ifdef DEBUG
//		snprintf(msg, sizeof(msg), "%s: strnlen_s failed for input (first 32 chars): '%.32s'", __func__, s);
//		fprintf(stderr, msg);
#endif
		return 0;
	}
#else
	size_t len = strnlen(s, effective_max);
#endif
	return len;
}

int wrap_sprintf(char *str, size_t size, const char *format, ...) {
	va_list args;
	va_start(args, format);
	int result;

#ifdef USE_SAFECLIB
	result = vsnprintf_s(str, size, format, args);
#else
	result = vsnprintf(str, size, format, args);
#endif

	va_end(args);
	return result;
}

int wrap_snprintf(char *str, size_t size, const char *format, ...)
{
	va_list ap;
	int result;

	/* Basic validation for sensitive data */
	if (!str || !format || size == 0) {
		if (str && size > 0) {
			str[0] = '\0'; /* Ensure null-termination */
		}
		return -1;
	}

	va_start(ap, format);

#ifdef USE_SAFECLIB
	/* Use wrap_vsnprintf for safeclib (secure handling for passwords/untrusted data) */
	result = wrap_vsnprintf(str, size, format, ap);
#else
	/* Use glibc's snprintf directly for performance */
	result = snprintf(str, size, format, ap);
#endif

	va_end(ap);
	return result;
}
