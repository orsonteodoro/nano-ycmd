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

#include "debug.h"
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
#include <ctype.h> /* For isprint() */

#define MAX_FILESIZE_LIMIT ( 10 * 1024 * 1024 )			/* 10 MB limit for ycmd requests. */
#define DEFAULT_JSON_SIZE (PATH_MAX * 16 + 44 * 10 + 80 * 50)	/* 69976 */

#if defined(__GLIBC__) && __GLIBC_PREREQ(2, 25)
#define HAVE_EXPLICIT_BZERO 1
#elif defined(__has_builtin)
#if __has_builtin(__builtin_memset_explicit)
#define explicit_bzero(p, l) __builtin_memset_explicit((p), 0, (l))
#define HAVE_EXPLICIT_BZERO 1
#endif
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
	debug_log("Called function");
	if (dest == NULL || src == NULL) {
		debug_log("Invalid input (dest=%p, src=%p, n=%zu)", (void *)dest, (void *)src, n);
		return NULL;
	}
#ifdef USE_SAFECLIB
	if (n == 0) {
		return dest;
	}
	size_t smax = get_smax();
	if (n > smax) {
		debug_log("n capped (input=%zu, max=%zu)", n, smax);
		n = smax;
	}
	size_t src_len = strnlen_s(src, n);
	if (src_len >= smax) {
		debug_log("src too long (src_len=%zu, smax=%zu)", src_len, smax);
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("src too long (src_len=%zu, smax=%zu), fatal error", src_len, smax);
			/* Fatal error */
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			/* Return error */
			return NULL;
		#else
			/* Fallback function */
			return strncpy(dest, src, n);
		#endif
	}
	/* Use memcpy_s to match original behavior, avoid strncpy_s truncation */
	errno_t err = memcpy_s(dest, n, src, src_len < n ? src_len : n);
	if (err != 0) {
		debug_log("memcpy_s failed (err=%d, dest=%.32s, src=%.32s, n=%zu)",
			err, dest ? dest : "(null)", src ? src : "(null)", n);
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("memcpy_s failed (err=%d, dest=%.32s, src=%.32s, n=%zu), fatal error",
				err, dest ? dest : "(null)", src ? src : "(null)", n);
			/* Fatal error */
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			/* Return error */
			return NULL;
		#else
			/* Fallback function */
			return strncpy(dest, src, n);
		#endif
	}
	if (src_len < n) {
		memset(dest + src_len, 0, n - src_len);
	}
	return dest;
#else
	return strncpy(dest, src, n);
#endif
}

size_t get_smax(void) {
	debug_log("Called function");
	static size_t smax = 0;
	if (smax == 0) {
		/* Adjustable buffer overflow limiter. */
		const char *env = getenv("NANO_YCMD_SMAX");
		debug_log("get_smax: NANO_YCMD_SMAX=%s", env ? env : "(null)");
		size_t max_limit = 10485760; /* 10 MB */
#ifdef NANO_YCMD_MAX_SMAX
		if (NANO_YCMD_MAX_SMAX < max_limit) {
			debug_log("RSIZE_MAX_STR=%zu is less than 10 MB. Large files may be truncated.", NANO_YCMD_MAX_SMAX);
			max_limit = NANO_YCMD_MAX_SMAX;
		}
#endif
		if (env) {
			char *endptr;
			unsigned long val = strtoul(env, &endptr, 10);
			debug_log("get_smax: Parsed NANO_YCMD_SMAX=%lu, endptr='%s'", val, *endptr ? endptr : "(empty)");
			if (*endptr == '\0' && val >= 1024 && val <= max_limit) {
				smax = val;
			} else {
				debug_log("Invalid NANO_YCMD_SMAX (must be 1 KB to %zu bytes), using default 1 MB", max_limit);
				smax = 1048576; /* 1 MB default */
			}
		} else {
			debug_log("NANO_YCMD_SMAX unset, using default 1 MB");
			smax = 1048576; /* 1 MB default */
		}
		debug_log("smax is set to %zu bytes. Large values may slow down nano.", smax);
	}
	return smax;
}

char *wrap_strcpy(char *dest, const char *src) {
	if (!dest || !src) {
		debug_log("null input");
		return NULL;
	}
	size_t smax = get_smax();
	size_t src_len = strnlen(src, smax);
	if (src_len == 0 || src_len >= smax) {
		debug_log("source string invalid or exceeds smax (%zu)", smax);
		return NULL;
	}
#ifdef USE_SAFECLIB
	errno_t err = strcpy_s(dest, src_len + 1, src);
	if (err != 0) {
		debug_log("strcpy_s failed with error %d", err);
		return NULL;
	}
#else
	if (strlcpy(dest, src, src_len + 1) >= src_len + 1) {
		debug_log("strlcpy truncated");
		return NULL;
	}
#endif
	return dest;
}

void *wrap_memcpy(void *dest, const void *src, size_t n) {
	debug_log("Called function");
#ifdef USE_SAFECLIB
	errno_t err = memcpy_s(dest, n, src, n);
	if (err != EOK) {
		debug_log("Error:  %s", strerror(err));
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
	debug_log("Called function");
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
			debug_log("vsnprintf_s failed in dummy case (res=%d)", res);
			return -1;
		}
		if (res >= DUMMY_BUFFER_SIZE) {
			debug_log("Warning:  Format string may exceed %d bytes (res=%d)", DUMMY_BUFFER_SIZE, res);
		}
		return res;
	}
	if (size > DEFAULT_JSON_SIZE) {
		debug_log("size capped (input=%zu, max=%d)", size, DEFAULT_JSON_SIZE);
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
	debug_log("Called function");
#ifdef USE_SAFECLIB
	/* There is an inconsistency in the safeclib implementation.  So rewrite. */
	/* Validate inputs */
	if (dest == NULL || src == NULL || n == 0) {
		debug_log("Invalid input (dest=%p, src=%p, n=%zu)", (void *)dest, (void *)src, n);
		return NULL;
	}

	/* Cap n at DEFAULT_JSON_SIZE because the safeclib limits on
	 * --enable-strmax= will cause strlen_s and other safeclib string
	 * functions to break.  It is assumed that safeclib is built with
	 * >= 128K strmax. */
	if (n > DEFAULT_JSON_SIZE) {
		debug_log("n capped (input=%zu, max=%d)", n, DEFAULT_JSON_SIZE);
		n = DEFAULT_JSON_SIZE;
	}

	/* Sanitize dest: Ensure null-termination */
	dest[n - 1] = '\0';
	size_t dest_len = strnlen_s(dest, n);
	if (dest_len >= n - 1) {
		debug_log("No space in dest (dest_len=%zu, n=%zu)", dest_len, n);
		return NULL;
	}

	/* Compute source length */
	size_t max_src_len = n - dest_len - 1;
	if (max_src_len > RSIZE_MAX_STR) {
		max_src_len = RSIZE_MAX_STR; /* Cap at 131072 */
	}
	size_t src_len = strnlen_s(src, max_src_len);
	if (src_len >= max_src_len && (src_len < n && src[src_len] != '\0')) {
		debug_log("src too long (src_len=%zu, max_src_len=%zu)", src_len, max_src_len);
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("src too long (src_len=%zu, max_src_len=%zu), fatal error", src_len, max_src_len);
			/* Fatal error */
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			/* Return error */
			return NULL;
		#else
			 /* Fallback function */
			return strncat(dest, src, max_src_len);
		#endif
	}

	/* Concatenate */
	errno_t res = strncat_s(dest, n, src, RSIZE_MAX_STR);
	if (res != 0) {
		debug_log("strncat_s failed (res=%d, n=%zu, src_len=%zu)", res, n, src_len);
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("strncat_s failed (res=%d, n=%zu, src_len=%zu), fatal error", res, n, src_len);
			/* Fatal error */
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			/* Return error */
			return NULL;
		#else
			/* Fallback function */
			return strncat(dest, src, max_src_len);
		#endif
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
	debug_log("Called function");
#ifdef USE_SAFECLIB
	if (s1 == NULL || s2 == NULL || n == 0) {
		debug_log("Invalid input (s1=%p, s2=%p, n=%zu)", (void *)s1, (void *)s2, n);
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("Invalid input (s1=%p, s2=%p, n=%zu), fatal error", (void *)s1, (void *)s2, n);
			/* Fatal error */
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			/* Return error */
			return -1;
		#else
			/* Fallback function */
			return strncmp(s1, s2, n);
		#endif
	}
	size_t smax = get_smax();
	size_t effective_n = n > smax ? smax : (n > 0 ? n - 1 : 0); /* Exclude null terminator */
	int result = 0;
	errno_t err = strcmp_s(s1, effective_n, s2, &result);
	if (err != 0) {
		debug_log("strcmp_s failed (err=%d, s1=%.32s, s2=%.32s, n=%zu)",
			err, s1 ? s1 : "(null)", s2 ? s2 : "(null)", effective_n);
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("strcmp_s failed (err=%d, s1=%.32s, s2=%.32s, n=%zu), fatal error",
				err, s1 ? s1 : "(null)", s2 ? s2 : "(null)", effective_n);
			/* Fatal error */
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			/* Return error */
			return -1;
		#else
			/* Fallback function */
			return strncmp(s1, s2, n);
		#endif
	}
	return result;
#else
	if (s1 == NULL || s2 == NULL) {
		debug_log("Invalid input (s1=%p, s2=%p, n=%zu)", (void *)s1, (void *)s2, n);
		return -EINVAL;
	}
	if (n == 0) {
		return 0;
	}
	return strncmp(s1, s2, n);
#endif
}

void *_safe_malloc(size_t size) {
	debug_log("Called function");
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
	debug_log("Called function");
	if (getpid() != parent_pid)
		return _safe_malloc(size);
	pthread_mutex_lock(&malloc_lock);
	void *ptr = _safe_malloc(size);
	pthread_mutex_unlock(&malloc_lock);
	return ptr;
}

void _safe_free(void *ptr) {
	debug_log("Called function");
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
	debug_log("Called function");
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
	debug_log("Called function");
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
	if (!haystack || !needle) {
		debug_log("Invalid input in wrap_strstr (haystack=%p, needle=%p)", (void *)haystack, (void *)needle);
		return NULL;
	}
#ifdef USE_SAFECLIB
	size_t smax = get_smax();
	debug_log("wrap_strstr: smax=%zu, haystack=%.32s, needle=%.32s", smax, haystack ? haystack : "(null)", needle ? needle : "(null)");

	/* Validate string contents */
	bool haystack_valid = true, needle_valid = true;
	for (size_t i = 0; haystack[i] && i < smax; i++) {
		if (!isprint((unsigned char)haystack[i]) && haystack[i] != '\0') {
			haystack_valid = false;
			break;
		}
	}
	for (size_t i = 0; needle[i] && i < smax; i++) {
		if (!isprint((unsigned char)needle[i]) && needle[i] != '\0') {
			needle_valid = false;
			break;
		}
	}
	debug_log("wrap_strstr: haystack_valid=%d, needle_valid=%d", haystack_valid, needle_valid);

	size_t haystack_len_glibc = strlen(haystack);
	size_t needle_len_glibc = strlen(needle);
	debug_log("wrap_strstr: glibc haystack_len=%zu, needle_len=%zu", haystack_len_glibc, needle_len_glibc);

	size_t haystack_len = strnlen_s(haystack, smax);
	size_t needle_len = strnlen_s(needle, smax);
	debug_log("wrap_strstr: safeclib haystack_len=%zu, needle_len=%zu", haystack_len, needle_len);

	if (haystack_len == 0 || needle_len == 0) {
		debug_log("Empty input in wrap_strstr (haystack_len=%zu, needle_len=%zu)", haystack_len, needle_len);
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("Aborting in wrap_strstr due to fatal mode (empty input)");
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			return NULL;
		#else
			return strstr(haystack, needle);
		#endif
	}
	if (haystack_len >= smax || needle_len >= smax) {
		debug_log("Input too long in wrap_strstr (haystack_len=%zu, needle_len=%zu, smax=%zu)", haystack_len, needle_len, smax);
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("Aborting in wrap_strstr due to fatal mode (length exceeded)");
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			return NULL;
		#else
			return strstr(haystack, needle);
		#endif
	}
	if (haystack_len != haystack_len_glibc || needle_len != needle_len_glibc || !haystack_valid || !needle_valid) {
		debug_log("Validation failed: haystack_len=%zu, glibc=%zu, needle_len=%zu, glibc=%zu, haystack_valid=%d, needle_valid=%d",
			haystack_len, haystack_len_glibc, needle_len, needle_len_glibc, haystack_valid, needle_valid);
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("Aborting in wrap_strstr due to fatal mode (validation failed)");
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			return NULL;
		#else
			return strstr(haystack, needle);
		#endif
	}
	/* Fallback to glibc for short strings */
	if (haystack_len_glibc < 256 && needle_len_glibc < 256) {
		debug_log("Using glibc strstr for short strings (haystack_len=%zu, needle_len=%zu)", haystack_len_glibc, needle_len_glibc);
		return strstr(haystack, needle);
	}
	char *result = NULL;
	errno_t err = strstr_s((char *)haystack, haystack_len, needle, needle_len, &result);
	if (err != 0) {
		debug_log("strstr_s failed in wrap_strstr (err=%d, haystack=%.32s, needle=%.32s, haystack_len=%zu, needle_len=%zu)",
			err, haystack ? haystack : "(null)", needle ? needle : "(null)", haystack_len, needle_len);
		if (err == ESNOTFND) {
			debug_log("Substring not found, returning NULL");
			return NULL;
		}
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("Aborting in wrap_strstr due to fatal mode (strstr_s error)");
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			return NULL;
		#else
			return strstr(haystack, needle);
		#endif
	}
	return result;
#else
	return strstr(haystack, needle);
#endif
}

size_t wrap_strlen(const char *s) {
	debug_log("Called function");
	if (!s) {
		debug_log("null input");
		return 0;
	}
	size_t smax = get_smax();
#ifdef USE_SAFECLIB
	/* Validate input for file contents (allow control chars) */
	for (size_t i = 0; i < smax; i++) { /* Reasonable limit */
		if (s[i] == '\0') break;
		unsigned char c = (unsigned char)s[i];
		/* Exclude only NUL (0x00) */
		if (c == 0) {
			debug_log("Invalid character 0x%02x at index %zu", c, i);
			return 0;
		}
	}
	rsize_t len = strnlen_s(s, smax);
	if (len == 0 && s[0] != '\0') {
		/* debug_log("strnlen_s failed for input (first 32 chars): '%.32s'", s); */
		size_t fallback_len = strlen(s); /* glibc fallback */
		if (fallback_len >= smax) {
			debug_log("String s exceeds 10 MB");
			return 0;
		}
		return fallback_len;
	}
#else
	size_t len = strlen(s);
	if (len >= smax) {
		debug_log("String s exceeds 10 MB");
		return 0;
	}
#endif
	return len;
}

size_t wrap_strnlen(const char *s, size_t maxlen) {
	debug_log("Called function");
	if (!s) {
		debug_log("Null input for s");
		return 0;
	}
	size_t smax = get_smax();
	size_t effective_max = maxlen < smax ? maxlen : smax;
#ifdef USE_SAFECLIB
	rsize_t len = strnlen_s(s, effective_max);
	if (len == 0 && s[0] != '\0') {
		/* debug_log("strnlen_s failed for input (first 32 chars): '%.32s'", s); */
		return 0;
	}
#else
	size_t len = strnlen(s, effective_max);
#endif
	return len;
}

int wrap_snprintf(char *str, size_t size, const char *format, ...)
{
	debug_log("Called function");
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

char* wrap_strdup(const char* str) {
	debug_log("Called function");
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
	size_t len = wrap_strlen(str) + 1;
	char* dup = NULL;
#pragma GCC diagnostic pop

#if defined(USE_HARDENED_MALLOC)
	extern void* hardened_malloc(size_t size);
	dup = hardened_malloc(len);
	if (dup != NULL) {
		return wrap_memcpy(dup, str, len);
	}
#elif defined(USE_MIMALLOC_SECURE)
	extern void* mimalloc_malloc(size_t size);
	dup = mimalloc_malloc(len);
	if (dup != NULL) {
		return wrap_memcpy(dup, str, len);
	}
#else
	/* Fallback to glibc strdup */
	return strdup(str);
#endif

}

char* wrap_strchr(const char *str, int c) {
	debug_log("Called function");
#ifdef USE_SAFECLIB
	char* result = NULL;
	errno_t err = strchr_s(str, wrap_strlen(str), c, &result);
	if (err != EOK) {
		/* Handle error as needed */
		return NULL;
	}
	return result;
#else
	return strchr(str, c);
#endif
}

char* wrap_strpbrk(const char *str1, const char *str2) {
	debug_log("Called function");
#ifdef USE_SAFECLIB
	char *result = NULL;
	errno_t err = strpbrk_s((char*)str1, wrap_strlen(str1), (char*)str2, wrap_strlen(str2), &result);
	if (err != EOK) {
		/* Handle error as needed */
		return NULL;
        }
	return result;
#else
	return strpbrk(str1, str2);
#endif
}

int wrap_strncasecmp(const char *s1, const char *s2, size_t n) {
	debug_log("Called function");
#ifdef USE_SAFECLIB
	if (s1 == NULL || s2 == NULL || n == 0) {
		debug_log("Invalid input (s1=%p, s2=%p, n=%zu)", (void *)s1, (void *)s2, n);
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("Invalid input (s1=%p, s2=%p, n=%zu), fatal error", (void *)s1, (void *)s2, n);
			/* Fatal error */
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			/* Return error */
			return -1;
		#else
			/* Fallback function */
			return strncasecmp(s1, s2, n); /* Fallback to glibc strncasecmp */
		#endif
	}

	/* Adjust dmax to exclude null terminator */
	size_t effective_n = n > 0 ? n - 1 : 0; /* Safe C expects content length */

	int result = 0;
	errno_t err = strcasecmp_s(s1, effective_n, s2, &result);
	if (err != 0) {
		debug_log("strcasecmp_s failed (err=%d, s1=%.32s, s2=%.32s, n=%zu)",
			err, s1 ? s1 : "(null)", s2 ? s2 : "(null)", effective_n);
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("strcasecmp_s failed (err=%d, s1=%.32s, s2=%.32s, n=%zu), fatal error",
				err, s1 ? s1 : "(null)", s2 ? s2 : "(null)", effective_n);
			/* Fatal error */
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			/* Return error */
			return -1;
		#else
			/* Fallback function */
			return strncasecmp(s1, s2, n); /* Fallback to glibc with original n */
		#endif
	}
	return result; /* strcasecmp_s returns -1, 0, or 1, matching strncasecmp */
#else
	if (s1 == NULL || s2 == NULL) {
		debug_log("Invalid input (s1=%p, s2=%p, n=%zu)", (void *)s1, (void *)s2, n);
		return -EINVAL; /* Consistent with wrap_strncmp */
	}
	if (n == 0) {
		return 0; /* strncasecmp returns 0 for n == 0 */
	}
	return strncasecmp(s1, s2, n);
#endif
}

int wrap_strcmp(const char *s1, const char *s2) {
	debug_log("Called function");
#ifdef USE_SAFECLIB
	if (s1 == NULL || s2 == NULL) {
		debug_log("Invalid input (s1=%p, s2=%p)", (void *)s1, (void *)s2);
		return s1 == s2 ? 0 : (s1 == NULL ? -1 : 1);
	}
	size_t smax = get_smax();
	size_t s1_len = strnlen_s(s1, smax);
	size_t s2_len = strnlen_s(s2, smax);
	if (s1_len == 0 || s2_len == 0) {
		debug_log("Empty string (s1_len=%zu, s2_len=%zu)", s1_len, s2_len);
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("Empty string (s1_len=%zu, s2_len=%zu), fatal error", s1_len, s2_len);
			/* Fatal error */
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			/* Return error */
			return -1;
		#else
			/* Fallback function */
			return strcmp(s1, s2);
		#endif
	}
	if (s1_len >= smax || s2_len >= smax) {
		debug_log("Input too long (s1_len=%zu, s2_len=%zu, smax=%zu)", s1_len, s2_len, smax);
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("Input too long (s1_len=%zu, s2_len=%zu, smax=%zu), fatal error", s1_len, s2_len, smax);
			/* Fatal error */
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			/* Return error */
			return -1;
		#else
			/* Fallback function */
			return strcmp(s1, s2);
		#endif
	}
	int result = 0;
	errno_t err = strcmp_s(s1, s1_len, s2, &result);
	if (err != 0) {
		debug_log("strcmp_s failed (err=%d, s1=%.32s, s2=%.32s)",
			err, s1 ? s1 : "(null)", s2 ? s2 : "(null)");
		#if SAFECLIB_ERROR_HANDLING == 1
			debug_log("strcmp_s failed (err=%d, s1=%.32s, s2=%.32s), fatal error",
				err, s1 ? s1 : "(null)", s2 ? s2 : "(null)");
			/* Fatal error */
			fflush(stderr);
			abort();
		#elif SAFECLIB_ERROR_HANDLING == 2
			/* Return error */
			return -1;
		#else
			/* Fallback function */
			return strcmp(s1, s2);
		#endif
	}
	return result;
#else
	if (s1 == NULL || s2 == NULL) {
		debug_log("Invalid input (s1=%p, s2=%p)", (void *)s1, (void *)s2);
		return s1 == s2 ? 0 : (s1 == NULL ? -1 : 1);
	}
	return strcmp(s1, s2);
#endif
}
