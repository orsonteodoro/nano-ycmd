/*
 * ld_preload.c - LD_PRELOAD validation for nano-ycmd
 *
 * Copyright (C) 2025 Orson Teodoro <orsonteodoro@hotmail.com>
 *
 * This file is part of nano-ycmd, a derivative work of the nano editor.
 *
 * nano-ycmd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nano-ycmd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* There is an issue with the first design.  It immediately used malloc
 * which runs the attacker's compromised code.
 *
 * The current design avoids use of malloc and indirect malloc calls
 * from crypto libraries that may call malloc. */

/* Space to tabs: */
/* clang-format -i -style="{IndentWidth: 4, TabWidth: 4, UseTab: Always}" src/ld_preload.c */

#include "config.h"

#define _GNU_SOURCE
#include "config.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* Avoid stdio.h and other headers that'll use malloc */
#ifndef SCUDO_LIB_PATH
#define SCUDO_LIB_PATH "none"
#endif
#ifndef SANDBOX_LIB_PATH
#define SANDBOX_LIB_PATH "none"
#endif
#ifndef SCUDO_FINGERPRINT
#define SCUDO_FINGERPRINT "none"
#endif
#ifndef SANDBOX_FINGERPRINT
#define SANDBOX_FINGERPRINT "none"
#endif
#ifndef LIB_SAFE_PATHS
#define LIB_SAFE_PATHS "/usr/lib/,/usr/lib64/,/usr/lib/clang/"
#endif

/* Thread-local logging buffer */
#define LOG_BUFFER_SIZE 1024
static __thread char log_buffer[LOG_BUFFER_SIZE];

/* External environ variable */
extern char **environ;

static void safe_memset(void *dst, int c, size_t n);

/* Safe logging using syscall */
static void safe_log(const char *msg) {
	if (!msg) {
		safe_log("safe_log: null msg\n");
		return;
	}
	size_t len = 0;
	safe_memset(log_buffer, 0, LOG_BUFFER_SIZE);
	while (len < LOG_BUFFER_SIZE - 2 && msg[len]) {
		volatile char probe = msg[len];
		(void)probe;
		if (msg[len] < 32 && msg[len] != '\n' && msg[len] != '\0') {
			log_buffer[len] = '?';
		} else {
			log_buffer[len] = msg[len];
		}
		len++;
	}
	log_buffer[len] = '\n';
	log_buffer[len + 1] = '\0';
	ssize_t written = syscall(SYS_write, STDERR_FILENO, log_buffer, len + 1);
	if (written < 0) {
		_exit(1);
	}
}

static void safe_log_string(const char *prefix, const char *str) {
	if (!prefix || !str) {
		safe_log("safe_log_string: null prefix or str\n");
		return;
	}
	char buf[LOG_BUFFER_SIZE];
	size_t i = 0;
	while (i < LOG_BUFFER_SIZE - 2 && *prefix) {
		buf[i++] = *prefix++;
	}
	while (i < LOG_BUFFER_SIZE - 2 && *str) {
		buf[i++] = *str++;
	}
	if (*str) {
		safe_log("safe_log_string: string truncated\n");
		buf[LOG_BUFFER_SIZE - 2] = '\n';
		buf[LOG_BUFFER_SIZE - 1] = '\0';
		i = LOG_BUFFER_SIZE - 1;
	} else {
		buf[i++] = '\n';
		buf[i] = '\0';
	}
	ssize_t written = syscall(SYS_write, STDERR_FILENO, buf, i);
	if (written < 0) {
		safe_log("safe_log_string: write failed\n");
		_exit(1);
	}
}

/* Log a pointer as hex with library info */
static void safe_log_pointer(const char *prefix, const void *ptr, const char *func_name) {
	if (!prefix || !ptr || !func_name) {
		safe_log("safe_log_pointer: null prefix, ptr, or func_name\n");
		return;
	}
	safe_memset(log_buffer, 0, LOG_BUFFER_SIZE);
	size_t prefix_len = 0;
	while (prefix_len < LOG_BUFFER_SIZE - 2 && prefix[prefix_len]) {
		volatile char probe = prefix[prefix_len];
		(void)probe;
		log_buffer[prefix_len] = prefix[prefix_len];
		prefix_len++;
	}
	char *buf = log_buffer + prefix_len;
	*buf++ = '0';
	*buf++ = 'x';
	for (int i = 15; i >= 0; i--) {
		uint8_t nibble = (uint64_t)ptr >> (i * 4) & 0xF;
		*buf++ = nibble < 10 ? '0' + nibble : 'a' + (nibble - 10);
		if (buf - log_buffer >= LOG_BUFFER_SIZE - 2) {
			safe_log("safe_log_pointer: buffer overrun\n");
			_exit(1);
		}
	}
	*buf++ = ' ';
	*buf++ = '(';
	const char *lib_name = "unknown";
	Dl_info info;
	if (dladdr(ptr, &info) && info.dli_fname) {
		lib_name = info.dli_fname;
	}
	size_t lib_len = 0;
	while (lib_len < LOG_BUFFER_SIZE - (buf - log_buffer) - 3 &&
		   lib_name[lib_len]) {
		volatile char probe = lib_name[lib_len];
		(void)probe;
		if (lib_name[lib_len] < 32 && lib_name[lib_len] != '\0') {
			*buf++ = '?';
		} else {
			*buf++ = lib_name[lib_len];
		}
		lib_len++;
	}
	*buf++ = ')';
	*buf++ = '\n';
	*buf = '\0';
	ssize_t written =
		syscall(SYS_write, STDERR_FILENO, log_buffer, buf - log_buffer);
	if (written < 0) {
		_exit(1);
	}
}

static void safe_memset(void *dst, int c, size_t n) {
	if (!dst) {
		safe_log("safe_memset: null dst\n");
		_exit(1);
	}
	if (n > LOG_BUFFER_SIZE) {
		safe_log("safe_memset: size too large\n");
		_exit(1);
	}
	char *d = (char *)dst;
	for (size_t i = 0; i < n; i++) {
		d[i] = (char)c;
	}
}

static void safe_memcpy(void *dst, const void *src, size_t n) {
	if (!dst || !src) {
		safe_log("safe_memcpy: null dst or src\n");
		_exit(1);
	}
	if (n > LOG_BUFFER_SIZE) {
		safe_log("safe_memcpy: size too large\n");
		_exit(1);
	}
	char *d = (char *)dst;
	const char *s = (const char *)src;
	for (size_t i = 0; i < n; i++) {
		volatile char probe = s[i];
		(void)probe;
		d[i] = s[i];
	}
}

/* SHA256 implementation (allocation-free) */
typedef struct {
	uint32_t state[8];
	uint64_t count;
	uint8_t buffer[64];
	uint32_t buf_len;
} sha256_context;

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static void sha256_init(sha256_context *ctx) {
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
	ctx->count = 0;
	ctx->buf_len = 0;
}

static void sha256_transform(sha256_context *ctx, const uint8_t *data) {
	uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];

	for (int i = 0; i < 16; ++i) {
		m[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) |
			   (data[i * 4 + 2] << 8) | (data[i * 4 + 3]);
	}
	for (int i = 16; i < 64; ++i) {
		uint32_t s0 = ((m[i - 15] >> 7) | (m[i - 15] << 25)) ^
					  ((m[i - 15] >> 18) | (m[i - 15] << 14)) ^
					  (m[i - 15] >> 3);
		uint32_t s1 = ((m[i - 2] >> 17) | (m[i - 2] << 15)) ^
					  ((m[i - 2] >> 19) | (m[i - 2] << 13)) ^ (m[i - 2] >> 10);
		m[i] = m[i - 16] + s0 + m[i - 7] + s1;
	}

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (int i = 0; i < 64; ++i) {
		t1 = h +
			 (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^
			  ((e >> 25) | (e << 7))) +
			 ((e & f) ^ (~e & g)) + K[i] + m[i];
		t2 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^
			  ((a >> 22) | (a << 10))) +
			 ((a & b) ^ (a & c) ^ (b & c));
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

static void sha256_update(sha256_context *ctx, const uint8_t *data,
						  size_t len) {
	size_t i = 0;
	if (ctx->buf_len > 0) {
		size_t to_copy = 64 - ctx->buf_len < len ? 64 - ctx->buf_len : len;
		safe_memcpy(ctx->buffer + ctx->buf_len, data, to_copy);
		ctx->buf_len += to_copy;
		i += to_copy;
		if (ctx->buf_len == 64) {
			sha256_transform(ctx, ctx->buffer);
			ctx->buf_len = 0;
		}
	}
	while (i + 63 < len) {
		sha256_transform(ctx, data + i);
		i += 64;
	}
	if (i < len) {
		safe_memcpy(ctx->buffer + ctx->buf_len, data + i, len - i);
		ctx->buf_len = len - i;
	}
	ctx->count += len * 8;
}

static void sha256_final(sha256_context *ctx, uint8_t *hash) {
	ctx->buffer[ctx->buf_len++] = 0x80;
	if (ctx->buf_len > 56) {
		safe_memset(ctx->buffer + ctx->buf_len, 0, 64 - ctx->buf_len);
		sha256_transform(ctx, ctx->buffer);
		ctx->buf_len = 0;
	}
	safe_memset(ctx->buffer + ctx->buf_len, 0, 56 - ctx->buf_len);
	ctx->buffer[56] = (ctx->count >> 56) & 0xff;
	ctx->buffer[57] = (ctx->count >> 48) & 0xff;
	ctx->buffer[58] = (ctx->count >> 40) & 0xff;
	ctx->buffer[59] = (ctx->count >> 32) & 0xff;
	ctx->buffer[60] = (ctx->count >> 24) & 0xff;
	ctx->buffer[61] = (ctx->count >> 16) & 0xff;
	ctx->buffer[62] = (ctx->count >> 8) & 0xff;
	ctx->buffer[63] = ctx->count & 0xff;
	sha256_transform(ctx, ctx->buffer);
	for (int i = 0; i < 8; i++) {
		hash[i * 4] = (ctx->state[i] >> 24) & 0xff;
		hash[i * 4 + 1] = (ctx->state[i] >> 16) & 0xff;
		hash[i * 4 + 2] = (ctx->state[i] >> 8) & 0xff;
		hash[i * 4 + 3] = ctx->state[i] & 0xff;
	}
}

/* Compute SHA256 hash of a file using syscalls */
static int compute_file_sha256(const char *path, char *hex_hash) {
	if (!path) {
		safe_log("Null path in compute_file_sha256\n");
		return -1;
	}
	safe_log_string("compute_file_sha256: path=", path);
	int fd = syscall(SYS_open, path, O_RDONLY, 0);
	if (fd < 0) {
		safe_log("Failed to open file for hashing\n");
		return -1;
	}
	sha256_context ctx;
	sha256_init(&ctx);
	uint8_t buffer[4096];
	ssize_t bytes;
	size_t total_bytes = 0;
	char total_buf[32];
	safe_memset(total_buf, 0, sizeof(total_buf));
	while ((bytes = syscall(SYS_read, fd, buffer, sizeof(buffer))) > 0) {
		sha256_update(&ctx, buffer, bytes);
		total_bytes += bytes;
	}
	if (bytes < 0) {
		safe_log("Failed to read file for hashing\n");
		syscall(SYS_close, fd);
		return -1;
	}
	size_t i = 0;
	uint64_t n = total_bytes;
	do {
		total_buf[sizeof(total_buf) - 1 - i++] = '0' + (n % 10);
		n /= 10;
	} while (n && i < sizeof(total_buf));
	total_buf[sizeof(total_buf) - i] = '\0';
	for (size_t j = 0; j < i / 2; j++) {
		char tmp = total_buf[sizeof(total_buf) - 1 - j];
		total_buf[sizeof(total_buf) - 1 - j] =
			total_buf[sizeof(total_buf) - i + j];
		total_buf[sizeof(total_buf) - i + j] = tmp;
	}
	safe_log_string("Total bytes read: ", total_buf + sizeof(total_buf) - i);
	uint8_t hash[32];
	sha256_final(&ctx, hash);
	for (int i = 0; i < 32; i++) {
		const char hex[] = "0123456789abcdef";
		hex_hash[i * 2] = hex[(hash[i] >> 4) & 0xf];
		hex_hash[i * 2 + 1] = hex[hash[i] & 0xf];
	}
	hex_hash[64] = '\0';
	safe_log_string("Computed SHA256: ", hex_hash);
	syscall(SYS_close, fd);
	return 0;
}

/* Custom string copy */
static void safe_strcpy(char *dst, const char *src, size_t max_len) {
	if (!src || !dst) {
		if (dst)
			dst[0] = '\0';
		safe_log("safe_strcpy: null src or dst\n");
		return;
	}
	size_t i = 0;
	while (i < max_len - 1 && src[i]) {
		volatile char probe = src[i];
		(void)probe;
		if (src[i] < 32 && src[i] != '\0') {
			safe_log("safe_strcpy: non-printable character detected\n");
			_exit(1);
		}
		dst[i] = src[i];
		i++;
	}
	dst[i] = '\0';
	if (i == max_len - 1 && src[i]) {
		safe_log("safe_strcpy: string too long\n");
		_exit(1);
	}
}

/* Custom string length */
static size_t safe_strlen(const char *str, size_t max_len) {
	if (!str)
		return 0;
	size_t i = 0;
	while (i < max_len && str[i]) {
		volatile char probe = str[i];
		(void)probe;
		if (str[i] < 32 && str[i] != '\0') {
			safe_log("safe_strlen: non-printable character detected\n");
			_exit(1);
		}
		i++;
	}
	return i;
}

/* Custom string comparison */
static int safe_strcmp(const char *s1, const char *s2) {
	if (!s1 || !s2) {
		safe_log("safe_strcmp: null s1 or s2\n");
		return s1 == s2 ? 0 : (s1 ? 1 : -1);
	}
	size_t i = 0;
	while (s1[i] && s1[i] == s2[i]) {
		volatile char probe = s1[i];
		(void)probe;
		if (s1[i] < 32 && s1[i] != '\0') {
			safe_log("safe_strcmp: non-printable character detected\n");
			_exit(1);
		}
		i++;
	}
	return *(unsigned char *)(s1 + i) - *(unsigned char *)(s2 + i);
}

/* Custom string search */
static const char *safe_strstr(const char *haystack, const char *needle) {
	if (!haystack || !needle || !*needle)
		return haystack;
	size_t i = 0;
	while (haystack[i]) {
		const char *h = haystack + i, *n = needle;
		size_t j = 0;
		while (h[j] && n[j] && h[j] == n[j]) {
			volatile char probe = h[j];
			(void)probe;
			if (h[j] < 32 && h[j] != '\0') {
				safe_log("safe_strstr: non-printable character detected\n");
				_exit(1);
			}
			j++;
		}
		if (!n[j])
			return haystack + i;
		i++;
	}
	return NULL;
}

/* Check for path traversal or invalid paths */
static int is_safe_path(const char *path) {
	if (!path) {
		safe_log("Invalid path (null)\n");
		return 0;
	}
	safe_log_string("is_safe_path: checking path=", path);
	if (path[0] != '/') {
		safe_log("Invalid path (non-absolute)\n");
		return 0;
	}
	if (safe_strstr(path, "..") || safe_strstr(path, "//") ||
		safe_strstr(path, "/./")) {
		safe_log("Path traversal detected\n");
		return 0;
	}

	char safe_paths_buf[256];
	safe_strcpy(safe_paths_buf, LIB_SAFE_PATHS, sizeof(safe_paths_buf));
	char *safe_paths[16] = {NULL};
	int path_count = 0;
	char *token = safe_paths_buf;
	const char *end;
	while (token && path_count < 15) {
		end = safe_strstr(token, ",");
		if (end) {
			size_t len = end - token;
			char *tmp = token + len;
			*tmp = '\0';
		}
		if (safe_strlen(token, 256) > 0) {
			safe_paths[path_count++] = token;
		}
		token = end ? (char *)(end + 1) : NULL;
	}

	int found = 0;
	for (int i = 0; i < path_count; i++) {
		size_t len = safe_strlen(safe_paths[i], 256);
		if (len > 0 && strncmp(path, safe_paths[i], len) == 0) {
			found = 1;
			break;
		}
	}
	if (!found) {
		safe_log("Path does not start with an allowed prefix\n");
		return 0;
	}
	return 1;
}

/* Whitelist of allowed libraries */
static const struct {
	const char *path;
	const char *fingerprint;
} allowed_libs[] = {
	{SCUDO_LIB_PATH, SCUDO_FINGERPRINT},
	{SANDBOX_LIB_PATH, SANDBOX_FINGERPRINT},
	{NULL, NULL}
};

static const char *safe_getenv(const char *name) {
	if (!name) {
		safe_log("safe_getenv: null name\n");
		return NULL;
	}
	size_t name_len = safe_strlen(name, 256);
	if (name_len == 0) {
		safe_log("safe_getenv: empty name\n");
		return NULL;
	}
	safe_log_string("safe_getenv: searching for ", name);
	for (char **env = environ; *env; env++) {
		if (!*env)
			continue;
		size_t i = 0;
		while (i < name_len && (*env)[i] && (*env)[i] == name[i]) {
			volatile char probe = (*env)[i];
			(void)probe;
			if ((*env)[i] < 32 && (*env)[i] != '\0') {
				safe_log("safe_getenv: non-printable character in env\n");
				continue;
			}
			i++;
		}
		if (i == name_len && (*env)[i] == '=') {
			const char *value = *env + i + 1;
			safe_log_string("safe_getenv: found ", value);
			return value;
		}
	}
	safe_log("safe_getenv: not found\n");
	return NULL;
}

/* Check for function overrides */
static void check_function_integrity(void) {
	const char *functions[] = {
		"memcpy",
		"memset",
		"strlen",
		"strchr",
		"strncmp",
		"open",
		"close",
		NULL
	};
	const char *allowed_libs_for_io[] = {SCUDO_LIB_PATH, SANDBOX_LIB_PATH, NULL};
	safe_log("Starting check_function_integrity\n");
	for (int i = 0; functions[i]; i++) {
		void *func_ptr = dlsym(RTLD_DEFAULT, functions[i]);
		if (!func_ptr) {
			safe_log_string("Function not found: ", functions[i]);
			_exit(1);
		}
		Dl_info info;
		if (!dladdr(func_ptr, &info) || !info.dli_fname) {
			safe_log_string("Failed to get library info for: ", functions[i]);
			_exit(1);
		}
		safe_log_pointer(functions[i], func_ptr, functions[i]);
		if (safe_strcmp(functions[i], "memcpy") == 0 ||
			safe_strcmp(functions[i], "memset") == 0 ||
			safe_strcmp(functions[i], "strlen") == 0 ||
			safe_strcmp(functions[i], "strchr") == 0 ||
			safe_strcmp(functions[i], "strncmp") == 0) {
			if (!safe_strstr(info.dli_fname, "libc")) {
				safe_log_string("Suspicious library for ", functions[i]);
				safe_log_string(": ", info.dli_fname);
				_exit(1);
			}
		} else {
			int from_allowed_lib = 0;
			if (safe_strstr(info.dli_fname, "libc")) {
				from_allowed_lib = 1;
			} else {
				for (int j = 0; allowed_libs_for_io[j]; j++) {
					if (safe_strcmp(allowed_libs_for_io[j], "none") != 0 &&
						safe_strstr(info.dli_fname, allowed_libs_for_io[j])) {
						from_allowed_lib = 1;
						break;
					}
				}
			}
			if (!from_allowed_lib) {
				safe_log_string("Suspicious library for ", functions[i]);
				safe_log_string(": ", info.dli_fname);
				_exit(1);
			}
		}
	}
	safe_log("check_function_integrity completed\n");
}

void validate_ld_preload(void) {
	safe_log("Starting validate_ld_preload\n");
	check_function_integrity();
	const char *ld_preload = safe_getenv("LD_PRELOAD");
	if (!ld_preload || !ld_preload[0]) {
		safe_log("LD_PRELOAD unset or empty, skipping validation\n");
		return;
	}
	safe_log_pointer("LD_PRELOAD pointer", ld_preload, "LD_PRELOAD");
	char ld_preload_buf[LOG_BUFFER_SIZE];
	safe_strcpy(ld_preload_buf, ld_preload, LOG_BUFFER_SIZE);
	if (!ld_preload_buf[0]) {
		safe_log("LD_PRELOAD copied value is empty, skipping validation\n");
		return;
	}
	safe_log_string("Validating LD_PRELOAD: ", ld_preload_buf);

	int has_valid_libs = 0;
	for (int i = 0; allowed_libs[i].path; i++) {
		if (safe_strcmp(allowed_libs[i].path, "none") != 0) {
			safe_log_string("Allowed library: ", allowed_libs[i].path);
			safe_log_string("Allowed fingerprint: ",
							allowed_libs[i].fingerprint);
			has_valid_libs = 1;
		}
	}
	if (!has_valid_libs) {
		safe_log("No valid libraries whitelisted, aborting\n");
		_exit(1);
	}

	int all_valid = 1;
	char parse_buf[LOG_BUFFER_SIZE];
	safe_strcpy(parse_buf, ld_preload,
				LOG_BUFFER_SIZE); /* Separate buffer for parsing */
	char *start = parse_buf;
	const char *end;
	while (*start) {
		end = safe_strstr(start, ":");
		if (end) {
			size_t len = end - start;
			char *tmp = start + len;
			*tmp = '\0';
		}
		if (safe_strlen(start, 256) > 0) {
			safe_log_string("Processing LD_PRELOAD path: ", start);
			if (syscall(SYS_access, start, F_OK) != 0) {
				safe_log_string("Inaccessible path in LD_PRELOAD: ", start);
				all_valid = 0;
				if (!end)
					break;
				start = (char *)(end + 1);
				continue;
			}
			if (!is_safe_path(start)) {
				safe_log_string("Unsafe path in LD_PRELOAD: ", start);
				all_valid = 0;
				if (!end)
					break;
				start = (char *)(end + 1);
				continue;
			}
			int found = 0;
			int lib_index = -1;
			for (int i = 0; allowed_libs[i].path; i++) {
				if (safe_strcmp(allowed_libs[i].path, "none") != 0 &&
					safe_strcmp(allowed_libs[i].path, start) == 0) {
					char index_buf[16];
					safe_memset(index_buf, 0, sizeof(index_buf));
					index_buf[0] = '0' + i;
					index_buf[1] = '\0';
					safe_log_string("Matched allowed library at index: ",
									index_buf);
					found = 1;
					lib_index = i;
					break;
				}
			}
			if (!found) {
				safe_log_string("Untrusted library in LD_PRELOAD: ", start);
				all_valid = 0;
				if (!end)
					break;
				start = (char *)(end + 1);
				continue;
			}
			safe_log_string("Validating library: ", start);
			if (safe_strcmp(allowed_libs[lib_index].fingerprint, "none") == 0) {
				safe_log("No fingerprint check required\n");
			} else {
				char hex_hash[65];
				if (compute_file_sha256(start, hex_hash) != 0) {
					safe_log_string("Failed fingerprint computation for: ",
									start);
					all_valid = 0;
				} else {
					safe_log_string("Computed fingerprint for ", start);
					safe_log_string(": ", hex_hash);
					safe_log_string("Expected fingerprint: ",
									allowed_libs[lib_index].fingerprint);
					if (safe_strcmp(hex_hash,
									allowed_libs[lib_index].fingerprint) != 0) {
						safe_log_string("Fingerprint mismatch for: ", start);
						all_valid = 0;
					}
				}
			}
		}
		if (!end)
			break;
		start = (char *)(end + 1);
	}
	if (!all_valid) {
		safe_log("Aborting due to invalid LD_PRELOAD libraries\n");
		_exit(1);
	}
	/* Use original ld_preload for final log to avoid corruption */
	safe_log_string("LD_PRELOAD validation passed: ", ld_preload);
}
