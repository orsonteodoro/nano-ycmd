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
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include "debug.h"

#ifdef USE_NETTLE
#include <nettle/sha2.h>
#endif
#ifdef USE_LIBGCRYPT
#include <gcrypt.h>
#endif
#ifdef USE_OPENSSL
#include <openssl/sha.h>
#endif

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

#ifndef SHA256_PROG
#define SHA256_PROG "sha256sum"
#endif
#ifndef SHA256_CMD
#define SHA256_CMD "sha256sum '%s' | awk '{print $1}'"
#endif

#ifndef LIB_SAFE_PATHS
#define LIB_SAFE_PATHS "/usr/lib/,/usr/lib64/,/usr/lib/clang/"
#endif

/* Whitelist of allowed libraries */
static const struct {
	const char *path;
	const char *fingerprint;
} allowed_libs[] = {
	{ SCUDO_LIB_PATH, SCUDO_FINGERPRINT },
	{ SANDBOX_LIB_PATH, SANDBOX_FINGERPRINT },
	{ NULL, NULL }
};

/* Compute SHA256 hash of a file */
static char *compute_file_sha256(const char *path) {
	char *hex_hash = malloc(65); /* SHA256 is 64 chars + null */
	if (!hex_hash) {
		debug_log("Failed to allocate memory for hash");
		return NULL;
	}
	FILE *fp = fopen(path, "rb");
	if (!fp) {
		debug_log("Failed to open %s for hashing: %s", path, strerror(errno));
		free(hex_hash);
		return NULL;
	}

#ifdef USE_NETTLE
	struct sha256_ctx ctx;
	unsigned char hash[SHA256_DIGEST_SIZE];
	sha256_init(&ctx);
	unsigned char buffer[4096];
	size_t bytes;
	while ((bytes = fread(buffer, 1, sizeof(buffer), fp))) {
		sha256_update(&ctx, bytes, buffer);
	}
	sha256_digest(&ctx, SHA256_DIGEST_SIZE, hash);
	for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
		sprintf(hex_hash + (i * 2), "%02x", hash[i]);
	}
	hex_hash[64] = '\0';
#elif defined(USE_LIBGCRYPT)
	gcry_md_hd_t hd;
	if (gcry_md_open(&hd, GCRY_MD_SHA256, 0) != 0) {
		debug_log("Failed to initialize libgcrypt for %s", path);
		fclose(fp);
		free(hex_hash);
		return NULL;
	}
	unsigned char buffer[4096];
	size_t bytes;
	while ((bytes = fread(buffer, 1, sizeof(buffer), fp))) {
		gcry_md_write(hd, buffer, bytes);
	}
	unsigned char *hash = gcry_md_read(hd, GCRY_MD_SHA256);
	for (int i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA256); i++) {
		sprintf(hex_hash + (i * 2), "%02x", hash[i]);
	}
	hex_hash[64] = '\0';
	gcry_md_close(hd);
#elif defined(USE_OPENSSL)
	SHA256_CTX ctx;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_Init(&ctx);
	unsigned char buffer[4096];
	size_t bytes;
	while ((bytes = fread(buffer, 1, sizeof(buffer), fp))) {
		SHA256_Update(&ctx, buffer, bytes);
	}
	SHA256_Final(hash, &ctx);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(hex_hash + (i * 2), "%02x", hash[i]);
	}
	hex_hash[64] = '\0';
#else /* USE_SHA256SUM */
	fclose(fp);
	char command[512];
	snprintf(command, sizeof(command), "%s 2>/dev/null", SHA256_CMD);
	FILE *fp_cmd = popen(command, "r");
	if (!fp_cmd) {
		debug_log("Failed to run %s for %s: %s", SHA256_PROG, path, strerror(errno));
		free(hex_hash);
		return NULL;
	}
	if (fgets(hex_hash, 65, fp_cmd) == NULL) {
		debug_log("Failed to read hash for %s", path);
		pclose(fp_cmd);
		free(hex_hash);
		return NULL;
	}
	hex_hash[strcspn(hex_hash, "\n")] = '\0';
	pclose(fp_cmd);
#endif
	fclose(fp);
	return hex_hash;
}

/* Mitigate against Path Traversal Vulnerability */
/* Check for path traversal or invalid paths */
static int is_safe_path(const char *path) {
	if (!path || path[0] != '/') {
		debug_log("Invalid path (null or non-absolute): %s", path ? path : "(null)");
		return 0;
	}
	if (strstr(path, "..") || strstr(path, "//") || strstr(path, "/./")) {
		debug_log("Path traversal detected in %s", path);
		return 0;
	}

	/* Parse SAFE_PATHS into an array */
	char *safe_paths_str = strdup(LIB_SAFE_PATHS);
	if (!safe_paths_str) {
		debug_log("Failed to allocate memory for safe_paths");
		return 0;
	}
	char *safe_paths[16] = { NULL }; /* Limit to 16 paths */
	int path_count = 0;
	debug_log("LIB_SAFE_PATHS: %s", LIB_SAFE_PATHS);
	char *token = strtok(safe_paths_str, ",");
	while (token && path_count < 15) {
		/* Remove leading/trailing whitespace and ensure non-empty */
		size_t len = strlen(token);
		while (len > 0 && isspace(token[len - 1])) {
			token[--len] = '\0';
		}
		while (len > 0 && isspace(token[0])) {
			token++;
			len--;
		}
		if (len > 0) {
			safe_paths[path_count++] = token;
		}
		token = strtok(NULL, ",");
	}

	int found = 0;
	for (int i = 0; i < path_count; i++) {
		size_t len = strlen(safe_paths[i]);
		debug_log("Checking path %s against prefix %s (len=%zu)", path, safe_paths[i], len);
		if (len > 0 && strncmp(path, safe_paths[i], len) == 0) {
			debug_log("Path %s matches prefix %s", path, safe_paths[i]);
			found = 1;
			break;
		}
	}
	free(safe_paths_str);
	if (!found) {
		debug_log("Path does not start with an allowed prefix: %s", path);
		return 0;
	}
	return 1;
}

/* Validate LD_PRELOAD */
void validate_ld_preload(void) {
	const char *ld_preload = getenv("LD_PRELOAD");
	if (!ld_preload || strlen(ld_preload) == 0) {
		debug_log("LD_PRELOAD unset or empty, skipping validation");
		return;
	}

	/* Check if any valid libraries are whitelisted */
	int has_valid_libs = 0;
	for (int i = 0; allowed_libs[i].path; i++) {
		if (strcmp(allowed_libs[i].path, "none") != 0) {
			has_valid_libs = 1;
			break;
		}
	}
	if (!has_valid_libs) {
		debug_log("No valid libraries whitelisted, aborting due to LD_PRELOAD: %s", ld_preload);
		abort();
	}

	char *ld_preload_copy = strdup(ld_preload);
	if (!ld_preload_copy) {
		debug_log("Failed to allocate memory for LD_PRELOAD copy");
		abort();
	}

	debug_log("Validating LD_PRELOAD: %s", ld_preload);
	char *start = ld_preload_copy;
	char *end;
	while (*start) {
		/* Find the next colon or end of string */
		end = strchr(start, ':');
		if (end) {
			*end = '\0'; /* Null-terminate the current path */
		}
		if (strlen(start) > 0) { /* Skip empty tokens */
			debug_log("Processing LD_PRELOAD path: %s", start);
			if (!is_safe_path(start)) {
				debug_log("Aborting due to unsafe path in LD_PRELOAD: %s", start);
				free(ld_preload_copy);
				abort();
			}

			int found = 0;
			for (int i = 0; allowed_libs[i].path; i++) {
				if (strcmp(allowed_libs[i].path, "none") == 0) {
					continue; /* Skip disabled libraries */
				}
				if (strcmp(start, allowed_libs[i].path) == 0) {
					/* Check if file exists */
					if (access(start, F_OK) != 0) {
						debug_log("Aborting due to non-existent library in LD_PRELOAD: %s (%s)", start, strerror(errno));
						free(ld_preload_copy);
						abort();
					}
					if (strcmp(allowed_libs[i].fingerprint, "none") == 0) {
						debug_log("No fingerprint available for %s, allowing", start);
						found = 1;
						break;
					}
					char *file_hash = compute_file_sha256(start);
					if (!file_hash) {
						debug_log("Aborting due to failed fingerprint computation for %s", start);
						free(ld_preload_copy);
						abort();
					}
					if (strcmp(file_hash, allowed_libs[i].fingerprint) == 0) {
						debug_log("Fingerprint match for %s: %s", start, file_hash);
						found = 1;
					} else {
						debug_log("Fingerprint mismatch for %s: expected %s, got %s",
							start, allowed_libs[i].fingerprint, file_hash);
						free(file_hash);
						free(ld_preload_copy);
						abort();
					}
					free(file_hash);
					break;
				}
			}
			if (!found) {
				debug_log("Aborting due to untrusted library in LD_PRELOAD: %s", start);
				free(ld_preload_copy);
				abort();
			}
		}
		if (end) {
			start = end + 1; /* Move to next path */
		} else {
			break; /* End of string */
		}
	}
	free(ld_preload_copy);
	debug_log("LD_PRELOAD validation passed: %s", ld_preload);
}
