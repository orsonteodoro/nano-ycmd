/*
 * test_ld_preload.c - Tester for LD_PRELOAD validation in nano-ycmd
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
/*
build:
gcc -c -g test_ld_preload.c -o test_ld_preload.o ; \
gcc -o test_ld_preload test_ld_preload.o ld_preload.o -ldl -lgcrypt

test:
LD_PRELOAD="/usr/lib/clang/18/lib/linux/libclang_rt.scudo_standalone-x86_64.so:/usr/lib64/libsandbox.so" ./test_ld_preload 2> test_ld_preload.log cat test_ld_preload.log

results:

env LD_PRELOAD="/usr/lib/clang/18/lib/linux/libclang_rt.scudo_standalone-x86_64.so:/usr/lib64/libsandbox.so" ./test_ld_preload
Starting validate_ld_preload

Starting check_function_integrity

memcpy<REDACTED> (/lib64/libc.so.6)
memset<REDACTED> (/lib64/libc.so.6)
strlen<REDACTED> (/lib64/libc.so.6)
strchr<REDACTED> (/lib64/libc.so.6)
strncmp<REDACTED> (/lib64/libc.so.6)
open<REDACTED> (/usr/lib64/libsandbox.so)
close<REDACTED> (/lib64/libc.so.6)
check_function_integrity completed

safe_getenv: searching for LD_PRELOAD
safe_getenv: found /usr/lib/clang/18/lib/linux/libclang_rt.scudo_standalone-x86_64.so:/usr/lib64/libsandbox.so
LD_PRELOAD pointer0x00007ffd551e9f8a (unknown)
Validating LD_PRELOAD: /usr/lib/clang/18/lib/linux/libclang_rt.scudo_standalone-x86_64.so:/usr/lib64/libsandbox.so
Allowed library: /usr/lib/clang/18/lib/linux/libclang_rt.scudo_standalone-x86_64.so
Allowed fingerprint: ea8f75c90060e8756631346610c96788f08728d49e56f5d2c5ab8aa2d3b3055b
Allowed library: /usr/lib64/libsandbox.so
Allowed fingerprint: 29a93c72b4c5a7609da18ee1135fd6d9f2e667a702aad658f6291c428fdf7d14
Processing LD_PRELOAD path: /usr/lib/clang/18/lib/linux/libclang_rt.scudo_standalone-x86_64.so
is_safe_path: checking path=/usr/lib/clang/18/lib/linux/libclang_rt.scudo_standalone-x86_64.so
Matched allowed library at index: 0
Validating library: /usr/lib/clang/18/lib/linux/libclang_rt.scudo_standalone-x86_64.so
compute_file_sha256: path=/usr/lib/clang/18/lib/linux/libclang_rt.scudo_standalone-x86_64.so
Total bytes read: 4206
Computed SHA256: ea8f75c90060e8756631346610c96788f08728d49e56f5d2c5ab8aa2d3b3055b
Computed fingerprint for /usr/lib/clang/18/lib/linux/libclang_rt.scudo_standalone-x86_64.so
: ea8f75c90060e8756631346610c96788f08728d49e56f5d2c5ab8aa2d3b3055b
Expected fingerprint: ea8f75c90060e8756631346610c96788f08728d49e56f5d2c5ab8aa2d3b3055b
Processing LD_PRELOAD path: /usr/lib64/libsandbox.so
is_safe_path: checking path=/usr/lib64/libsandbox.so
Matched allowed library at index: 1
Validating library: /usr/lib64/libsandbox.so
compute_file_sha256: path=/usr/lib64/libsandbox.so
Total bytes read: 6540
Computed SHA256: 29a93c72b4c5a7609da18ee1135fd6d9f2e667a702aad658f6291c428fdf7d14
Computed fingerprint for /usr/lib64/libsandbox.so
: 29a93c72b4c5a7609da18ee1135fd6d9f2e667a702aad658f6291c428fdf7d14
Expected fingerprint: 29a93c72b4c5a7609da18ee1135fd6d9f2e667a702aad658f6291c428fdf7d14
LD_PRELOAD validation passed: /usr/lib/clang/18/lib/linux/libclang_rt.scudo_standalone-x86_64.so:/usr/lib64/libsandbox.so
Test completed

*/
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void validate_ld_preload(void);

int main() {
	validate_ld_preload();
	char buf[256];
	strcpy(buf, "test");
	strlen(buf);
	strchr(buf, 'e');
	strncmp(buf, "test", 4);
	memset(buf, 0, 256);
	memcpy(buf, "copy", 5);
	int fd = open("test.txt", O_CREAT | O_WRONLY, 0644);
	if (fd >= 0) {
		write(fd, "test", 4);
		close(fd);
	}
	printf("Test completed\n");
	return 0;
}
