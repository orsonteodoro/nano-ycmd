/* debug.h - Debug header for nano-ycmd
 *
 * Copyright (C) 2025 Orson Teodoro (for nano-ycmd modifications)
 *
 * This file is part of nano-ycmd, a fork of GNU nano with ycmd integration.
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
 * along with nano-ycmd.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "config.h"
#include <stdio.h>



#ifdef DEBUG
#define debug_log(format, ...) \
	do { \
		fprintf(stderr, "%s:  " format "\n", __func__, ##__VA_ARGS__); \
		fflush(stderr); \
	} while (0)

#define debug_log2(format, ...) \
	do { \
            FILE *log_file = fopen("/tmp/ycmd_debug.log", "a"); \
            if (log_file) { \
                fprintf(log_file, "%s: " format "\n", __func__, ##__VA_ARGS__); \
                fflush(log_file); \
                fclose(log_file); \
            } \
            fprintf(stderr, "%s: " format "\n", __func__, ##__VA_ARGS__); \
            fflush(stderr); \
	} while (0)
#else
#define debug_log(...)
#endif

