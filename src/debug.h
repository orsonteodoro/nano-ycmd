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

#ifdef DEBUG
#define debug_log(format, ...) \
	do { \
		fprintf(stderr, "%s:  " format "\n", __func__, ##__VA_ARGS__); \
	} while (0)
#else
#define debug_log(...)
#endif
