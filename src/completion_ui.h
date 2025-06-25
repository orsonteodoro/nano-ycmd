/* completion_ui.h - Header for code completion UI in nano-ycmd
 *
 * Copyright (C) 2025 Orson Teodoro
 *
 * This file is part of nano-ycmd, a fork of GNU nano with ycmd integration.
 *
 * Note: This code was developed with assistance from Grok, created by xAI.
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
#ifndef COMPLETION_UI_H
#define COMPLETION_UI_H
#include <jansson.h>
#include "definitions.h"
extern bool ycmd_handling;
extern json_t *active_completions;
extern size_t cursor_x;
extern size_t cursor_y;
extern int get_current_y(const openfilestruct *file);
extern int logical_to_display_x(const char *line_data, int logical_x, int tabsize);
extern void hide_completions(void);
#endif
