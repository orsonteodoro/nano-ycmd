/* nano.h - A header for nano-ycmd
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
#ifndef NANO_H
#define NANO_H
#include <ncurses.h>
#include <jansson.h>
#include "definitions.h"
int get_current_y(const struct openfilestruct *file);
extern bool is_popup_mode; /* Global popup mode flag */
extern bool refresh_needed;
extern struct openfilestruct *openfile;
extern WINDOW *midwin;
extern WINDOW *topwin;
extern WINDOW *footwin;
extern int get_current_line_number(const struct openfilestruct *file);
extern int is_popup_active(void);
extern int parse_kbinput(WINDOW *win);
extern int ycmd_req_completions_suggestions(int linenum, int columnnum, char *filepath,
                                    struct linestruct *filetop, char *completertarget,
                                    int event, json_t **completions_out);
extern json_t *request_completions(const char *filename, int line, int column, linestruct *filetop, int event);
extern void bottombars(int menu);
extern void edit_redraw(linestruct *old_current, update_type manner);
extern void handle_completion_input(int ch, char **completion_text);
extern void show_completions(json_t *completions, int cursor_x, int cursor_y);

extern WINDOW *get_popup(void);

#endif
