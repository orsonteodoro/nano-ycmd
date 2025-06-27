/* completion_ui.c - User interface for code completion in nano-ycmd
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
#include "config.h"
#include "completion_ui.h"
#include "debug.h"
#include "definitions.h"				/* For openfilestruct, linestruct, update_type */
#include "prototypes.h"
#include "safe_wrapper.h"

#include <jansson.h>
#include <ncurses.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>					/* For MIN, MAX */
#include <time.h>
#include <unistd.h>

json_t *active_completions = NULL;
int popup_start_x = 0;
int popup_start_y = 0;
static const int max_popup_height = 10;			/* Maximum popup height */
static const int max_popup_width = 40;			/* Maximum popup width */
static int completion_limit = 7;
static size_t selected_index = 0;			/* Shared between handle_completion_input and redraw_popup */
WINDOW *popup = NULL;
extern bool is_popup_mode;
extern bool refresh_needed;
extern openfilestruct *openfile;
extern WINDOW *midwin;					/* Edit window */
extern WINDOW *topwin;					/* Title window */
extern WINDOW *footwin;					/* Foot window */
void redraw_popup(json_t *completions, int screen_y, int screen_x);

WINDOW *get_popup(void) {
	return popup;
}

bool is_popup_active(void) {
	bool active = (popup != NULL && is_popup_mode);
	debug_log("popup=%p, is_popup_mode=%d, active=%d", (void *)popup, is_popup_mode, active);
	return active;
}

void init_completion_ui(void) {
	set_escdelay(0);
	debug_log("Set ESCDELAY=0");
	const char *ui_mode = getenv("NANO_YCMD_UI_MODE");
	if (ui_mode) {
		debug_log("NANO_YCMD_UI_MODE=%s", ui_mode);
		if (wrap_strcmp(ui_mode, "popup") == 0) {
			is_popup_mode = true;
		} else if (wrap_strcmp(ui_mode, "bottom") == 0) {
			is_popup_mode = false;
		} else {
#ifdef ENABLE_YCMD_POPUP
			debug_log("Unknown NANO_YCMD_UI_MODE=%s, defaulting to popup", ui_mode);
			is_popup_mode = true;
#else
			debug_log("Unknown NANO_YCMD_UI_MODE=%s, defaulting to bottom", ui_mode);
			is_popup_mode = false;
#endif
		}
	} else {
#ifdef ENABLE_YCMD_POPUP
		debug_log("NANO_YCMD_UI_MODE unset, defaulting to popup");
		is_popup_mode = true;
#else
		debug_log("NANO_YCMD_UI_MODE unset, defaulting to bottom");
		is_popup_mode = false;
#endif
	}
	debug_log("PID=%d, Checking environment", getpid());
	extern char **environ;
	for (char **env = environ; *env; env++) {
		if (wrap_strstr(*env, "NANO_YCMD_UI_MODE")) {
			debug_log("Env:  %s", *env);
		}
	}
	const char *limit = getenv("NANO_YCMD_COMPLETION_LIMIT");
	if (limit) {
		int val = atoi(limit);
		if (val >= 3 && val <= 10) {
			completion_limit = val;
			debug_log("Set completion_limit to %d", val);
		} else {
			debug_log("Invalid NANO_YCMD_COMPLETION_LIMIT=%s (must be 3-10)", limit);
		}
	}
	debug_log("UI mode: %s", is_popup_mode ? "popup" : "bottom");
}

void show_completions(json_t *completions, int y, int x) {
	debug_log("Start, completions=%p, y=%d, x=%d, is_popup_mode=%d",
		  (void *)completions, y, x, is_popup_mode);

	if (!completions || !json_is_array(completions)) {
		debug_log("Invalid completions=%p", (void *)completions);
		return;
	}

	size_t num_completions = json_array_size(completions);
	if (num_completions == 0) {
		debug_log("No completions");
		return;
	}

	int max_y, max_x;
	getmaxyx(stdscr, max_y, max_x);
	int popup_height = MIN(num_completions, max_popup_height) + 2;
	int popup_width = max_popup_width;
	popup_start_y =	(y + 1 < max_y - popup_height ? y + 1 : max_y - popup_height);
	popup_start_x = (x + popup_width < max_x ? x : max_x - popup_width);
	if (popup_start_y < 0)
		popup_start_y = 0;
	if (popup_start_x < 0)
		popup_start_x = 0;

	hide_completions();
	popup = newwin(popup_height, popup_width, popup_start_y, popup_start_x);
	if (!popup) {
		debug_log("newwin failed");
		return;
	}
	keypad(popup, TRUE);
	wtimeout(popup, 50);

	box(popup, 0, 0);
	for (size_t i = 0; i < num_completions && i < max_popup_height; i++) {
		json_t *item = json_array_get(completions, i);
		if (!json_is_object(item))
			continue;
		json_t *text_obj = json_object_get(item, "insertion_text");
		if (!text_obj || !json_is_string(text_obj))
			continue;
		const char *text = json_string_value(text_obj);
		char display_text[max_popup_width - 3];
		wrap_strncpy(display_text, text, max_popup_width - 4);
		display_text[max_popup_width - 4] = '\0';
		if (i == selected_index) {
			wattron(popup, A_REVERSE | A_BOLD);
			mvwprintw(popup, i + 1, 2, "%-*s", max_popup_width - 4,
				  display_text);
			wattroff(popup, A_REVERSE | A_BOLD);
		} else {
			mvwprintw(popup, i + 1, 2, "%-*s", max_popup_width - 4,
				  display_text);
		}
	}

	active_completions = json_incref(completions);
	selected_index = 0;
	is_popup_mode = TRUE;
	wmove(popup, 1, 2);
	wnoutrefresh(popup);
	debug_log("Displayed %zu completions, popup=%p, start_y=%d, start_x=%d",
		  num_completions, (void *)popup, popup_start_y, popup_start_x);
}

void redraw_popup(json_t *completions, int screen_y, int screen_x) {
	debug_log("Start, screen_y=%d, screen_x=%d, popup=%p, is_popup_mode=%d, selected_index=%zu",
		  screen_y, screen_x, (void *)popup, is_popup_mode, selected_index);

	if (!completions || !json_is_array(completions)) {
		debug_log("Invalid completions, hiding popup");
		hide_completions();
		return;
	}

	size_t num_completions = json_array_size(completions);
	if (num_completions == 0) {
		debug_log("No completions, hiding popup");
		hide_completions();
		return;
	}

	if (selected_index >= num_completions) {
		selected_index = num_completions - 1;
	}

	if (!popup) {
		debug_log("Popup null, recreating at y=%d, x=%d", popup_start_y, popup_start_x);
		/* int max_y, max_x; */
		/* getmaxyx(stdscr, max_y, max_x); */
		int popup_height = MIN(num_completions, max_popup_height) + 2;
		int popup_width = max_popup_width;
		popup = newwin(popup_height, popup_width, popup_start_y, popup_start_x);
		if (!popup) {
			debug_log("newwin failed");
			is_popup_mode = FALSE;
			return;
		}
		keypad(popup, TRUE);
		wtimeout(popup, 50);
	} else {
		/* Avoid moving the window */
		wclear(popup);
	}

	box(popup, 0, 0);
	for (size_t i = 0; i < num_completions && i < max_popup_height; i++) {
		json_t *completion = json_array_get(completions, i);
		if (!json_is_object(completion)) {
			debug_log("Invalid completion at index %zu", i);
			continue;
		}
		json_t *text_obj = json_object_get(completion, "insertion_text");
		if (!text_obj || !json_is_string(text_obj)) {
			debug_log("Missing insertion_text at index %zu", i);
			continue;
		}
		const char *text = json_string_value(text_obj);
		char display_text[max_popup_width - 3];
		wrap_strncpy(display_text, text, max_popup_width - 4);
		display_text[max_popup_width - 4] = '\0';
		if (i == selected_index) {
			wattron(popup, A_REVERSE | A_BOLD);
			mvwprintw(popup, i + 1, 2, "%-*s", max_popup_width - 4, display_text);
			wattroff(popup, A_REVERSE | A_BOLD);
		} else {
			mvwprintw(popup, i + 1, 2, "%-*s", max_popup_width - 4,
				  display_text);
		}
	}

	wmove(popup, selected_index + 1, 2);
	wnoutrefresh(popup);
	debug_log("Completed, popup=%p, start_y=%d, start_x=%d",
		  (void *)popup, popup_start_y, popup_start_x);
}

void handle_completion_input(int input, char **completion_text) {
	debug_log("input=0x%x, completions=%p, selected_index=%zu",
		  input, (void *)active_completions, selected_index);

	*completion_text = NULL;
	if (!active_completions || !json_is_array(active_completions)) {
		debug_log("No active completions, closing popup");
		hide_completions();
		return;
	}

	size_t completions_size = json_array_size(active_completions);
	if (completions_size == 0) {
		debug_log("Empty completions, closing popup");
		hide_completions();
		return;
	}

	switch (input) {
	case KEY_UP:
		if (selected_index > 0) {
			selected_index--;
		} else {
			selected_index = completions_size - 1;
		}
		redraw_popup(active_completions, 0, 0); /* Coordinates ignored */
		break;

	case KEY_DOWN:
		if (selected_index < completions_size - 1) {
			selected_index++;
		} else {
			selected_index = 0;
		}
		redraw_popup(active_completions, 0, 0); /* Coordinates ignored */
		break;

	case '\n':
	case '\r':
	case KEY_ENTER: {
		json_t *selected = json_array_get(active_completions, selected_index);
		if (!json_is_object(selected)) {
			debug_log("Invalid completion at index %zu", selected_index);
			hide_completions();
			break;
		}
		json_t *text = json_object_get(selected, "insertion_text");
		if (text && json_is_string(text)) {
			*completion_text = wrap_strdup(json_string_value(text));
			debug_log("Selected completion: %s", *completion_text);
		} else {
			debug_log("Missing insertion_text at index %zu", selected_index);
		}
		hide_completions();
		break;
	}

	case 0x1B: /* ESC */
		hide_completions();
		flushinp();
		break;

	case KEY_LEFT:
	case KEY_RIGHT:
		debug_log("Ignored input=0x%x", input);
		break;

	default:
		debug_log("Unhandled input=0x%x, closing popup", input);
		hide_completions();
		break;
	}
}

void hide_completions(void) {
	debug_log("Start, popup=%p, is_popup_mode=%d, active_completions=%p",
		(void *)popup, is_popup_mode, (void *)active_completions);

	if (popup == NULL && !active_completions) {
		debug_log("Nothing to hide");
		return;
	}

	if (popup != NULL) {
		if (delwin(popup) == ERR) {
			debug_log("delwin failed for popup=%p", (void *)popup);
		}
		popup = NULL;
	}

	if (active_completions) {
		json_decref(active_completions);
		active_completions = NULL;
	}

	selected_index = 0;
	popup_start_y = 0;
	popup_start_x = 0;

	debug_log("Completed, popup=%p, is_popup_mode=%d, active_completions=%p",
		(void *)popup, is_popup_mode, (void *)active_completions);

	edit_refresh();
	if (doupdate() == ERR) {
		debug_log("doupdate failed");
	}
}
