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
#include <jansson.h>
#include <ncurses.h>
#include <safeclib/safe_str_lib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h> // For MIN, MAX
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "definitions.h" // For openfilestruct, linestruct, update_type
#include "prototypes.h"
#include "safe_wrapper.h"

json_t *active_completions = NULL;
int popup_start_x = 0;
int popup_start_y = 0;
WINDOW *popup = NULL;
extern bool is_popup_mode;
extern bool refresh_needed;
extern openfilestruct *openfile;
extern WINDOW *midwin; /* Edit window */
extern WINDOW *topwin; /* Title window */
extern WINDOW *footwin; /* Foot window */
static const int max_popup_height = 10; /* Maximum popup height */
static const int max_popup_width = 40;  /* Maximum popup width */
static int completion_limit = 7;
static json_t *completions_list = NULL;
static size_t selected_index = 0; // Shared between handle_completion_input and redraw_popup
void redraw_popup(json_t *completions, int screen_y, int screen_x);


WINDOW *get_popup(void) {
    return popup;
}


bool is_popup_active(void) {
    bool active = (popup != NULL && is_popup_mode);
    char msg[256];
    snprintf(msg, sizeof(msg), "is_popup_active: popup=%p, is_popup_mode=%d, active=%d\n",
             (void *)popup, is_popup_mode, active);
    fprintf(stderr, "%s\n", msg);
    return active;
}






void init_completion_ui(void) {
	char msg[256];
	set_escdelay(0);
	snprintf(msg, sizeof(msg), "init_completion_ui: Set ESCDELAY=0\n");
	fprintf(stderr, msg);
	const char *mode = getenv("NANO_YCMD_UI_MODE");
	if (mode) {
		snprintf(msg, sizeof(msg), "NANO_YCMD_UI_MODE=%s\n", mode);
		fprintf(stderr, msg);
		if (strcmp(mode, "popup") == 0) {
			is_popup_mode = true;
		} else if (strcmp(mode, "bottom") == 0) {
			is_popup_mode = false;
		} else {
			snprintf(msg, sizeof(msg),
					 "Unknown NANO_YCMD_UI_MODE=%s, defaulting to popup\n",
					 mode);
			fprintf(stderr, msg);
			is_popup_mode = true;
		}
	} else {
		fprintf(stderr, "NANO_YCMD_UI_MODE unset, defaulting to popup\n");
		is_popup_mode = true;
	}
	snprintf(msg, sizeof(msg), "PID=%d, Checking environment\n", getpid());
	fprintf(stderr, msg);
	extern char **environ;
	for (char **env = environ; *env; env++) {
		if (strstr(*env, "NANO_YCMD_UI_MODE")) {
			snprintf(msg, sizeof(msg), "Env: %s\n", *env);
			fprintf(stderr, msg);
		}
	}
	const char *limit = getenv("NANO_YCMD_COMPLETION_LIMIT");
	if (limit) {
		int val = atoi(limit);
		if (val >= 3 && val <= 10) {
			completion_limit = val;
			snprintf(msg, sizeof(msg), "Set completion_limit to %d\n", val);
			fprintf(stderr, msg);
		} else {
			snprintf(msg, sizeof(msg),
					 "Invalid NANO_YCMD_COMPLETION_LIMIT=%s (must be 3-10)\n",
					 limit);
			fprintf(stderr, msg);
		}
	}
	snprintf(msg, sizeof(msg), "UI mode: %s\n",
			 is_popup_mode ? "popup" : "bottom");
	fprintf(stderr, msg);
}


void show_completions(json_t *completions, int y, int x) {
    char msg[256];
    snprintf(msg, sizeof(msg), "show_completions: Start, completions=%p, y=%d, x=%d, is_popup_mode=%d\n",
             (void *)completions, y, x, is_popup_mode);
    fprintf(stderr, "%s\n", msg);

    if (!completions || !json_is_array(completions)) {
        snprintf(msg, sizeof(msg), "show_completions: Invalid completions=%p\n", (void *)completions);
        fprintf(stderr, "%s\n", msg);
        return;
    }

    size_t num_completions = json_array_size(completions);
    if (num_completions == 0) {
        snprintf(msg, sizeof(msg), "show_completions: No completions\n");
        fprintf(stderr, "%s\n", msg);
        return;
    }

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
    int popup_height = MIN(num_completions, max_popup_height) + 2;
    int popup_width = max_popup_width;
    popup_start_y = (y + 1 < max_y - popup_height ? y + 1 : max_y - popup_height);
    popup_start_x = (x + popup_width < max_x ? x : max_x - popup_width);
    if (popup_start_y < 0) popup_start_y = 0;
    if (popup_start_x < 0) popup_start_x = 0;

    hide_completions();
    popup = newwin(popup_height, popup_width, popup_start_y, popup_start_x);
    if (!popup) {
        snprintf(msg, sizeof(msg), "show_completions: newwin failed\n");
        fprintf(stderr, "%s\n", msg);
        return;
    }
    keypad(popup, TRUE);
    wtimeout(popup, 50);

    box(popup, 0, 0);
    for (size_t i = 0; i < num_completions && i < max_popup_height; i++) {
        json_t *item = json_array_get(completions, i);
        if (!json_is_object(item)) continue;
        json_t *text_obj = json_object_get(item, "insertion_text");
        if (!text_obj || !json_is_string(text_obj)) continue;
        const char *text = json_string_value(text_obj);
        char display_text[max_popup_width - 3];
        strncpy_s(display_text, sizeof(display_text), text, max_popup_width - 4);
        display_text[max_popup_width - 4] = '\0';
        if (i == selected_index) {
            wattron(popup, A_REVERSE | A_BOLD);
            mvwprintw(popup, i + 1, 2, "%-*s", max_popup_width - 4, display_text);
            wattroff(popup, A_REVERSE | A_BOLD);
        } else {
            mvwprintw(popup, i + 1, 2, "%-*s", max_popup_width - 4, display_text);
        }
    }

    active_completions = json_incref(completions);
    selected_index = 0;
    is_popup_mode = TRUE;
    wmove(popup, 1, 2);
    wnoutrefresh(popup);
    snprintf(msg, sizeof(msg), "show_completions: Displayed %zu completions, popup=%p, start_y=%d, start_x=%d\n",
             num_completions, (void *)popup, popup_start_y, popup_start_x);
    fprintf(stderr, "%s\n", msg);
}


void redraw_popup(json_t *completions, int screen_y, int screen_x) {
    char msg[256];
    snprintf(msg, sizeof(msg), "redraw_popup: Start, screen_y=%d, screen_x=%d, popup=%p, is_popup_mode=%d, selected_index=%zu\n",
             screen_y, screen_x, (void *)popup, is_popup_mode, selected_index);
    fprintf(stderr, "%s\n", msg);

    if (!completions || !json_is_array(completions)) {
        snprintf(msg, sizeof(msg), "redraw_popup: Invalid completions, hiding popup\n");
        fprintf(stderr, "%s\n", msg);
        hide_completions();
        return;
    }

    size_t num_completions = json_array_size(completions);
    if (num_completions == 0) {
        snprintf(msg, sizeof(msg), "redraw_popup: No completions, hiding popup\n");
        fprintf(stderr, "%s\n", msg);
        hide_completions();
        return;
    }

    if (selected_index >= num_completions) {
        selected_index = num_completions - 1;
    }

    if (!popup) {
        snprintf(msg, sizeof(msg), "redraw_popup: Popup null, recreating at y=%d, x=%d\n",
                 popup_start_y, popup_start_x);
        fprintf(stderr, "%s\n", msg);
        int max_y, max_x;
        getmaxyx(stdscr, max_y, max_x);
        int popup_height = MIN(num_completions, max_popup_height) + 2;
        int popup_width = max_popup_width;
        popup = newwin(popup_height, popup_width, popup_start_y, popup_start_x);
        if (!popup) {
            snprintf(msg, sizeof(msg), "redraw_popup: newwin failed\n");
            fprintf(stderr, "%s\n", msg);
            is_popup_mode = FALSE;
            return;
        }
        keypad(popup, TRUE);
        wtimeout(popup, 50);
    } else {
        // Avoid moving the window
        wclear(popup);
    }

    box(popup, 0, 0);
    for (size_t i = 0; i < num_completions && i < max_popup_height; i++) {
        json_t *completion = json_array_get(completions, i);
        if (!json_is_object(completion)) {
            snprintf(msg, sizeof(msg), "redraw_popup: Invalid completion at index %zu\n", i);
            fprintf(stderr, "%s\n", msg);
            continue;
        }
        json_t *text_obj = json_object_get(completion, "insertion_text");
        if (!text_obj || !json_is_string(text_obj)) {
            snprintf(msg, sizeof(msg), "redraw_popup: Missing insertion_text at index %zu\n", i);
            fprintf(stderr, "%s\n", msg);
            continue;
        }
        const char *text = json_string_value(text_obj);
        char display_text[max_popup_width - 3];
        strncpy_s(display_text, sizeof(display_text), text, max_popup_width - 4);
        display_text[max_popup_width - 4] = '\0';
        if (i == selected_index) {
            wattron(popup, A_REVERSE | A_BOLD);
            mvwprintw(popup, i + 1, 2, "%-*s", max_popup_width - 4, display_text);
            wattroff(popup, A_REVERSE | A_BOLD);
        } else {
            mvwprintw(popup, i + 1, 2, "%-*s", max_popup_width - 4, display_text);
        }
    }

    wmove(popup, selected_index + 1, 2);
    wnoutrefresh(popup);
    snprintf(msg, sizeof(msg), "redraw_popup: Completed, popup=%p, start_y=%d, start_x=%d\n",
             (void *)popup, popup_start_y, popup_start_x);
    fprintf(stderr, "%s\n", msg);
}

void handle_completion_input(int input, char **completion_text) {
    char msg[256];
    snprintf(msg, sizeof(msg), "handle_completion_input: input=0x%x, completions=%p, selected_index=%zu\n",
             input, (void *)active_completions, selected_index);
    fprintf(stderr, "%s\n", msg);

    *completion_text = NULL;
    if (!active_completions || !json_is_array(active_completions)) {
        snprintf(msg, sizeof(msg), "handle_completion_input: No active completions, closing popup\n");
        fprintf(stderr, "%s\n", msg);
        hide_completions();
        return;
    }

    size_t completions_size = json_array_size(active_completions);
    if (completions_size == 0) {
        snprintf(msg, sizeof(msg), "handle_completion_input: Empty completions, closing popup\n");
        fprintf(stderr, "%s\n", msg);
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
            redraw_popup(active_completions, 0, 0); // Coordinates ignored
            break;

        case KEY_DOWN:
            if (selected_index < completions_size - 1) {
                selected_index++;
            } else {
                selected_index = 0;
            }
            redraw_popup(active_completions, 0, 0); // Coordinates ignored
            break;

        case '\n':
        case '\r':
        case KEY_ENTER:
            {
                json_t *selected = json_array_get(active_completions, selected_index);
                if (!json_is_object(selected)) {
                    snprintf(msg, sizeof(msg), "handle_completion_input: Invalid completion at index %zu\n", selected_index);
                    fprintf(stderr, "%s\n", msg);
                    hide_completions();
                    break;
                }
                json_t *text = json_object_get(selected, "insertion_text");
                if (text && json_is_string(text)) {
                    *completion_text = strdup(json_string_value(text));
                    snprintf(msg, sizeof(msg), "handle_completion_input: Selected completion: %s\n", *completion_text);
                    fprintf(stderr, "%s\n", msg);
                } else {
                    snprintf(msg, sizeof(msg), "handle_completion_input: Missing insertion_text at index %zu\n", selected_index);
                    fprintf(stderr, "%s\n", msg);
                }
                hide_completions();
                break;
            }

        case 0x1B: // ESC
            hide_completions();
            flushinp();
            break;

        case KEY_LEFT:
        case KEY_RIGHT:
            snprintf(msg, sizeof(msg), "handle_completion_input: Ignored input=0x%x\n", input);
            fprintf(stderr, "%s\n", msg);
            break;

        default:
            snprintf(msg, sizeof(msg), "handle_completion_input: Unhandled input=0x%x, closing popup\n", input);
            fprintf(stderr, "%s\n", msg);
            hide_completions();
            break;
    }
}


void hide_completions(void) {
    char msg[256];
    if (popup == NULL && !is_popup_mode) {
        snprintf(msg, sizeof(msg), "hide_completions: Nothing to hide, popup=%p, is_popup_mode=%d\n",
                 (void *)popup, is_popup_mode);
        fprintf(stderr, "%s\n", msg);
        return;
    }

    if (popup != NULL) {
        if (delwin(popup) == ERR) {
            snprintf(msg, sizeof(msg), "hide_completions: delwin failed for popup=%p\n", (void *)popup);
            fprintf(stderr, "%s\n", msg);
        }
        popup = NULL;
    }

    if (active_completions) {
        json_decref(active_completions);
        active_completions = NULL;
    }
    selected_index = 0;
    is_popup_mode = FALSE;
    popup_start_y = 0;
    popup_start_x = 0;

    snprintf(msg, sizeof(msg), "hide_completions: Cleared, popup=%p, is_popup_mode=%d\n",
             (void *)popup, is_popup_mode);
    fprintf(stderr, "%s\n", msg);
}
