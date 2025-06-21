/**************************************************************************
 *   ycmd.c  --  This file is part of GNU nano.                           *
 *                                                                        *
 *   Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,  *
 *   2010, 2011, 2013, 2014, 2015 Free Software Foundation, Inc.          *
 *   Copyright (C) 2015, 2016 Benno Schulenberg                           *
 *   Copyright (C) 2017 Orson Teodoro                                     *
 *                                                                        *
 *   GNU nano is free software: you can redistribute it and/or modify     *
 *   it under the terms of the GNU General Public License as published    *
 *   by the Free Software Foundation, either version 3 of the License,    *
 *   or (at your option) any later version.                               *
 *                                                                        *
 *   GNU nano is distributed in the hope that it will be useful,          *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty          *
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.              *
 *   See the GNU General Public License for more details.                 *
 *                                                                        *
 *   You should have received a copy of the GNU General Public License    *
 *   along with this program.  If not, see http://www.gnu.org/licenses/.  *
 *                                                                        *
 **************************************************************************/


#ifndef YCMD_H
#define YCMD_H

#include <curl/curl.h>

/* Buffer sizes */
#define QUARTER_LINE_LENGTH 20
#define HALF_LINE_LENGTH 40
#define LINE_LENGTH 80 /* Approximate for 800x600, 8pt */
#define DOUBLE_LINE_LENGTH 160
#define TRIPLE_LINE_LENGTH 240 /* Approximate for 1040p, 8pt */
#define LINES_PER_PAGE 66 /* Approximate for 1080P 8pt */

#define DEFAULT_JSON_FILETYPE_SPECIFIC_COMPLETION_TO_DISABLE_MAX 200	/* Arbitrary, not in spec */
#define DEFAULT_JSON_FILETYPE_WHITELIST_MAX 200				/* Arbitrary, not in spec */
#define DEFAULT_JSON_FILETYPE_BLACKLIST_MAX 200				/* Arbitrary, not in spec */
#define DEFAULT_JSON_SEMANTIC_TRIGGERS_MAX 10				/* Arbitrary, not in spec */
#define DEFAULT_JSON_EXTRA_CONF_GLOBLIST_MAX 10				/* Arbitrary, not in spec */

#define CSPRNG_CHACHA20_BLOCK_SIZE 64
#define CSPRNG_CHACHA20_KEY_SIZE 32
#define CSPRNG_CHACHA20_NONCE_SIZE 8
#define DIGITS_MAX 11							/* It includes the NULL character. */
#define HTTP_HEADER_YCM_HMAC "X-Ycm-Hmac"
#define HMAC_SIZE 256/8							/* 32 bytes */
#define SECRET_KEY_LENGTH 16
#define IDLE_SUICIDE_SECONDS 10800					/* 3 Hours */
#define SEND_TO_SERVER_DELAY 500000
#ifdef YCMD_CORE_VERSION
#define DEFAULT_YCMD_CORE_VERSION YCMD_CORE_VERSION
#else
#define DEFAULT_YCMD_CORE_VERSION 48
#endif
/* size = path strings + whitelist strings + blacklist strings + integer strings */
#define DEFAULT_JSON_SIZE ( PATH_MAX * 16 + 44 * 10 + 80 * 50 )

/* Max file supported (_MEMFILE_MAX) */
/* https://github.com/ycm-core/ycmd/blob/master/ycmd/web_plumbing.py#L29 */
/* < 10 MiB */
#define MAX_FILESIZE_LIMIT ( 10 * 1024 * 1024 )

/* See also https://github.com/ycm-core/YouCompleteMe/blob/4654e1bf7001128195ae7692c35fe91b4024d632/doc/youcompleteme.txt#L3118 */
typedef struct filetype_specific_completion_to_disable_struct {
	char filetype[NAME_MAX + 1]; /* NAME_MAX does not contain null */
	int off;
} filetype_specific_completion_to_disable_struct;

typedef struct filetype_whitelist_struct {
	char filetype[NAME_MAX + 1];
	int whitelisted;
} filetype_whitelist_struct;

typedef struct filetype_blacklist_struct {
	char filetype[NAME_MAX + 1];
	int blacklisted;
} filetype_blacklist_struct;

typedef struct extra_conf_globlist_struct {
	char pattern[QUARTER_LINE_LENGTH]; /* It must be a regex pattern. */
} extra_conf_globlist_struct;

typedef struct semantic_triggers_struct {
	char lang[QUARTER_LINE_LENGTH];
	char triggers[10][QUARTER_LINE_LENGTH]; /* [entries index, length of trigger] = "<language syntax token>" */
	int triggers_num;
	/* A trigger is a language syntax token (e.g. ::, ->). */
} semantic_triggers_struct;

typedef struct default_settings_struct {
	int filepath_completion_use_working_dir;
	int auto_trigger;
	int min_num_of_chars_for_completion;
	int min_num_identifier_candidate_chars;
	semantic_triggers_struct semantic_triggers[DEFAULT_JSON_SEMANTIC_TRIGGERS_MAX];
	int semantic_triggers_num;										/* Metadata, not in spec */
	filetype_specific_completion_to_disable_struct filetype_specific_completion_to_disable[DEFAULT_JSON_FILETYPE_SPECIFIC_COMPLETION_TO_DISABLE_MAX];
	int filetype_specific_completion_to_disable_num;							/* Metadata, not in spec */
	int seed_identifiers_with_syntax;
	int collect_identifiers_from_comments_and_strings;
	int collect_identifiers_from_tags_files;
	int max_num_identifier_candidates;
	int max_num_candidates;
	int max_num_candidates_to_detail;
	extra_conf_globlist_struct extra_conf_globlist[DEFAULT_JSON_EXTRA_CONF_GLOBLIST_MAX];
	int extra_conf_globlist_num;										/* Metadata, not in spec */
	char global_ycm_extra_conf[PATH_MAX];
	int confirm_extra_conf;
	int complete_in_comments;
	int complete_in_strings;
	int max_diagnostics_to_display;
	filetype_whitelist_struct filetype_whitelist[DEFAULT_JSON_FILETYPE_WHITELIST_MAX];
	int filetype_whitelist_num;										/* Metadata, not in spec */
	filetype_blacklist_struct filetype_blacklist[DEFAULT_JSON_FILETYPE_BLACKLIST_MAX];
	int filetype_blacklist_num;										/* Metadata, not in spec */
	int auto_start_csharp_server;
	int auto_stop_csharp_server;
	int use_ultisnips_completer;
	int csharp_server_port;
	char hmac_secret[SECRET_KEY_LENGTH * 2 + 1];								/* As base64 encoded */
	int server_keep_logfiles;
	char gocode_binary_path[PATH_MAX]; /* PATH_MAX includes null */
	char godef_binary_path[PATH_MAX];
	char rust_src_path[PATH_MAX];
	char racerd_binary_path[PATH_MAX];
	char python_binary_path[PATH_MAX];
	/* TODO: language_server_type */
	char java_jdtls_workspace_root_path[PATH_MAX];
	/* char java_jdtls_extension_path */
	int use_clangd;
	char clangd_binary_path[PATH_MAX];
	/* TODO: clangd_args_type clangd_args[ARG_MAX]; */
	int clangd_uses_ycmd_caching;
	int disable_signature_help;
	char gopls_binary_path[PATH_MAX];
	/* TODO: gopls_args_type gopls_args[ARG_MAX]; */
	char rls_binary_path[PATH_MAX];
	char rustc_binary_path[PATH_MAX];
	char rust_toolchain_root[PATH_MAX];
	char tsserver_binary_path[PATH_MAX];
	char roslyn_binary_path[PATH_MAX];
	int java_jdtls_use_clean_workspace;
	char mono_binary_path[PATH_MAX];
	char java_binary_path[PATH_MAX];
} default_settings_struct;

typedef struct file_ready_to_parse_results_struct
{
	int usable;
	char *json; /* Diagnostic data for FileReadyToParse */
	long response_code;
} file_ready_to_parse_results_struct;

typedef struct ycmd_globals_struct {
	char *scheme;
	char *hostname;
	int port;
	int tcp_socket;
	CURL *curl;
	char json[DEFAULT_JSON_SIZE];
	int running;
	int connected;
	char secret_key_base64[SECRET_KEY_LENGTH * 2 + 1];
	uint8_t secret_key_raw[SECRET_KEY_LENGTH];
	char default_settings_json_path[PATH_MAX];
	pid_t child_pid;
	size_t apply_column;

	/* It is used to fix a off-by-one error for column number. */
	int clang_completer;

	file_ready_to_parse_results_struct file_ready_to_parse_results;

	/* It can only be 39, 43, 44, 45, 46, 47, 48. */
	int core_version;

	int max_entries;

	default_settings_struct default_settings;

	pthread_mutex_t mutex;

} ycmd_globals_struct;

extern void ycmd_constructor();
extern void delete_ycmd();

extern void ycmd_event_file_ready_to_parse(int columnnum, int linenum, char *filepath, linestruct *filetop);
extern void ycmd_event_buffer_unload(int columnnum, int linenum, char *filepath, linestruct *filetop);
extern void ycmd_event_buffer_visit(int columnnum, int linenum, char *filepath, linestruct *filetop);
extern void ycmd_event_current_identifier_finished(int columnnum, int linenum, char *filepath, linestruct *filetop);

extern ycmd_globals_struct ycmd_globals;

extern void do_code_completion_a(void);
extern void do_code_completion_b(void);
extern void do_code_completion_c(void);
extern void do_code_completion_d(void);
extern void do_code_completion_e(void);
extern void do_code_completion_f(void);
extern void do_end_code_completion(void);

extern void do_completer_command_gotoinclude(void);
extern void do_completer_command_gotodeclaration(void);
extern void do_completer_command_gotodefinition(void);
extern void do_completer_command_gotodefinitionelsedeclaration(void);
extern void do_completer_command_goto(void);
extern void do_completer_command_gotoimprecise(void);
extern void do_completer_command_gotoreferences(void);
extern void do_completer_command_gotoimplementation(void);
extern void do_completer_command_gotoimplementationelsedeclaration(void);
extern void do_completer_command_fixit(void);
extern void do_completer_command_getdoc(void);
extern void do_completer_command_getdocimprecise(void);
extern void do_completer_command_refactorrename(void);
extern void do_completer_command_gettype(void);
extern void do_completer_command_gettypeimprecise(void);
extern void do_completer_command_reloadsolution(void);
extern void do_completer_command_restartserver(void);
extern void do_completer_command_stopserver(void);
extern void do_completer_command_gototype(void);
extern void do_completer_command_clearcompliationflagcache(void);
extern void do_completer_command_getparent(void);

extern void do_completer_command_show(void);
extern void do_end_completer_commands(void);

extern void do_completer_refactorrename_apply(void);
extern void do_completer_refactorrename_cancel(void);
extern void do_end_ycm_extra_conf(void);

extern void ycmd_display_parse_results(void);
extern void do_ycm_extra_conf_accept(void);
extern void do_ycm_extra_conf_reject(void);
extern void do_ycm_extra_conf_generate(void);
extern void do_n_entries(void);
#endif
