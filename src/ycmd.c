/**************************************************************************
 *   ycmd.c  --  This file is part of GNU nano.                           *
 *                                                                        *
 *   Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,  *
 *   2010, 2011, 2013, 2014, 2015 Free Software Foundation, Inc.          *
 *   Copyright (C) 2015, 2016 Benno Schulenberg                           *
 *   Copyright (C) 2017-2020 Orson Teodoro                                *
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

#include "config.h"
#include "debug.h"

#include "safe_wrapper.h"

#define HTTP_OK 200

#define COMMAND_LINE_COMMAND_NUM 21
#define COMMAND_LINE_WIDTH 34

/* GH line width (hard limit):  147 chars at 1080p */
/* Mod default (soft limit):  120 chars */
//2345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456
//2345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789

char _command_line[COMMAND_LINE_COMMAND_NUM][COMMAND_LINE_WIDTH] = {
	"ClearCompilationFlagCache",
	"GetDoc",
	"GetDocImprecise",
	"GetType",
	"GetTypeImprecise",
	"GoTo",
	"GoToDeclaration",
	"GoToDefinition",
	"GoToDefinitionElseDeclaration",
	"GoToImprecise",
	"GoToImplementation",
	"GoToImplementationElseDeclaration",
	"GoToInclude",
	"GoToReferences",
	"GoToType",
	"FixIt",
	"GetParent",
	"RefactorRename",
	"ReloadSolution",
	"RestartServer",
};

#if defined(USE_LIBGCRYPT)
#include <gcrypt.h>
#include <glib.h>
#define CRYPTO_LIB "LIBGCRYPT"
#elif defined(USE_NETTLE)
#include <nettle/base64.h>
#include <nettle/chacha.h>
#include <nettle/hmac.h>
#define CRYPTO_LIB "NETTLE"
#elif defined(USE_OPENSSL)
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#define CRYPTO_LIB "OPENSSL"
#else
#error "You must choose a cryptographic library to use ycmd code completion support.  " \
	"Currently Libgcrypt, Nettle, OpenSSL 3.x are supported."
#endif

/*
 * CE = Code Execution
 * DF = Double Free
 * DoS = Denial of Service
 * DP = Dangling Pointer
 * DT = Data Tampering
 * HO = Heap Overflow
 * ID = Information Disclosure
 * IO = Integer Overflow
 * NPD = Null Pointer Dereference
 * OOBA = Out of Bounds Access
 * OOBR = Out of Bounds Read
 * OOBW = Out of Bounds Write
 * PF = Poison Free
 * RC = Race Condition
 * SO = Stack Overflow
 * SF = String Format Vulnerability
 * UAF = Use After Free
 * UAR = Use After Return
 * ZF = Zero Free
 *
 * The scores are 1-10.
 *
 * Mitigations (curl):  DF, DP, DoS, ID, DT, HO, IO, NPD, OOBA, OOBR, OOBW, RC, SO, UAF
 * Mitigations (glibc malloc/free):  RC
 * Mitigations (glibc str/mem functions):  RC, SO
 * Mitigations (hardened_malloc):  DF, DoS, DP, DT, HO, ID, IO, NPD, OOBA, OOBR, OOBW, PF, RC, SO, UAF
 * Mitigations (http neon):  NPD, SO
 * Mitigations (jansson):  DF, DP, DoS, DT, ID, IO, HO, NPD, OOBA, OOBR, OOBW, RC, SO, UAF
 * Mitigations (mimalloc-secure):  DF, DoS, DP, DT, HO, ID, IO, NPD, OOBA, OOBR, OOBW, PF, RC, SO, UAF
 * Mitigations (musl malloc/free):  DF, DoS, DP, DT, HO, ID, IO, OOBA, OOBR, OOBW, PF, RC, SO, UAF
 * Mitigations (musl str/mem functions): RC, SO
 * Mitigations (nxjson):  NPD
 * Mitigations (safeclib):  DF, DP, DoS, DT, ID, IO, HO, NPD, OOBA, OOBR, OOBW, RC, SO, UAF
 * Mitigations (scudo):  DF, DoS, DP, DT, HO, ID, IO, NPD, OOBA, OOBR, OOBW, PF, RC, SO, UAF
 * Mitigations (yyjson): DF, DP, DoS, ID, IO, DT HO, NPD, OOBA, OOBR, OOBW, SO, UAF

 * curl:			# Security: 9, Performance: 8, Overall: 9
 * glibc malloc/free:		# Security: 3, Performance: 8, Overall: 5
 * glibc str/mem functions:	# Security: 3, Performance: 9, Overall: 5
 * hardened_malloc:		# Security: 10, Performance: 6, Overall: 9
 * http neon:			# Security: 3, Performance: 7, Overall: 5; Removed support
 * jansson:			# Security: 9, Performance: 7, Overall: 8
 * mimalloc-secure:		# Security: 9, Performance: 8, Overall: 9
 * musl malloc/free:		# Security: 8, Performance: 6, Overall: 7
 * musl str/mem functions:	# Security: 4, Performance: 9, Overall: 6
 * nxjson:			# Security: 2, Performance: 5, Overall 3; Removed support
 * safeclib:			# Security: 9, Performance: 7, Overall: 8
 * scudo:			# Security: 8, Performance: 7, Overall: 8; Available via LD_PRELOAD
 * yyjson:			# Security: 8, Performance: 9, Overall: 8; Considered but no RC mitigation,
 *				# not widely adopted in distros, faster alternative
 */

#include <curl/curl.h>
#include <jansson.h>
#include <netinet/ip.h>
#include <pwd.h> /* For getpwuid */
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "prototypes.h"
#include "ycmd.h"
#ifdef DEBUG
#include <string.h>
#include <time.h>
#endif
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <pthread.h>
#include <regex.h>

/* Notes:
 *
 * HTTP methods documentation:  https://micbou.github.io/ycmd/
 *
 * Protocol documentation:
 * https://gist.github.com/hydrargyrum/78c6fccc9de622ad9d7b Reference client:
 * https://github.com/Valloric/ycmd/blob/master/examples/example_client.py YCM
 * https://github.com/Valloric/YouCompleteMe/blob/master/README.md
 */

typedef struct memory_struct {
	char *memory;
	size_t size;
} memory_struct;

typedef struct defined_subcommands_results_struct {
	int usable;
	char *json;
	long response_code;
} defined_subcommands_results_struct;

typedef struct run_completer_command_result_struct {
	int usable;
	char *message;
	int line_num;
	int column_num;
	char *filepath;
	char *json;
	char *detailed_info;
	long response_code;
} run_completer_command_result_struct;

char *ycmd_create_default_json();
char *_curl_read_response_body_full(CURL *curl, struct memory_struct *chunk);
char *_ycmd_get_filetype(char *filepath);
int check_ace(const char* file_path);
int check_obfuscated_text(const char* file_path);
int ycmd_is_hmac_valid(const char *hmac_rsp_header, char *rsp_hmac_base64);
int ycmd_rsp_is_server_ready(char *filetype);
int ycmd_req_defined_subcommands(int linenum, int columnnum, char *filepath, linestruct *filetop, char *completertarget,
	defined_subcommands_results_struct *dsr);
int ycmd_req_run_completer_command(int linenum, int columnnum, char *filepath, linestruct *filetop,
	char *completertarget, char *completercommand, run_completer_command_result_struct *rccr);
size_t _req_file(char *req_buffer, size_t req_buffer_size, linestruct *filetop);
size_t _req_sprintf(char *req_buffer, size_t req_buffer_size, const char *format, ...);
size_t ycmd_escape_json(char *unescaped, char *escaped);
void curl_setup_request(CURL *curl, struct memory_struct *chunk);
void default_settings_constructor(default_settings_struct *settings);
void file_ready_to_parse_results_constructor(file_ready_to_parse_results_struct *frtpr);
void ycmd_generate_secret_key_base64(uint8_t *secret, char *secret_base64);
void ycmd_generate_secret_key_raw(uint8_t *secret);
void ycmd_get_extra_conf_path(char *path_project, char *path_extra_conf);
void ycmd_get_project_path(char *path_project);
void ycmd_get_hmac_request(char *req_hmac_base64, char *method, char *path, char *body,
	size_t body_len /* strlen based */);
void ycmd_get_hmac_response(char *rsp_hmac_base64, char *response_body);
void ycmd_restart_server();
void ycmd_req_load_extra_conf_file(char *filepath);
void ycmd_req_ignore_extra_conf_file(char *filepath);
void ycmd_start_server();
void ycmd_stop_server();

extern int is_popup_active(void);
extern bool is_popup_mode;

ycmd_globals_struct ycmd_globals;
bool need_bottombar_update = FALSE;
const char *ycmd_filename = NULL;
int ycmd_line_num = 0, ycmd_column_num = 0;
linestruct *ycmd_filetop = NULL; /* Store filetop for deferred updates */

struct curl_slist *_curl_sprintf_header(struct curl_slist *headers, const char *format, ...) {
	char buffer[LINE_LENGTH];
	va_list args;
	va_start(args, format);
	int len = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	if (len >= sizeof(buffer)) {
		/* Handle buffer too small error */
		return headers;
	}

	struct curl_slist *new_headers = curl_slist_append(headers, buffer);
	if (!new_headers) {
		/* Handle curl_slist_append error */
		return headers;
	}

	return new_headers;
}

void ycmd_send_to_server(int signum) {
	ycmd_event_file_ready_to_parse(
		openfile->current_x,
		(long)openfile->current->lineno,
		openfile->filename,
		openfile->filetop);
}

#ifdef USE_SAFECLIB
#include <safe_str_lib.h>
#endif


#define YCM_EXTRA_CONF_PY_LINE_LENGTH 1024
#define YCM_EXTRA_CONF_PY_NAME_LENGTH 256

/* Whitelist of allowed modules for .ycm_extra_conf.py */
const char* allowed_imported_modules_for_ycm_extra_conf_py[] = {"sysconfig", "platform", "os", "subprocess", "ycm_core"};
int num_allowed_imported_modules_for_ycm_extra_conf_py = 4;

/* Function to check if a module is in the whitelist */
int is_module_allowed_for_ycm_extra_conf_py(const char* module_name) {
	for (int i = 0; i < num_allowed_imported_modules_for_ycm_extra_conf_py; i++) {
		if (strcmp(module_name, allowed_imported_modules_for_ycm_extra_conf_py[i]) == 0) {
			return 1; /* Module is allowed */
		}
	}
	return 0; /* Module is not allowed */
}

/* Function to check a Python script for restricted imports */
int check_ycm_extra_conf_py_imports(const char* filename) {
	FILE* file = fopen(filename, "r");
	if (!file) {
		printf("Error opening file '%s'\n", filename);
		return -1;
	}

	char line[YCM_EXTRA_CONF_PY_LINE_LENGTH];
	regex_t import_regex;
	regcomp(&import_regex, "^[[:space:]]*(import|from)[[:space:]]+([a-zA-Z_][a-zA-Z0-9_]*)", REG_EXTENDED);
	regex_t from_import_regex;
	regcomp(&from_import_regex, "^[[:space:]]*from[[:space:]]+([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]+import", REG_EXTENDED);

	while (fgets(line, sizeof(line), file)) {
		regmatch_t match[3];

		/* Check for import statements */
		if (regexec(&import_regex, line, 3, match, 0) == 0) {
			char module_name[YCM_EXTRA_CONF_PY_NAME_LENGTH];
			int length = match[2].rm_eo - match[2].rm_so;
			if (length >= YCM_EXTRA_CONF_PY_NAME_LENGTH) {
				printf("Error: Module name too long\n");
				regfree(&import_regex);
				regfree(&from_import_regex);
				fclose(file);
				return -1;
			}
			strncpy(module_name, line + match[2].rm_so, length);
			module_name[length] = '\0';

			/* Check if the module is allowed */
			if (!is_module_allowed_for_ycm_extra_conf_py(module_name)) {
				printf("Error: Module '%s' is not allowed\n", module_name);
				regfree(&import_regex);
				regfree(&from_import_regex);
				fclose(file);
				return -1;
			}
		}

		/* Check for from-import statements */
		if (regexec(&from_import_regex, line, 2, match, 0) == 0) {
			char module_name[YCM_EXTRA_CONF_PY_NAME_LENGTH];
			int length = match[1].rm_eo - match[1].rm_so;
			if (length >= YCM_EXTRA_CONF_PY_NAME_LENGTH) {
				printf("Error: Module name too long\n");
				regfree(&import_regex);
				regfree(&from_import_regex);
				fclose(file);
				return -1;
			}
			strncpy(module_name, line + match[1].rm_so, length);
			module_name[length] = '\0';

			/* Check if the module is allowed */
			if (!is_module_allowed_for_ycm_extra_conf_py(module_name)) {
				printf("Error: Module '%s' is not allowed\n", module_name);
				regfree(&import_regex);
				regfree(&from_import_regex);
				fclose(file);
				return -1;
			}
		}
	}

	regfree(&import_regex);
	regfree(&from_import_regex);
	fclose(file);
	return 0; /* No restricted imports found */
}

/* Function to check for potential ACE (Arbitrary Code Execution) in a Python file. */
int check_ace(const char* file_path) {
	FILE* file = fopen(file_path, "r");
	if (!file) {
		return -1; /* Unable to open file */
	}

	char line[1024];
	regex_t ace_regex;
	regcomp(&ace_regex, "exec\\s*\\(|eval\\s*\\(|__import__\\s*\\(", REG_EXTENDED);

	while (fgets(line, sizeof(line), file)) {
		if (regexec(&ace_regex, line, 0, NULL, 0) == 0) {
			regfree(&ace_regex);
			fclose(file);
			return 1; // Potential ACE detected
		}
	}

	regfree(&ace_regex);
	fclose(file);
	return 0; /* No potential ACE detected */
}

/* Function to check for obfuscated text in a Python file. */
int check_obfuscated_text(const char* file_path) {
	FILE* file = fopen(file_path, "r");
	if (!file) {
		return -1; /* Unable to open file */
	}

	char line[1024];
	regex_t obfuscation_regex;
	regcomp(&obfuscation_regex, "(base64|eval|exec|compile|lambda|map|filter|reduce)", REG_EXTENDED | REG_ICASE);

	while (fgets(line, sizeof(line), file)) {
		if (regexec(&obfuscation_regex, line, 0, NULL, 0) == 0) {
			/* Check for encoded strings */
			if (strstr(line, "b'") != NULL || strstr(line, "\"\"\"") != NULL) {
				regfree(&obfuscation_regex);
				fclose(file);
				return 1; /* Potential obfuscated text detected */
			}
		}
	}

	regfree(&obfuscation_regex);
	fclose(file);
	return 0; /* No potential obfuscated text detected */
}

typedef struct header_data_struct {
	char name[256];
	char value[256];
} header_data_struct;

static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
	struct header_data_struct *hd = (struct header_data_struct *)userdata;
	size_t len = size * nitems;
	if (len > 0 && strncasecmp(buffer, hd->name, strlen(hd->name)) == 0) {
		char *value = strchr(buffer, ':');
		if (value) {
			value++;
			while (*value == ' ')
				value++;
			strncpy(hd->value, value, sizeof(hd->value) - 1);
			hd->value[sizeof(hd->value) - 1] = '\0';
			char *nl = strchr(hd->value, '\r');
			if (!nl)
				nl = strchr(hd->value, '\n');
			if (nl)
				*nl = '\0';
		}
	}
	return len;
}

static size_t header_callbackB(char *buffer, size_t size, size_t nitems, void *userdata) {
	header_data_struct *hd = (header_data_struct *)userdata;
	size_t len = size * nitems;
	if (len > 0 && strncasecmp(buffer, hd->name, strlen(hd->name)) == 0) {
		char *value = strchr(buffer, ':');
		if (value) {
			value++;
			while (*value == ' ')
				value++;
			char *end = strpbrk(value, "\r\n");
			if (end) {
				size_t value_len = end - value;
				strncpy(hd->value, value, value_len < sizeof(hd->value) - 1
					? value_len : sizeof(hd->value) - 1);
				hd->value[value_len < sizeof(hd->value) - 1 ? value_len : sizeof(hd->value) - 1] = '\0';
			} else {
				strncpy(hd->value, value, sizeof(hd->value) - 1);
				hd->value[sizeof(hd->value) - 1] = '\0';
			}
			debug_log("Captured %s: %s", hd->name, hd->value);
		}
	}
	return len;
}

static void ycmd_signal_handler(int signum) {
	debug_log("Setting need_bottombar_update, filename=%s, line=%d, col=%d",
		 ycmd_filename ? ycmd_filename : "null", ycmd_line_num,
		 ycmd_column_num);
	need_bottombar_update = TRUE;
}

void ycmd_constructor() {
	wrap_secure_zero(&ycmd_globals, sizeof(ycmd_globals_struct));
	ycmd_globals.core_version = DEFAULT_YCMD_CORE_VERSION;
	ycmd_globals.scheme = YCMD_PROTOCOL;
	ycmd_globals.hostname = YCMD_HOST;
	ycmd_globals.port = YCMD_PORT;
	ycmd_globals.child_pid = -1;
	wrap_secure_zero(&ycmd_globals.json, sizeof(ycmd_globals.json));

	init_wrapper();

	if (COLS <= HALF_LINE_LENGTH)
		ycmd_globals.max_entries = 2;
	else if (COLS <= LINE_LENGTH)
		ycmd_globals.max_entries = 4;
	else
		ycmd_globals.max_entries = 6;

	file_ready_to_parse_results_constructor(
		&ycmd_globals.file_ready_to_parse_results);

	if (is_popup_mode) {
		struct sigaction sa;
		sa.sa_handler = ycmd_signal_handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		sigaction(SIGALRM, &sa, NULL);
	} else {
		signal(SIGALRM, ycmd_send_to_server);
	}

#if defined(USE_LIBGCRYPT)
	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	/* gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0); */
	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif

	ycmd_generate_secret_key_raw(ycmd_globals.secret_key_raw);
	ycmd_generate_secret_key_base64(ycmd_globals.secret_key_raw, ycmd_globals.secret_key_base64);

	default_settings_constructor(&ycmd_globals.default_settings);

	int tries = 3;
	int i = 0;
	for (i = 0; i < tries && ycmd_globals.connected == 0; i++)
		ycmd_restart_server();
}

/* Generates a compile_commands.json for the Clang completer. */
/* Returns 1 on success. */
int bear_generate(char *project_path) {
	char file_path[PATH_MAX];
	char command[PATH_MAX + LINE_LENGTH];
	int ret = -1;

	snprintf(file_path, PATH_MAX, "%s/compile_commands.json", project_path);

	if (access(file_path, F_OK) == 0) {
		; /* statusline(HUSH, "Using previously generated compile_commands.json file."); */
		ret = 0;
	} else {
		statusline(HUSH, "Please wait.  Generating a compile_commands.json file.");
		snprintf(command, PATH_MAX + LINE_LENGTH, "cd '%s'; make clean > /dev/null", project_path);
		ret = system(command);

		snprintf(command, PATH_MAX + LINE_LENGTH, "cd '%s'; bear make > /dev/null", project_path);
		ret = system(command);
		full_refresh();
		draw_all_subwindows();

		if (ret == 0)
			statusline(HUSH, "Sucessfully generated a compile_commands.json file.");
		else
			statusline(HUSH, "Failed generating a compile_commands.json file.");
	}
	blank_statusbar();

	return ret == 0;
}

/* Generate a compile_commands.json for projects using the ninja build system */
/* Returns:
 * 1 on success.
 * 0 on failure. */
int ninja_compdb_generate(char *project_path) {
	/* Try ninja. */
	char command[PATH_MAX * 4 + LINE_LENGTH];

	char ninja_build_path[PATH_MAX];
	char *_ninja_build_path = getenv("NINJA_BUILD_PATH");
	if (_ninja_build_path &&
		wrap_strncmp(_ninja_build_path, "(null)", PATH_MAX) != 0)
		snprintf(ninja_build_path, PATH_MAX, "%s", _ninja_build_path);
	else
		ninja_build_path[0] = 0;

	snprintf(command, PATH_MAX + LINE_LENGTH,
		"find '%s' -maxdepth 1 -name '*.ninja' > /dev/null",
		ninja_build_path);
	int ret = system(command);

	if (ret != 0) {
		;
	} else {
		char ninja_build_targets[PATH_MAX];
		char *_ninja_build_targets = getenv("NINJA_BUILD_TARGETS");
		if (_ninja_build_targets &&
			wrap_strncmp(_ninja_build_targets, "(null)", PATH_MAX) != 0) {
			snprintf(ninja_build_targets, PATH_MAX, "%s", _ninja_build_targets);
		} else {
			ninja_build_targets[0] = 0;
		}

		snprintf(command, PATH_MAX * 4 + LINE_LENGTH,
			"cd '%s'; '%s' -t compdb %s > '%s/compile_commands.json'",
			ninja_build_path, NINJA_PATH, ninja_build_targets, project_path);
		ret = system(command);
		full_refresh();
		draw_all_subwindows();
	}
	return ret == 0;
}

/* Returns:  path_project */
void ycmd_get_project_path(char *path_project) {
	char *ycmg_project_path = getenv("YCMG_PROJECT_PATH");
	if (ycmg_project_path &&
		wrap_strncmp(ycmg_project_path, "(null)", PATH_MAX) != 0) {
		snprintf(path_project, PATH_MAX, "%s", ycmg_project_path);
	} else {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
		getcwd(path_project, PATH_MAX);
#pragma GCC diagnostic pop
	}
}

/* Precondition:  path_project must be populated first from
 * ycmd_get_project_path(). */
void ycmd_get_extra_conf_path(char *path_project, char *path_extra_conf) {
	snprintf(path_extra_conf, PATH_MAX, "%s/.ycm_extra_conf.py", path_project);
}


/* Function to extract include paths from clang's output */
char* extract_include_paths(const char* language) {
	FILE* pipe = popen("clang -v -E -x", "w");
	if (!pipe) return NULL;

	fprintf(pipe, "%s -\n", language);
	pclose(pipe);

	pipe = popen("clang -v -E -x", "r");
	if (!pipe) return NULL;

	char* output = NULL;
	size_t output_len = 0;
	char line[1024];

	while (fgets(line, sizeof(line), pipe)) {
		output = realloc(output, output_len + strlen(line) + 1);
		strcpy(output + output_len, line);
		output_len += strlen(line);
	}

	pclose(pipe);

	// Extract the include paths from the output
	const char* start_marker = "#include <...> search starts here:";
	const char* end_marker = "End of search list.";
	char* start = strstr(output, start_marker);
	char* end = strstr(output, end_marker);

	if (start && end) {
		start += strlen(start_marker);
		end += strlen(end_marker);
		*end = '\0';
		memmove(output, start, end - start);
	}

	return output;
}

/* Function to format the include paths */
char* format_include_paths(const char* include_paths) {
	size_t formatted_len = strlen(include_paths) * 2;
	char* formatted_paths = malloc(formatted_len + 1);

	char* p = formatted_paths;
	for (const char* q = include_paths; *q; q++) {
		if (*q == '\n') {
			sprintf(p, "',\n    '-isystem','");
			p += strlen(p);
		} else {
			*p++ = *q;
		}
	}
	*p = '\0';

	return formatted_paths;
}

/* Function to update the configuration file */
int update_config_file(const char* path_extra_conf, const char* formatted_paths) {
	FILE* file = fopen(path_extra_conf, "r+");
	if (!file) return -1;

	char line[1024];
	while (fgets(line, sizeof(line), file)) {
		if (strstr(line, "'do_cache': True")) {
			fseek(file, -strlen(line), SEEK_CUR);
			fprintf(file, "'do_cache': False");
		} else if (strstr(line, "'-I.'")) {
			fseek(file, -strlen(line), SEEK_CUR);
			fprintf(file, "'-isystem','%s','-I.'", formatted_paths);
		}
	}

	fclose(file);
	return 0;
}

/* The following bash4 code has been transpiled to c for security-critical reasons.
	"V=$(echo | clang -v -E -x %s - |& "
	"sed "
		"-r "
		"-e ':a' "
		"-e 'N' "
		"-e '$!ba' "
		"-e \"s|.*#include <...> search starts here:[ \\n]+(.*)[ \\n]+End of search list.\\n.*|\\1|g\" "
		"-e \"s|[ \\n]+|\\n|g\" "
		"| tac);"
	"V=$(echo -e ${V} |"
		"sed -r -e \"s|[ \\n]+|\',\\n    \'-isystem\','|g\");"
		"sed -i -e \"s|'do_cache': True|'do_cache': False|g\" "
			"-e \"s|'-I.'|'-isystem','$(echo -e $V)','-I.'|g\" "
	"\"%s\"",
	 language, path_extra_conf);
*/
/* Inject Clang includes to find stdio.h and other headers. */
/* Caching disabled because of problems */
int _ycm_inject_clang_includes(char * language, char *path_extra_conf) {
	char* include_paths = extract_include_paths(language);
	if (!include_paths) return 1;

	char* formatted_paths = format_include_paths(include_paths);
	if (!formatted_paths) return 1;

	int ret = update_config_file(path_extra_conf, formatted_paths);

	free(include_paths);
	free(formatted_paths);

	return ret;
}

/* Generates a .ycm_extra_conf.py for the C family completer. */
/* Language must be:  c, c++, objective-c, objective-c++ */
int ycm_generate(void) {
	char path_project[PATH_MAX];
	char path_extra_conf[PATH_MAX];
	char command[PATH_MAX * 3 + LINE_LENGTH * 4];
	char flags[PATH_MAX];
	int ret = -1;
	int ret2 = -1;

	ycmd_get_project_path(path_project);
	if (wrap_strncmp(path_project, "(null)", PATH_MAX) != 0 &&
		access(path_project, F_OK) == 0) {
		;
	} else {
		return ret;
	}

	ycmd_get_extra_conf_path(path_project, path_extra_conf);

#ifdef ENABLE_YCM_GENERATOR
	char *ycmg_flags = getenv("YCMG_FLAGS");
	if (!ycmg_flags || wrap_strncmp(ycmg_flags, "(null)", PATH_MAX) == 0) {
		flags[0] = 0;
	} else {
		snprintf(flags, PATH_MAX, "%s", ycmg_flags);
	}
#endif

	/* Generate Bear's JSON first because ycm-generator deletes the Makefiles.
	 */
#ifdef ENABLE_BEAR
	if (!bear_generate(path_project))
#endif
#ifdef ENABLE_NINJA
		/* Handle the ninja build system. */
		ninja_compdb_generate(path_project);
#else
	;
#endif

	if (access(path_extra_conf, F_OK) == 0) {
		; /* statusline(HUSH, "Using previously generated .ycm_extra_conf.py.");
		   */
	} else {
#ifdef ENABLE_YCM_GENERATOR
		statusline(HUSH, "Please wait.  Generating a .ycm_extra_conf.py file.");
		snprintf(command, PATH_MAX * 3 + LINE_LENGTH, "'%s' '%s' -f %s '%s' >/dev/null", YCMG_PYTHON_PATH,
			YCMG_PATH, flags, path_project);
		int ret = system(command);
		if (ret == 0) {
			statusline(HUSH, "Sucessfully generated a .ycm_extra_conf.py file.");

#if defined(ENABLE_BEAR) || defined(ENABLE_NINJA)
			snprintf(command, PATH_MAX * 2 + LINE_LENGTH,
				"sed -i -e \"s|compilation_database_folder = ''|compilation_database_folder = '%s'|g\" \"%s\"",
				path_project, path_extra_conf);
			ret2 = system(command);
			if (ret2 == 0)
				statusline(HUSH, "Patching .ycm_extra_conf.py file with compile_commands.json was a success.");
			else
				statusline(HUSH, "Failed patching .ycm_extra_conf.py with compile_commands.json.");
#endif

			int has_objcxx = -1;
			int has_objc = -1;
			int has_cxx = -1;
			int has_c = -1;
			int has_h = -1;
			int has_cxx_code = -1;

#ifdef ENABLE_YCM_GENERATOR
			debug_log("path_project = %s", path_project);
			snprintf(command, PATH_MAX + LINE_LENGTH, "find '%s' -name '*.mm'", path_project);
			has_objcxx = system(command);
			snprintf(command, PATH_MAX + LINE_LENGTH, "find '%s' -name '*.m'", path_project);
			has_objc = system(command);
			snprintf(command, PATH_MAX + LINE_LENGTH,
				"find '%s' -name '*.cpp' -o -name '*.C' -o -name '*.cxx' -o -name '*.cc'",
				path_project);
			has_cxx = system(command);
			snprintf(command, PATH_MAX + LINE_LENGTH, "find '%s' -name '*.c'", path_project);
			has_c = system(command);
			snprintf(command, PATH_MAX + LINE_LENGTH, "find '%s' -name '*.c'", path_project);
			has_h = system(command);
			snprintf(command, PATH_MAX + LINE_LENGTH,
				"grep -r -e 'using namespace' "
					"-e 'iostream' "
					"-e '\tclass ' "
					"-e ' class ' "
					"-e 'private:' "
					"-e 'public:' "
					"-e 'protected:' '%s'",
				path_project);
			has_cxx_code = system(command);
#endif

			char language[QUARTER_LINE_LENGTH];
			if (has_objcxx == 0)
				sprintf(language, "objective-c++");
			else if (has_objc == 0)
				sprintf(language, "objective-c");
			else if (has_cxx == 0)
				sprintf(language, "c++");
			else if (has_c == 0)
				sprintf(language, "c");
			else if (has_h == 0) {
				/* Handle header only projects */
				if (has_cxx_code == 0)
					sprintf(language, "c++");
				else
					sprintf(language, "c");
			}

			ret2 = _ycm_inject_clang_includes(language, path_extra_conf);

			/* Check for potential ACE in the Python file. */
			if (check_ace(path_extra_conf) != 0) {
				debug_log("Error: Potential ACE (Arbitrary Code Execution) detected in '%s'\n", path_extra_conf);
				return -1;
			}

			/* Check for obfuscated text in the Python file. */
			if (check_obfuscated_text(path_extra_conf) != 0) {
				debug_log("Error: Potential obfuscated text detected in '%s'\n", path_extra_conf);
				return -1;
			}

			/* Check for ACE check bypass. */
			if (check_ycm_extra_conf_py_imports(path_extra_conf) != 0) {
				debug_log("Error: Potential circumvention of ACE (Arbitrary Code Execution) check with untrusted imported module in '%s'\n", path_extra_conf);
				return -1;
			}

			if (ret2 == 0) {
				debug_log("Patching .ycm_extra_conf.py file with clang includes was a success.");
				ret = 0;
			} else {
				debug_log("Failed patching .ycm_extra_conf.py with clang includes.");
				ret = ret2;
			}
		} else
			statusline(HUSH, "Failed to generate a .ycm_extra_conf.py file.");
#endif
	}
	blank_statusbar();
	return ret;
}

semantic_triggers_struct json_default_set_semantic_trigger(char *lang, char triggers[10][QUARTER_LINE_LENGTH]) {
	semantic_triggers_struct row;
	wrap_secure_zero(&row, sizeof(semantic_triggers_struct));
	wrap_strncpy(row.lang, lang, QUARTER_LINE_LENGTH);
	wrap_memcpy(row.triggers, triggers, 10 * QUARTER_LINE_LENGTH);
	return row;
}

filetype_specific_completion_to_disable_struct
json_default_set_filetype_specific_completion_to_disable(char *filetype, int off) {
	filetype_specific_completion_to_disable_struct row;
	wrap_secure_zero(&row, sizeof(filetype_specific_completion_to_disable_struct));
	wrap_strncpy(row.filetype, filetype, NAME_MAX);
	row.off = off;
	return row;
}

filetype_whitelist_struct json_default_set_filetype_whitelist(char *filetype, int whitelisted) {
	filetype_whitelist_struct row;
	wrap_secure_zero(&row, sizeof(filetype_whitelist_struct));
	wrap_strncpy(row.filetype, filetype, NAME_MAX);
	row.whitelisted = whitelisted;
	return row;
}

filetype_blacklist_struct json_default_set_filetype_blacklist(char *filetype, int blacklisted) {
	filetype_blacklist_struct row;
	wrap_secure_zero(&row, sizeof(filetype_blacklist_struct));
	wrap_strncpy(row.filetype, filetype, NAME_MAX);
	row.blacklisted = blacklisted;
	return row;
}

/* Preconditions:  ycmd_globals.secret_key_base64 must be set before calling
 * function. */
void default_settings_constructor(default_settings_struct *settings) {
	wrap_secure_zero(settings, sizeof(default_settings_struct));
	settings->filepath_completion_use_working_dir = 1;
	settings->auto_trigger = 1;
	settings->min_num_of_chars_for_completion = 2;
	settings->min_num_identifier_candidate_chars = 0;

	settings->semantic_triggers_num = 0;

	settings->filetype_specific_completion_to_disable[0] =
		json_default_set_filetype_specific_completion_to_disable("gitcommit", 1);
	settings->filetype_specific_completion_to_disable_num = 1;

	if (ycmd_globals.core_version < 43) {
		settings->seed_identifiers_with_syntax = 0;
	}
	settings->collect_identifiers_from_comments_and_strings = 0;
	if (ycmd_globals.core_version < 43) {
		settings->collect_identifiers_from_tags_files = 0;
	}
	settings->max_num_identifier_candidates = 10;
	settings->max_num_candidates = 50;
	if (ycmd_globals.core_version >= 45) {
		settings->max_num_candidates_to_detail = -1;
	}

	settings->extra_conf_globlist_num = 0;

	settings->confirm_extra_conf = 1;
	if (ycmd_globals.core_version < 43) {
		settings->complete_in_comments = 0;
		settings->complete_in_strings = 1;
	}
	settings->max_diagnostics_to_display = 30;

	if (ycmd_globals.core_version < 43) {
		settings->filetype_whitelist[0] = json_default_set_filetype_whitelist("*", 1);
		settings->filetype_whitelist_num = 1;
	}

	if (ycmd_globals.core_version < 43) {
		settings->filetype_blacklist[0] = json_default_set_filetype_blacklist("tagbar", 1);
		settings->filetype_blacklist[1] = json_default_set_filetype_blacklist("qf", 1);
		settings->filetype_blacklist[2] = json_default_set_filetype_blacklist("notes", 1);
		settings->filetype_blacklist[3] = json_default_set_filetype_blacklist("markdown", 1);
		settings->filetype_blacklist[4] = json_default_set_filetype_blacklist("netrw", 1);
		settings->filetype_blacklist[5] = json_default_set_filetype_blacklist("unite", 1);
		settings->filetype_blacklist[6] = json_default_set_filetype_blacklist("text", 1);
		settings->filetype_blacklist[7] = json_default_set_filetype_blacklist("vimwiki", 1);
		settings->filetype_blacklist[8] = json_default_set_filetype_blacklist("pandoc", 1);
		settings->filetype_blacklist[9] = json_default_set_filetype_blacklist("infolog", 1);
		settings->filetype_blacklist[10] = json_default_set_filetype_blacklist("mail", 1);
		settings->filetype_blacklist_num = 11;
	}

	if (ycmd_globals.core_version >= 43) {
		settings->filetype_blacklist[0] = json_default_set_filetype_blacklist("html", 1);
		settings->filetype_blacklist[1] = json_default_set_filetype_blacklist("jsx", 1);
		settings->filetype_blacklist[2] = json_default_set_filetype_blacklist("xml", 1);
		settings->filetype_blacklist_num = 3;
	}

	settings->auto_start_csharp_server = 1;
	settings->auto_stop_csharp_server = 1;
	settings->use_ultisnips_completer = 1;
	settings->csharp_server_port = 0;
	sprintf(settings->hmac_secret, "%s", ycmd_globals.secret_key_base64);
	settings->server_keep_logfiles = 0;

	if (ycmd_globals.core_version < 43) {
		wrap_strncpy(settings->gocode_binary_path, GOCODE_PATH, PATH_MAX);
		wrap_strncpy(settings->godef_binary_path, GODEF_PATH, PATH_MAX);
		wrap_strncpy(settings->rust_src_path, RUST_SRC_PATH, PATH_MAX);
		wrap_strncpy(settings->racerd_binary_path, RACERD_PATH, PATH_MAX);
	}
	wrap_strncpy(settings->python_binary_path, YCMD_PYTHON_PATH, PATH_MAX);

	if (ycmd_globals.core_version >= 43) {
		/* language_server = [] */
		/* java_jdtls_workspace_root_path = "" */
		/* java_jdtls_extension_path = [] */
		settings->use_clangd = 0;
		wrap_strncpy(settings->clangd_binary_path, CLANGD_PATH, PATH_MAX);
		/* clangd_args = [] */
		settings->clangd_uses_ycmd_caching = 0;
		settings->disable_signature_help = 0;
		wrap_strncpy(settings->gopls_binary_path, GOPLS_PATH, PATH_MAX);
		/* gopls_args = [] */
		if (ycmd_globals.core_version < 45) {
			wrap_strncpy(settings->rls_binary_path, RLS_PATH, PATH_MAX);
			wrap_strncpy(settings->rustc_binary_path, RUSTC_PATH, PATH_MAX);
		}
		if (ycmd_globals.core_version >= 45) {
			wrap_strncpy(settings->rust_toolchain_root, RUST_TOOLCHAIN_PATH, PATH_MAX);
		}
		wrap_strncpy(settings->tsserver_binary_path, TSSERVER_PATH, PATH_MAX);
		wrap_strncpy(settings->roslyn_binary_path, OMNISHARP_PATH, PATH_MAX);
	}

	if (ycmd_globals.core_version >= 44) {
		wrap_strncpy(settings->mono_binary_path, MONO_PATH, PATH_MAX);
	}

	if (ycmd_globals.core_version >= 45) {
		wrap_strncpy(settings->java_binary_path, JAVA_PATH, PATH_MAX);
	}
	settings->java_jdtls_use_clean_workspace = 1;
}

/* Revised Jun 2025 changes. */

/* The versioning is confusing because there are no repo tags for ycmd.  The
 * ycmd_create_default_json_core_version_<ver>() is assumed to be like Python,
 * each core version bump is the final CORE_VERSION.  Any changes is for the
 * new unbumped CORE_VERSION. */

/* CORE_VERSION default jsons: */

/* 48 https://github.com/ycm-core/ycmd/blob/99c068120c14257c236e1dcfbf55838e33ae141e/ycmd/default_settings.json
 * 47 https://github.com/ycm-core/ycmd/blob/671fee16bbaa5da3858108b3717b76bc833b3953/ycmd/default_settings.json
 * 46 https://github.com/ycm-core/ycmd/blob/18808eae493548f37c50e1e3e0b5607b5f94093d/ycmd/default_settings.json
 * 45 https://github.com/ycm-core/ycmd/blob/a9f616e24f4bc71cd0e7f227a41e8bc2640193fd/ycmd/default_settings.json
 * 44 https://github.com/ycm-core/ycmd/blob/ff428c9976c93e217cd3f502d92ea68ca2ac5210/ycmd/default_settings.json
 * 43 https://github.com/ycm-core/ycmd/blob/228adf91f5ea15cca837f3ccc85f4e55edfa1b4f/ycmd/default_settings.json
 * 39 https://github.com/ycm-core/ycmd/blob/683cb5e51d9e2379903189d7be6b16cf7fe80e7e/ycmd/default_settings.json
 */

/* Needs to be freed */

void default_settings_json_constructor(char *json) {
	debug_log("Called function");
	int i;
	int j;

	default_settings_struct *settings = &ycmd_globals.default_settings;

	size_t json_size = DEFAULT_JSON_SIZE;
	wrap_secure_zero(json, json_size);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmisleading-indentation"

	_req_sprintf(json, json_size, "{\n");
	_req_sprintf(json, json_size, "\"filepath_completion_use_working_dir\": %d,\n",
		settings->filepath_completion_use_working_dir);
	_req_sprintf(json, json_size, "\"auto_trigger\": %d,\n", settings->auto_trigger);
	_req_sprintf(json, json_size, "\"min_num_of_chars_for_completion\": %d,\n",
		settings->min_num_of_chars_for_completion);
	_req_sprintf(json, json_size, "\"min_num_identifier_candidate_chars\": %d,\n",
		settings->min_num_identifier_candidate_chars);
	_req_sprintf(json, json_size, "\"semantic_triggers\": {\n");

	for (i = 0; i < settings->semantic_triggers_num; i++) {
		char comma1[2];
		if (i < settings->semantic_triggers_num - 1)
			wrap_strncpy(comma1, ",", 1);
		else
			wrap_strncpy(comma1, "", 1);
		_req_sprintf(json, json_size, "\"%s\": [", settings->semantic_triggers[i].lang);
		for (j = 0; j < settings->semantic_triggers[i].triggers_num; j++) {
			char comma2[2];
			if (j < settings->semantic_triggers[i].triggers_num - 1)
				wrap_strncpy(comma2, ",", 1);
			else
				wrap_strncpy(comma2, "", 1);
			_req_sprintf(json, json_size, "\"%s\"%s", settings->semantic_triggers[i].lang,
				settings->semantic_triggers[i].triggers[j], comma2);
		}
		_req_sprintf(json, json_size, "]%s\n", comma1);
	}

	_req_sprintf(json, json_size, "},\n");

	_req_sprintf(json, json_size,
				 "\"filetype_specific_completion_to_disable\": {\n");

	for (i = 0; i < settings->filetype_specific_completion_to_disable_num;
		 i++) {
		char comma[2];
		if (i < settings->filetype_specific_completion_to_disable_num - 1)
			wrap_strncpy(comma, ",", 1);
		else
			wrap_strncpy(comma, "", 1);
		_req_sprintf(json, json_size, "\"%s\": %d%s\n",
			settings->filetype_specific_completion_to_disable[i].filetype,
			settings->filetype_specific_completion_to_disable[i].off, comma);
	}

	_req_sprintf(json, json_size, "},\n");

	if (ycmd_globals.core_version < 43) {
		_req_sprintf(json, json_size, "\"seed_identifiers_with_syntax\": %d,\n",
			settings->seed_identifiers_with_syntax);
	}
	_req_sprintf(json, json_size, "\"collect_identifiers_from_comments_and_strings\": %d,\n",
		settings->collect_identifiers_from_comments_and_strings);
	if (ycmd_globals.core_version < 43) {
		_req_sprintf(json, json_size, "\"collect_identifiers_from_tags_files\": %d,\n",
			settings->collect_identifiers_from_tags_files);
	}
	_req_sprintf(json, json_size, "\"max_num_identifier_candidates\": %d,\n",
		settings->max_num_identifier_candidates);
	_req_sprintf(json, json_size, "\"max_num_candidates\": %d,\n",
		settings->max_num_candidates);
	if (ycmd_globals.core_version >= 45) {
		_req_sprintf(json, json_size, "\"max_num_candidates_to_detail\": %d,\n",
			settings->max_num_candidates_to_detail);
	}

	_req_sprintf(json, json_size, "\"extra_conf_globlist\": [");

	for (i = 0; i < settings->extra_conf_globlist_num; i++) {
		_req_sprintf(json, json_size, "'%s',", settings->extra_conf_globlist[i].pattern);
	}
	_req_sprintf(json, json_size, "],\n");
	_req_sprintf(json, json_size, "\"global_ycm_extra_conf\": \"%s\",\n", settings->global_ycm_extra_conf);
	_req_sprintf(json, json_size, "\"confirm_extra_conf\": %d,\n", settings->confirm_extra_conf);
	if (ycmd_globals.core_version < 43) {
		_req_sprintf(json, json_size, "\"complete_in_comments\": %d,\n", settings->complete_in_comments);
		_req_sprintf(json, json_size, "\"complete_in_strings\": %d,\n", settings->complete_in_strings);
	}

	_req_sprintf(json, json_size, "\"max_diagnostics_to_display\": %d,\n", settings->max_diagnostics_to_display);

	if (ycmd_globals.core_version < 43) {
		_req_sprintf(json, json_size, "\"filetype_whitelist\": {\n");

		for (i = 0; i < settings->filetype_whitelist_num; i++) {
			char comma[2];
			if (i < settings->filetype_whitelist_num - 1)
				wrap_strncpy(comma, ",", 1);
			else
				wrap_strncpy(comma, "", 1);
			_req_sprintf(json, json_size, "\"%s\": %d%s\n",
				 settings->filetype_whitelist[i].filetype,
				 settings->filetype_whitelist[i].whitelisted, comma);
		}

		_req_sprintf(json, json_size, "},\n");
	}

	_req_sprintf(json, json_size, "\"filetype_blacklist\": {\n");

	for (i = 0; i < settings->filetype_blacklist_num; i++) {
		char comma[2];
		if (i < settings->filetype_blacklist_num - 1)
			wrap_strncpy(comma, ",", 1);
		else
			wrap_strncpy(comma, "", 1);
		_req_sprintf(json, json_size, "\"%s\": %d%s\n",
			settings->filetype_blacklist[i].filetype,
			settings->filetype_blacklist[i].blacklisted, comma);
	}

	_req_sprintf(json, json_size, "},\n");
	_req_sprintf(json, json_size, "\"auto_start_csharp_server\": %d,\n", settings->auto_start_csharp_server);
	_req_sprintf(json, json_size, "\"auto_stop_csharp_server\": %d,\n", settings->auto_stop_csharp_server);
	_req_sprintf(json, json_size, "\"use_ultisnips_completer\": %d,\n", settings->use_ultisnips_completer);
	_req_sprintf(json, json_size, "\"csharp_server_port\": %d,\n", settings->csharp_server_port);
	_req_sprintf(json, json_size, "\"hmac_secret\": \"%s\",\n", settings->hmac_secret);
	_req_sprintf(json, json_size, "\"server_keep_logfiles\": %d,\n", settings->server_keep_logfiles);
	if (ycmd_globals.core_version < 43) {
		_req_sprintf(json, json_size, "\"gocode_binary_path\": \"%s\",\n", settings->gocode_binary_path);
		_req_sprintf(json, json_size, "\"godef_binary_path\": \"%s\",\n", settings->godef_binary_path);
		_req_sprintf(json, json_size, "\"rust_src_path\": \"%s\",\n", settings->rust_src_path);
		_req_sprintf(json, json_size, "\"racerd_binary_path\": \"%s\",\n", settings->racerd_binary_path);
	}

	_req_sprintf(json, json_size, "\"python_binary_path\": \"%s\",\n", settings->python_binary_path);

	if (ycmd_globals.core_version >= 43) {
		_req_sprintf(json, json_size, "\"language_server\": [],\n");
		_req_sprintf(json, json_size, "\"java_jdtls_use_clean_workspace\": %d,\n", settings->java_jdtls_use_clean_workspace);
		_req_sprintf(json, json_size, "\"java_jdtls_extension_path\": [],\n");
		_req_sprintf(json, json_size, "\"use_clangd\": %d,\n", settings->use_clangd);
		_req_sprintf(json, json_size, "\"clangd_binary_path\": \"%s\",\n", settings->clangd_binary_path);
		_req_sprintf(json, json_size, "\"clangd_args\": [],\n");
		_req_sprintf(json, json_size, "\"clangd_uses_ycmd_caching\": %d,\n", settings->clangd_uses_ycmd_caching);
		_req_sprintf(json, json_size, "\"disable_signature_help\": %d,\n", settings->disable_signature_help);
		_req_sprintf(json, json_size, "\"gopls_binary_path\": \"%s\",\n", settings->gopls_binary_path);
		_req_sprintf(json, json_size, "\"gopls_args\": [],\n");
		_req_sprintf(json, json_size, "\"rls_binary_path\": \"%s\",\n", settings->rls_binary_path);
		_req_sprintf(json, json_size, "\"rustc_binary_path\": \"%s\",\n", settings->rustc_binary_path);
		_req_sprintf(json, json_size, "\"tsserver_binary_path\": \"%s\",\n", settings->tsserver_binary_path);
		_req_sprintf(json, json_size, "\"roslyn_binary_path\": \"%s\",\n", settings->roslyn_binary_path);
	}

	if (ycmd_globals.core_version < 43) {
		_req_sprintf(json, json_size, "\"java_jdtls_use_clean_workspace\": %d\n", settings->java_jdtls_use_clean_workspace);
	}

	if (ycmd_globals.core_version >= 44) {
		_req_sprintf(json, json_size, "\"mono_binary_path\": \"%s\",\n", settings->mono_binary_path);
	}

	if (ycmd_globals.core_version >= 44) {
		_req_sprintf(json, json_size, "\"java_binary_path\": \"%s\"\n", settings->java_binary_path);
	}

	_req_sprintf(json, json_size, "}\n");
#pragma GCC diagnostic pop
}

void ycmd_gen_extra_conf() {
	char command[PATH_MAX + DOUBLE_LINE_LENGTH];
	char path_project[PATH_MAX];
	ycmd_get_project_path(path_project);

	if (wrap_strncmp(path_project, "(null)", PATH_MAX) != 0 &&
		access(path_project, F_OK) == 0)
		;
	else
		return;

	snprintf(command, PATH_MAX + DOUBLE_LINE_LENGTH,
		"find '%s' "
			   "-name '*.C' "
			"-o -name '*.c' "
			"-o -name '*.cc' "
			"-o -name '*.cpp' "
			"-o -name '*.cxx' "
			"-o -name '*.h' "
			"-o -name '*.hh' "
			"-o -name '*.hpp' "
			"-o -name '*.m' "
			"-o -name '*.mm' "
			">/dev/null",
		path_project);
	int ret = system(command);

	if (ret == 0) {
		int ret = ycm_generate();
		if (!ret)
			ycmd_globals.clang_completer = 1;
		else
			ycmd_globals.clang_completer = 0;
	} else {
		ycmd_globals.clang_completer = 0;
	}
}

void file_ready_to_parse_results_constructor(
	file_ready_to_parse_results_struct *frtpr) {
	wrap_secure_zero(frtpr, sizeof(file_ready_to_parse_results_struct));
}

void delete_file_ready_to_parse_results(
	file_ready_to_parse_results_struct *frtpr) {
	if (frtpr->json) {
		wrap_free((void **)&frtpr->json);
		frtpr->json = NULL;
	}
}

void get_abs_path(char *filepath, char *abs_filepath) {
	wrap_secure_zero(abs_filepath, PATH_MAX);
	if (filepath[0] != '/') {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
		getcwd(abs_filepath, PATH_MAX);
#pragma GCC diagnostic pop
		wrap_strncat(abs_filepath, "/", PATH_MAX);
		wrap_strncat(abs_filepath, filepath, PATH_MAX);
	} else {
		wrap_strncpy(abs_filepath, filepath, PATH_MAX);
	}
}

int ycmd_json_event_notification(int columnnum, int linenum, char *filepath, char *eventname, linestruct *filetop) {
	debug_log("Called function with eventname = %s", eventname);
	char *filetype = _ycmd_get_filetype(filepath);
	char *method = "POST";
	char *path = "/event_notification";
	char abspath[PATH_MAX];
	int compromised = 0;
	char req_hmac_base64[HMAC_SIZE * 2];
	char rsp_hmac_base64[HMAC_SIZE * 2];
	long response_code = -1;

	if (!ycmd_globals.curl) {
		ycmd_globals.curl = curl_easy_init();
		if (!ycmd_globals.curl) {
			return -1;
		}
	}

	curl_easy_reset(ycmd_globals.curl);
	char url[LINE_LENGTH];
	sprintf(url, "%s://%s:%d%s", ycmd_globals.scheme, ycmd_globals.hostname, ycmd_globals.port, path);
	debug_log("url = %s", url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_URL, url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_TIMEOUT_MS, 500L);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_NONE);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_CUSTOMREQUEST, method);

	get_abs_path(filepath, abspath);

	/* We send the data directly skipping the json and string lib because we
	 * need to stream the file it. */
	size_t req_buffer_size = MAX_FILESIZE_LIMIT;
	char *req_buffer = wrap_malloc(req_buffer_size);
	if (!req_buffer) {
		statusline(HUSH, "Out of Memory");
		return -1;
	}
	wrap_secure_zero(req_buffer, req_buffer_size);
	_req_sprintf(req_buffer, req_buffer_size, "{\n");
	_req_sprintf(req_buffer, req_buffer_size, "  \"column_num\": %d,\n", columnnum + (ycmd_globals.clang_completer ? 0 : 1));
	_req_sprintf(req_buffer, req_buffer_size, "  \"event_name\": \"%s\",\n", eventname);
	_req_sprintf(req_buffer, req_buffer_size, "  \"file_data\": {\n");
	_req_sprintf(req_buffer, req_buffer_size, "    \"%s\": {\n", abspath);
	_req_sprintf(req_buffer, req_buffer_size, "      \"contents\": \"");
	_req_file(req_buffer, req_buffer_size, filetop);
	_req_sprintf(req_buffer, req_buffer_size, "\",\n");
	_req_sprintf(req_buffer, req_buffer_size, "      \"filetypes\": [\"%s\"]\n", filetype);
	_req_sprintf(req_buffer, req_buffer_size, "    }\n");
	_req_sprintf(req_buffer, req_buffer_size, "  },\n");
	_req_sprintf(req_buffer, req_buffer_size, "  \"filepath\": \"%s\",\n", abspath);
	_req_sprintf(req_buffer, req_buffer_size, "  \"line_num\": %d\n", linenum);
	_req_sprintf(req_buffer, req_buffer_size, "}\n");

	/* Set headers to match HTTP Neon */
	struct curl_slist *headers = NULL;
	ycmd_get_hmac_request(req_hmac_base64, method, path, req_buffer,
						  strlen(req_buffer));
	debug_log("HMAC inputs:  method=%s, path=%s, body='%s', body_size=%zu",
		method, path,
		req_buffer && strlen(req_buffer) ? req_buffer : "NULL",
		req_buffer && strlen(req_buffer) ? strlen(req_buffer) : 0);
	debug_log("X-Ycm-Hmac = %s", req_hmac_base64);
	headers = curl_slist_append(headers, "Keep-Alive: ");
	headers = curl_slist_append(headers, "Connection: TE, Keep-Alive");
	headers = curl_slist_append(headers, "content-type: application/json");
	headers = curl_slist_append(headers, "Accept:");
	headers = _curl_sprintf_header(headers, "%s: %s", HTTP_HEADER_YCM_HMAC, req_hmac_base64);

	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTPHEADER, headers);

	if (strcmp(method, "POST") == 0) {
		curl_easy_setopt(ycmd_globals.curl, CURLOPT_POST, 1L);
		if (req_buffer && req_buffer_size > 0) {
			curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDS, req_buffer);
			curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDSIZE, strlen(req_buffer));
		} else {
			curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDS, "");
			curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDSIZE, 0L);
		}
	} else {
		curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTPGET, 1L);
	}

	curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDS, req_buffer);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDSIZE, strlen(req_buffer));
	memory_struct chunk;
	curl_setup_request(ycmd_globals.curl, &chunk);

	header_data_struct header_data;
	wrap_secure_zero(&header_data, sizeof(header_data_struct));
	sprintf(header_data.name, "%s", HTTP_HEADER_YCM_HMAC);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERDATA, &header_data);

	CURLcode req_ret = curl_easy_perform(ycmd_globals.curl); /* Synchronous */
	if (req_ret != CURLE_OK) {
		debug_log("cURL error:  %s", curl_easy_strerror(req_ret));
		wrap_secure_zero(req_buffer, HALF_LINE_LENGTH);
		wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));

		curl_slist_free_all(headers);
		wrap_free((void **)&req_buffer);

		return -1;
	}
	char *response_body = _curl_read_response_body_full(ycmd_globals.curl, &chunk);
	if (response_body == NULL) {
		/* Sanitize sensitive data */
		wrap_secure_zero(req_buffer, req_buffer_size);
		wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));

		curl_slist_free_all(headers);
		wrap_free((void **)&req_buffer);

		return -1;
	}

	curl_easy_getinfo(ycmd_globals.curl, CURLINFO_RESPONSE_CODE, &response_code);

	if (wrap_strstr(eventname, "FileReadyToParse")) {
		delete_file_ready_to_parse_results(&ycmd_globals.file_ready_to_parse_results);
		file_ready_to_parse_results_constructor(&ycmd_globals.file_ready_to_parse_results);
		if (req_ret == CURLE_OK)
			ycmd_globals.file_ready_to_parse_results.response_code = response_code;
	}

	debug_log("response_code = %ld, req_ret = %d", response_code, req_ret);
	debug_log("response_body = %s", response_body);
	debug_log("response X-Ycm-Hmac = %s", header_data.value);
	if (response_code == HTTP_OK) {
		const char *hmac_rsp_header = header_data.value;
		ycmd_get_hmac_response(rsp_hmac_base64, response_body);
		if (!response_body) {
			; /* Invalid */
		} else if (!ycmd_is_hmac_valid(hmac_rsp_header, rsp_hmac_base64)) {
			debug_log("Response HMAC validation failed:  expected=%s, received=%s",	rsp_hmac_base64,
				header_data.value);
			compromised = 1;
		} else {
			ycmd_get_hmac_response(rsp_hmac_base64, response_body);
			if (wrap_strstr(eventname, "FileReadyToParse")) {
				ycmd_globals.file_ready_to_parse_results.usable = 1;
				ycmd_globals.file_ready_to_parse_results.json =
					strdup(response_body); /* Unfinished? */
			}
		}
	}

	/* Sanitize sensitive data */
	wrap_secure_zero(req_buffer, req_buffer_size);
	wrap_secure_zero(rsp_hmac_base64, sizeof(rsp_hmac_base64));
	wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));
	if (response_body) {
		/* wrap_secure_zero(response_body, strlen(response_body)); */ /* Segfaults */
		wrap_free((void **)&response_body);
	}

	curl_slist_free_all(headers);
	wrap_free((void **)&req_buffer);

	return response_code == HTTP_OK && !compromised;
}

/* realloc() may have sanitization issues as in deleting the buffer prematurely
   before sanitization, so we do an explicit rewrite to reassure buffers are
   cleared properly and mitigate against information disclosure. */
void *safe_resize_buffer(void *ptr, size_t old_size, size_t new_size) {
	void *new_ptr = wrap_malloc(new_size);
	if (new_ptr == NULL)
		return NULL;
	memcpy(new_ptr, ptr, old_size < new_size ? old_size : new_size);
	volatile char *volatile_ptr = (volatile char *)ptr;
	for (size_t i = 0; i < old_size; i++)
		volatile_ptr[i] = 0;
	free(ptr);
	return new_ptr;
}

void *safe_resize_bufferB(void *ptr, size_t old_size, size_t new_size) {
	void *new_ptr = wrap_malloc(new_size);
	if (new_ptr == NULL) {
		/* Handle out of memory error */
		return NULL;
	}

	/* Copy data from old buffer to new buffer */
	memcpy(new_ptr, ptr, old_size < new_size ? old_size : new_size);

	/* Securely erase the old buffer */
	volatile char *volatile_ptr = (volatile char *volatile)ptr;
	for (size_t i = 0; i < old_size; i++) {
		volatile_ptr[i] = 0;
	}

	/* Free the old buffer */
	free(ptr);

	return new_ptr;
}

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *data) {
	struct memory_struct *mem = (struct memory_struct *)data;
	size_t realsize = size * nmemb;
	size_t new_size = mem->size + realsize + 1;
	mem->memory = safe_resize_buffer(mem->memory, mem->size, new_size);
	if (mem->memory == NULL)
		return 0;
	memcpy(&(mem->memory[mem->size]), ptr, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}

static size_t write_callbackB(void *ptr, size_t size, size_t nmemb, void *data) {
	struct memory_struct *mem = (struct memory_struct *)data;
	size_t realsize = size * nmemb;

	size_t new_size = mem->size + realsize + 1;
	mem->memory = safe_resize_buffer(mem->memory, mem->size + 1, new_size);

	if (mem->memory == NULL) {
		/* Handle out of memory error */
		return 0;
	}

	/* Append new data to the buffer */
	memcpy(&(mem->memory[mem->size]), ptr, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	/* Sanitize the original buffer */

	volatile char *volatile_ptr = (volatile char *volatile)ptr;
	for (size_t i = 0; i < realsize; i++) {
		volatile_ptr[i] = 0;
	}

	return realsize;
}

void curl_setup_request(CURL *curl, struct memory_struct *chunk) {
	wrap_secure_zero(chunk, sizeof(struct memory_struct));

	chunk->memory = wrap_malloc(1); /* Initialize with a small block */
	chunk->size = 0;

	curl_easy_setopt(ycmd_globals.curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_WRITEDATA, (void *)chunk);
#if defined(DEBUG)
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_VERBOSE, 1L); /* Debug output */
#endif
}

char *_curl_read_response_body_full(CURL *curl, struct memory_struct *chunk) {
	char *body = wrap_malloc(chunk->size + 1);
	if (!body)
		return NULL;
	memcpy(body, chunk->memory, chunk->size);
	body[chunk->size] = '\0';
	return body;
}

char *_curl_read_response_body_fullB(CURL *curl, struct memory_struct *chunk) {
	long response_code = -1;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
	debug_log("chunk->memory = %s", chunk->memory);
	if (response_code != HTTP_OK) {
		debug_log("Error detected.  response_code = %ld", response_code);
		/* Handle invalid status code */
		wrap_free((void **)&chunk->memory);
		return NULL;
	}

	return chunk->memory;
}

/* Returns:
   1 is valid.
   0 is invalid. */
int ycmd_is_hmac_valid(const char *hmac_rsp_header, char *rsp_hmac_base64) {
	return strcmp(hmac_rsp_header, rsp_hmac_base64) == 0;
	/*
	 * if (wrap_strncmp((char *)hmac_rsp_header, (char *)rsp_hmac_base64, HMAC_SIZE * 2) == 0)
	 *	return 1;
	 * else
	 *	return 0;
	 */
}

/* Gets the list of possible completions. */
int ycmd_req_completions_suggestions(int linenum, int columnnum, char *filepath, linestruct *filetop,
	char *completertarget, int event, json_t **completions_out) {

	char *filetype = _ycmd_get_filetype(filepath);
	char *method = "POST";
	char *path = "/completions";
	char abspath[PATH_MAX];
	char req_hmac_base64[HMAC_SIZE * 2];
	char rsp_hmac_base64[HMAC_SIZE * 2];
	int compromised = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
	int ret = -1;
#pragma GCC diagnostic pop
	long response_code = -1;

	if (!ycmd_globals.curl) {
		ycmd_globals.curl = curl_easy_init();
		if (!ycmd_globals.curl) {
			debug_log("curl_easy_init failed");
			return -1;
		}
	}

	curl_easy_reset(ycmd_globals.curl);
	char url[LINE_LENGTH];
	snprintf(url, sizeof(url), "%s://%s:%d%s", ycmd_globals.scheme, ycmd_globals.hostname, ycmd_globals.port, path);
	debug_log("url = %s", url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_URL, url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_TIMEOUT_MS, 500L); /* Increased timeout */
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_NONE);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_CUSTOMREQUEST, method);

	get_abs_path(filepath, abspath);

	size_t req_buffer_size = MAX_FILESIZE_LIMIT;
	char *req_buffer = wrap_malloc(req_buffer_size);
	if (!req_buffer) {
		debug_log("Out of memory");
		statusline(ALERT, "Out of Memory");
		return -1;
	}
	wrap_secure_zero(req_buffer, req_buffer_size);
	_req_sprintf(req_buffer, req_buffer_size, "{\n");
	_req_sprintf(req_buffer, req_buffer_size, "  \"line_num\": %d,\n", linenum);
	_req_sprintf(req_buffer, req_buffer_size, "  \"column_num\": %d,\n", columnnum + (ycmd_globals.clang_completer ? 0 : 1));
	_req_sprintf(req_buffer, req_buffer_size, "  \"filepath\": \"%s\",\n", abspath);
	_req_sprintf(req_buffer, req_buffer_size, "  \"file_data\": {\n");
	_req_sprintf(req_buffer, req_buffer_size, "    \"%s\": {\n", abspath);
	_req_sprintf(req_buffer, req_buffer_size, "      \"contents\": \"");
	_req_file(req_buffer, req_buffer_size, filetop);
	_req_sprintf(req_buffer, req_buffer_size, "\",\n");
	_req_sprintf(req_buffer, req_buffer_size, "      \"filetypes\": [\"%s\"]\n", filetype);
	_req_sprintf(req_buffer, req_buffer_size, "    }\n");
	_req_sprintf(req_buffer, req_buffer_size, "  },\n");
	_req_sprintf(req_buffer, req_buffer_size, "  \"completer_target\": \"%s\"\n", completertarget);
	_req_sprintf(req_buffer, req_buffer_size, "}\n");

	struct curl_slist *headers = NULL;
	ycmd_get_hmac_request(req_hmac_base64, method, path, req_buffer, strlen(req_buffer));
	headers = curl_slist_append(headers, "Keep-Alive: ");
	headers = curl_slist_append(headers, "Connection: TE, Keep-Alive");
	headers = curl_slist_append(headers, "content-type: application/json");
	headers = curl_slist_append(headers, "Accept:");
	headers = _curl_sprintf_header(headers, "%s: %s", HTTP_HEADER_YCM_HMAC, req_hmac_base64);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDS, req_buffer);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDSIZE, strlen(req_buffer));
	memory_struct chunk = {0};
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_WRITEDATA, &chunk);

	struct header_data_struct header_data;
	wrap_secure_zero(&header_data, sizeof(struct header_data_struct));
	snprintf(header_data.name, sizeof(header_data.name), "%s",
			 HTTP_HEADER_YCM_HMAC);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERDATA, &header_data);

	debug_log("Before curl_easy_perform");
	struct timespec start, now;
	clock_gettime(CLOCK_MONOTONIC, &start);
	CURLcode req_ret = curl_easy_perform(ycmd_globals.curl);
	clock_gettime(CLOCK_MONOTONIC, &now);
	double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;
	debug_log("After curl_easy_perform, ret=%d, elapsed=%.2fs", req_ret, elapsed);

	if (req_ret != CURLE_OK) {
		debug_log("cURL error:  %s (%.2fs)", curl_easy_strerror(req_ret), elapsed);
		wrap_secure_zero(req_buffer, req_buffer_size);
		curl_slist_free_all(headers);
		wrap_free((void **)&req_buffer);
		free(chunk.memory);
		return -1;
	}

	curl_easy_getinfo(ycmd_globals.curl, CURLINFO_RESPONSE_CODE, &response_code);
	debug_log("response_code=%ld, req_ret=%d", response_code, req_ret);

	if (response_code == HTTP_OK) {
		const char *hmac_rsp_header = header_data.value;
		ycmd_get_hmac_response(rsp_hmac_base64, chunk.memory);
		if (!chunk.memory) {
			debug_log("Empty response body");
		} else if (!ycmd_is_hmac_valid(hmac_rsp_header, rsp_hmac_base64)) {
			debug_log("Response HMAC validation failed:  expected=%s, received=%s", rsp_hmac_base64, header_data.value);
			compromised = 1;
		} else {
			if (event == YCMD_REQ_COMPLETIONS_SUGGESTIONS_EVENT_FILE_READY_TO_PARSE) {
				debug_log("EVENT YCMD_REQ_COMPLETIONS_SUGGESTIONS_EVENT_FILE_READY_TO_PARSE");
				if (chunk.memory && strstr(chunk.memory, "completion_start_column")) {
					json_error_t error;
					json_t *root = json_loads(chunk.memory, 0, &error);
					if (root && json_is_object(root)) {
						json_t *completions = json_object_get(root, "completions");
						if (completions && json_is_array(completions)) {
							struct funcstruct *func = allfuncs;
							while (func && func->menus != MCODECOMPLETION)
								func = func->next;
							int i = 0, j = 0;
							size_t maximum = (((COLS + HALF_LINE_LENGTH) / QUARTER_LINE_LENGTH) * 2);
							size_t completions_size =
								json_array_size(completions);
							for (i = 0; i < completions_size && j < maximum && j < 6 && func; i++, j++) {
								json_t *candidate = json_array_get(completions, i);
								json_t *insertion_text_value = json_object_get(candidate, "insertion_text");
								if (insertion_text_value &&
									json_is_string(insertion_text_value)) {
									if (func->tag) {
										wrap_secure_zero(func->tag,
														 strlen(func->tag));
										wrap_free((void **)&func->tag);
									}
									func->tag = strdup(json_string_value(
										insertion_text_value));
									func = func->next;
								}
							}
							for (; i < completions_size && i < maximum && i < 6 && func; i++, func = func->next) {
								if (func->tag) {
									wrap_secure_zero(func->tag, strlen(func->tag));
									wrap_free((void **)&func->tag);
								}
								func->tag = strdup("");
							}
							json_t *completion_start_column_value =	json_object_get(root, "completion_start_column");
							if (completion_start_column_value && json_is_integer(completion_start_column_value)) {
								ycmd_globals.apply_column = json_integer_value(completion_start_column_value);
							}
							json_decref(root);
							if (j > 0 && !is_popup_mode) {
								bottombars(MCODECOMPLETION);
								statusline(HUSH, "Code completion triggered, ^X to cancel");
							}
						} else {
							debug_log("No valid completions array");
						}
					} else {
						debug_log("json_loads failed: %s", error.text);
					}
				}
			} else if (event == YCMD_REQ_COMPLETIONS_SUGGESTIONS_EVENT_REQUEST_COMPLETIONS) {
				json_error_t error;
				json_t *root = json_loads(chunk.memory, 0, &error);
				if (root && json_is_object(root)) {
					json_t *completions = json_object_get(root, "completions");
					if (completions && json_is_array(completions)) {
						*completions_out = json_incref(completions);
						ret = 0;
						json_t *completion_start_column = json_object_get(root, "completion_start_column");
						if (completion_start_column && json_is_integer(completion_start_column)) {
							ycmd_globals.apply_column = json_integer_value(completion_start_column);
							debug_log("Set apply_column=%zu", ycmd_globals.apply_column);
						}
					} else {
						debug_log("No valid completions array");
					}
					json_decref(root);
				} else {
					debug_log("json_loads() failed:  %s", error.text);
				}
			}
		}
	} else {
		debug_log("Invalid response code: %ld", response_code);
	}

	wrap_secure_zero(req_buffer, req_buffer_size);
	wrap_secure_zero(rsp_hmac_base64, sizeof(rsp_hmac_base64));
	wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));
	if (chunk.memory)
		free(chunk.memory);
	curl_slist_free_all(headers);
	wrap_free((void **)&req_buffer);

	return response_code == HTTP_OK && !compromised ? 0 : -1;
}

void _run_completer_command_execute_command(
	char *completercommand, run_completer_command_result_struct *rccr) {
	/* It doesn't work for some reason if used with
	 * ycmd_req_run_completer_command. */
	/* char *completertarget2 = _ycmd_get_filetype(openfile->filename); */

	/* It works when passed to ycmd_req_run_completer_command. */
	char *completertarget = "filetype_default";

	/* Check the server if it is compromised before sending sensitive source
	 * code (e.g. CMS passwords). */
	int ready = ycmd_rsp_is_server_ready(completertarget);

	if (ycmd_globals.running && ready) {
		/* Loading is required by the C family languages. */
		ycmd_req_run_completer_command((long)openfile->current->lineno,
					   openfile->current_x, openfile->filename,
					   openfile->filetop, completertarget,
					   completercommand, rccr);
	}
}

void constructor_run_completer_command_result(
	run_completer_command_result_struct *rccr) {
	wrap_secure_zero(rccr, sizeof(run_completer_command_result_struct));
}

void delete_run_completer_command_result(
	run_completer_command_result_struct *rccr) {
	if (rccr->message)
		wrap_free((void **)&rccr->message);
	if (rccr->filepath)
		wrap_free((void **)&rccr->filepath);
	if (rccr->detailed_info)
		wrap_free((void **)&rccr->detailed_info);
	if (rccr->json)
		wrap_free((void **)&rccr->json);
}

/* It must call delete_run_completer_command_result() aftr using it. */
void parse_run_completer_command_result(
	run_completer_command_result_struct *rccr) {
	if (!rccr->usable || rccr->response_code != HTTP_OK) {
		return;
	}

	char *json; /* nxjson does inplace edits so back it up. */
	json = strdup(rccr->json);

	json_error_t error;
	json_t *root = json_loads(rccr->json, 0, &error);

	if (root && json_is_object(root) && rccr->usable) {
		json_t *value;
		value = json_object_get(root, "message");
		if (value && json_is_string(value))
			rccr->message = strdup(json_string_value(value));

		value = json_object_get(root, "filepath");
		if (value && json_is_string(value))
			rccr->filepath = strdup(json_string_value(value));

		value = json_object_get(root, "line_num");
		if (value && json_is_integer(value))
			rccr->line_num = json_integer_value(value);

		value = json_object_get(root, "column_num");
		if (value && json_is_integer(value))
			rccr->column_num = json_integer_value(value);

		value = json_object_get(root, "detailed_info");
		if (value && json_is_string(value))
			rccr->detailed_info = strdup(json_string_value(value));

		/* Sanitize root? */
		json_decref(root);
	}

	rccr->json = json;
}

/* Returns:
 * 1 on success.
 * 0 on failure. */
void _do_goto(run_completer_command_result_struct *rccr) {
	if (wrap_strstr(rccr->filepath, openfile->filename)) {
		/* ycm treats tabs as one column.
		 * nano treats a tab as many columns. */
		goto_line_and_column(rccr->line_num, 1, FALSE, FALSE);
		openfile->current_x = rccr->column_num - 1;
	} else {
#ifndef DISABLE_MULTIBUFFER
		SET(MULTIBUFFER);
#endif
		open_buffer(rccr->filepath, FALSE);
		prepare_for_display();
		goto_line_and_column(rccr->line_num, 1, FALSE, FALSE);
		openfile->current_x = rccr->column_num - 1;
	}
	refresh_needed = TRUE;
}

void do_completer_command_gotoinclude(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"GoToInclude\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK)
		statusline(HUSH, "Completer command failed.");
	else
		_do_goto(&rccr);

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void do_completer_command_gotodeclaration(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"GoToDeclaration\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK)
		statusline(HUSH, "Completer command failed.");
	else
		_do_goto(&rccr);

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void do_completer_command_gotodefinition(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"GoToDefinition\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK)
		statusline(HUSH, "Completer command failed.");
	else
		_do_goto(&rccr);

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void do_completer_command_gotodefinitionelsedeclaration(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"GoToDefinitionElseDeclaration\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK)
		statusline(HUSH, "Completer command failed.");

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void do_completer_command_goto(void) {
	/* It should be number of columns. */
	char display_text[DOUBLE_LINE_LENGTH];

	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"GoTo\"", &rccr);
	parse_run_completer_command_result(&rccr);

	display_text[0] = 0;

	if (!rccr.usable || rccr.response_code != HTTP_OK) {
		statusline(HUSH, "Completer command failed.");
	} else {
		json_error_t error;
		json_t *root = json_loads(rccr.json, 0, &error);

		if (root && json_is_array(root)) {
			json_t *a = root;
			int i;

			size_t size = json_array_size(a);
			for (i = 0; i < size; i++) {
				json_t *item = json_array_get(a, i);
				json_t *description_value =
					json_object_get(item, "description");
				const char *description_str = NULL;
				if (description_value && json_is_string(description_value)) {
					description_str = json_string_value(description_value);
					if (i == 0) {
						wrap_strncat(display_text, description_str, DOUBLE_LINE_LENGTH);
					} else {
						wrap_strncat(display_text, ", ", DOUBLE_LINE_LENGTH);
						wrap_strncat(display_text, description_str, DOUBLE_LINE_LENGTH);
					}
				}
			}

			/* Sanitize root? */
			json_decref(root);
		}
		statusline(HUSH, display_text);
	}

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void do_completer_command_gotoimprecise(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"GoToImprecise\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK)
		statusline(HUSH, "Completer command failed.");
	else
		_do_goto(&rccr);

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void do_completer_command_gotoreferences(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"GoToReferences\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK) {
		statusline(HUSH, "Completer command failed.");
	} else {
		/* TODO: Finish implementation
		json_error_t error;
		json_t *root = json_loads(rccr.json, 0, &error);

		if (root && json_is_array(root)) {
			json_t *a = json;
			int i;

			size_t size = json_array_size(a);
			for (i = 0; i < size; i++) {
				json_t *item = json_array_get(a, i);
				json_t *value;
				const char *description;
				const char *filepath;
				int column_num;
				int line_num

				value = json_object_get(item, "description");
				if (value && json_is_string(value))
					description = json_string_value(value);

				value = json_object_get(item, "filepath");
				if (value && json_is_string(value))
					filepath = json_string_value(value);

				value = json_object_get(item, "column_num");
				if (value && json_is_integer(value))
					column_num = json_integer_value(value);

				value = json_object_get(item, "line_num");
				if (value && json_is_integer(value))
					line_num = json_integer_value(value);
			}

			// Sanitize root?
			json_decref(root);
		}
		*/
	}

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void do_completer_command_gotoimplementation(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"GoToImplementation\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK)
		statusline(HUSH, "Completer command failed.");
	else
		_do_goto(&rccr);

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void do_completer_command_gotoimplementationelsedeclaration(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"GoToImplementationElseDeclaration\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK)
		statusline(HUSH, "Completer command failed.");

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void fixit_refresh(void) {
	refresh_needed = FALSE;
}

void do_completer_command_fixit(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"FixIt\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK) {
		statusline(HUSH, "Completer command failed.");
	} else {
		json_error_t error;
		json_t *root = json_loads(rccr.json, 0, &error);

		/* The server can only handle one at a time.  After that, it bombs out.
		 */
		if (root && json_is_object(root)) {
			json_t *a_fixits = json_object_get(root, "fixits");
			int i = 0, j = 0;

			if (a_fixits && json_is_array(a_fixits)) {
				size_t a_fixits_size = json_array_size(a_fixits);
				/* Only 1 array element supported. */
				if (a_fixits_size) {
					json_t *item_fixit = json_array_get(a_fixits, i);
					json_t *a_chunks = json_object_get(item_fixit, "chunks");
					size_t a_chunks_size = json_array_size(a_chunks);

					json_t *item_chunk_value, *range_value, *range_start_value, *range_end_value;
					const char *replacement_text = NULL;
					/* const char *fcrs_filepath; */
					int fcrs_column_num = -1, fcrs_line_num = -1; /* Start point */

					/* const char *fcre_filepath; */
					int fcre_column_num = -1, fcre_line_num = -1; /* End point */
					json_t *value;

					if (a_chunks && a_chunks_size >= 1) {
						/* Only 1 array element supported. */
						if (a_chunks_size == 1) {
							item_chunk_value = json_array_get(a_chunks, j);
							if (item_chunk_value &&
								json_is_object(item_chunk_value)) {
								value = json_object_get(item_chunk_value, "replacement_text");
								if (value && json_is_string(value))
									replacement_text = json_string_value(value);

								range_value =
									json_object_get(item_chunk_value, "range");
								if (range_value &&
									json_is_object(range_value)) {
									range_start_value =
										json_object_get(range_value, "start");
									if (range_start_value &&
										json_is_object(range_start_value)) {
										/*
										value =	json_object_get(range_start_value, "filepath");
										if (value && json_is_string(value))
											fcrs_filepath =	json_string_value(value);
										*/

										value = json_object_get(
											range_start_value, "column_num");
										if (value && json_is_integer(value))
											fcrs_column_num =
												json_integer_value(value);

										value = json_object_get(
											range_start_value, "line_num");
										if (value && json_is_integer(value))
											fcrs_line_num =
												json_integer_value(value);
									}

									range_end_value = json_object_get(range_value, "end");
									if (range_end_value &&
										json_is_object(range_end_value)) {
										/*
										value = json_object_get(range_end_value, "filepath");
										if (value && json_is_string(value))
											fcre_filepath = json_string_value(value);
										*/

										value = json_object_get(range_end_value, "column_num");
										if (value && json_is_integer(value))
											fcre_column_num =
												json_integer_value(value);

										value = json_object_get(range_end_value, "line_num");
										if (value && json_is_integer(value))
											fcre_line_num =
												json_integer_value(value);
									}
								}
							}
						}
					}

					const char *text = json_string_value(json_object_get(item_fixit, "text"));
					char prompt_msg[QUARTER_LINE_LENGTH];
					snprintf(prompt_msg, QUARTER_LINE_LENGTH, "Apply fix It? %s", text);

					/* TODO:  Finish implementation or remove deadcode
					const char *fl_filepath;
					int fl_column_num;
					int fl_line_num;
					json_t *location_value = json_object_get(item_fixit,
					"location"); if (location_value &&
					json_is_object(location_value)) { value =
					json_object_get(location, "filepath"); if (value &&
					json_is_string(value)) fl_filepath =
					json_string_value(value);

						value = json_object_get(location, "column_num");
						if (value && json_is_integer(value))
							fl_column_num = json_integer_value(value);

						value = json_object_get(location, "line_num");
						if (value && json_is_integer(value))
							fl_line_num = json_integer_value(value);
					}
					*/

					/* Present the user dialog prompt for the FixIt. */
					int ret = ask_user(YESORNO, prompt_msg);
					if (ret == YES && fcrs_column_num >= 0 &&
						fcre_column_num >= 0 && fcrs_column_num >= 0 &&
						fcre_line_num >= 0) {
						if (replacement_text && strlen(replacement_text)) {
							/* Assumes that the flag was previously set. */
							/* openfile->mark_set = 1; */

							/* nano column num means distance within a tab character. */
							/* ycmd column num means treat tabs as indivisible. */
							/* Move cursor to start */
							goto_line_and_column(fcrs_line_num, 1, FALSE, FALSE);
							/* nano treats current_x as 0 based and linenum as 1 based. */
							openfile->current_x = fcrs_column_num -	1;
							do_mark(); /* Flip flag and unset marker. */
							do_mark(); /* Flip flag and sets marker. */

							/* Move cursor to end */
							goto_line_and_column(fcre_line_num, 1, FALSE, FALSE);
							openfile->current_x = fcre_column_num - 1;

							/* Delete selection */
							cut_text(); /* It serves the same function as (cut
										   character) ^K in global.c. */

							/* Sanitize replacement_text? */

							/* Insert the fix */
							inject((char *)replacement_text,
								   strlen(replacement_text));
							statusline(HUSH, "Applied FixIt.");
						}
					} else {
						statusline(HUSH, "Canceled FixIt.");
					}
				}

				/* Sanitize root? */
				json_decref(root);
			}
		}
	}

	bottombars(MMAIN);

	delete_run_completer_command_result(&rccr);
}

void _run_completer_command_execute_command_getdoc(char *command) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command(command, &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK) {
		statusline(HUSH, "Completer command failed.");
	} else {
		struct passwd *pw = getpwuid(getuid());
		char cache_dir[PATH_MAX];
		sprintf(cache_dir, "%s/.cache/nano-ycmd", pw->pw_dir);
		debug_log("cache_dir = %s", cache_dir);
		mkdir(cache_dir, 0700); /* Create the cache directory if it doesn't exist */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-overflow"
		char doc_filename[PATH_MAX];
		sprintf(doc_filename, "%s/tmpXXXXXX", cache_dir);
#pragma GCC diagnostic pop
		int fdtemp = mkstemp(doc_filename);
		FILE *f = fdopen(fdtemp, "w+");
		fprintf(f, "%s", rccr.detailed_info);
		fclose(f);

#ifndef DISABLE_MULTIBUFFER
		SET(MULTIBUFFER);
#endif

		/* do_output doesn't handle \n properly and displays it as ^@ so we do it this way. */
		open_buffer(doc_filename, TRUE);
		prepare_for_display();

		/* Delete file */
		unlink(doc_filename);
	}

	bottombars(MMAIN);

	delete_run_completer_command_result(&rccr);

	refresh_needed = TRUE;
}

void do_completer_command_getdoc(void) {
	_run_completer_command_execute_command_getdoc("\"GetDoc\"");
}

void do_completer_command_getdocimprecise(void) {
	_run_completer_command_execute_command_getdoc("\"GetDocImprecise\"");
}

void refactorrename_refresh(void) { refresh_needed = TRUE; }

void do_completer_command_refactorrename(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);

	char cc_command[LINE_LENGTH];
	wrap_secure_zero(cc_command, sizeof(cc_command));

	int ret = do_prompt(MREFACTORRENAME, NULL,
#ifndef DISABLE_HISTORIES
			NULL,
#endif
			refactorrename_refresh, _("Rename identifier as"));

	/*  0 means to enter.
	 * -1 means to cancel. */
	if (ret == 0) {
		sprintf(cc_command, "\"RefactorRename\",\"%s\"", answer);

		statusline(HUSH, "Applying refactor rename...");

		_run_completer_command_execute_command(cc_command, &rccr);

		parse_run_completer_command_result(&rccr);

		if (!rccr.usable || rccr.response_code != HTTP_OK)
			statusline(HUSH, "Refactor rename failed.");
		else
			statusline(HUSH, "Refactor rename thoughrout project success.");

		delete_run_completer_command_result(&rccr);
	} else {
		statusline(HUSH, "Canceled refactor rename.");
	}

	bottombars(MMAIN);
}

void do_completer_command_gettype(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"GetType\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK)
		statusline(HUSH, "Completer command failed.");
	else
		statusline(HUSH, rccr.message);

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void do_completer_command_gettypeimprecise(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"GetTypeImprecise\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK)
		statusline(HUSH, "Completer command failed.");
	else
		statusline(HUSH, rccr.message);

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void do_completer_command_reloadsolution(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"ReloadSolution\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK)
		statusline(HUSH, "Completer command failed.");
	else
		statusline(HUSH, "Reloaded solution.");

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void do_completer_command_restartserver(void) {
	char completercommand[LINE_LENGTH];
	wrap_secure_zero(completercommand, LINE_LENGTH);

	char *completertarget = "filetype_default";
	sprintf(completercommand, "[\"RestartServer\"]");

	/* Check the server if it is compromised before sending sensitive source
	 * code (e.g. CMS passwords). */
	int ready = ycmd_rsp_is_server_ready(completertarget);

	if (ycmd_globals.running && ready) {
		/* Loading is required by the C family languages. */

		run_completer_command_result_struct rccr;
		constructor_run_completer_command_result(&rccr);
		ycmd_req_run_completer_command((long)openfile->current->lineno,
					   openfile->current_x, openfile->filename,
					   openfile->filetop, completertarget,
					   completercommand, &rccr);

		parse_run_completer_command_result(&rccr);

		if (!rccr.usable || rccr.response_code != HTTP_OK)
			statusline(HUSH, "Restart server fail.");
		else
			statusline(HUSH, "Restarted server.");

		delete_run_completer_command_result(&rccr);
	}

	bottombars(MMAIN);
}

void do_completer_command_stopserver(void) {
	char completercommand[LINE_LENGTH];
	wrap_secure_zero(completercommand, LINE_LENGTH);

	char *completertarget = "filetype_default";
	sprintf(completercommand, "[\"StopServer\"]");

	/* Check the server if it is compromised before sending sensitive source
	 * code (e.g. CMS passwords). */
	int ready = ycmd_rsp_is_server_ready(completertarget);

	if (ycmd_globals.running && ready) {
		/* Loading is required by the C family languages. */

		run_completer_command_result_struct rccr;
		constructor_run_completer_command_result(&rccr);
		ycmd_req_run_completer_command((long)openfile->current->lineno,
					   openfile->current_x, openfile->filename,
					   openfile->filetop, completertarget,
					   completercommand, &rccr);

		parse_run_completer_command_result(&rccr);

		if (!rccr.usable || rccr.response_code != HTTP_OK)
			statusline(HUSH, "Stop server fail.");
		else
			statusline(HUSH, "Stopped server.");

		delete_run_completer_command_result(&rccr);
	}

	bottombars(MMAIN);
}

void do_completer_command_gototype(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"GoToType\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK)
		statusline(HUSH, "Completer command failed.");
	else
		_do_goto(&rccr);

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void do_completer_command_clearcompliationflagcache(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"ClearCompilationFlagCache\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK) {
		statusline(HUSH, "Completer command failed.");
		bottombars(MMAIN);
	} else {
		statusline(HUSH, "Clear compliation flag cached performed.");
	}

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

void do_completer_command_getparent(void) {
	run_completer_command_result_struct rccr;
	constructor_run_completer_command_result(&rccr);
	_run_completer_command_execute_command("\"GetParent\"", &rccr);
	parse_run_completer_command_result(&rccr);

	if (!rccr.usable || rccr.response_code != HTTP_OK)
		statusline(HUSH, "Completer command failed.");
	else
		statusline(HUSH, rccr.message);

	delete_run_completer_command_result(&rccr);

	bottombars(MMAIN);
}

int ycmd_req_run_completer_command(int linenum, int columnnum, char *filepath, linestruct *filetop,
	char *completertarget, char *completercommand, run_completer_command_result_struct *rccr) {

	debug_log("Called function");
	char *filetype = _ycmd_get_filetype(filepath);
	char *method = "POST";
	char *path = "/run_completer_command";
	char *insertspaces = "true";
	char abspath[PATH_MAX];
	char req_hmac_base64[HMAC_SIZE * 2];
	char rsp_hmac_base64[HMAC_SIZE * 2];
	int compromised = 0;
	long response_code = -1;
	int tabsize = 4;

	if (!ycmd_globals.curl) {
		ycmd_globals.curl = curl_easy_init();
		if (!ycmd_globals.curl) {
			return -1;
		}
	}

	curl_easy_reset(ycmd_globals.curl);
	char url[LINE_LENGTH];
	sprintf(url, "%s://%s:%d%s", ycmd_globals.scheme, ycmd_globals.hostname, ycmd_globals.port, path);
	debug_log("url = %s", url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_URL, url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_TIMEOUT_MS, 500L);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_NONE);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_CUSTOMREQUEST, method);

	get_abs_path(filepath, abspath);

	/* We send the data directly skipping the json and string lib because we
	 * need to stream the file it. */
	size_t req_buffer_size = MAX_FILESIZE_LIMIT;
	char *req_buffer = wrap_malloc(req_buffer_size);
	if (!req_buffer) {
		statusline(HUSH, "Out of Memory");
		return -1;
	}
	wrap_secure_zero(req_buffer, req_buffer_size);
	_req_sprintf(req_buffer, req_buffer_size, "{\n");
	_req_sprintf(req_buffer, req_buffer_size, "  \"column_num\": %d,\n", columnnum + (ycmd_globals.clang_completer ? 0 : 1));
	_req_sprintf(req_buffer, req_buffer_size, "  \"command_arguments\": [%s],\n", completercommand);
	_req_sprintf(req_buffer, req_buffer_size, "  \"completer_target\": \"%s\",\n", completertarget);
	_req_sprintf(req_buffer, req_buffer_size, "  \"file_data\": {\n");
	_req_sprintf(req_buffer, req_buffer_size, "    \"%s\": {\n", abspath);
	_req_sprintf(req_buffer, req_buffer_size, "      \"filetypes\": [\"%s\"],\n", filetype);
	_req_sprintf(req_buffer, req_buffer_size, "      \"contents\": \"");
	_req_file(req_buffer, req_buffer_size, filetop);
	_req_sprintf(req_buffer, req_buffer_size, "\"\n");
	_req_sprintf(req_buffer, req_buffer_size, "    }");
	_req_sprintf(req_buffer, req_buffer_size, "  },");
	_req_sprintf(req_buffer, req_buffer_size, "  \"filepath\": \"%s\",\n", abspath);
	_req_sprintf(req_buffer, req_buffer_size, "  \"line_num\": %d,\n", linenum);
	_req_sprintf(req_buffer, req_buffer_size, "  \"options\": {\n");
	_req_sprintf(req_buffer, req_buffer_size, "    \"insert_spaces\": %s,\n", insertspaces);
	_req_sprintf(req_buffer, req_buffer_size, "    \"tab_size\": %d,\n", tabsize);
	_req_sprintf(req_buffer, req_buffer_size, "  }\n");
	_req_sprintf(req_buffer, req_buffer_size, "}\n");

	/* Set headers to match HTTP Neon */
	struct curl_slist *headers = NULL;
	ycmd_get_hmac_request(req_hmac_base64, method, path, req_buffer,
						  strlen(req_buffer));
	debug_log("HMAC inputs:  method=%s, path=%s, body='%s', body_size=%zu",
		method, path,
		req_buffer && strlen(req_buffer) ? req_buffer : "NULL",
		req_buffer && strlen(req_buffer) ? strlen(req_buffer) : 0);
	debug_log("X-Ycm-Hmac = %s", req_hmac_base64);
	headers = curl_slist_append(headers, "Keep-Alive: ");
	headers = curl_slist_append(headers, "Connection: TE, Keep-Alive");
	headers = curl_slist_append(headers, "content-type: application/json");
	headers = curl_slist_append(headers, "Accept:");
	headers = _curl_sprintf_header(headers, "%s: %s", HTTP_HEADER_YCM_HMAC, req_hmac_base64);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDS, req_buffer);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDSIZE, strlen(req_buffer));
	memory_struct chunk;
	curl_setup_request(ycmd_globals.curl, &chunk);

	header_data_struct header_data;
	wrap_secure_zero(&header_data, sizeof(header_data_struct));
	sprintf(header_data.name, "%s", HTTP_HEADER_YCM_HMAC);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERDATA, &header_data);

	CURLcode req_ret = curl_easy_perform(ycmd_globals.curl); /* Synchronous */
	if (req_ret != CURLE_OK) {
		debug_log("cURL error:  %s", curl_easy_strerror(req_ret));
		wrap_secure_zero(req_buffer, HALF_LINE_LENGTH);
		wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));

		curl_slist_free_all(headers);
		wrap_free((void **)&req_buffer);

		return -1;
	}
	/* Sometimes the subservers will throw exceptions so capture it. */
	rccr->response_code = response_code;
	char *response_body = _curl_read_response_body_full(ycmd_globals.curl, &chunk);
	if (response_body == NULL) {
		/* Sanitize sensitive data */
		wrap_secure_zero(req_buffer, req_buffer_size);
		wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));

		curl_slist_free_all(headers);
		wrap_free((void **)&req_buffer);

		return -1;
	}

	curl_easy_getinfo(ycmd_globals.curl, CURLINFO_RESPONSE_CODE, &response_code);
	debug_log("response_code = %ld, req_ret = %d", response_code, req_ret);
	debug_log("response_body = %s", response_body);
	debug_log("response X-Ycm-Hmac = %s", header_data.value);
	if (response_code == HTTP_OK) {
		const char *hmac_rsp_header = header_data.value;
		ycmd_get_hmac_response(rsp_hmac_base64, response_body);
		if (!response_body) {
			; /* Invalid */
		} else if (!ycmd_is_hmac_valid(hmac_rsp_header, rsp_hmac_base64)) {
			debug_log("Response HMAC validation failed:  expected=%s, received=%s",	rsp_hmac_base64,
				header_data.value);
			compromised = 1;
		} else {
			ycmd_get_hmac_response(rsp_hmac_base64, response_body);
			rccr->json = strdup(response_body);
			rccr->usable = 1;
		}
	}

	/* Sanitize sensitive data */
	wrap_secure_zero(req_buffer, req_buffer_size);
	wrap_secure_zero(rsp_hmac_base64, sizeof(rsp_hmac_base64));
	wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));
	if (response_body) {
		/* wrap_secure_zero(response_body, strlen(response_body)); */ /* Segfaults */
		wrap_free((void **)&response_body);
	}

	curl_slist_free_all(headers);
	wrap_free((void **)&req_buffer);

	return response_code == HTTP_OK && !compromised;
}

int ycmd_rsp_is_healthy(int include_subservers) {
	debug_log("Function called");
	char *method = "GET";
	char *path = "/healthy";
	char req_buffer[LINE_LENGTH];
	char req_hmac_base64[HMAC_SIZE * 2];
	char rsp_hmac_base64[HMAC_SIZE * 2];
	int compromised = 0;
	long response_code = -1;

	if (!ycmd_globals.curl) {
		ycmd_globals.curl = curl_easy_init();
		if (!ycmd_globals.curl) {
			return -1;
		}
	}

	curl_easy_reset(ycmd_globals.curl);
	char url[LINE_LENGTH];
	if (include_subservers == 2) {
		req_buffer[0] = '\0';
	} else if (include_subservers) {
		sprintf(req_buffer, "include_subservers=1");
	} else {
		sprintf(req_buffer, "include_subservers=0");
	}
	sprintf(url, "%s://%s:%d%s", ycmd_globals.scheme, ycmd_globals.hostname, ycmd_globals.port, path);
	debug_log("url = %s", url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_URL, url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_TIMEOUT_MS, 500L);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_CUSTOMREQUEST, "GET");
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_NONE);

	/* Set headers to match HTTP Neon */
	struct curl_slist *headers = NULL;
	ycmd_get_hmac_request(req_hmac_base64, method, path, req_buffer,
						  strlen(req_buffer));
	debug_log("HMAC inputs:  method=%s, path=%s, body='%s', body_size=%zu",
		method, path, strlen(req_buffer) ? req_buffer : "NULL",
		strlen(req_buffer) ? strlen(req_buffer) : 0);
	debug_log("X-Ycm-Hmac: %s", req_hmac_base64);
	headers = curl_slist_append(headers, "Keep-Alive: ");
	headers = curl_slist_append(headers, "Connection: TE, Keep-Alive");
	headers = curl_slist_append(headers, "Accept:");
	headers = _curl_sprintf_header(headers, "%s: %s", HTTP_HEADER_YCM_HMAC, req_hmac_base64);
	headers = curl_slist_append(headers, "Content-Type:");
	if (strlen(req_buffer)) {
		headers = _curl_sprintf_header(headers, "Content-Length: %d", strlen(req_buffer));
	}
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTPHEADER, headers);

	if (strlen(req_buffer)) {
		curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDS, req_buffer);
		curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDSIZE, strlen(req_buffer));
	}

	memory_struct chunk;
	curl_setup_request(ycmd_globals.curl, &chunk);

	header_data_struct header_data;
	wrap_secure_zero(&header_data, sizeof(header_data_struct));
	sprintf(header_data.name, "%s", HTTP_HEADER_YCM_HMAC);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERDATA, &header_data);

	CURLcode req_ret = curl_easy_perform(ycmd_globals.curl); /* Synchronous */
	if (req_ret != CURLE_OK) {
		debug_log("cURL error:  %s", curl_easy_strerror(req_ret));
		wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));
		curl_slist_free_all(headers);
		return -1;
	}
	char *response_body = _curl_read_response_body_full(ycmd_globals.curl, &chunk);
	if (response_body == NULL) {
		/* Sanitize sensitive data */
		wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));
		curl_slist_free_all(headers);
		return -1;
	}

	curl_easy_getinfo(ycmd_globals.curl, CURLINFO_RESPONSE_CODE, &response_code);
	debug_log("response_code = %ld, req_ret = %d", response_code, req_ret);
	debug_log("response_body = %s", response_body);
	debug_log("response X-Ycm-Hmac = %s", header_data.value);
	if (response_code == HTTP_OK) {
		const char *hmac_rsp_header = header_data.value;
		ycmd_get_hmac_response(rsp_hmac_base64, response_body);
		if (!response_body) {
			; /* Invalid */
		} else if (!ycmd_is_hmac_valid(hmac_rsp_header, rsp_hmac_base64)) {
			debug_log("Response HMAC validation failed:  expected=%s, received=%s",	rsp_hmac_base64,
				header_data.value);
			compromised = 1;
		}
	}

	/* Sanitize sensitive data */
	wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));
	curl_slist_free_all(headers);
	if (response_body) {
		/* wrap_secure_zero(response_body, strlen(response_body)); */ /* Segfaults */
		wrap_free((void **)&response_body);
	}

	return response_code == HTTP_OK && !compromised;
}

/* Preconditon:  The server must be up and initalized. */
int ycmd_rsp_is_healthy_simple() { return ycmd_rsp_is_healthy(2); }

/* include_subservers refers to checking the OmniSharp server or other completer servers. */
int ycmd_rsp_is_server_ready(char *filetype) {
	debug_log("Called function");

	char *method = "GET";
	char *path = "/ready";
	char req_buffer[LINE_LENGTH];
	char req_hmac_base64[HMAC_SIZE * 2];
	char rsp_hmac_base64[HMAC_SIZE * 2];
	int compromised = 0;
	long response_code = -1;

	if (!ycmd_globals.curl) {
		ycmd_globals.curl = curl_easy_init();
		if (!ycmd_globals.curl) {
			return -1;
		}
	}

	curl_easy_reset(ycmd_globals.curl);
	char url[LINE_LENGTH];
	sprintf(req_buffer, "subserver=%s", filetype);
	sprintf(url, "%s://%s:%d%s", ycmd_globals.scheme, ycmd_globals.hostname, ycmd_globals.port, path);
	debug_log("url = %s", url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_URL, url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_TIMEOUT_MS, 500L);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_CUSTOMREQUEST, "GET");
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_NONE);

	/* Set headers to match HTTP Neon */
	struct curl_slist *headers = NULL;
	ycmd_get_hmac_request(req_hmac_base64, method, path, req_buffer, strlen(req_buffer));
	debug_log("HMAC inputs:  method=%s, path=%s, body='%s', body_size=%zu",
		method, path, strlen(req_buffer) ? req_buffer : "NULL",
		strlen(req_buffer) ? strlen(req_buffer) : 0);
	debug_log("X-Ycm-Hmac = %s", req_hmac_base64);
	headers = curl_slist_append(headers, "Keep-Alive: ");
	headers = curl_slist_append(headers, "Connection: TE, Keep-Alive");
	headers = curl_slist_append(headers, "Accept:");
	headers = curl_slist_append(headers, "Content-Type:");
	headers = _curl_sprintf_header(headers, "%s: %s", HTTP_HEADER_YCM_HMAC, req_hmac_base64);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDS, req_buffer);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDSIZE, strlen(req_buffer));

	memory_struct chunk;
	curl_setup_request(ycmd_globals.curl, &chunk);

	header_data_struct header_data;
	wrap_secure_zero(&header_data, sizeof(header_data_struct));
	sprintf(header_data.name, "%s", HTTP_HEADER_YCM_HMAC);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERDATA, &header_data);

	CURLcode req_ret = curl_easy_perform(ycmd_globals.curl); /* Synchronous */
	if (req_ret != CURLE_OK) {
		debug_log("cURL error:  %s", curl_easy_strerror(req_ret));
		wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));
		curl_slist_free_all(headers);
		return -1;
	}
	char *response_body = _curl_read_response_body_full(ycmd_globals.curl, &chunk);
	if (response_body == NULL) {
		/* Sanitize sensitive data */
		wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));
		curl_slist_free_all(headers);
		return -1;
	}

	curl_easy_getinfo(ycmd_globals.curl, CURLINFO_RESPONSE_CODE,
					  &response_code);
	debug_log("response_code = %ld, req_ret = %d",
		response_code, req_ret);
	debug_log("response_body = %s", response_body);
	debug_log("response X-Ycm-Hmac = %s", header_data.value);
	if (response_code == HTTP_OK) {
		const char *hmac_rsp_header = header_data.value;
		ycmd_get_hmac_response(rsp_hmac_base64, response_body);
		if (!response_body) {
			; /* Invalid */
		} else if (!ycmd_is_hmac_valid(hmac_rsp_header, rsp_hmac_base64)) {
			debug_log("Response HMAC validation failed:  expected=%s, received=%s",	rsp_hmac_base64,
				header_data.value);
			compromised = 1;
		}
	}

	/* Sanitize sensitive data */
	wrap_secure_zero(rsp_hmac_base64, sizeof(rsp_hmac_base64));
	wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));
	curl_slist_free_all(headers);
	if (response_body) {
		/* wrap_secure_zero(response_body, strlen(response_body)); */ /* Segfaults */
		wrap_free((void **)&response_body);
	}

	return response_code == HTTP_OK && !compromised;
}

int _ycmd_req_simple_request(char *method, char *path, int linenum, int columnnum, char *filepath,
	linestruct *filetop) {

	debug_log("Called function");
	char *filetype = _ycmd_get_filetype(filepath);
	char abspath[PATH_MAX];
	char req_hmac_base64[HMAC_SIZE * 2];
	char rsp_hmac_base64[HMAC_SIZE * 2];
	int compromised = 0;
	long response_code = -1;

	if (!ycmd_globals.curl) {
		ycmd_globals.curl = curl_easy_init();
		if (!ycmd_globals.curl) {
			return -1;
		}
	}

	curl_easy_reset(ycmd_globals.curl);
	char url[LINE_LENGTH];
	sprintf(url, "%s://%s:%d%s", ycmd_globals.scheme, ycmd_globals.hostname, ycmd_globals.port, path);
	debug_log("url = %s", url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_URL, url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_TIMEOUT_MS, 500L);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTP_VERSION,
					 CURL_HTTP_VERSION_NONE);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_CUSTOMREQUEST, method);

	get_abs_path(filepath, abspath);

	/* We send the data directly skipping the json and string lib because we
	 * need to stream the file it. */
	size_t req_buffer_size = MAX_FILESIZE_LIMIT;
	char *req_buffer = wrap_malloc(req_buffer_size);
	if (!req_buffer) {
		statusline(HUSH, "Out of Memory");
		return -1;
	}
	wrap_secure_zero(req_buffer, req_buffer_size);
	_req_sprintf(req_buffer, req_buffer_size, "{\n");
	_req_sprintf(req_buffer, req_buffer_size, "  \"line_num\": %d,\n", linenum);
	_req_sprintf(req_buffer, req_buffer_size, "  \"column_num\": %d,\n", columnnum + (ycmd_globals.clang_completer ? 0 : 1));
	_req_sprintf(req_buffer, req_buffer_size, "  \"filepath\": \"%s\",\n", abspath);
	_req_sprintf(req_buffer, req_buffer_size, "  \"file_data\": {\n");
	_req_sprintf(req_buffer, req_buffer_size, "    \"%s\": {\n", abspath);
	_req_sprintf(req_buffer, req_buffer_size, "      \"filetypes\": [\"%s\"],\n", filetype);
	if (filetop == NULL) {
		_req_sprintf(req_buffer, req_buffer_size, "\"contents\": \"\"\n");
	} else {
		_req_sprintf(req_buffer, req_buffer_size, "\"contents\": \"");
		_req_file(req_buffer, req_buffer_size, filetop);
		_req_sprintf(req_buffer, req_buffer_size, "\"\n");
	}
	_req_sprintf(req_buffer, req_buffer_size, "    }\n");
	_req_sprintf(req_buffer, req_buffer_size, "  }\n");
	_req_sprintf(req_buffer, req_buffer_size, "}\n");

	/* Set headers to match HTTP Neon */
	struct curl_slist *headers = NULL;
	ycmd_get_hmac_request(req_hmac_base64, method, path, req_buffer,
						  strlen(req_buffer));
	debug_log("HMAC inputs:  method=%s, path=%s, body='%s', body_size=%zu",
		method, path,
		req_buffer && strlen(req_buffer) ? req_buffer : "NULL",
		req_buffer && strlen(req_buffer) ? strlen(req_buffer) : 0);
	debug_log("X-Ycm-Hmac = %s", req_hmac_base64);
	headers = curl_slist_append(headers, "Keep-Alive: ");
	headers = curl_slist_append(headers, "Connection: TE, Keep-Alive");
	headers = curl_slist_append(headers, "content-type: application/json");
	headers = curl_slist_append(headers, "Accept:");
	headers = _curl_sprintf_header(headers, "%s: %s", HTTP_HEADER_YCM_HMAC, req_hmac_base64);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTPHEADER, headers);

	if (strcmp(method, "POST") == 0) {
		curl_easy_setopt(ycmd_globals.curl, CURLOPT_POST, 1L);
		if (req_buffer && req_buffer_size > 0) {
			curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDS, req_buffer);
			curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDSIZE,
							 strlen(req_buffer));
		} else {
			curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDS, "");
			curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDSIZE, 0L);
		}
	} else {
		curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTPGET, 1L);
	}

	memory_struct chunk;
	curl_setup_request(ycmd_globals.curl, &chunk);

	header_data_struct header_data;
	wrap_secure_zero(&header_data, sizeof(header_data_struct));
	sprintf(header_data.name, "%s", HTTP_HEADER_YCM_HMAC);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERFUNCTION,
					 header_callback);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERDATA, &header_data);

	CURLcode req_ret = curl_easy_perform(ycmd_globals.curl); /* Synchronous */
	if (req_ret != CURLE_OK) {
		debug_log("cURL error:  %s", curl_easy_strerror(req_ret));
		wrap_secure_zero(req_buffer, HALF_LINE_LENGTH);
		wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));

		curl_slist_free_all(headers);
		wrap_free((void **)&req_buffer);

		return -1;
	}
	char *response_body = _curl_read_response_body_full(ycmd_globals.curl, &chunk);
	if (response_body == NULL) {
		/* Sanitize sensitive data */
		wrap_secure_zero(req_buffer, req_buffer_size);
		wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));

		curl_slist_free_all(headers);
		wrap_free((void **)&req_buffer);

		return -1;
	}

	curl_easy_getinfo(ycmd_globals.curl, CURLINFO_RESPONSE_CODE, &response_code);
	debug_log("response_code = %ld, req_ret = %d", response_code, req_ret);
	debug_log("response_body = %s", response_body);
	debug_log("response X-Ycm-Hmac = %s", header_data.value);
	if (response_code == HTTP_OK) {
		const char *hmac_rsp_header = header_data.value;
		ycmd_get_hmac_response(rsp_hmac_base64, response_body);
		if (!response_body) {
			; /* Invalid */
		} else if (!ycmd_is_hmac_valid(hmac_rsp_header, rsp_hmac_base64)) {
			debug_log("Response HMAC validation failed:  expected=%s, received=%s",	rsp_hmac_base64,
				header_data.value);
			compromised = 1;
		}
	}

	/* Sanitize sensitive data */
	wrap_secure_zero(req_buffer, req_buffer_size);
	wrap_secure_zero(rsp_hmac_base64, sizeof(rsp_hmac_base64));
	wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));
	if (response_body) {
		/* wrap_secure_zero(response_body, strlen(response_body)); */ /* Segfaults */
		wrap_free((void **)&response_body);
	}

	curl_slist_free_all(headers);
	wrap_free((void **)&req_buffer);

	return response_code == HTTP_OK && !compromised;
}

typedef struct defined_subcommands {
	int line_num;
	int column_num;
	char filepath[PATH_MAX];
	char completer_target[NAME_MAX + 1];
} defined_subcommands;

/* Get the list completer commands available for the completer target. */
int ycmd_req_defined_subcommands(int linenum, int columnnum, char *filepath, linestruct *filetop, char *completertarget,
	defined_subcommands_results_struct *dsr) {
	debug_log("Called function");
	char *filetype = _ycmd_get_filetype(filepath);
	char *method = "POST";
	char *path = "/defined_subcommands";
	char abspath[PATH_MAX];
	char req_hmac_base64[HMAC_SIZE * 2];
	char rsp_hmac_base64[HMAC_SIZE * 2];
	int compromised = 0;
	long response_code = -1;

	if (!ycmd_globals.curl) {
		ycmd_globals.curl = curl_easy_init();
		if (!ycmd_globals.curl) {
			return -1;
		}
	}

	curl_easy_reset(ycmd_globals.curl);
	char url[LINE_LENGTH];
	sprintf(url, "%s://%s:%d%s", ycmd_globals.scheme, ycmd_globals.hostname, ycmd_globals.port, path);
	debug_log("url = %s", url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_URL, url);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_TIMEOUT_MS, 500L);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_NONE);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_CUSTOMREQUEST, method);

	get_abs_path(filepath, abspath);

	/* We send the data directly skipping the json and string lib because we
	 * need to stream the file it. */
	size_t req_buffer_size = MAX_FILESIZE_LIMIT;
	char *req_buffer = wrap_malloc(req_buffer_size);
	if (!req_buffer) {
		statusline(HUSH, "Out of Memory");
		return -1;
	}
	wrap_secure_zero(req_buffer, req_buffer_size);
	_req_sprintf(req_buffer, req_buffer_size, "{\n");
	_req_sprintf(req_buffer, req_buffer_size, "  \"line_num\": %d,\n", linenum);
	_req_sprintf(req_buffer, req_buffer_size, "  \"column_num\": %d,\n", columnnum + (ycmd_globals.clang_completer ? 0 : 1));
	_req_sprintf(req_buffer, req_buffer_size, "  \"filepath\": \"%s\",\n", abspath);
	_req_sprintf(req_buffer, req_buffer_size, "  \"file_data\": {\n");
	_req_sprintf(req_buffer, req_buffer_size, "    \"%s\": {\n", abspath);
	_req_sprintf(req_buffer, req_buffer_size, "      \"filetypes\": [\"%s\"],\n", filetype);
	_req_sprintf(req_buffer, req_buffer_size, "      \"contents\": \"");
	_req_file(req_buffer, req_buffer_size, filetop);
	_req_sprintf(req_buffer, req_buffer_size, "\"\n");
	_req_sprintf(req_buffer, req_buffer_size, "    }\n");
	_req_sprintf(req_buffer, req_buffer_size, "  },\n");
	_req_sprintf(req_buffer, req_buffer_size, "  \"completer_target\": \"%s\"\n", completertarget);
	_req_sprintf(req_buffer, req_buffer_size, "}\n");

	/* Set headers to match HTTP Neon */
	struct curl_slist *headers = NULL;
	ycmd_get_hmac_request(req_hmac_base64, method, path, req_buffer,
						  strlen(req_buffer));
	debug_log("HMAC inputs:  method=%s, path=%s, body='%s', body_size=%zu",
		method, path,
		req_buffer && strlen(req_buffer) ? req_buffer : "NULL",
		req_buffer && strlen(req_buffer) ? strlen(req_buffer) : 0);
	debug_log("X-Ycm-Hmac = %s", req_hmac_base64);
	headers = curl_slist_append(headers, "Keep-Alive: ");
	headers = curl_slist_append(headers, "Connection: TE, Keep-Alive");
	headers = curl_slist_append(headers, "content-type: application/json");
	headers = curl_slist_append(headers, "Accept:");
	headers = _curl_sprintf_header(headers, "%s: %s", HTTP_HEADER_YCM_HMAC, req_hmac_base64);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDS, req_buffer);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_POSTFIELDSIZE, strlen(req_buffer));
	memory_struct chunk;
	curl_setup_request(ycmd_globals.curl, &chunk);

	header_data_struct header_data;
	wrap_secure_zero(&header_data, sizeof(header_data_struct));
	sprintf(header_data.name, "%s", HTTP_HEADER_YCM_HMAC);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_HEADERDATA, &header_data);

	CURLcode req_ret = curl_easy_perform(ycmd_globals.curl); /* Synchronous */
	if (req_ret != CURLE_OK) {
		debug_log("cURL error:  %s", curl_easy_strerror(req_ret));
		wrap_secure_zero(req_buffer, HALF_LINE_LENGTH);
		wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));

		curl_slist_free_all(headers);
		wrap_free((void **)&req_buffer);

		return -1;
	}
	dsr->response_code = response_code; /* Sometimes the subservers will throw exceptions so capture it. */
	char *response_body = _curl_read_response_body_full(ycmd_globals.curl, &chunk);
	if (response_body == NULL) {
		/* Sanitize sensitive data */
		wrap_secure_zero(req_buffer, req_buffer_size);
		wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));

		curl_slist_free_all(headers);
		wrap_free((void **)&req_buffer);

		return -1;
	}

	curl_easy_getinfo(ycmd_globals.curl, CURLINFO_RESPONSE_CODE, &response_code);
	debug_log("response_code = %ld, req_ret = %d", response_code, req_ret);
	debug_log("response_body = %s", response_body);
	debug_log("response X-Ycm-Hmac = %s", header_data.value);
	if (response_code == HTTP_OK) {
		const char *hmac_rsp_header = header_data.value;
		ycmd_get_hmac_response(rsp_hmac_base64, response_body);
		if (!response_body) {
			; /* Invalid */
		} else if (!ycmd_is_hmac_valid(hmac_rsp_header, rsp_hmac_base64)) {
			debug_log("Response HMAC validation failed:  expected=%s, received=%s", rsp_hmac_base64,
				header_data.value);
			compromised = 1;
		} else {
			ycmd_get_hmac_response(rsp_hmac_base64, response_body);
			dsr->json = strdup(response_body);
			dsr->usable = 1;
		}
	}

	/* Sanitize sensitive data */
	wrap_secure_zero(req_buffer, req_buffer_size);
	wrap_secure_zero(rsp_hmac_base64, sizeof(rsp_hmac_base64));
	wrap_secure_zero(req_hmac_base64, sizeof(req_hmac_base64));
	if (response_body) {
		/* wrap_secure_zero(response_body, strlen(response_body)); */ /* Segfaults */
		wrap_free((void **)&response_body);
	}

	curl_slist_free_all(headers);
	wrap_free((void **)&req_buffer);

	return response_code == HTTP_OK && !compromised;
}

/* filepath should be the .ycm_extra_conf.py file. */
/* It should load before parsing. */
void ycmd_req_load_extra_conf_file(char *filepath) {
	debug_log("Called function");
	char *method = "POST";
	char *path = "/load_extra_conf_file";

	_ycmd_req_simple_request(method, path, 0, 0, filepath, NULL);
}

/* filepath should be the .ycm_extra_conf.py file. */
void ycmd_req_ignore_extra_conf_file(char *filepath) {
	debug_log("Called function");
	char *method = "POST";
	char *path = "/ignore_extra_conf_file";

	_ycmd_req_simple_request(method, path, 0, 0, filepath, NULL);
}

void ycmd_req_semantic_completion_available(int linenum, int columnnum, char *filepath, linestruct *filetop) {
	debug_log("Called function");
	char *method = "POST";
	char *path = "/semantic_completer_available";

	_ycmd_req_simple_request(method, path, linenum, columnnum, filepath, filetop);
}

int find_unused_localhost_port() {
	debug_log("Called function");
	int port = 0;

	struct sockaddr_in address;
	ycmd_globals.tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (ycmd_globals.tcp_socket == -1)
		return -1;

	wrap_secure_zero(&address, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = 0;

	if (!bind(ycmd_globals.tcp_socket, &address, sizeof(address))) {
		socklen_t addrlen = sizeof(address);
		if (getsockname(ycmd_globals.tcp_socket, &address, &addrlen) == -1) {
			close(ycmd_globals.tcp_socket);
			return -1;
		}

		port = address.sin_port;
		close(ycmd_globals.tcp_socket);

		return port;
	}

	close(ycmd_globals.tcp_socket);
	return -1;
}

/* The main exit function. */
void delete_ycmd() {
	debug_log("Called function");
	delete_file_ready_to_parse_results(&ycmd_globals.file_ready_to_parse_results);

	ycmd_stop_server();

	/* Sanitize sensitive data */
	wrap_secure_zero(&ycmd_globals, sizeof(ycmd_globals_struct));
}

void show_ycm_extra_conf_py_security_prompt(void) {
	/* Set currmenu for keybindings */
	currmenu = MYCMEXTRACONF;
	debug_log("currmenu set to %d", currmenu);

	/* Refresh editor first */
	edit_refresh();
	statusline(HUSH, "%s", "SECURITY: Load and execute the project's .ycm_extra_conf.py for ycmd support? [^Y/^N]");
	bottombars(MYCMEXTRACONF);
	full_refresh();

	/* Handle input */
	int input;
	WINDOW *frame = footwin ? footwin : midwin;
	keypad(frame, TRUE);
	wtimeout(frame, -1);
	while (true) {
		input = get_kbinput(frame, TRUE);
		debug_log("input=0x%x", input);

		const keystruct *shortcut = get_shortcut(input);
		if (shortcut && currmenu == MYCMEXTRACONF) {
			if (shortcut->func == do_ycm_extra_conf_accept) {
				do_ycm_extra_conf_accept();
				break;
			} else if (shortcut->func == do_ycm_extra_conf_reject) {
				do_ycm_extra_conf_reject();
				break;
			}
		}
		statusline(ALERT, "Please press ^Y (Accept) or ^N (Reject)");
		full_refresh();
		bottombars(MYCMEXTRACONF);
		full_refresh();
	}
	currmenu = MMOST; /* Restore default menu */
	debug_log("currmenu restored to %d", currmenu);
}

void ycmd_start_server() {
	debug_log("Called function");
	if (YCMD_PORT == 0) {
		ycmd_globals.port = find_unused_localhost_port();
	} else if (YCMD_PORT > 0) {
		ycmd_globals.port = YCMD_PORT;
	}

	if (ycmd_globals.port < 0) {
		debug_log("Cannot find unused port");
		statusline(ALERT, "Failed to find unused port for ycmd");
		full_refresh();
		return;
	}

	debug_log("port = %d", ycmd_globals.port);

	default_settings_json_constructor(ycmd_globals.json);

	/* Get the user's home directory */
	struct passwd *pw = getpwuid(getuid());
	char cache_dir[PATH_MAX];
	sprintf(cache_dir, "%s/.cache/nano-ycmd", pw->pw_dir);
	debug_log("cache_dir = %s", cache_dir);
	mkdir(cache_dir, 0700); /* Create the cache directory if it doesn't exist */

// #if defined(DEBUG)
#if 0
	char combined_output_file[PATH_MAX];
	sprintf(combined_output_file, "%s/tmpXXXXXX", cache_dir); /* Do not add .txt suffix */
	int fd2 = mkstemp(combined_output_file);
	if (fd2 == -1) {
		debug_log("mkstemp creation failed for combined_output_file");
		statusline(ALERT, "Failed to create temp file for ycmd output");
		full_refresh();
		exit(EXIT_FAILURE);
	}
	close(fd2);
	debug_log("stdout_output_file = %s", combined_output_file);
#else
	char combined_output_file[PATH_MAX];
	sprintf(combined_output_file, "/dev/null");
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-overflow"
	char default_settings_json_path[PATH_MAX];
	sprintf(default_settings_json_path, "%s/tmpXXXXXX", cache_dir); /* Do not add .txt suffix */
#pragma GCC diagnostic pop
	int fd3 = mkstemp(default_settings_json_path);
	if (fd3 == -1) {
		debug_log("mkstemp creation failed for default_settings_json_path");
		statusline(ALERT, "Failed to create temp file for ycmd settings");
		full_refresh();
		exit(EXIT_FAILURE);
	}
	debug_log("default_settings_json_path = %s", default_settings_json_path);

	sprintf(ycmd_globals.default_settings_json_path, "%s", default_settings_json_path);
	FILE *f = fdopen(fd3, "w+");
	fprintf(f, "%s", ycmd_globals.json);
	fclose(f);

	int pid = fork();
	if (pid == 0) {
		/* Child */
		char port_value[DIGITS_MAX];
		char options_file_value[PATH_MAX];
		char idle_suicide_seconds_value[DIGITS_MAX];
		char ycmd_path[PATH_MAX];

		snprintf(port_value, DIGITS_MAX, "%d", ycmd_globals.port);
		snprintf(options_file_value, PATH_MAX, "%s", ycmd_globals.default_settings_json_path);
		snprintf(idle_suicide_seconds_value, DIGITS_MAX, "%d", IDLE_SUICIDE_SECONDS);
		snprintf(ycmd_path, PATH_MAX, "%s", YCMD_PATH);

		/* After execl() executes, the server will delete the tmpfile (aka options_file_value). */
		/* For inspecting for changes:
		   python /usr/lib/python3.11/site-packages/ycmd/48/ycmd \
		 	--port 0 \
			--options_file $(pwd)"/default_settings.json" \
			--idle_suicide_seconds 10800
		 */
		/* The port is obtained with find_unused_localhost_port() or via --with-port=PORT with configure */
		execl(YCMD_PYTHON_PATH, YCMD_PYTHON_PATH,
			ycmd_path,
			"--port", port_value,
			"--options_file", options_file_value,
			"--idle_suicide_seconds", idle_suicide_seconds_value,
			"--stdout", combined_output_file,
			"--stderr", combined_output_file, NULL);

		/* Continue if it fails. */

		if (access(ycmd_globals.default_settings_json_path, F_OK) == 0)
			unlink(ycmd_globals.default_settings_json_path);

		exit(1);
	}

	curl_global_init(CURL_GLOBAL_DEFAULT);
	ycmd_globals.curl = curl_easy_init();

#if defined(DEBUG)
	FILE *debug_file = stderr;
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_STDERR, debug_file);
#else
	curl_easy_setopt(ycmd_globals.curl, CURLOPT_VERBOSE, 0L);
#endif

	ycmd_globals.child_pid = pid;

	if (waitpid(pid, 0, WNOHANG) == 0) {
		statusline(HUSH, "%s", "Starting ycmd server...");
		full_refresh();
		ycmd_globals.running = 1;
	} else {
		statusline(ALERT, "%s", "Failed to start ycmd server");
		full_refresh();
		ycmd_globals.running = 0;

		ycmd_stop_server();
		return;
	}

	statusline(HUSH, "%s", "Letting the server initialize...");
	full_refresh();

	/* Give it some time for the server to initialize. */
	usleep(1500000);

	statusline(HUSH, "%s", "Checking server health...");

	int i;
	int tries = 5;
	for (i = 0; i < tries && ycmd_globals.connected == 0; i++) {
		if (ycmd_rsp_is_healthy_simple()) {
			debug_log("Connected to ycmd server.  Tries attempted:  %d out of 5.", i);
			statusline(HUSH, "%s", "Connected to ycmd server");
			ycmd_globals.connected = 1;
		} else {
			debug_log("Failed to connect to ycmd server.  Tries attempted:  %d out of 5", i);
			statusline(HUSH, "%s", "Failed to connect to ycmd server");
			ycmd_globals.connected = 0;
			usleep(1000000);
		}
		full_refresh();
	}

	char path_project[PATH_MAX];
	char path_extra_conf[PATH_MAX];
	ycmd_get_project_path(path_project);
	if (wrap_strncmp(path_project, "(null)", PATH_MAX) != 0 &&
		access(path_project, F_OK) == 0) {
		ycmd_get_extra_conf_path(path_project, path_extra_conf);
		if (access(path_extra_conf, F_OK) == 0) {
			open_buffer(path_extra_conf, TRUE);
			show_ycm_extra_conf_py_security_prompt();
		} else {
			statusline(INFO, "%s", "No .ycm_extra_conf.py found");
			full_refresh();
		}
	} else {
		statusline(INFO, "%s", "No project path found");
		full_refresh();
	}
}

void ycmd_stop_server() {
	debug_log("Called function");
	curl_global_cleanup();
	close(ycmd_globals.tcp_socket);

	if (access(ycmd_globals.default_settings_json_path, F_OK) == 0)
		unlink(ycmd_globals.default_settings_json_path);
	if (ycmd_globals.child_pid != -1)
		kill(ycmd_globals.child_pid, SIGKILL);
	ycmd_globals.child_pid = -1;

	ycmd_globals.running = 0;
	ycmd_globals.connected = 0;
}

void ycmd_restart_server() {
	if (ycmd_globals.running)
		ycmd_stop_server();

	ycmd_start_server();
}

/* Function to generate entropy for the key */
void generate_entropy(uint8_t *key) {
	/* Get the current time */
	time_t current_time = time(NULL);

	/* Get the PID */
	pid_t pid = getpid();

	/* Generate random numbers */
	srand(current_time ^ pid);
	for (int i = 0; i < CSPRNG_CHACHA20_KEY_SIZE; i++) {
		key[i] = rand() % 256;
	}
}

/* Nettle doesn't have a random function */
void generate_random_bytes(uint8_t *buf, size_t len) {
	FILE *fp = fopen("/dev/urandom", "r");
	if (fp) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
		fread(buf, 1, len, fp);
#pragma GCC diagnostic pop
		fclose(fp);
	}
}

/*
 * Trade-off table for CSPRNG
 *
 * | CSPRNG       | Entropy | Security | Performance | Estimated worst case startup time |
 * | ----         | ----    | ----     | ----        | ----                              |
 * | ChaCha20     | 8/10    | 9/10     | 9/10        | 1 microsecond or less             |
 * | /dev/random  | 9/10    | 9/10     | 6/10        | A few seconds                     |
 *
 */
/*
 * CSPRNG generation to generate the secret key used with HMAC function for requests.
 * Input:  Entropy sources (Time, PID, PRNG, ...)
 * Output:  128-bit key
 * Algorithm:  ChaCha20
 *
 * F(Time, PID, PRNG) -> E1
 * Nonce -> E2
 * ChaCha20(E1, E2) -> KEY
 */
void csprng_chacha20_get_key(uint8_t *key, size_t key_size) {
#if defined(USE_NETTLE)
	uint8_t chacha_key[CSPRNG_CHACHA20_KEY_SIZE];
	generate_entropy(chacha_key);

	struct chacha_ctx ctx;
	chacha_set_key(&ctx, chacha_key);

	uint8_t nonce[CSPRNG_CHACHA20_NONCE_SIZE];
	generate_random_bytes(nonce, sizeof nonce);
	/* Nettle's chacha_set_nonce expects 8 bytes nonce */
	chacha_set_nonce(&ctx, nonce);

	uint8_t block[CSPRNG_CHACHA20_BLOCK_SIZE];
	chacha_crypt(&ctx, CSPRNG_CHACHA20_BLOCK_SIZE, block, NULL);
	wrap_memcpy(key, block, key_size);

	/* Sanitize sensitive data */
	wrap_secure_zero(chacha_key, CSPRNG_CHACHA20_KEY_SIZE);
	wrap_secure_zero(nonce, CSPRNG_CHACHA20_NONCE_SIZE);
	wrap_secure_zero(block, CSPRNG_CHACHA20_BLOCK_SIZE);
#elif defined(USE_OPENSSL)
	uint8_t chacha_key[CSPRNG_CHACHA20_KEY_SIZE];
	generate_entropy(chacha_key);

	uint8_t nonce[CSPRNG_CHACHA20_NONCE_SIZE];
	RAND_bytes(nonce, sizeof(nonce));

	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, chacha_key, nonce);

	uint8_t block[CSPRNG_CHACHA20_BLOCK_SIZE];
	int len;
	EVP_EncryptUpdate(ctx, block, &len, NULL, CSPRNG_CHACHA20_BLOCK_SIZE);
	wrap_memcpy(key, block, key_size);
	EVP_CIPHER_CTX_free(ctx);

	/* Sanitize sensitive data */
	wrap_secure_zero(chacha_key, CSPRNG_CHACHA20_KEY_SIZE);
	wrap_secure_zero(nonce, CSPRNG_CHACHA20_NONCE_SIZE);
	wrap_secure_zero(block, CSPRNG_CHACHA20_BLOCK_SIZE);
#elif defined(USE_LIBGCRYPT)
	uint8_t chacha_key[CSPRNG_CHACHA20_KEY_SIZE];
	generate_entropy(chacha_key);

	gcry_cipher_hd_t ctx;
	gcry_cipher_open(&ctx, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0);
	gcry_cipher_setkey(ctx, chacha_key, CSPRNG_CHACHA20_KEY_SIZE);

	uint8_t nonce[CSPRNG_CHACHA20_NONCE_SIZE];
	gcry_randomize(nonce, sizeof(nonce), GCRY_STRONG_RANDOM);
	gcry_cipher_setiv(ctx, nonce, CSPRNG_CHACHA20_NONCE_SIZE);

	uint8_t block[CSPRNG_CHACHA20_BLOCK_SIZE];
	gcry_cipher_encrypt(ctx, block, CSPRNG_CHACHA20_BLOCK_SIZE, NULL, 0);
	wrap_memcpy(key, block, key_size);
	gcry_cipher_close(ctx);

	/* Sanitize sensitive data */
	wrap_secure_zero(chacha_key, CSPRNG_CHACHA20_KEY_SIZE);
	wrap_secure_zero(nonce, CSPRNG_CHACHA20_NONCE_SIZE);
	wrap_secure_zero(block, CSPRNG_CHACHA20_BLOCK_SIZE);
#endif
}

int get_secret_otp_key(uint8_t *secret_otp_key) {
#if defined(USE_RANDOM)
	FILE *random_file;
	statusline(HUSH, "Obtaining the secret key.  I need more entropy.  Type on "
					 "the keyboard or move the mouse.");
	random_file = fopen("/dev/random", "r");
	size_t nread = fread(secret_otp_key, 1, SECRET_KEY_LENGTH, random_file);
	if (nread != SECRET_KEY_LENGTH) {
		debug_log("Failed to obtain 16 bytes of data for the secret key.");
	}
	debug_log("Read %d bytes of /dev/random", (int)nread);
	fclose(random_file);
	blank_statusbar();
#else
	/* ChaCha20 Keystream */
	csprng_chacha20_get_key(secret_otp_key, SECRET_KEY_LENGTH);
#endif
	return 0;
}

void ycmd_clear_input_buffer() {
	blank_statusbar();

	/* This section is credited to marchelzo and twkm from the
	 * freenode ##C channel for flushing stdin excessive characters after
	 * user adds entropy. */
	full_refresh();
	statusline(HUSH, "Please stop typing.  Clearing input buffer...");
	nodelay(stdscr, TRUE);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wempty-body"
	while (getch() != ERR)
		;
#pragma GCC diagnostic pop
	nodelay(stdscr, FALSE);
	full_refresh();
	statusline(HUSH, "Please stop typing.  Clearing input buffer...");

	usleep(1000000);
	fflush(stdin);

	full_refresh();
	statusline(HUSH, "Please stop typing.  Clearing input buffer...");
	nodelay(stdscr, TRUE);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wempty-body"
	while (getch() != ERR)
		;
#pragma GCC diagnostic pop
	nodelay(stdscr, FALSE);
	full_refresh();
	draw_all_subwindows();

	statusline(HUSH, "Input buffer cleared.");
}

void ycmd_generate_secret_key_raw(uint8_t *secret) {
	get_secret_otp_key(secret);

	ycmd_clear_input_buffer();
}

void ycmd_generate_secret_key_base64(uint8_t *secret, char *secret_base64) {
	wrap_secure_zero(secret_base64, SECRET_KEY_LENGTH * 2);
#if defined(USE_NETTLE)
	base64_encode_raw(secret_base64, SECRET_KEY_LENGTH, secret);
#elif defined(USE_OPENSSL)
	BIO *b, *append;
	BUF_MEM *pp;
	b = BIO_new(BIO_f_base64());
	append = BIO_new(BIO_s_mem());
	b = BIO_push(b, append);

	BIO_set_flags(b, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b, secret, SECRET_KEY_LENGTH);
	BIO_flush(b);
	BIO_get_mem_ptr(b, &pp);

	wrap_memcpy(secret_base64, pp->data, pp->length);
	BIO_free_all(b);
#elif defined(USE_LIBGCRYPT)
	gchar *_secret_base64 = g_base64_encode((unsigned char *)secret, SECRET_KEY_LENGTH);
	wrap_strncpy(secret_base64, _secret_base64, SECRET_KEY_LENGTH * 2 - 1);
	wrap_secure_zero(_secret_base64, strlen(_secret_base64));
	g_free(_secret_base64);
#else
#error "You need to define a crypto library to use."
#endif
}

/*
 * HMAC generation for ycmd requests
 * Inputs:  128-bit secret key, method, path, body
 * Output:   base64 encoded HMAC
 * Algorithm:  256-bit HMAC-SHA2
 *
 * HMAC-SHA2(key, method) + HMAC-SHA2(key, path) + HMAC-SHA2(key, body) -> A
 * # + = concat operator, order matters HMAC-SHA2(key, A) -> B GET_BASE64(B) ->
 * base64 encoded HMAC
 */

void ycmd_get_hmac_request(char *req_hmac_base64, char *method, char *path, char *body,
	size_t body_len /* strlen based */) {
	wrap_secure_zero(req_hmac_base64, HMAC_SIZE * 2);
#if defined(USE_NETTLE)
	char join[HMAC_SIZE * 3];
	static char hmac_request[HMAC_SIZE];
	struct hmac_sha256_ctx hmac_ctx;

	hmac_sha256_set_key(&hmac_ctx, SECRET_KEY_LENGTH, (unsigned char *)ycmd_globals.secret_key_raw);
	hmac_sha256_update(&hmac_ctx, strlen(method), (const uint8_t *)method);
	hmac_sha256_digest(&hmac_ctx, HMAC_SIZE, (unsigned char *)join);

	hmac_sha256_update(&hmac_ctx, strlen(path), (const uint8_t *)path);
	hmac_sha256_digest(&hmac_ctx, HMAC_SIZE, (unsigned char *)(join + HMAC_SIZE));

	hmac_sha256_update(&hmac_ctx, body_len, (const uint8_t *)body);
	hmac_sha256_digest(&hmac_ctx, HMAC_SIZE, (unsigned char *)(join + 2 * HMAC_SIZE));

	hmac_sha256_update(&hmac_ctx, HMAC_SIZE * 3, (const uint8_t *)join);
	hmac_sha256_digest(&hmac_ctx, HMAC_SIZE, (unsigned char *)hmac_request);

	base64_encode_raw(req_hmac_base64, HMAC_SIZE, (const uint8_t *)hmac_request);

	/* Sanitize sensitive data */
	wrap_secure_zero(join, HMAC_SIZE * 3);
	wrap_secure_zero(hmac_request, HMAC_SIZE);
#elif defined(USE_OPENSSL)
	unsigned char hmac_method[HMAC_SIZE];
	unsigned char hmac_path[HMAC_SIZE];
	unsigned char hmac_body[HMAC_SIZE];
	unsigned char hmac_final[EVP_MAX_MD_SIZE];

	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	OSSL_PARAM params[2];
	params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA2-256", 0);
	params[1] = OSSL_PARAM_construct_end();

	EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
	EVP_MAC_init(ctx, ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH, params);

	/* Calculate HMAC for method */
	EVP_MAC_update(ctx, (unsigned char *)method, strlen(method));
	size_t hmac_method_len = EVP_MAX_MD_SIZE;
	EVP_MAC_final(ctx, hmac_method, &hmac_method_len, EVP_MAX_MD_SIZE);
	EVP_MAC_init(ctx, ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH, params); /* Reset ctx */

	/* Calculate HMAC for path */
	EVP_MAC_update(ctx, (unsigned char *)path, strlen(path));
	size_t hmac_path_len = EVP_MAX_MD_SIZE;
	EVP_MAC_final(ctx, hmac_path, &hmac_path_len, EVP_MAX_MD_SIZE);
	EVP_MAC_init(ctx, ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH, params); /* Reset ctx */

	/* Calculate HMAC for body */
	EVP_MAC_update(ctx, (unsigned char *)body, body_len);
	size_t hmac_body_len = EVP_MAX_MD_SIZE;
	EVP_MAC_final(ctx, hmac_body, &hmac_body_len, EVP_MAX_MD_SIZE);
	EVP_MAC_init(ctx, ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH, params); /* Reset ctx */

	/* Concatenate HMACs and calculate final HMAC */
	EVP_MAC_update(ctx, hmac_method, hmac_method_len);
	EVP_MAC_update(ctx, hmac_path, hmac_path_len);
	EVP_MAC_update(ctx, hmac_body, hmac_body_len);
	size_t hmac_final_len = EVP_MAX_MD_SIZE;
	EVP_MAC_final(ctx, hmac_final, &hmac_final_len, EVP_MAX_MD_SIZE);

	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(mac);

	/* Convert the final HMAC to base64 */
	BIO *b, *append;
	BUF_MEM *pp;
	b = BIO_new(BIO_f_base64());
	append = BIO_new(BIO_s_mem());
	b = BIO_push(b, append);

	BIO_set_flags(b, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b, hmac_final, HMAC_SIZE);
	BIO_flush(b);
	BIO_get_mem_ptr(b, &pp);

	wrap_memcpy(req_hmac_base64, pp->data, pp->length);
	BIO_free_all(b);

	/* Sanitize sensitive data */
	wrap_secure_zero(hmac_method, HMAC_SIZE);
	wrap_secure_zero(hmac_path, HMAC_SIZE);
	wrap_secure_zero(hmac_body, HMAC_SIZE);
	wrap_secure_zero(hmac_final, HMAC_SIZE);
#elif defined(USE_LIBGCRYPT)
	unsigned char join[HMAC_SIZE * 3];
	size_t length;

	gcry_mac_hd_t hd;
	gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, 0 /*GCRY_MAC_FLAG_SECURE*/, NULL);
	gcry_mac_setkey(hd, ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH);

	gcry_mac_write(hd, method, strlen(method));
	length = HMAC_SIZE;
	gcry_mac_read(hd, join, &length);

	gcry_mac_reset(hd);

	gcry_mac_write(hd, path, strlen(path));
	length = HMAC_SIZE;
	gcry_mac_read(hd, join + HMAC_SIZE, &length);

	gcry_mac_reset(hd);

	gcry_mac_write(hd, body, body_len);
	length = HMAC_SIZE;
	gcry_mac_read(hd, join + 2 * HMAC_SIZE, &length);

	gcry_mac_reset(hd);

	unsigned char digest_join[HMAC_SIZE];
	gcry_mac_write(hd, join, HMAC_SIZE * 3);
	length = HMAC_SIZE;
	gcry_mac_read(hd, digest_join, &length);

	gcry_mac_close(hd);

	gchar *_req_hmac_base64 =
		g_base64_encode((unsigned char *)digest_join, HMAC_SIZE);
	wrap_strncpy(req_hmac_base64, _req_hmac_base64, HMAC_SIZE * 2 - 1);

	/* Sanitize sensitive data */
	wrap_secure_zero(_req_hmac_base64, strlen(_req_hmac_base64));

	wrap_free((void **)&_req_hmac_base64);
#else
#error "You need to define a crypto library to use."
#endif
}

/*
 * HMAC generation for ycmd response
 * Input:  128-bit secret key, response body
 * Output:  base64 encoded HMAC
 * Algorithm:  256-bit HMAC-SHA2
 *
 * HMAC-SHA2(key, response_body) -> A
 * GET_BASE64(A) -> base64 encoded HMAC
 */

void ycmd_get_hmac_response(char *rsp_hmac_base64, char *response_body) {
	wrap_secure_zero(rsp_hmac_base64, HMAC_SIZE * 2);
#if defined(USE_NETTLE)
	static char hmac_response[HMAC_SIZE];
	struct hmac_sha256_ctx hmac_ctx;

	hmac_sha256_set_key(&hmac_ctx, SECRET_KEY_LENGTH, (unsigned char *)ycmd_globals.secret_key_raw);
	hmac_sha256_update(&hmac_ctx, strlen(response_body), (const uint8_t *)response_body);
	hmac_sha256_digest(&hmac_ctx, HMAC_SIZE, (unsigned char *)hmac_response);

	base64_encode_raw(rsp_hmac_base64, HMAC_SIZE, (const uint8_t *)hmac_response);
#elif defined(USE_OPENSSL)
	unsigned char *response_digest = HMAC(EVP_sha256(), ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH,
		(unsigned char *)response_body,	strlen(response_body), NULL, NULL);

	BIO *b, *append;
	BUF_MEM *pp;
	b = BIO_new(BIO_f_base64());
	append = BIO_new(BIO_s_mem());
	b = BIO_push(b, append);

	BIO_set_flags(b, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b, response_digest, HMAC_SIZE);
	BIO_flush(b);
	BIO_get_mem_ptr(b, &pp);

	wrap_memcpy(rsp_hmac_base64, pp->data, pp->length);

	BIO_free_all(b);
#elif defined(USE_LIBGCRYPT)
	gcry_mac_hd_t hd;
	gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, 0 /*GCRY_MAC_FLAG_SECURE*/, NULL);
	gcry_mac_setkey(hd, ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH);

	char response_digest[HMAC_SIZE];
	gcry_mac_write(hd, response_body, strlen(response_body));
	size_t length = HMAC_SIZE;
	gcry_mac_read(hd, response_digest, &length);

	gcry_mac_close(hd);

	gchar *_rsp_hmac_base64 = g_base64_encode((unsigned char *)response_digest, HMAC_SIZE);
	wrap_strncpy(rsp_hmac_base64, _rsp_hmac_base64, HMAC_SIZE * 2 - 1);

	/* Sanitize sensitive data */
	wrap_secure_zero(_rsp_hmac_base64, strlen(_rsp_hmac_base64));

	g_free(_rsp_hmac_base64);
#else
#error "You need to define a crypto library to use."
#endif
}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define YCMD_ESCAPE_JSON_SHIFT_AMOUNT(c) ((c - 0x08) * 8)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define YCMD_ESCAPE_JSON_SHIFT_AMOUNT(c) ((5 - (c - 0x08)) * 8)
#else
#error "Unsupported endianness"
#endif

/* In the past, gprof reports this function takes 33% of the time. */
/* We use the naive version because it is more secure. */
size_t ycmd_escape_json(char *unescaped, char *escaped) {
	int before_len = strlen(unescaped);
	size_t after_len = 0;

	int j = 0;
	char *p = unescaped;

	for (int i = 0; i < before_len && j + 6 + 1 < MAX_FILESIZE_LIMIT; i++) {
		char c = p[i];
		if (c == '\\') {
			/* Escape the already escaped */
			*(escaped + j) = '\\';
			*(escaped + j + 1) = '\\';
			j += 2;
			after_len += 2;
		} else if ('\b' <= c && c <= '\r') {
			/* C escape sequences */
			*(escaped + j) = '\\';
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
			/* 0x72 = r, 0x66 = f, 0x76 = v, 0x6e = n, 0x74 = t, 0x62 = b */
			uint64_t chars = 0x7266766e7462;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			/* 0x62 = b, 0x74 = t, 0x6e = n, 0x76 = v, 0x66 = f, 0x72 = r, 0x72 = r */
			uint64_t chars = 0x62746e76667272;
#endif
			char val = (chars >> YCMD_ESCAPE_JSON_SHIFT_AMOUNT(c)) & 0xff;
			*(escaped + j + 1) = val;
			j += 2;
			after_len += 2;
		} else if (c == '\"') {
			*(escaped + j) = '\\';
			*(escaped + j + 1) = '"';
			j += 2;
			after_len += 2;
		} else if (c == '/') {
			*(escaped + j) = '\\';
			*(escaped + j + 1) = '/';
			j += 2;
			after_len += 2;
		} else if (('\x01' <= c &&
					c <= '\x1f') /* || p[i] == 0x7f delete char */) {
			/* Escape control characters */
			*(escaped + j) = '\\';
			*(escaped + j + 1) = 'u';
			*(escaped + j + 2) = '0';
			*(escaped + j + 3) = '0';
			*(escaped + j + 4) = (c >> 4) + (c >> 4 > 9 ? 87 : 48);
			*(escaped + j + 5) = (c & 0x0f) + ((c & 0x0f) > 9 ? 87 : 48);
			j += 6;
			after_len += 6;
		} else {
			*(escaped + j) = c;
			j++;
			after_len++;
		}
	}
#ifdef DEBUG
	fprintf(stderr, escaped);
#endif
	return after_len;
}

/* Precondition caller is responsible for clearing req_buffer before calling. */
size_t _req_sprintf(char *req_buffer, size_t req_buffer_size, const char *format, ...) {
	va_list args;
	char line[PATH_MAX + LINE_LENGTH];
	/* PATH_MAX + LINE_LENGTH for default_settings */
	/* LINE_LENGTH for json requests */
	int len;

	wrap_secure_zero(line, sizeof(line));

	va_start(args, format);
	len = wrap_vsnprintf(line, sizeof(line), format, args);
	va_end(args);

	if (len < 0)
		return -1;

#ifdef DEBUG
	fprintf(stderr, line);
#endif
	wrap_strncat(req_buffer, line, req_buffer_size);

	/* Sanitize sensitive data */
	wrap_secure_zero(line, sizeof(line));

	return len; /* length without null */
}

/* Assemble the entire file of *unsaved* buffers. */
/* The consumer must free it. */
size_t _req_file(char *req_buffer, size_t req_buffer_size, linestruct *filetop) {
	char *escaped = NULL;
	size_t total_len = 0;
	size_t expanded_len = 0;

	size_t base_offset = strlen(req_buffer);

	linestruct *node;
	node = filetop;

	if (node == NULL)
		return -1;

	size_t escaped_length = req_buffer_size;
	escaped = wrap_malloc(escaped_length);
	if (!escaped) {
		statusline(HUSH, "Out of Memory");
	}
	wrap_secure_zero(escaped, escaped_length);

	expanded_len = ycmd_escape_json(node->data, escaped);
	if (total_len + expanded_len + 1 >= req_buffer_size) {
		statusline(HUSH, "You reached the 10 MiB per file limit allowed by the server.  Aborting.");
		wrap_free((void **)&escaped);
		return -1;
	}
	wrap_memcpy(req_buffer + base_offset, escaped, expanded_len);
	total_len += expanded_len;

	node = node->next;

	while (node) {
		if (node->data == NULL)
			node = node->next;

		if (total_len + 2 + 1 >= req_buffer_size) {
			statusline(HUSH, "You reached the 10 MiB per file limit allowed by the server.  Aborting.");
			break;
		}
		*(req_buffer + base_offset + total_len) = '\\';
		*(req_buffer + base_offset + total_len + 1) = 'n';
		total_len += 2;

		expanded_len = ycmd_escape_json(node->data, escaped);
		if (total_len + expanded_len + 1 >= req_buffer_size) {
			statusline(HUSH, "You reached the 10 MiB per file limit allowed by the server.  Aborting.");
			break;
		}
		wrap_memcpy(req_buffer + base_offset + total_len, escaped,
					expanded_len);
		total_len += expanded_len;

		node = node->next;
	}

#ifdef DEBUG
	fprintf(stderr, escaped);
#endif

	/* Sanitize sensitive data */
	wrap_secure_zero(escaped, escaped_length);

	wrap_free((void **)&escaped);

	return total_len;
}

char *_ycmd_get_filetype(char *filepath) {
	static char type[QUARTER_LINE_LENGTH];
	type[0] = '\0';

	static char main_filetype[QUARTER_LINE_LENGTH] = "";
	if (openfile && openfile->filename && main_filetype[0] == '\0') {
		char *ext = strrchr(openfile->filename, '.');
		if (ext) {
			if (strcmp(ext, ".c") == 0) {
				wrap_strncpy(main_filetype, "c", QUARTER_LINE_LENGTH);
			} else if (strcmp(ext, ".cpp") == 0
				|| strcmp(ext, ".cxx") == 0
				|| strcmp(ext, ".cc") == 0) {
				wrap_strncpy(main_filetype, "cpp", QUARTER_LINE_LENGTH);
			} else {
				wrap_strncpy(main_filetype, "identifier", QUARTER_LINE_LENGTH);
			}
			debug_log("Main file %s, set main_filetype=%s", openfile->filename, main_filetype);
		}
	}

	if (!filepath) {
		wrap_strncpy(type, main_filetype[0] ? main_filetype : "identifier", QUARTER_LINE_LENGTH);
	} else if (strstr(filepath, ".cs")) {
		wrap_strncpy(type, "cs", QUARTER_LINE_LENGTH);
	} else if (strstr(filepath, ".go")) {
		wrap_strncpy(type, "go", QUARTER_LINE_LENGTH);
	} else if (strstr(filepath, ".rs")) {
		wrap_strncpy(type, "rust", QUARTER_LINE_LENGTH);
	} else if (strstr(filepath, ".mm")) {
		wrap_strncpy(type, "objcpp", QUARTER_LINE_LENGTH);
	} else if (strstr(filepath, ".m")) {
		wrap_strncpy(type, "objc", QUARTER_LINE_LENGTH);
	} else if (strstr(filepath, ".cpp")
		|| strstr(filepath, ".cxx")
		|| strstr(filepath, ".cc")) {
		wrap_strncpy(type, "cpp", QUARTER_LINE_LENGTH);
	} else if (strstr(filepath, ".c")) {
		wrap_strncpy(type, "c", QUARTER_LINE_LENGTH);
	} else if (strstr(filepath, ".hpp")
		|| strstr(filepath, ".hh")
		|| strstr(filepath, ".h")) {
		wrap_strncpy(type, main_filetype[0] ? main_filetype : "c", QUARTER_LINE_LENGTH);
	} else if (strstr(filepath, ".js")) {
		wrap_strncpy(type, "javascript", QUARTER_LINE_LENGTH);
	} else if (strstr(filepath, ".py")) {
		wrap_strncpy(type, "python", QUARTER_LINE_LENGTH);
	} else if (strstr(filepath, ".ts")) {
		wrap_strncpy(type, "typescript", QUARTER_LINE_LENGTH);
	} else {
		wrap_strncpy(type, "identifier", QUARTER_LINE_LENGTH);
	}

	debug_log("Returning type=%s", type);
	return type;
}

void ycmd_event_file_ready_to_parse(int columnnum, int linenum, char *filepath, linestruct *filetop) {
	if (!ycmd_globals.connected)
		return;

	char *ft = _ycmd_get_filetype(filepath);

	/* Check server if it is compromised before sending sensitive source code (e.g. CMS passwords). */
	int ready = ycmd_rsp_is_server_ready(ft);

	if (ycmd_globals.running && ready) {
		ycmd_json_event_notification(columnnum, linenum, filepath, "FileReadyToParse", filetop);
		ycmd_req_completions_suggestions(linenum, columnnum, filepath, filetop, "filetype_default",
			YCMD_REQ_COMPLETIONS_SUGGESTIONS_EVENT_FILE_READY_TO_PARSE, NULL);
	}
}

void ycmd_event_buffer_unload(int columnnum, int linenum, char *filepath, linestruct *filetop) {
	if (!ycmd_globals.connected)
		return;

	char *ft = _ycmd_get_filetype(filepath);

	/* Check server if it is compromised before sending sensitive source code (e.g. CMS passwords). */
	int ready = ycmd_rsp_is_server_ready(ft);

	if (ycmd_globals.running && ready)
		ycmd_json_event_notification(columnnum, linenum, filepath, "BufferUnload", filetop);
}

void ycmd_event_buffer_visit(int columnnum, int linenum, char *filepath, linestruct *filetop) {
	if (!ycmd_globals.connected)
		return;

	char *ft = _ycmd_get_filetype(filepath);

	/* Check server if it is compromised before sending sensitive source code (e.g. CMS passwords). */
	int ready = ycmd_rsp_is_server_ready(ft);

	if (ycmd_globals.running && ready)
		ycmd_json_event_notification(columnnum, linenum, filepath, "BufferVisit", filetop);
}

void ycmd_event_current_identifier_finished(int columnnum, int linenum, char *filepath, linestruct *filetop) {
	if (!ycmd_globals.connected)
		return;

	char *ft = _ycmd_get_filetype(filepath);

	/* Check server if it is compromised before sending sensitive source code (e.g. CMS passwords). */
	int ready = ycmd_rsp_is_server_ready(ft);

	if (ycmd_globals.running && ready)
		ycmd_json_event_notification(columnnum, linenum, filepath, "CurrentIdentifierFinished", filetop);
}

void do_code_completion(char letter) {
	if (!ycmd_globals.connected)
		return;

	struct funcstruct *func = allfuncs;

	while (func) {
		if (func && (func->menus == MCODECOMPLETION))
			break;
		func = func->next;
	}

	int nbackspaces = openfile->current_x - (ycmd_globals.apply_column - 1);

	int i;
	int j;
	size_t maximum = (((COLS + HALF_LINE_LENGTH) / QUARTER_LINE_LENGTH) * 2);

	for (i = 'A', j = 0; j < maximum && i <= 'F' && func;
		 i++, j++, func = func->next) {
		if (i == letter) {
			if (wrap_strncmp(func->tag, "", 1) == 0)
				break;

			if (func->tag != NULL) {
				while (nbackspaces) {
					do_backspace();
					nbackspaces--;
				}

				openfile->current_x = ycmd_globals.apply_column - 1;

				/* Sanitize func->tag? */
				inject(func->tag, strlen(func->tag));

				wrap_secure_zero(func->tag, strlen(func->tag));
				wrap_free((void **)&func->tag);
				func->tag = strdup("");
				blank_statusbar();
			}

			break;
		}
	}

	bottombars(MMAIN);
}

void do_code_completion_a(void) {
	do_code_completion('A');
}

void do_code_completion_b(void) {
	do_code_completion('B');
}

void do_code_completion_c(void) {
	do_code_completion('C');
}

void do_code_completion_d(void) {
	do_code_completion('D');
}

void do_code_completion_e(void) {
	do_code_completion('E');
}

void do_code_completion_f(void) {
	do_code_completion('F');
}

void do_end_code_completion(void) {
	debug_log("Called function");
	bottombars(MMAIN);
}

void do_end_completer_commands(void) {
	debug_log("Called function");
	bottombars(MMAIN);
}

void constructor_defined_subcommands_results(
	defined_subcommands_results_struct *dsr) {
	wrap_secure_zero(dsr, sizeof(defined_subcommands_results_struct));
}

void destroy_defined_subcommands_results(
	defined_subcommands_results_struct *dsr) {
	if (dsr->json)
		wrap_free((void **)&dsr->json);
}

void do_completer_command_show(void) {
	keystruct *s;
	for (s = sclist; s != NULL; s = s->next) {
		/* 0 is hidden.  1 is visible. */
		s->visibility = 0;
	}

	char *ft = _ycmd_get_filetype(openfile->filename);

	/* It should cache. */
	defined_subcommands_results_struct dsr;
	constructor_defined_subcommands_results(&dsr);
	ycmd_req_defined_subcommands((long)openfile->current->lineno,
				 openfile->current_x, openfile->filename,
				 openfile->filetop, ft, &dsr);

	if (dsr.usable && dsr.response_code == HTTP_OK) {
		for (s = sclist; s != NULL; s = s->next) {
			/* The order matters because of collision.  Do not sort. */
			if (s->func == do_completer_command_clearcompliationflagcache
				&& wrap_strstr(dsr.json, "\"ClearCompilationFlagCache\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_fixit
				&& wrap_strstr(dsr.json, "\"FixIt\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_gotodeclaration
				&& wrap_strstr(dsr.json, "\"GoToDeclaration\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_gotodefinitionelsedeclaration
				&& wrap_strstr(dsr.json, "\"GoToDefinitionElseDeclaration\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_gotodefinition
				&& wrap_strstr(dsr.json, "\"GoToDefinition\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_getdocimprecise
				&& wrap_strstr(dsr.json, "\"GetDocImprecise\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_gotoimprecise
				&& wrap_strstr(dsr.json, "\"GoToImprecise\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_gotoimplementationelsedeclaration
				&& wrap_strstr(dsr.json, "\"GoToImplementationElseDeclaration\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_gotoimplementation
				&& wrap_strstr(dsr.json, "\"GoToImplementation\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_gotoinclude
				&& wrap_strstr(dsr.json, "\"GoToInclude\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_gotoreferences
				&& wrap_strstr(dsr.json, "\"GoToReferences\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_getdoc
				&& wrap_strstr(dsr.json, "\"GetDoc\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_getparent
				&& wrap_strstr(dsr.json, "\"GetParent\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_gettypeimprecise
				&& wrap_strstr(dsr.json, "\"GetTypeImprecise\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_gettype
				&& wrap_strstr(dsr.json, "\"GetType\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_gototype
				&& wrap_strstr(dsr.json, "\"GoToType\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_goto
				&& wrap_strstr(dsr.json, "\"GoTo\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_refactorrename
				&& wrap_strstr(dsr.json, "\"RefactorRename\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_reloadsolution
				&& wrap_strstr(dsr.json, "\"ReloadSolution\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_restartserver
				&& wrap_strstr(dsr.json, "\"RestartServer\""))
				s->visibility = 1;
			else if (s->func == do_completer_command_stopserver
				&& wrap_strstr(dsr.json, "\"StopServer\""))
				s->visibility = 1;

			if (s->func == ycmd_display_parse_results)
				s->visibility = 1;
			if (s->func == do_n_entries)
				s->visibility = 1;
		}
	} else {
		for (s = sclist; s != NULL; s = s->next) {
			/* 0 is hidden.
			 * 1 is visible. */
			s->visibility = 1;
		}
	}

	bottombars(MCOMPLETERCOMMANDS);

	destroy_defined_subcommands_results(&dsr);
}

void do_completer_refactorrename_apply(void) {
	debug_log("Called function");
	bottombars(MMAIN);
}

void do_completer_refactorrename_cancel(void) {
	debug_log("Called function");
	bottombars(MMAIN);
}

void do_end_ycm_extra_conf(void) {
	debug_log("Called function");
	bottombars(MMAIN);
}

void ycmd_display_parse_results() {
	if (!ycmd_globals.file_ready_to_parse_results.json) {
		statusline(HUSH, "Parse results are not usable.");
		return;
	}

	struct passwd *pw = getpwuid(getuid());
	char cache_dir[PATH_MAX];
	sprintf(cache_dir, "%s/.cache/nano-ycmd", pw->pw_dir);
	debug_log("cache_dir = %s", cache_dir);
	mkdir(cache_dir, 0700); /* Create the cache directory if it doesn't exist */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-overflow"
	char doc_filename[PATH_MAX];
	sprintf(doc_filename, "%s/tmpXXXXXX", cache_dir);
#pragma GCC diagnostic pop
	int fdtemp = mkstemp(doc_filename);
	FILE *f = fdopen(fdtemp, "w+");
	fprintf(f, "%s", ycmd_globals.file_ready_to_parse_results.json);
	fclose(f);

	char command[PATH_MAX * 4 + LINE_LENGTH];
	snprintf(command, PATH_MAX * 4 + LINE_LENGTH,
		 "cat '%s' | jq 'to_entries | map({name:.value, index:.key})' > "
		 "'%s.t'; mv '%s.t' '%s'",
		 doc_filename, doc_filename, doc_filename, doc_filename);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
	system(command);
#pragma GCC diagnostic pop

#ifndef DISABLE_MULTIBUFFER
	SET(MULTIBUFFER);
#endif
	/* do_output doesn't handle \n properly and displays it as ^@ so we do it this way */
	open_buffer(doc_filename, FALSE);
	prepare_for_display();

	/* Delete file */
	unlink(doc_filename);
}

void do_ycm_extra_conf_accept(void) {
	char path_project[PATH_MAX];
	char path_extra_conf[PATH_MAX];
	ycmd_get_project_path(path_project);
	int file_safe = 1;
	if (wrap_strncmp(path_project, "(null)", PATH_MAX) != 0 &&
		access(path_project, F_OK) == 0) {
		ycmd_get_extra_conf_path(path_project, path_extra_conf);

		/* Check for potential ACE in the Python file */
		if (check_ace(path_extra_conf) != 0) {
			debug_log("Error: Potential ACE (Arbitrary Code Execution) detected in '%s'\n", path_extra_conf);
			file_safe = 0;
			statusline(ALERT, "Error: Potential ACE detected in .ycm_extra_conf.py");
		}

		/* Check for obfuscated text in the Python file */
		if (check_obfuscated_text(path_extra_conf) != 0) {
			debug_log("Error: Potential obfuscated text detected in '%s'\n", path_extra_conf);
			file_safe = 0;
			statusline(ALERT, "Error: Obfuscated text detected in .ycm_extra_conf.py");
		}

		/* Check for ACE check bypass. */
		if (check_ycm_extra_conf_py_imports(path_extra_conf) != 0) {
			debug_log("Error: Potential circumvention of ACE (Arbitrary Code Execution) check with untrusted imported module in '%s'\n", path_extra_conf);
			file_safe = 0;
			statusline(ALERT, "Error: Untrusted imports in .ycm_extra_conf.py");
		}

		if (access(path_extra_conf, F_OK) == 0 && file_safe == 1) {
			/* It should be number of columns. */
			debug_log("Accepted %s", path_extra_conf);
			statusline(HUSH, "%s", "Loading .ycm_extra_conf.py...");
			ycmd_req_load_extra_conf_file(path_extra_conf);
			statusline(INFO, "%s", "Loaded .ycm_extra_conf.py");
		}
	} else {
		statusline(ALERT, "%s", "No valid project path found");
	}
	close_buffer();
	edit_refresh();
	bottombars(MMAIN);
	full_refresh();
}

void do_ycm_extra_conf_reject(void) {
	char path_project[PATH_MAX];
	char path_extra_conf[PATH_MAX];
	ycmd_get_project_path(path_project);
	if (wrap_strncmp(path_project, "(null)", PATH_MAX) != 0 &&
		access(path_project, F_OK) == 0) {
		ycmd_get_extra_conf_path(path_project, path_extra_conf);

		if (access(path_extra_conf, F_OK) == 0) {
			/* It should be number of columns. */
			debug_log("Rejected %s", path_extra_conf);
			statusline(HUSH, "%s", "Rejected .ycm_extra_conf.py");
			ycmd_req_ignore_extra_conf_file(path_extra_conf);
		} else {
			statusline(ALERT, "%s", "No .ycm_extra_conf.py found");
		}
	} else {
		statusline(ALERT, "%s", "No valid project path found");
	}
	close_buffer();
	edit_refresh();
	bottombars(MMAIN);
	full_refresh();
}

void do_ycm_extra_conf_generate(void) {
#ifndef ENABLE_YCM_GENERATOR
	return;
#endif
	char path_project[PATH_MAX];
	char path_extra_conf[PATH_MAX];
	ycmd_get_project_path(path_project);
	if (wrap_strncmp(path_project, "(null)", PATH_MAX) != 0 &&
		access(path_project, F_OK) == 0) {
		ycmd_get_extra_conf_path(path_project, path_extra_conf);
#ifdef ENABLE_YCM_GENERATOR
		/* It should be number of columns. */
		char display_text[DOUBLE_LINE_LENGTH];
		snprintf(display_text, DOUBLE_LINE_LENGTH, "Generated and accepted %s", path_extra_conf);
		statusline(HUSH, display_text);
		ycmd_gen_extra_conf();
#endif
		ycmd_req_load_extra_conf_file(path_extra_conf);
	}
	close_buffer();
	edit_refresh();
	bottombars(MMAIN);
	full_refresh();
}

void n_entries_refresh(void) { refresh_needed = TRUE; }

void do_n_entries() {
	int max;
	if (COLS <= HALF_LINE_LENGTH)
		max = 2;
	else if (COLS <= LINE_LENGTH)
		max = 4;
	else
		max = 6;
	char max_str[2];
	snprintf(max_str, 2, "%d", max);
	int ret = do_prompt(MNUMSUGGEST, max_str,
#ifndef DISABLE_HISTORIES
		NULL,
#endif
		n_entries_refresh, _("Max number of suggestions"));
	if (ret == 0) {
		ycmd_globals.max_entries = atoi(answer);

		if (ycmd_globals.max_entries > max)
			ycmd_globals.max_entries = max;
		if (ycmd_globals.max_entries < 1)
			ycmd_globals.max_entries = 1;
	}
}

json_t *request_completions(const char *filename, int line, int column,	linestruct *filetop, int event) {
	debug_log("filename='%s', line=%d, column=%d, event=%d",
		filename ? filename : "null", line, column, event);

	json_t *completions = NULL;
	char *completer_target = _ycmd_get_filetype((char *)filename);
	debug_log("completer_target='%s'", completer_target);

	int event_result = ycmd_json_event_notification(column, line, (char *)filename, "FileReadyToParse", filetop);
	debug_log("ycmd_json_event_notification(FileReadyToParse) returned %d", event_result);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
	int result = ycmd_req_completions_suggestions(line, column, (char *)filename, filetop, completer_target, event,
		&completions);
	(void)result; /* Silence warning */
#pragma GCC diagnostic pop

	if (!completions || !json_is_array(completions)) {
		debug_log("Invalid completions, returning empty array");
		if (completions)
			json_decref(completions);
		completions = json_array();
	}

	debug_log("Returning %zu completions", json_array_size(completions));
	return completions;
}
