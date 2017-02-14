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

#include <ne_session.h>

#define HTTP_HEADER_YCM_HMAC "X-Ycm-Hmac"
#define HMAC_SIZE 256/8
#define SECRET_KEY_LENGTH 16
#define DIGITS_MAX 11 //including null character
#define IDLE_SUICIDE_SECONDS 10800 //3 HOURS
#define SEND_TO_SERVER_DELAY 500000

typedef struct file_ready_to_parse_results
{
	int usable;
	char *json_blob; //diagnostic data for FileReadyToParse
	int status_code;
} FILE_READY_TO_PARSE_RESULTS;

typedef struct _ycmd_globals {
	char *scheme;
	char *hostname;
	int port;
	int tcp_socket;
	ne_session *session;
	char *json;
	int running;
	int connected;
	char *secret_key_base64;
	char secret_key_raw[SECRET_KEY_LENGTH];
	char tmp_options_filename[PATH_MAX];
	pid_t child_pid;
	size_t apply_column;
	int clang_completer; //used to fix off by one error for column number
	FILE_READY_TO_PARSE_RESULTS file_ready_to_parse_results;

	//requires gcc5.3 or later  or  clang 3.7.0 or later.  curently disabled since i only have gcc 4.9.4 and clang 3.9.1
	//int have_avx512vl;
	//int have_avx512f;
	//int have_avx512bw;
	int have_avx2;
	int have_sse2;
	int have_sse;
	int have_sse4_1;
	int have_sse4_2;
	int have_mmx;
	int have_popcnt;
	int have_cmov;
} YCMD_GLOBALS;

extern void ycmd_init();
extern void ycmd_destroy();

extern void ycmd_event_file_ready_to_parse(int columnnum, int linenum, char *filepath, filestruct *fileage);
extern void ycmd_event_buffer_unload(int columnnum, int linenum, char *filepath, filestruct *fileage);
extern void ycmd_event_buffer_visit(int columnnum, int linenum, char *filepath, filestruct *fileage);
extern void ycmd_event_current_identifier_finished(int columnnum, int linenum, char *filepath, filestruct *fileage);

extern YCMD_GLOBALS ycmd_globals;

extern void do_code_completion_a(void);
extern void do_code_completion_b(void);
extern void do_code_completion_c(void);
extern void do_code_completion_d(void);
extern void do_code_completion_e(void);
extern void do_code_completion_f(void);
extern void do_code_completion_g(void);
extern void do_code_completion_h(void);
extern void do_code_completion_i(void);
extern void do_code_completion_j(void);
extern void do_code_completion_k(void);
extern void do_code_completion_l(void);
extern void do_code_completion_m(void);
extern void do_code_completion_n(void);
extern void do_code_completion_o(void);
extern void do_code_completion_p(void);
extern void do_code_completion_q(void);
extern void do_code_completion_r(void);
extern void do_code_completion_s(void);
extern void do_code_completion_t(void);
extern void do_code_completion_u(void);
extern void do_code_completion_v(void);
extern void do_code_completion_w(void);
extern void do_code_completion_x(void);
extern void do_code_completion_y(void);
extern void do_code_completion_z(void);
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
extern void do_completer_command_gototype(void);
extern void do_completer_command_clearcompliationflagcache(void);
extern void do_completer_command_getparent(void);
extern void do_completer_command_solutionfile(void);

extern void do_completer_command_show(void);
extern void do_end_completer_commands(void);

extern void do_completer_refactorrename_apply(void);
extern void do_completer_refactorrename_cancel(void);

extern void ycmd_display_parse_results(void);
#endif
