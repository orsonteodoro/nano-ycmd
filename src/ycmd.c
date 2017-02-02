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


#ifdef USE_NETTLE
#include <nettle/base64.h>
#include <nettle/hmac.h>
#define SSL_LIB "NETTLE"
#endif
#ifdef USE_OPENSSL
#include <openssl/hmac.h>
#include <glib/gstdio.h>
#define SSL_LIB "OPENSSL"
#endif
#ifndef SSL_LIB
#error "You must choose a crypto library to use ycmd code completion support.  Currently nettle and openssl are supported."
#endif

#include <fcntl.h>
#include <glib.h>
#include <glib/gregex.h>
#include <limits.h>
#include <ne_request.h>
#include <ne_session.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "nxjson.h"
#include "proto.h"
#include "ycmd.h"
#include "nano.h"
#include "proto.h"

//notes:
//protocol documentation: https://gist.github.com/hydrargyrum/78c6fccc9de622ad9d7b
//method documentation: http://micbou.github.io/ycmd/
//reference client: https://github.com/Valloric/ycmd/blob/master/examples/example_client.py
//ycm https://github.com/Valloric/YouCompleteMe/blob/master/README.md
//json escape: http://szydan.github.io/json-escape/

//todo add C/C++ with ycm-generator
//notes: currently only works non C family languages

char *ycmd_compute_request(char *method, char *path, char *body);
void ycmd_stop_server();
void ycmd_start_server();
char *_ne_read_response_body_full(ne_request *request);
void escape_json(char **buffer);
void ycmd_generate_secret_raw(char *secret);
char *ycmd_generate_secret_base64(char *secret);
void ycmd_restart_server();

//A function signature to use.  Either it can come from an external library or object code.
extern char* string_replace(const char* src, const char* find, const char* replace);

YCMD_GLOBALS ycmd_globals;

void *_expand(void *ptr, size_t new_size)
{
	void *out;
	out = realloc(ptr, new_size);
	if (out == NULL)
	{
#ifdef DEBUG
		fprintf(stderr,"Error\n");
		exit(-1);
#endif
	}
	return out;
}

//There was no gpl3+ string replace so I made one from scratch.
char *string_replace_gpl3(char *buffer, char *find, char *replace)
{
	char *out;
	int lenb = strlen(buffer);
	int lenf = strlen(find);
	int lenr = strlen(replace);
	int cf;
	int i = 0;
	int j = 0;
	int k = 0;
	int oi = 0;
	char *p;

	out = malloc(1);
	out[0] = 0;

	p = buffer;
	int outlen = 1;

	for (i=0;i<lenb;)
	{
		cf = 0;
		for(j=0;j<lenf && i+j < lenb;j++)
		{
			if ( p[i+j] == find[j] )
				cf++;
		}
		if (cf == lenf)
		{
#ifdef DEBUG
		        fprintf(stderr, "string_replace_gpl3 found: %s\n", find);
#endif
			out=_expand(out, outlen+=lenr);
			for(k=0;k<lenr;k++)
				out[oi++] = replace[k];
			i+=lenf;
		}
		else
		{
			out=_expand(out, outlen+=1);
			out[oi++]=p[i];
			i++;
		}
	}
	out[oi]=0;

#ifdef DEBUG
	fprintf(stderr, "string_replace_gpl3: %s\n", out);
#endif

	return out;
}

//A wrapper function that takes any string_replace.
void string_replace_w(char **buffer, char *find, char *replace)
{
	char *b;
	b = *buffer;
	*buffer = string_replace_gpl3(*buffer, find, replace);
	free(b);
}

void ycmd_init()
{
#ifdef DEBUG
	fprintf(stderr, "Init ycmd.\n");
#endif
	ycmd_globals.session = 0;
	ycmd_globals.scheme = "http";
	ycmd_globals.hostname = "127.0.0.1";
	ycmd_globals.port = 0;
	ycmd_globals.child_pid=-1;
	ycmd_globals.secret_key_base64 = NULL;
	ycmd_globals.json = NULL;

	ycmd_generate_secret_raw(ycmd_globals.secret_key_raw);
	ycmd_globals.secret_key_base64 = strdup(ycmd_generate_secret_base64(ycmd_globals.secret_key_raw));
#ifdef DEBUG
	fprintf(stderr, "HMAC secret is: %s\n", ycmd_globals.secret_key_base64);
#endif

	ne_sock_init();

	int tries = 10;
	int i = 0;
	for(i = 0; i < tries && ycmd_globals.connected == 0; i++)
		ycmd_restart_server();

	if (!ycmd_globals.connected)
	{
#ifdef DEBUG
		fprintf(stderr, "Check your ycmd or recompile nano with the proper settings...\n");
#endif
	}
}

//needs to be freed
char *ycmd_create_default_json()
{

	char *_json = "{"
		"  \"filepath_completion_use_working_dir\": 0,"
		"  \"auto_trigger\": 1,"
		"  \"min_num_of_chars_for_completion\": 2,"
		"  \"min_num_identifier_candidate_chars\": 0,"
		"  \"semantic_triggers\": {},"
		"  \"filetype_specific_completion_to_disable\": {"
		"    \"gitcommit\": 1"
		"  },"
		"  \"seed_identifiers_with_syntax\": 0,"
		"  \"collect_identifiers_from_comments_and_strings\": 0,"
		"  \"collect_identifiers_from_tags_files\": 0,"
		"  \"max_num_identifier_candidates\": 10,"
		"  \"extra_conf_globlist\": [],"
		"  \"global_ycm_extra_conf\": \"\","
		"  \"confirm_extra_conf\": 1,"
		"  \"complete_in_comments\": 0,"
		"  \"complete_in_strings\": 1,"
		"  \"max_diagnostics_to_display\": 30,"
		"  \"filetype_whitelist\": {"
		"    \"*\": 1"
		"  },"
		"  \"filetype_blacklist\": {"
		"    \"tagbar\": 1,"
		"    \"qf\": 1,"
		"    \"notes\": 1,"
		"    \"markdown\": 1,"
		"    \"netrw\": 1,"
		"    \"unite\": 1,"
		"    \"text\": 1,"
		"    \"vimwiki\": 1,"
		"    \"pandoc\": 1,"
		"    \"infolog\": 1,"
		"    \"mail\": 1"
		"  },"
		"  \"auto_start_csharp_server\": 1,"
		"  \"auto_stop_csharp_server\": 1,"
		"  \"use_ultisnips_completer\": 1,"
		"  \"csharp_server_port\": 0,"
		"  \"hmac_secret\": \"HMAC_SECRET\","
		"  \"server_keep_logfiles\": 0,"
		"  \"gocode_binary_path\": \"GOCODE_PATH\","
		"  \"godef_binary_path\": \"GODEF_PATH\","
		"  \"rust_src_path\": \"RUST_SRC_PATH\","
		"  \"racerd_binary_path\": \"RACERD_PATH\","
		"  \"python_binary_path\": \"PYTHON_PATH\""
		"}";
	static char *json;
	json = strdup(_json);
	return json;
}

void _ycmd_json_replace_file_data(char **json, char *filepath, char *content)
{
	if (filepath[0] != '/')
	{
		char abs_filepath[PATH_MAX];
		getcwd(abs_filepath, PATH_MAX);
		strcat(abs_filepath,"/");
		strcat(abs_filepath,filepath);
		string_replace_w(json, "FILEPATH", abs_filepath);
	}
	else
		string_replace_w(json, "FILEPATH", filepath);

	if (strstr(filepath,".cs"))
		string_replace_w(json, "FILETYPES", "cs");
	else if (strstr(filepath,".go"))
		string_replace_w(json, "FILETYPES", "go");
	else if (strstr(filepath,".rs"))
		string_replace_w(json, "FILETYPES", "rust");
	else if (strstr(filepath,".mm"))
		string_replace_w(json, "FILETYPES", "objcpp");
	else if (strstr(filepath,".m"))
		string_replace_w(json, "FILETYPES", "objc");
	else if (strstr(filepath,".cpp") || strstr(filepath,".C") || strstr(filepath,".cxx"))
		string_replace_w(json, "FILETYPES", "cpp");
	else if (strstr(filepath,".c"))
		string_replace_w(json, "FILETYPES", "c");
	else if (strstr(filepath,".hpp"))
		string_replace_w(json, "FILETYPES", "cpp");
	else if (strstr(filepath,".h"))
	{
		if (strstr(content, "using namespace") || strstr(content, "iostream") || strstr(content, "\tclass ") || strstr(content, " class ")
			|| strstr(content, "private:") || strstr(content, "public:") || strstr(content, "protected:"))
			string_replace_w(json, "FILETYPES", "cpp");
		else
			string_replace_w(json, "FILETYPES", "c");
	}
	else if (strstr(filepath,".js"))
		string_replace_w(json, "FILETYPES", "javascript");
	else if (strstr(filepath,".py"))
		string_replace_w(json, "FILETYPES", "python");
	else if (strstr(filepath,".ts"))
		string_replace_w(json, "FILETYPES", "typescript");

	string_replace_w(json, "CONTENTS", content);
}

int ycmd_json_event_notification(int columnnum, int linenum, char *filepath, char *eventname, char *content)
{
#ifdef DEBUG
	fprintf(stderr, "Entering ycmd_json_event_notification()\n");
#endif
	char *method = "POST";
	char *path = "/event_notification";
	//we should use a json library but licensing problems
	char *_json = "{"
		"        \"column_num\": COLUMN_NUM,"
		"        \"event_name\": \"EVENT_NAME\","
		"        \"file_data\": {"
		"		\"FILEPATH\": {"
		"                \"contents\": \"CONTENTS\","
		"                \"filetypes\": [\"FILETYPES\"]"
		"        	}"
		"	 },"
		"        \"filepath\": \"FILEPATH\","
		"        \"line_num\": LINE_NUM"
		"}";
	char *json;
	json = strdup(_json);

	char line_num[DIGITS_MAX];
	char column_num[DIGITS_MAX];

	snprintf(line_num, DIGITS_MAX, "%d", linenum+1);
	snprintf(column_num, DIGITS_MAX, "%d", columnnum+1);

	string_replace_w(&json, "COLUMN_NUM", column_num);
	string_replace_w(&json, "EVENT_NAME", eventname);

	string_replace_w(&json, "LINE_NUM", line_num);

	_ycmd_json_replace_file_data(&json, filepath, content);

#ifdef DEBUG
	fprintf(stderr, "json body in ycmd_json_event_notification: %s\n", json);
#endif

	int status_code = 0;
	ne_request *request;
	request = ne_request_create(ycmd_globals.session, method, path);
	{
		ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,0);
		ne_add_request_header(request,"content-type","application/json");
		char *ycmd_b64_hmac = ycmd_compute_request(method, path, json);
		ne_add_request_header(request, HTTP_REQUEST_HEADER_YCM_HMAC, ycmd_b64_hmac);
		ne_set_request_body_buffer(request, json, strlen(json));

#ifdef DEBUG
		fprintf(stderr,"Getting server response\n");
#endif

		int ret = ne_begin_request(request);
		if (ret >= 0)
		{
			char *response = _ne_read_response_body_full(request);
			ne_end_request(request);
#ifdef DEBUG
			fprintf(stderr,"Server response: %s\n", response);
#endif

			free(response);
		}

		status_code = ne_get_status(request)->code;
	}
        ne_request_destroy(request);

	free(json);

#ifdef DEBUG
	fprintf(stderr, "Status code in ycmd_json_event_notification is %d\n", status_code);
#endif

	return status_code == 200;
}

//returned value must be free()
char *_ne_read_response_body_full(ne_request *request)
{
#ifdef DEBUG
	fprintf(stderr, "Entering _ne_read_response_body_full()\n");
#endif
	char *response_body;
	response_body = NULL;

	ssize_t chunksize = 512;
	ssize_t nread = 0;
	response_body = malloc(chunksize);
	memset(response_body,0,chunksize);
	ssize_t readlen = 0;
	while(666)
	{
#ifdef DEBUG
		fprintf(stderr, "looping\n");
#endif
		if (ne_get_status(request)->klass == 2)
		{
			readlen = ne_read_response_block(request, response_body+nread, chunksize);
		}
		else
		{
#ifdef DEBUG
			fprintf(stderr, "Request is not success.  Discarding request. (2)\n");
#endif
			ne_discard_response(request);
			break;
		}
#ifdef DEBUG
		fprintf(stderr, "readlen %d\n",readlen);
#endif
		if (readlen <= 0)
		{
#ifdef DEBUG
			fprintf(stderr,"%s\n",ne_get_error(ycmd_globals.session));
#endif
			break;
		}

		nread+=readlen;
		char *response_body_new = realloc(response_body, nread+chunksize);
		if (response_body_new == NULL)
		{
#ifdef DEBUG
			fprintf(stderr, "realloc failed in _ne_read_response_body_full\n");
#endif
			break;
		}
		response_body = response_body_new;
	}
#ifdef DEBUG
	fprintf(stderr, "Done _ne_read_response_body_full\n");
#endif

	return response_body;
}

//get the list of possible completions
int ycmd_req_completions_suggestions(int linenum, int columnnum, char *filepath, char *content, char *completertarget)
{
#ifdef DEBUG
	fprintf(stderr, "Entering ycmd_req_completions_suggestions()\n");
#endif

	char *method = "POST";
	char *path = "/completions";

	//todo handle without string replace
	char *_json = "{"
		"        \"line_num\": LINE_NUM,"
		"        \"column_num\": COLUMN_NUM,"
		"        \"filepath\": \"FILEPATH\","
		"        \"file_data\": {"
		"		\"FILEPATH\": {"
		"                \"contents\": \"CONTENTS\","
		"                \"filetypes\": [\"FILETYPES\"]"
		"        	}"
		"	 },"
		"        \"completer_target\": \"COMPLETER_TARGET\""
		"}";

	char *json;
	json = strdup(_json);

	char line_num[DIGITS_MAX];
	char column_num[DIGITS_MAX];

	snprintf(line_num, DIGITS_MAX, "%d", linenum+1);
	snprintf(column_num, DIGITS_MAX, "%d", columnnum+1);

	string_replace_w(&json, "LINE_NUM", line_num);
	string_replace_w(&json, "COLUMN_NUM", column_num);
	string_replace_w(&json, "COMPLETER_TARGET", completertarget);

	_ycmd_json_replace_file_data(&json, filepath, content);

#ifdef DEBUG
	fprintf(stderr, "json body in ycmd_req_completions_suggestions: %s\n", json);
#endif

	struct subnfunc *func = allfuncs;

	while(func)
	{
		if (func && func->menus & MCODECOMPLETION)
			break;
		func = func->next;
	}

	int status_code = 0;
	ne_request *request;
	request = ne_request_create(ycmd_globals.session, method, path);
	if (request)
	{
		ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,0);
		char *response_body;
		//int apply_column = -1;

		ne_add_request_header(request,"content-type","application/json");
		char *ycmd_b64_hmac = ycmd_compute_request(method, path, json);
		ne_add_request_header(request, HTTP_REQUEST_HEADER_YCM_HMAC, ycmd_b64_hmac);
		ne_set_request_body_buffer(request, json, strlen(json));

		int ret = ne_begin_request(request);
		if (ret >= 0)
		{
			response_body = _ne_read_response_body_full(request);
			ne_end_request(request);
#ifdef DEBUG
			fprintf(stderr,"Server response (SUGGESTIONS): %s\n", response_body);
#endif
		}

		//output should look like:
		//{"errors": [], "completion_start_column": 22, "completions": [{"insertion_text": "Wri", "extra_menu_info": "[ID]"}, {"insertion_text": "WriteLine", "extra_menu_info": "[ID]"}]}

		//int apply_column = 0;
		status_code = ne_get_status(request)->code;
		int found_cc_entry = 0;
		if (strstr(response_body, "completion_start_column"))
		{
			const nx_json *pjson = nx_json_parse_utf8(response_body);

			const nx_json *completions = nx_json_get(pjson, "completions");
			int i = 0;
			int j = 0;
			int maxlist = MAIN_VISIBLE;
#ifdef DEBUG
			fprintf(stderr,"maxlist = %d, cols = %d\n", maxlist, COLS);
#endif

			for (i = 0; i < completions->length && j < maxlist && j < 26 && func; i++, j++) //26 for 26 letters A-Z
			{
				const nx_json *candidate = nx_json_item(completions, i);
				const nx_json *insertion_text = nx_json_get(candidate, "insertion_text");
				if (func->desc != NULL)
					free((void *)func->desc);
				func->desc = strdup(insertion_text->text_value);
#ifdef DEBUG
				fprintf(stderr,">Added completion entry to nano toolbar: %s\n", insertion_text->text_value);
#endif
				found_cc_entry = 1;
				func = func->next;
			}
			for (i = j; i < maxlist && i < 26 && func; i++, func = func->next)
			{
				if (func->desc != NULL)
					free((void *)func->desc);
				func->desc = strdup("");
#ifdef DEBUG
				fprintf(stderr,">Deleting unused entry: %d\n", i);
#endif
			}
			ycmd_globals.apply_column = nx_json_get(pjson, "completion_start_column")->int_value;

			nx_json_free(pjson);
		}

		if (found_cc_entry)
		{
#ifdef DEBUG
			fprintf(stderr,"Showing completion bar.\n");
#endif
			bottombars(MCODECOMPLETION);
			statusline(HUSH, "Code completion triggered");
		}

		free(response_body);
		ne_request_destroy(request);
	}

	free(json);

#ifdef DEBUG
	fprintf(stderr, "Status code in ycmd_req_completions_suggestions is %d\n", status_code);
#endif

	return status_code == 200;
}

//preconditon: server must be up and initalized
int ycmd_rsp_is_healthy_simple()
{
	//this function works
#ifdef DEBUG
	fprintf(stderr, "Entering ycmd_rsp_is_healthy_simple()\n");
#endif
	char *method = "GET";
	char *path = "/healthy";

	int status_code = 0;
	ne_request *request;
	request = ne_request_create(ycmd_globals.session, method, path);
	{
		ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,1);
		char *ycmd_b64_hmac = ycmd_compute_request(method, path, "");
		ne_add_request_header(request, HTTP_REQUEST_HEADER_YCM_HMAC, ycmd_b64_hmac);

		int ret = ne_begin_request(request);
		if (ret >= 0)
		{
			char *response_body = _ne_read_response_body_full(request);
			ne_end_request(request);
#ifdef DEBUG
			fprintf(stderr, "Server response: %s\n", response_body); //should just say: true
#endif
			free(response_body);
		}

		status_code = ne_get_status(request)->code;
	}
        ne_request_destroy(request);

#ifdef DEBUG
	fprintf(stderr, "Status code in ycmd_rsp_is_healthy_simple is %d\n", status_code);
#endif

	return status_code == 200;
}



int ycmd_rsp_is_healthy(int include_subservers)
{
	//this function doesn't work
#ifdef DEBUG
	fprintf(stderr, "Entering ycmd_rsp_is_healthy()\n");
#endif
	char *method = "GET";
	char *_path = "/healthy?include_subservers=VALUE";
	char *path;
	path = strdup(_path);

	if (include_subservers)
		string_replace_w(&path, "VALUE", "1");
	else
		string_replace_w(&path, "VALUE", "0");

	int status_code = 0;
	ne_request *request;
	request = ne_request_create(ycmd_globals.session, method, path);
	if (request)
	{
		ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,1);
		char *ycmd_b64_hmac = ycmd_compute_request(method, path, "");
		ne_add_request_header(request, HTTP_REQUEST_HEADER_YCM_HMAC, ycmd_b64_hmac);

		int ret = ne_begin_request(request);
		if (ret >= 0)
		{

			char *response_body = _ne_read_response_body_full(request);
			ne_end_request(request);
#ifdef DEBUG
			fprintf(stderr, "Server response: %s\n", response_body); //should just say: true
#endif
			free(response_body);
		}

		status_code = ne_get_status(request)->code;
		ne_request_destroy(request);
	}
	else
	{
#ifdef DEBUG
		fprintf(stderr, "Create request failed in ycmd_rsp_is_healthy\n");
#endif
	}

	free(path);

#ifdef DEBUG
	fprintf(stderr, "Status code in ycmd_rsp_is_healthy is %d\n", status_code);
#endif

	return status_code == 200;
}

//include_subservers refers to checking omnisharp server or other completer servers
int ycmd_rsp_is_server_ready(char *filetype)
{
#ifdef DEBUG
	fprintf(stderr, "Entering ycmd_rsp_is_server_ready()\n");
#endif
	char *method = "GET";
	char *_path = "/ready?subserver=FILE_TYPE";
	char *path;
	path = strdup(_path);

	string_replace_w(&path, "FILE_TYPE", filetype);

#ifdef DEBUG
	fprintf(stderr,"ycmd_rsp_is_server_ready path is %s\n",path);
#endif

	int status_code = 0;

	ne_request *request;
	request = ne_request_create(ycmd_globals.session, method, path);
	if (request)
	{
		ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,1);
		ne_request_dispatch(request);
		status_code = ne_get_status(request)->code;
		ne_request_destroy(request);
	}
	else
	{
#ifdef DEBUG
		fprintf(stderr, "Create request failed in ycmd_rsp_is_server_ready\n");
#endif
	}

	free(path);

#ifdef DEBUG
	fprintf(stderr, "Status code in ycmd_rsp_is_server_ready is %d\n", status_code);
#endif

	return status_code == 200;
}

int _ycmd_req_simple_request(char *method, char *path, int linenum, int columnnum, char *filepath, char *content)
{
#ifdef DEBUG
	fprintf(stderr, "Entering _ycmd_req_simple_request()\n");
#endif
	char *_json = "{"
		"        \"line_num\": LINE_NUM,"
		"        \"column_num\": COLUMN_NUM,"
		"        \"filepath\": \"FILEPATH\","
		"        \"file_data\": {"
		"		\"FILEPATH\": {"
		"                \"contents\": \"CONTENTS\","
		"                \"filetypes\": [\"FILETYPES\"]"
		"        	}"
		"	 }"
		"}";
	char *json;
	json = strdup(_json);

	char line_num[DIGITS_MAX];
	char column_num[DIGITS_MAX];

	snprintf(line_num, DIGITS_MAX, "%d", linenum+1);
	snprintf(column_num, DIGITS_MAX, "%d", columnnum+1);

	string_replace_w(&json, "LINE_NUM", line_num);
	string_replace_w(&json, "COLUMN_NUM", column_num);

	_ycmd_json_replace_file_data(&json, filepath, content);

	int status_code = 0;
	ne_request *request;
	request = ne_request_create(ycmd_globals.session, method, path);
	if (request)
	{
		ne_add_request_header(request,"content-type","application/json");
		if (strcmp(method, "POST") == 0)
		{
			ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,0);
			char *ycmd_b64_hmac = ycmd_compute_request(method, path, json);
			ne_add_request_header(request, HTTP_REQUEST_HEADER_YCM_HMAC, ycmd_b64_hmac);
		}
		else
		{
			ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,1);
		}

		ne_set_request_body_buffer(request, json, strlen(json));

		int ret = ne_begin_request(request);
		if (ret >= 0)
		{
			char *response_body = _ne_read_response_body_full(request);
			ne_end_request(request);
#ifdef DEBUG
			fprintf(stderr, "Server response: %s",response_body);
#endif
			free(response_body);
		}

		status_code = ne_get_status(request)->code;
		ne_request_destroy(request);
	}

	free(json);

#ifdef DEBUG
	fprintf(stderr, "Status code in _ycmd_req_simple_request is %d\n", status_code);
#endif

	return status_code == 200;
}

void ycmd_req_load_extra_conf_file(int linenum, int columnnum, char *filepath, char *filedata)
{
#ifdef DEBUG
	fprintf(stderr, "Entering ycmd_req_load_extra_conf_file()\n");
#endif
	char *method = "POST";
	char *path = "/load_extra_conf_file";

	_ycmd_req_simple_request(method, path, linenum, columnnum, filepath, filedata);
}

void ycmd_req_ignore_extra_conf_file(int linenum, int columnnum, char *filepath, char *filedata)
{
#ifdef DEBUG
	fprintf(stderr, "Entering ycmd_req_ignore_extra_conf_file()\n");
#endif
	char *method = "POST";
	char *path = "/ignore_extra_conf_file";

	_ycmd_req_simple_request(method, path, linenum, columnnum, filepath, filedata);
}

void ycmd_req_semantic_completion_available(int linenum, int columnnum, char *filepath, char *filedata)
{
#ifdef DEBUG
	fprintf(stderr, "Entering ycmd_req_semantic_completion_available()\n");
#endif
	char *method = "POST";
	char *path = "/semantic_completer_available";

	_ycmd_req_simple_request(method, path, linenum, columnnum, filepath, filedata);
}

int find_unused_localhost_port()
{
	int port = 0;

	struct sockaddr_in address;
	ycmd_globals.tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (ycmd_globals.tcp_socket == -1)
	{
#ifdef DEBUG
		fprintf(stderr,"Failed to create socket.\n");
#endif
		return -1;
	}

	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = 0;

	if (!bind(ycmd_globals.tcp_socket, &address, sizeof(address)))
	{
		socklen_t addrlen = sizeof(address);
		if (getsockname(ycmd_globals.tcp_socket, &address, &addrlen) == -1)
		{
			close(ycmd_globals.tcp_socket);

#ifdef DEBUG
			fprintf(stderr,"Failed to obtain unused socket.\n");
#endif
			return -1;
		}

		port = address.sin_port;
		close(ycmd_globals.tcp_socket);
#ifdef DEBUG
		fprintf(stderr,"Found unused port at %d.\n", port);
#endif

		return port;
	}
	else
	{
#ifdef DEBUG
		fprintf(stderr,"Failed to find unused port.\n");
#endif
	}

	close(ycmd_globals.tcp_socket);
	return -1;
}

void ycmd_destroy()
{
	if (ycmd_globals.secret_key_base64)
		free(ycmd_globals.secret_key_base64);

#ifdef DEBUG
	fprintf(stderr, "Called ycmd_destroy.\n");
#endif
	ycmd_stop_server();
}

void ycmd_start_server()
{
#ifdef DEBUG
	fprintf(stderr, "Starting ycmd server.\n");
#endif
	ycmd_globals.port = find_unused_localhost_port();

	if (ycmd_globals.port == -1)
	{
#ifdef DEBUG
		fprintf(stderr,"Failed to find unused port.\n");
#endif
		return;
	}

#ifdef DEBUG
	fprintf(stderr, "Server will be running on http://localhost:%d\n", ycmd_globals.port);
#endif

	ycmd_globals.json = ycmd_create_default_json();

	string_replace_w(&ycmd_globals.json, "HMAC_SECRET", ycmd_globals.secret_key_base64);
	string_replace_w(&ycmd_globals.json, "GOCODE_PATH", GOCODE_PATH);
	string_replace_w(&ycmd_globals.json, "GODEF_PATH", GODEF_PATH);
	string_replace_w(&ycmd_globals.json, "RUST_SRC_PATH", RUST_SRC_PATH);
	string_replace_w(&ycmd_globals.json, "RACERD_PATH", RACERD_PATH);
	string_replace_w(&ycmd_globals.json, "PYTHON_PATH", PYTHON_PATH);

#ifdef DEBUG
	fprintf(stderr,"JSON file contents: %s\n",ycmd_globals.json);

	fprintf(stderr,"Attempting to create temp file\n");
#endif
	strcpy(ycmd_globals.tmp_options_filename,"/tmp/nanoXXXXXX");
	int fdtemp = mkstemp(ycmd_globals.tmp_options_filename);
#ifdef DEBUG
	fprintf(stderr, "tempname is %s\n", ycmd_globals.tmp_options_filename);
#endif
	FILE *f = fdopen(fdtemp,"w+");
	fprintf(f, "%s", ycmd_globals.json);
	fclose(f);

	//fork
	int pid = fork();
#ifdef DEBUG
	fprintf(stderr,"pid is %d.\n",pid);
#endif
	if (pid == 0)
	{
		//child
		char port_value[DIGITS_MAX];
		char options_file_value[PATH_MAX];
		char idle_suicide_seconds_value[DIGITS_MAX];
		char ycmd_path[PATH_MAX];

		snprintf(port_value,DIGITS_MAX,"%d",ycmd_globals.port);
		snprintf(options_file_value,PATH_MAX,"%s", ycmd_globals.tmp_options_filename);
		snprintf(idle_suicide_seconds_value,DIGITS_MAX,"%d",IDLE_SUICIDE_SECONDS);
		snprintf(ycmd_path,PATH_MAX,"%s",YCMD_PATH);

#ifdef DEBUG
		fprintf(stderr, "PYTHON_PATH is %s\n",PYTHON_PATH);
		fprintf(stderr, "YCMD_PATH is %s\n",YCMD_PATH);
		fprintf(stderr, "port_value %s\n", port_value);
		fprintf(stderr, "options_file_value %s\n", options_file_value);
		fprintf(stderr, "idle_suicide_seconds_value %s\n", idle_suicide_seconds_value);
		fprintf(stderr, "generated server command: %s %s %s %s %s %s %s %s\n", PYTHON_PATH, YCMD_PATH, "--port", port_value, "--options_file", options_file_value, "--idle_suicide_seconds", idle_suicide_seconds_value);

		fprintf(stderr, "Child process is going to start the server...\n");
#endif

		//after execl executes, the server will delete the tmpfile
		execl(PYTHON_PATH, PYTHON_PATH, ycmd_path, "--port", port_value, "--options_file", options_file_value, "--idle_suicide_seconds", idle_suicide_seconds_value, "--stdout", "/dev/null", "--stderr", "/dev/null", NULL);

#ifdef DEBUG
		fprintf(stderr, "Child process server exit on abnormal condition.  Exiting child process...\n");
#endif
		//continue if fail

		if (access(ycmd_globals.tmp_options_filename, F_OK) == 0)
			unlink(ycmd_globals.tmp_options_filename);

		exit(1);
	}
	else
	{
		//parent
#ifdef DEBUG
		fprintf(stderr, "Parent process is waiting for server to load...\n");
#endif
		//parent
	}

#ifdef DEBUG
	fprintf(stderr, "Parent process creating neon session...\n");
#endif
	ycmd_globals.child_pid = pid;
	ycmd_globals.session = ne_session_create(ycmd_globals.scheme, ycmd_globals.hostname, ycmd_globals.port);
	ne_set_read_timeout(ycmd_globals.session,1);

	/*
#ifdef DEBUG
	fprintf(stderr, "Parent process checking server status...\n");
#endif
	if (ycmd_rsp_is_server_ready(1))
	{
#ifdef DEBUG
		fprintf(stderr,"ycmd server is up.\n");
#endif
		ycmd_globals.running = 1;
	}
	else
	{
#ifdef DEBUG
		fprintf(stderr,"ycmd server is down.\n");
#endif
		ycmd_stop_server();
	}
	*/

#ifdef DEBUG
	fprintf(stderr, "Parent process: checking if child PID is still alive...\n");
#endif
	if (waitpid(pid,0,WNOHANG) == 0)
	{
		statusline(HUSH, "Server just ran....");
#ifdef DEBUG
		fprintf(stderr,"ycmd server is up.\n");
#endif
		ycmd_globals.running = 1;
	}
	else
	{
		statusline(HUSH, "Server didn't ran....");
#ifdef DEBUG
		fprintf(stderr,"ycmd failed to load server.\n");
#endif
		ycmd_globals.running = 0;

		ycmd_stop_server();
		return;
	}

	statusline(HUSH, "Letting the server initialize.  Wait....");

	//give time for the server initialize
	usleep(5000000);

	statusline(HUSH, "Checking server health....");

	int i;
	int tries = 5;
	for (i = 0; i < tries && ycmd_globals.connected == 0; i++)
	{
#ifdef DEBUG
		fprintf(stderr, "Parent process: checking ycmd server health by communicating with it...\n");
#endif
		if (ycmd_rsp_is_healthy_simple())
		{
			statusline(HUSH, "Connected....");
#ifdef DEBUG
			fprintf(stderr,"Client can communicate with server.\n");
#endif
			ycmd_globals.connected = 1;
		}
		else
		{
			statusline(HUSH, "Connect failed....");
#ifdef DEBUG
			fprintf(stderr,"Client cannot communicate with server.  Retrying...\n");
#endif
			ycmd_globals.connected = 0;
			usleep(1000000);
		}
	}
}

void ycmd_stop_server()
{
#ifdef DEBUG
	fprintf(stderr, "ycmd_stop_server called.\n");
#endif
	ne_close_connection(ycmd_globals.session);
	ne_session_destroy(ycmd_globals.session);
	close(ycmd_globals.tcp_socket);

	if (ycmd_globals.json)
		free(ycmd_globals.json);
	if (access(ycmd_globals.tmp_options_filename, F_OK) == 0)
		unlink(ycmd_globals.tmp_options_filename);
	if (ycmd_globals.child_pid != -1)
	{
		kill(ycmd_globals.child_pid, SIGKILL);
#ifdef DEBUG
		fprintf(stderr, "Kill called\n");
#endif
	}
	ycmd_globals.child_pid = -1;

	ycmd_globals.running = 0;
	ycmd_globals.connected = 0;
}

void ycmd_restart_server()
{
	if (ycmd_globals.running)
		ycmd_stop_server();

	ycmd_start_server();
}

void ycmd_generate_secret_raw(char *secret)
{
	FILE *random_file;
	statusline(HUSH, "Obtaining secret random key.  I need more entropy.  Type on the keyboard or move the mouse.");
	random_file = fopen("/dev/random", "r");
	size_t nread = fread(secret, 1, SECRET_KEY_LENGTH, random_file);
	if (nread != SECRET_KEY_LENGTH)
	{
#ifdef DEBUG
		fprintf(stderr, "Failed to obtain 16 bytes of data for the secret key.\n");
#endif
	}
#ifdef DEBUG
	fprintf(stderr, "read %d bytes of /dev/random\n", (int)nread);
#endif
	fclose(random_file);
	blank_statusbar();

	//this section is credited to marchelzo and twkm from freenode ##C channel for flushing stdin excessive characters after user adds entropy.
	total_refresh();
	statusline(HUSH, "Please stop typing.  Clearing input buffer...");
	nodelay(stdscr, TRUE);  while (getch() != ERR); nodelay(stdscr, FALSE);
	total_refresh();
	statusline(HUSH, "Please stop typing.  Clearing input buffer...");

	usleep(1000000*5);
	fflush(stdin);

	total_refresh();
	statusline(HUSH, "Please stop typing.  Clearing input buffer...");
	nodelay(stdscr, TRUE); while (getch() != ERR); nodelay(stdscr, FALSE);
	total_refresh();

	statusline(HUSH, "Input buffer cleared.");
}

char *ycmd_generate_secret_base64(char *secret)
{
#ifdef USE_NETTLE
	static char b64_secret[BASE64_ENCODE_RAW_LENGTH(SECRET_KEY_LENGTH)];
	base64_encode_raw((unsigned char *)b64_secret, SECRET_KEY_LENGTH, (unsigned char *)secret);
#ifdef DEBUG
	fprintf(stderr,"base64 secret is %s\n",b64_secret);
#endif
	return b64_secret;
#elif USE_OPENSSL
	static char b64_secret[80];
        gchar *_b64_secret = g_base64_encode((unsigned char *)secret, SECRET_KEY_LENGTH);
	strcpy(b64_secret, _b64_secret);
	free (_b64_secret);
#ifdef DEBUG
	fprintf(stderr,"base64 secret is %s\n",b64_secret);
#endif
	return b64_secret;
#else
#error "You need to define a crypto library to use."
#endif
}

char *ycmd_compute_request(char *method, char *path, char *body)
{
#ifdef USE_NETTLE
#ifdef DEBUG
	fprintf(stderr, "ycmd_compute_request entered\n");
#endif
	char join[HMAC_SIZE*3];
	static char hmac_request[HMAC_SIZE];
	struct hmac_sha256_ctx hmac_ctx;
	hmac_sha256_set_key(&hmac_ctx, SECRET_KEY_LENGTH, (unsigned char *)ycmd_globals.secret_key_raw);
	hmac_sha256_update(&hmac_ctx, strlen(method), (unsigned char *)method);
	hmac_sha256_digest(&hmac_ctx, HMAC_SIZE, (unsigned char *)join);

	hmac_sha256_update(&hmac_ctx, strlen(path), (unsigned char *)path);
	hmac_sha256_digest(&hmac_ctx, HMAC_SIZE, (unsigned char *)(join+HMAC_SIZE));

	hmac_sha256_update(&hmac_ctx, strlen(body), (unsigned char *)body);
	hmac_sha256_digest(&hmac_ctx, HMAC_SIZE, (unsigned char *)(join+2*HMAC_SIZE));

	hmac_sha256_update(&hmac_ctx, HMAC_SIZE*3, (unsigned char *)join);
	hmac_sha256_digest(&hmac_ctx, HMAC_SIZE, (unsigned char *)hmac_request);

	static char b64_request[BASE64_ENCODE_RAW_LENGTH(HMAC_SIZE)];
	base64_encode_raw((unsigned char *)b64_request, HMAC_SIZE, (unsigned char *)hmac_request);
#ifdef DEBUG
	fprintf(stderr,"base64 hmac is %s\n",b64_request);
#endif
	return b64_request;
#elif USE_OPENSSL
        unsigned char join[HMAC_SIZE*3];
        HMAC(EVP_sha256(), ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH,(unsigned char *) method,strlen(method), join, NULL);
        HMAC(EVP_sha256(), ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH,(unsigned char *) path,strlen(path), join+HMAC_SIZE, NULL);
        HMAC(EVP_sha256(), ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH,(unsigned char *) body,strlen(body), join+2*HMAC_SIZE, NULL);

        unsigned char *digest_join = HMAC(EVP_sha256(), ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH,(unsigned char *) join,HMAC_SIZE*3, NULL, NULL);

	static char b64_request[80];
        gchar *_b64_request = g_base64_encode(digest_join, HMAC_SIZE);
	strcpy(b64_request, _b64_request);
	free (_b64_request);
#ifdef DEBUG
	fprintf(stderr,"base64 hmac is %s\n",b64_request);
#endif
	return b64_request;
#else
#error "You need to define a crypto library to use."
#endif
}

char *ycmd_compute_response(char *response_body)
{
#ifdef USE_NETTLE
#ifdef DEBUG
	fprintf(stderr, "ycmd_compute_response entered\n");
#endif
	static char hmac_response[HMAC_SIZE];
	struct hmac_sha256_ctx hmac_ctx;

	hmac_sha256_set_key(&hmac_ctx, SECRET_KEY_LENGTH, (unsigned char *)ycmd_globals.secret_key_raw);
	hmac_sha256_update(&hmac_ctx, strlen(response_body), (unsigned char *)response_body);
	hmac_sha256_digest(&hmac_ctx, HMAC_SIZE, (unsigned char *)hmac_response);

	static char b64_response[BASE64_ENCODE_RAW_LENGTH(HMAC_SIZE)];
	base64_encode_raw((unsigned char *)b64_response, HMAC_SIZE, (unsigned char *)hmac_response);
#ifdef DEBUG
	fprintf(stderr,"base64 hmac is %s\n",b64_response);
#endif
	return b64_response;
#elif USE_OPENSSL
        unsigned char *response_digest = HMAC(EVP_sha256(), ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH,(unsigned char *) response_body,strlen(response_body), NULL, NULL);

	static char b64_response[80];
        gchar *_b64_response = g_base64_encode(response_digest, HMAC_SIZE);
	strcpy(b64_response, _b64_response);
	free (_b64_response);
#ifdef DEBUG
	fprintf(stderr,"base64 hmac is %s\n",b64_response);
#endif
	return b64_response;
#else
#error "You need to define a crypto library to use."
#endif
}

void escape_json(char **buffer)
{
	int i = 0;
	int len = strlen(*buffer);
	char *out;

	out = malloc(1);
	out[0] = '\0';
	int outlen;
	outlen = 1;

	int j = 0;
	char *p = *buffer;
	for (i = 0; i < len; i++)
	{
		switch(p[i])
		{
			//details about json sequences in page 3-4: https://www.ietf.org/rfc/rfc4627.txt

			//not all commented out because it breaks test cases (ycmd.c and solutiondetection.py)

			//escape already escaped
			case '\\': out=_expand(out, outlen+=2); out[j++]='\\'; out[j++]='\\'; break; //x5c

			//c escape sequences
			case '\b': out=_expand(out, outlen+=2); out[j++]='\\'; out[j++]='b'; break; //x08
			case '\t': out=_expand(out, outlen+=2); out[j++]='\\'; out[j++]='t'; break; //x09
			case '\n': out=_expand(out, outlen+=2); out[j++]='\\'; out[j++]='n'; break; //x0a
			case '\v': out=_expand(out, outlen+=2); out[j++]='\\'; out[j++]='v'; break; //x0b
			case '\f': out=_expand(out, outlen+=2); out[j++]='\\'; out[j++]='f'; break; //x0c
			case '\r': out=_expand(out, outlen+=2); out[j++]='\\'; out[j++]='r'; break; //x0d
			case '\"': out=_expand(out, outlen+=2); out[j++]='\\'; out[j++]='\"'; break; //x22 "
			case '/': out=_expand(out, outlen+=2); out[j++]='\\'; out[j++]='/'; break; //x2f

			//escape control characters
			case '\x01': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='1'; break;
			case '\x02': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='2'; break;
			case '\x03': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='3'; break;
			case '\x04': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='4'; break;
			case '\x05': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='5'; break;
			case '\x06': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='6'; break;
			case '\x07': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='7'; break;

			//duplicate cases for c escape sequences
			//case '\x08': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='8'; break;
			//case '\x09': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='9'; break;
			//case '\x0a': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='a'; break;
			//case '\x0b': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='b'; break;
			//case '\x0c': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='c'; break;
			//case '\x0d': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='d'; break;

			case '\x0e': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='e'; break;
			case '\x0f': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='0'; out[j++]='f'; break;

			case '\x10': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='0'; break;
			case '\x11': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='1'; break;
			case '\x12': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='2'; break;
			case '\x13': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='3'; break;
			case '\x14': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='4'; break;
			case '\x15': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='5'; break;
			case '\x16': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='6'; break;
			case '\x17': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='7'; break;
			case '\x18': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='8'; break;
			case '\x19': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='9'; break;
			case '\x1a': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='a'; break;
			case '\x1b': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='b'; break;
			case '\x1c': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='c'; break;
			case '\x1d': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='d'; break;
			case '\x1e': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='e'; break;
			case '\x1f': out=_expand(out, outlen+=6); out[j++]='\\';out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='1'; out[j++]='f'; break;

			//delete character
			//case '\x7f': out=_expand(out, outlen+=6); out[j++]='\\'; out[j++]='u'; out[j++]='0'; out[j++]='0'; out[j++]='7'; out[j++]='f'; break;
			default: out=_expand(out, outlen+=1); out[j++] = p[i]; break;
		}
	}
	out[j] = 0;

	*buffer=out;
	free(p);
}

//assemble the entire file of unsaved buffers
//consumer must free it
char *get_all_content(filestruct *fileage)
{
#ifdef DEBUG
	fprintf(stderr, "Assembling content...\n");
#endif
	char *buffer;
	buffer = NULL;

	filestruct *node;
	node = fileage;

	if (node == NULL)
	{
#ifdef DEBUG
		fprintf(stderr, "Node is null\n");
#endif
		return NULL;
	}

	buffer = malloc(strlen(node->data)+1);
	sprintf(buffer, "%s", node->data);
	node = node->next;

	while (node)
	{
		if (node->data == NULL)
			node = node->next;

		int len = strlen(node->data);
		int len2 = strlen(buffer);
		char *newbuffer = realloc(buffer, len2+len+2);
		if (newbuffer == NULL) {
#ifdef DEBUG
			fprintf(stderr, "*newbuffer is null\n");
#endif
			break;
		}
		buffer = newbuffer;
		sprintf(buffer, "%s\n%s", buffer, node->data);

		node = node->next;
	}

#ifdef DEBUG
	//fprintf(stderr, "Content is: %s\n", buffer);
#endif
	escape_json(&buffer);

	return buffer;
}

void ycmd_event_file_ready_to_parse(int columnnum, int linenum, char *filepath, filestruct *fileage)
{
	if (!ycmd_globals.connected)
		return;

#ifdef DEBUG
	fprintf(stderr,"ycmd_event_file_ready_to_parse called\n");
#endif

	char *content = get_all_content(fileage);
	if (ycmd_globals.running)
	{
		ycmd_json_event_notification(columnnum, linenum, filepath, "FileReadyToParse", content);
		ycmd_req_completions_suggestions(linenum, columnnum, filepath, content, "filetype_default");
	}
	free(content);
}

void ycmd_event_buffer_unload(int columnnum, int linenum, char *filepath, filestruct *fileage)
{
	if (!ycmd_globals.connected)
		return;

#ifdef DEBUG
	fprintf(stderr,"Entering ycmd_event_buffer_unload.\n");
#endif

	char *content = get_all_content(fileage);
	if (ycmd_globals.running)
		ycmd_json_event_notification(columnnum, linenum, filepath, "BufferUnload", content);
	free(content);
}

void ycmd_event_buffer_visit(int columnnum, int linenum, char *filepath, filestruct *fileage)
{
	if (!ycmd_globals.connected)
		return;

#ifdef DEBUG
	fprintf(stderr,"Entering ycmd_event_buffer_visit.\n");
#endif

	char *content = get_all_content(fileage);
	if (ycmd_globals.running)
		ycmd_json_event_notification(columnnum, linenum, filepath, "BufferVisit", content);
	free(content);
}

void ycmd_event_current_identifier_finished(int columnnum, int linenum, char *filepath, filestruct *fileage)
{
	if (!ycmd_globals.connected)
		return;

#ifdef DEBUG
	fprintf(stderr,"Entering ycmd_event_current_identifier_finished.\n");
#endif

	char *content = get_all_content(fileage);
	if (ycmd_globals.running)
		ycmd_json_event_notification(columnnum, linenum, filepath, "CurrentIdentifierFinished", content);
	free(content);
}

void do_code_completion(char letter)
{
	if (!ycmd_globals.connected)
		return;

#ifdef DEBUG
	fprintf(stderr,"Entered do_code_completion.\n");
#endif
	struct subnfunc *func = allfuncs;
	int maxlist = MAIN_VISIBLE;

	while(func)
	{
		if (func && func->menus & MCODECOMPLETION)
			break;
		func = func->next;
	}

	int nbackspaces = openfile->current_x-(ycmd_globals.apply_column-1);

	int i;
	int j;
	for (i = 'A', j = 0; j < maxlist && i <= 'Z' && func; i++, j++, func = func->next)
	{
#ifdef DEBUG
		fprintf(stderr,">Scanning %c.\n", i);
#endif
		if (i == letter)
		{
#ifdef DEBUG
			fprintf(stderr,">Chosen %c.\n", i);
#endif
			if (strcmp(func->desc,"") == 0)
				break;

			if (func->desc != NULL)
			{
#ifdef DEBUG
				fprintf(stderr,"Choosing %s for replacing text\n",func->desc);
#endif

				while(nbackspaces)
				{
					do_backspace();
					nbackspaces--;
				}

				openfile->current_x = ycmd_globals.apply_column-1;

				do_output(func->desc,strlen(func->desc), FALSE);

				free((void *)func->desc);
				func->desc = strdup("");
				blank_statusbar();
			}

			break;
		}
	}

	bottombars(MMAIN);
}

void do_code_completion_a(void)
{
	do_code_completion('A');
}

void do_code_completion_b(void)
{
	do_code_completion('B');
}

void do_code_completion_c(void)
{
	do_code_completion('C');
}

void do_code_completion_d(void)
{
	do_code_completion('D');
}

void do_code_completion_e(void)
{
	do_code_completion('E');
}

void do_code_completion_f(void)
{
	do_code_completion('F');
}

void do_code_completion_g(void)
{
	do_code_completion('G');
}

void do_code_completion_h(void)
{
	do_code_completion('H');
}

void do_code_completion_i(void)
{
	do_code_completion('I');
}

void do_code_completion_j(void)
{
	do_code_completion('J');
}

void do_code_completion_k(void)
{
	do_code_completion('K');
}

void do_code_completion_l(void)
{
	do_code_completion('L');
}

void do_code_completion_m(void)
{
	do_code_completion('M');
}

void do_code_completion_n(void)
{
	do_code_completion('N');
}

void do_code_completion_o(void)
{
	do_code_completion('O');
}

void do_code_completion_p(void)
{
	do_code_completion('P');
}

void do_code_completion_q(void)
{
	do_code_completion('Q');
}

void do_code_completion_r(void)
{
	do_code_completion('R');
}

void do_code_completion_s(void)
{
	do_code_completion('S');
}

void do_code_completion_t(void)
{
	do_code_completion('T');
}

void do_code_completion_u(void)
{
	do_code_completion('U');
}

void do_code_completion_v(void)
{
	do_code_completion('V');
}

void do_code_completion_w(void)
{
	do_code_completion('W');
}

void do_code_completion_x(void)
{
	do_code_completion('X');
}

void do_code_completion_y(void)
{
	do_code_completion('Y');
}

void do_code_completion_z(void)
{
	do_code_completion('Z');
}
