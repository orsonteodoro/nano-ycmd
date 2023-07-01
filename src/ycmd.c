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


#ifdef USE_NETTLE
#include <nettle/base64.h>
#include <nettle/hmac.h>
#define CRYPTO_LIB "NETTLE"
#endif

#ifdef USE_OPENSSL
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#define CRYPTO_LIB "OPENSSL"
#endif

#ifdef USE_LIBGCRYPT
#include <gcrypt.h>
#include <glib.h>
#define CRYPTO_LIB "LIBGCRYPT"
#endif

#ifndef CRYPTO_LIB
#error "You must choose a crypto library to use ycmd code completion support.  Currently nettle, openssl, libgcrypt are supported."
#endif

#ifdef __MMX__
#include <mmintrin.h>
#endif

#ifdef __SSE2__
#include <emmintrin.h>
#endif

#ifdef __SSE4_1__
#include <smmintrin.h>
#endif

#ifdef __AVX__
#include <immintrin.h>
#endif

#ifdef __AVX2__
#include <immintrin.h>
#endif

//avx512 requires gcc5.3 or later  or  clang 3.7.0 or later.
#ifdef __AVX512__
#include <immintrin.h>
#include <zmmintrin.h>
#endif

#include <popcntintrin.h> //sse4a on AMD or sse4.2 on Intel or fallback to non simd algorithm

#include <ne_request.h>
#include <netinet/ip.h>
#include <nxjson.h>
#include <string.h>
#include <sys/wait.h>
#include "config.h"
#include <unistd.h>

#include "prototypes.h"
#include "ycmd.h"
#ifdef DEBUG
#include <time.h>
#include <string.h>
#endif
#include <assert.h>

#if USE_OPENMP
#include <omp.h>
#endif

//notes:
//protocol documentation: https://gist.github.com/hydrargyrum/78c6fccc9de622ad9d7b
//http methods documentation: http://micbou.github.io/ycmd/
//reference client: https://github.com/Valloric/ycmd/blob/master/examples/example_client.py
//ycm https://github.com/Valloric/YouCompleteMe/blob/master/README.md

typedef struct completer_command_results
{
	int usable;
	char *message;
	int line_num;
	int column_num;
	char *filepath;
	char *json_blob;
	char *detailed_info;
	int status_code;
} COMPLETER_COMMAND_RESULTS;

typedef struct defined_subcommands_results
{
	int usable;
	char *json_blob;
	int status_code;
} DEFINED_SUBCOMMANDS_RESULTS;

void escape_json(char **buffer);
char *get_all_content(linestruct *filetop);
void get_extra_conf_path(char *path_project, char *path_extra_conf);
void get_project_path(char *path_project);
void init_file_ready_to_parse_results(FILE_READY_TO_PARSE_RESULTS *frtpr);
char *_ne_read_response_body_full(ne_request *request);
char *ycmd_compute_request(char *method, char *path, char *body);
char *ycmd_compute_response(char *response_body);
char *ycmd_create_default_json_core_version_44();
char *ycmd_create_default_json_core_version_43();
char *ycmd_create_default_json_core_version_39();
void ycmd_start_server();
void ycmd_stop_server();
char *ycmd_generate_secret_base64(char *secret);
void ycmd_generate_secret_raw(char *secret);
char *_ycmd_get_filetype(char *filepath, char *content);
int ycmd_req_defined_subcommands(int linenum, int columnnum, char *filepath, char *content, char *completertarget, DEFINED_SUBCOMMANDS_RESULTS *dsr);
int ycmd_rsp_is_server_ready(char *filetype);
void ycmd_req_load_extra_conf_file(char *filepath);
void ycmd_req_ignore_extra_conf_file(char *filepath);
int ycmd_req_run_completer_command(int linenum, int columnnum, char *filepath, char *content, char *completertarget, char *completercommand, COMPLETER_COMMAND_RESULTS *ccr);
void ycmd_restart_server();


//A function signature to use.  Either it can come from an external library or object code.
extern char* string_replace(const char* src, const char* find, const char* replace);

YCMD_GLOBALS ycmd_globals;

//we count the length to reduce the overhead of expanding/realloc the string by simulating it
size_t _predict_string_replace_size(char *buffer, char *find, char *replace, int global)
{
	int lenb = strlen(buffer);
	int lenf = strlen(find);
	int lenr = strlen(replace);
	int cf;
	int i = 0;
	int j = 0;
	char *p;

	p = buffer;
	size_t outlen = 1;
	int keep_finding = 1;

	for (i=0;i<lenb;)
	{
		cf = 0;

		if (keep_finding)
		{
			for(j=0;j<lenf && i+j < lenb;j++)
			{
				if ( p[i+j] == find[j] )
					cf++;
				else
					break;
			}
		}

		if (keep_finding && cf == lenf)
		{
			outlen+=lenr;
			i+=lenf;
			if (!global)
				keep_finding = 0;
		}
		else
		{
			if (!keep_finding)
			{
				//simulate dump the remaining
				outlen+=(lenb-i);
				i+=(lenb-i);
			}
			else
			{
				outlen+=1;
				i++;
			}
		}
	}

	return outlen;
}

//simd version
//There was no gpl3+ string replace so I made one from scratch.
//1 for global means search entire buffer.  setting to 0 searches only the first instance of find.  it's useful to eliminating the search space so speed up.
char *string_replace_gpl3(char *buffer, char *find, char *replace, int global)
{
#ifdef DEBUG
        fprintf(stderr, "string_replace_gpl3 find arg: %s\n", find);
        fprintf(stderr, "string_replace_gpl3 replace arg: %s\n", replace);
#endif
	char *out;
	int lenb = strlen(buffer);
	int lenf = strlen(find);
	int lenr = strlen(replace);
	int cf;
	int i = 0;
	int j = 0;
	int oi = 0;
	char *p;

	size_t new_length = _predict_string_replace_size(buffer, find, replace, global); //includes null character so +1
	out = malloc(new_length);
	out[0] = 0;

	p = buffer;
	int keep_finding = 1;

	for (i=0;i<lenb;)
	{
#ifdef DEBUG
	        fprintf(stderr, "string_replace_gpl3 out is currently (befor): %s\n", out);
#endif
		cf = 0;

		//find phase count cf
		if (keep_finding)
		{
			int stop = 0;
#if USE_OPENMP
			if (ycmd_globals.cpu_cores > 1)
			{
//SINGLE CORE NO SIMD
				int max_register_width = 4;
				if (0)
					;
#if defined(__AVX512__)
				else if (ycmd_globals.have_avx512)
					max_register_width = 64;
#endif
#if defined(__AVX2__)
				else if (ycmd_globals.have_avx2)
					max_register_width = 32;
#endif
#if defined(__SSE2__)
				else if (ycmd_globals.have_sse2)
					max_register_width = 16;
#endif
#if defined(__MMX__)
				else if (ycmd_globals.have_mmx)
					max_register_width = 8;
#endif

				//we need to scan remaining still less than ncores * register width
				if (lenf < ycmd_globals.cpu_cores * max_register_width)
				{
					//use multicore only but single byte comparisons.  for quad core, it counts 4 bytes at a time using naive algorithm.
					#pragma omp parallel for \
						default(none) \
						reduction(+:cf) \
						shared(p,lenb,lenf,i,find,stderr) \
						firstprivate(stop) \
						private(j)
					for(j=0;j<lenf;j++)
					{
						if (i+j >= lenb)
						{
							stop = 1;
						}

						if (stop == 0)
						{
							if ( p[i+j] == find[j] )
							{
#ifdef DEBUG
								fprintf(stderr, "j=%d running multicore single byte compare threadid=%d\n",j,omp_get_thread_num());
#endif
								cf++;
							}
							else
								stop = 1;
						}
					}
					goto skip_simd;
				}

				if (0)
					;
//scan haystack only either one of AVX512, AVX2, SSE2, MMX.  this will eliminate overhead of rescan of smaller width.  after scanning with one of those, use byte comparison to resume scan haystack with ncores * register_width.
#if defined(__AVX512__)
				else if (ycmd_globals.have_avx512)
				{
					int resume_j;
					resume_j = 0;
					int width = 64; //register width in bytes
					#pragma omp parallel for \
						default(none) \
						reduction(+:cf,resume_j) \
						shared(p,lenb,lenf,i,find,stderr.width) \
						firstprivate(stop) \
						private(j)
					for(j=0;j<lenf;j+=width)
					{
						if (i+j >= lenb)
						{
							stop = 1;
						}

						if (stop == 0)
						{
#ifdef DEBUG
							fprintf(stderr, "j=%d running multicore avx512 compare threadid=%d\n",j,omp_get_thread_num());
#endif
							//just count

							__m512i a, b;
							a = _mm512_setzero();
							b = _mm512_setzero();
							int a_size = lenb < width ? lenb : width;
							int b_size = lenf < width ? lenf : width;
							memcpy(&a, p+i+j, a_size);
							memcpy(&b, find+j, b_size);

							//compare 64 bytes at a time * n cores
							int c;
							c = 0;
							//need to simulate sse4.2 behavior but extened to 64 bytes
							__mmask64 result = _mm512_cmpeq_epi8_mask(a,b);
							c = __builtin_popcountll(result);
							cf += c;
							if (b_size != c)
								stop = 1;

							resume_j+=width;
						}
					}
				}
#endif
#if defined(__AVX2__)
				else if (ycmd_globals.have_avx2)
				{
					int resume_j;
					resume_j = 0;
					int width = 32; //register width in bytes
					#pragma omp parallel for \
						default(none) \
						reduction(+:cf,resume_j) \
						shared(p,lenb,lenf,i,find,stderr,width) \
						firstprivate(stop) \
						private(j)
					for(j=0;j<lenf;j+=width)
					{
						if (i+j >= lenb)
						{
							stop = 1;
						}

						if (stop == 0)
						{
#ifdef DEBUG
							fprintf(stderr, "j=%d running multicore avx2 compare threadid=%d\n",j,omp_get_thread_num());
#endif
							//just count

							__m256i a, b;
							a = _mm256_setzero_si256();
							b = _mm256_setzero_si256();
							int a_size = lenb < width ? lenb : width;
							int b_size = lenf < width ? lenf : width;
							memcpy(&a, p+i+j, a_size);
							memcpy(&b, find+j, b_size);

							//compare 32 bytes at a time * ncores
							int c;
							c = 0;
							//need to simulate sse4.2 behavior but extened to 32 bytes
							__m256i result = _mm256_cmpeq_epi8(a,b);
							int mask _mm256_movemask_epi8(result);
							c = __builtin_popcount(mask);
							cf += c;
							if (b_size != c)
								stop = 1;

							resume_j+=width;
						}
					}
				}
#endif
#if defined(__SSE2__)
				else if (ycmd_globals.have_sse2)
				{
					int resume_j;
					resume_j = 0;
					int width = 16; //register width in bytes
					#pragma omp parallel for \
						default(none) \
						reduction(+:cf,resume_j) \
						shared(p,lenb,lenf,i,find,stderr,width) \
						firstprivate(stop) \
						private(j)
					for(j=0;j<lenf;j+=width)
					{
						if (i+j >= lenb)
						{
							stop = 1;
						}

						if (stop == 0)
						{
#ifdef DEBUG
							fprintf(stderr, "j=%d running multicore sse2 compare threadid=%d\n",j,omp_get_thread_num());
#endif
							//just count

							__m128i a, b;
							a = _mm_setzero_si128();
							b = _mm_setzero_si128();
							int a_size = lenb < width ? lenb : width;
							int b_size = lenf < width ? lenf : width;
							memcpy(&a, p+i+j, a_size);
							memcpy(&b, find+j, b_size);

							//compare 16 bytes at a time * ncores
							int c;
							c = 0;
#if defined(__SSE4_2__) //needs testing
							if (ycmd_globals.have_sse4_2)
							{
								int mask = _mm_cmpestri(a, a_size, b, b_size, _SIDD_UBYTE_OPS | _SIDD_CMP_EQUAL_EACH | _SIDD_BIT_MASK);
							}
							else
#endif
							{
								//need to simulate sse4.2
								__m128i result = _mm_cmpeq_epi8(a,b);
								int mask = _mm_movemask_epi8(result);
								c = __builtin_popcount(mask);
								cf += c;
							}
							if (b_size != c)
								stop = 1;

							resume_j+=width;
						}
					}
				}
#endif
#if defined(__MMX__)
				else if (ycmd_globals.have_mmx)
				{
					int have_sse = ycmd_globals.have_sse;
					int resume_j;
					resume_j = 0;
					int width = 8; //register width in bytes
					#pragma omp parallel for \
						default(none) \
						reduction(+:cf,resume_j) \
						shared(p,lenb,lenf,i,find,stderr,width,have_sse) \
						firstprivate(stop) \
						private(j)
					for(j=0;j<lenf;j+=width)
					{
						if (i+j >= lenb)
						{
							stop = 1;
						}

						if (stop == 0)
						{
#ifdef DEBUG
							fprintf(stderr, "j=%d running multicore mmx compare threadid=%d (0)\n",j,omp_get_thread_num());
#endif
							//just count

							__m64 a, b;
							a = _mm_setzero_si64();
							b = _mm_setzero_si64();
							int a_size = lenb < width ? lenb : width;
							int b_size = lenf < width ? lenf : width;
							memcpy(&a, p+i+j, a_size);
							memcpy(&b, find+j, b_size);

							//compare 8 bytes at a time * ncores
							int c;
							c = 0;
							//need to simulate sse4.2
							__m64 result = _mm_cmpeq_pi8(a,b);
							int mask;


#ifdef __SSE__
							if (have_sse)
							{
								int mask = _mm_movemask_pi8(result);
								c = __builtin_popcount(mask);
								cf += c;


#ifdef DEBUG
								fprintf(stderr, "j=%d running multicore mmx threadid=%d matches: c=%d (1a)\n",j,omp_get_thread_num(),c);
#endif
							}
							else
#else
							{
								//we need to extract a bit per each 8 byte block so we don't over count
								c = 0;
								int result_x;
								result_x = _m_to_int(result);
								result_x = (result_x & 0x01010101);
								if (result_x)
								{
									c = __builtin_popcount(result_x);
									cf += c;

#ifdef DEBUG
									fprintf(stderr, "j=%d running multicore mmx threadid=%d matches: c=%d (1b)\n",j,omp_get_thread_num(),c);
#endif
								}

								c = 0;
								result = _m_psrlqi(result, 4);
								result_x = _m_to_int(result);
								result_x = (result_x & 0x01010101);
								if (result_x)
								{
									c = __builtin_popcount(result_x);
									cf += c;

#ifdef DEBUG
									fprintf(stderr, "j=%d running multicore mmx threadid=%d matches: c=%d (2)\n",j,omp_get_thread_num(),c);
#endif
								}
							}
#endif

							if (b_size != c)
								stop = 1;

							resume_j+=width;
						}
					}
				}
#endif //end SIMD BLOCK
				skip_simd:
					;
			}//end multicore
			else //single core
#endif //end USE_OPENMP
			{
				//naive algorithm should be faster for many random comparisons but not long chains
				for(j=0;j<lenf && i+j < lenb;j++)
				{
					if ( p[i+j] == find[j] )
						cf++;
					else
						break;
				}
			}
		}//end keep_finding

		//replace phase
		if (keep_finding && cf == lenf)
		{
#ifdef DEBUG
		        fprintf(stderr, "string_replace_gpl3 found: %s\n", find);
#endif
			memcpy(out+oi, replace, lenr);
			oi+=lenr;
			i+=lenf;

			if (!global)
				keep_finding = 0;
		}
		else
		{
			if (!keep_finding)
			{
				//dump the rest
				memcpy(out+oi, p+i, lenb-i); //hopefully memcpy is simd/multicore optimized
				oi+=(lenb-i);
				i+=(lenb-i);
				out[oi] = 0;
			}
			else
			{
				//this section scans a chunk without find[0] character
				//if no find[0] in chunk, transfer mmx/sse/avx256/avx512 full register sized chunks instead of a byte at a time ahead of finding the chunk
				unsigned int fragsize = 1;
				if (0)
					;
#ifdef __AVX512__
				else if (ycmd_globals.have_avx512bw && lenb-i > (fragsize=64)) //avx512 needs testing
				{
					__m512i find_mask, chunk_data, rb0, rb1;
					__m256i rb0, rb1;
					find_mask = _mm512_set1_epi8(find[0]);
					memcpy(&chunk_data, p+i, fragsize);

					unsigned long long result = 0;
					result r = _mm512_cmpeq_epi8_mask(chunk_data, find_mask); //mask is 64

					if (result)
					{
						//dump everything leading up to the header to avoid overhead cost of calling simd set and compare
						do
						{
							out[oi]=p[i]; //transfer 1 at a time since we seen the head in the chunk
							oi++;
							i++;
						} while(i < lenb && p[i] != find[0]);
					}
					else
					{
#ifdef DEBUG
						fprintf(stderr, "used avx2 string_replace_gpl3 section\n");
#endif

						//transfer 64 bytes at a time
						memcpy(out+oi, p+i, fragsize);
						oi+=fragsize;
						i+=fragsize;
					}
				}
#endif
#ifdef __AVX2__
				else if (ycmd_globals.have_avx2 && lenb-i > (fragsize=32)) //avx2 needs testing
				{
					avx2_fallback:
					__m256i find_mask, chunk_data;
					find_mask = _mm256_set1_epi8(find[0]);
					memcpy(&chunk_data, p+i, fragsize);

					r = _mm256_cmpeq_epi8(chunk_data, find_mask);
					int result = _mm256_movemask_epi8(r);
					if (result)
					{
						//dump everything leading up to the header to avoid overhead cost of calling simd set and compare
						do
						{
							out[oi]=p[i]; //transfer 1 at a time since we seen the head in the chunk
							oi++;
							i++;
						} while(i < lenb && p[i] != find[0]);
					}
					else
					{
#ifdef DEBUG
						fprintf(stderr, "used avx2 string_replace_gpl3 section\n");
#endif
						//transfer 32 bytes at a time
						memcpy(out+oi, p+i, fragsize);
						oi+=fragsize;
						i+=fragsize;
					}

				}
#endif
#ifdef __SSE2__
				else if (ycmd_globals.have_sse2 && lenb-i > (fragsize=16)) //sse2
				{
					__m128i find_mask, chunk_data, rb;
					find_mask = _mm_set1_epi8(find[0]);
					memcpy(&chunk_data, p+i, fragsize);

					unsigned int result;
#if defined(__AVX512__)
					if (ycmd_globals.have_avx512vl && ycmd_globals.have_avx512bw)
						result = _mm_cmpeq_epi8_mask(chunk_data, find_mask); //fastest
					else
						goto sse_fallback;
#else /* SSE2 */
					sse_fallback:
					rb = _mm_cmpeq_epi8(chunk_data, find_mask);
					result = _mm_movemask_epi8(rb);
#endif

					if (result)
					{
						//dump everything leading up to the header to avoid overhead cost of calling simd set and compare
						do
						{
							out[oi]=p[i]; //transfer 1 at a time since we seen the head in the chunk
							oi++;
							i++;
						} while(i < lenb && p[i] != find[0]);
					}
					else
					{
#ifdef DEBUG
						fprintf(stderr, "used sse2 string_replace_gpl3 section\n");
#endif
						//transfer 16 we don't see the start of string
						memcpy(out+oi, p+i, fragsize);
						oi+=fragsize;
						i+=fragsize;
					}
				}
#endif
				else if (lenb-i > (fragsize=8) && sizeof(long) == 8) //64 bit machine check... lacking simd
				{
					unsigned long long find_mask;
					find_mask = 0x0101010101010101 * find[0]; //propagate the byte across the mask
					unsigned long long chunk_data;
					memcpy(&chunk_data, p+i, fragsize);
					if (chunk_data & find_mask)
					{
						//dump everything leading up to the header to avoid overhead cost of calling simd set and compare
						do
						{
							out[oi]=p[i]; //transfer 1 at a time since we seen the head in the chunk
							oi++;
							i++;
						} while(i < lenb && p[i] != find[0]);
					}
					else
					{
#ifdef DEBUG
						fprintf(stderr, "used alu 32 bits string_replace_gpl3 section\n");
#endif
						//transfer 8 we don't see the start of string
						memcpy(out+oi, p+i, fragsize);
						oi+=fragsize;
						i+=fragsize;
					}
				}
#ifdef __MMX__
				else if (sizeof(long) == 4 && ycmd_globals.have_mmx && lenb-i > (fragsize=8)) //mmx for older 32 bit cpus... could be slightly shower on 64 bit because it requires 2 steps here (cmpeq+movemask) and the above just require 1 (chunk_data & find_mask)
				{
					__m64 find_mask, chunk_data, r;
					find_mask = _mm_set1_pi8(find[0]);
					memcpy(&chunk_data, p+i, fragsize);

					r = _mm_cmpeq_pi8(chunk_data, find_mask);

					int result;
#ifdef __SSE__
					result = _mm_movemask_pi8(r); //fastest because popcount is pretty costly
#else
					result = __builtin_popcountll((unsigned long long)r) > 0; //either simd or non simd version
#endif

					if (result)
					{
						//dump everything leading up to the header to avoid overhead cost of calling simd set and compare
						do
						{
							out[oi]=p[i]; //transfer 1 at a time since we seen the head in the chunk
							oi++;
							i++;
						} while(i < lenb && p[i] != find[0]);
					}
					else
					{
#ifdef DEBUG
						fprintf(stderr, "used mmx string_replace_gpl3 section\n");
#endif
						//transfer 8 we don't see start of string
						memcpy(out+oi, p+i, fragsize);
						oi+=fragsize;
						i+=fragsize;
					}
				}
#endif
				else if (lenb-i > (fragsize=4) && sizeof(long) == 4) //32 bit machine... lacking simd
				{
					unsigned int find_mask;
					find_mask = 0x01010101 * find[0]; //propagate the byte across the mask
					unsigned int chunk_data;
					memcpy(&chunk_data, p+i, fragsize);
					if (chunk_data & find_mask)
					{
						//dump everything leading up to the header to avoid overhead cost of calling simd set and compare
						do
						{
							out[oi]=p[i]; //transfer 1 at a time since we seen the head in the chunk
							oi++;
							i++;
						} while(i < lenb && p[i] != find[0]);
					}
					else
					{
#ifdef DEBUG
						fprintf(stderr, "used alu 32 bit string_replace_gpl3 section\n");
#endif
						//transfer 4 at a time.  we don't see the start of string.
						memcpy(out+oi, p+i, fragsize);
						oi+=fragsize;
						i+=fragsize;
					}
				}
				else if (lenb-i > (fragsize=2))
				{
					unsigned short find_mask;
					find_mask = 0x0101 * find[0]; //propagate the byte across the mask
					unsigned short chunk_data;
					memcpy(&chunk_data, p+i, fragsize);
					if (chunk_data & find_mask)
					{
						//dump everything leading up to the header to avoid overhead cost of calling simd set and compare
						do
						{
							out[oi]=p[i]; //transfer 1 at a time since we seen the head in the chunk
							oi++;
							i++;
						} while(i < lenb && p[i] != find[0]);
					}
					else
					{
#ifdef DEBUG
						fprintf(stderr, "used alu 16 bit string_replace_gpl3 section\n");
#endif
						//transfer 2 at a time.  we don't see the start of string.
						memcpy(out+oi, p+i, fragsize);
						oi+=fragsize;
						i+=fragsize;
					}
				}
				else
				{
#ifdef DEBUG
					fprintf(stderr, "using byte at a time string_replace_gpl3 section\n");
#endif
					out[oi]=p[i]; //transfer 1 at a time since we seen the head in the chunk
					oi++;
					i++;
				}
			}
		}
		out[oi] = 0;
#ifdef DEBUG
	        fprintf(stderr, "string_replace_gpl3 out is currently (after): %s\n", out);
#endif
	}
	out[oi]=0;

#ifdef DEBUG
	fprintf(stderr, "string_replace_gpl3 final: %s\n", out);
#endif

	return out;
}

//A wrapper function that takes any string_replace.
//1 for global means search entire buffer.  setting to 0 searches only the first instance of find.  it's useful for eliminating the search space so speed up.
void string_replace_w(char **buffer, char *find, char *replace, int global)
{
	char *b;
	b = *buffer;
	*buffer = string_replace_gpl3(*buffer, find, replace, global);
	free(b);
}

void send_to_server(int signum) {
#ifdef DEBUG
    char buffer[5000];
    time_t mytime;
    mytime = time(NULL);
    sprintf(buffer,"caught SIGALARM %s",ctime (&mytime));
    statusline(HUSH, buffer);
#endif
    ycmd_event_file_ready_to_parse(openfile->current_x,(long)openfile->current->lineno,openfile->filename,openfile->filetop);
}

void ycmd_init()
{
#ifdef DEBUG
	fprintf(stderr, "Init ycmd.\n");
#endif
	ycmd_globals.core_version = DEFAULT_YCMD_CORE_VERSION;
	ycmd_globals.session = 0;
	ycmd_globals.scheme = "http";
	ycmd_globals.hostname = "127.0.0.1";
	ycmd_globals.port = 0;
	ycmd_globals.child_pid=-1;
	ycmd_globals.secret_key_base64 = NULL;
	ycmd_globals.json = NULL;
	init_file_ready_to_parse_results(&ycmd_globals.file_ready_to_parse_results);

	signal(SIGALRM, send_to_server);

#if USE_OPENMP
	ycmd_globals.cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
#else
	ycmd_globals.cpu_cores = 1;
#endif


#ifdef __AVX512__
	ycmd_globals.have_avx512vl = __builtin_cpu_supports("avx512vl");
	if (ycmd_globals.have_avx512vl)
	{
#ifdef DEBUG
		fprintf(stderr, "Detected avx512vl.\n");
#endif
	}

	ycmd_globals.have_avx512f = __builtin_cpu_supports("avx512f");
	if (ycmd_globals.have_avx512f)
	{
#ifdef DEBUG
		fprintf(stderr, "Detected avx512f.\n");
#endif
	}


	ycmd_globals.have_avx512bw = __builtin_cpu_supports("avx512bw");
	if (ycmd_globals.have_avx512bw)
	{
#ifdef DEBUG
		fprintf(stderr, "Detected avx512bw.\n");
#endif
	}
#else
	ycmd_globals.have_avx512vl = 0;
	ycmd_globals.have_avx512f = 0;
	ycmd_globals.have_avx512bw = 0;
#endif

#ifdef __AVX2__
	ycmd_globals.have_avx2 = __builtin_cpu_supports("avx2");
	if (ycmd_globals.have_avx2)
	{
#ifdef DEBUG
		fprintf(stderr, "Detected avx2.\n");
#endif
	}
#else
	ycmd_globals.have_avx2 = 0;
#endif

#ifdef __SSE4_2__
	ycmd_globals.have_sse4_2 = __builtin_cpu_supports("sse4.2");
	if (ycmd_globals.have_sse4_2)
	{
#ifdef DEBUG
		fprintf(stderr, "Detected sse4.2.\n");
#endif
	}
#else
	ycmd_globals.have_sse4_2 = 0;
#endif

#ifdef __SSE4_1__
	ycmd_globals.have_sse4_1 = __builtin_cpu_supports("sse4.1");
	if (ycmd_globals.have_sse4_1)
	{
#ifdef DEBUG
		fprintf(stderr, "Detected sse4.1.\n");
#endif
	}
#else
	ycmd_globals.have_sse4_1 = 0;
#endif

#ifdef __SSE2__
	ycmd_globals.have_sse2 = __builtin_cpu_supports("sse2");
	if (ycmd_globals.have_sse2)
	{
#ifdef DEBUG
		fprintf(stderr, "Detected sse2.\n");
#endif
	}
#else
	ycmd_globals.have_sse2 = 0;
#endif

#ifdef __SSE__
	ycmd_globals.have_sse = __builtin_cpu_supports("sse");
	if (ycmd_globals.have_sse)
	{
#ifdef DEBUG
		fprintf(stderr, "Detected sse.\n");
#endif
	}
#else
	ycmd_globals.have_sse = 0;
#endif

#ifdef __MMX__
	ycmd_globals.have_mmx = __builtin_cpu_supports("mmx");
	if (ycmd_globals.have_mmx)
	{
#ifdef DEBUG
		fprintf(stderr, "Detected mmx.\n");
#endif
	}
#else
	ycmd_globals.have_mmx = 0;
#endif

	ycmd_globals.have_popcnt = __builtin_cpu_supports("popcnt");
	if (ycmd_globals.have_popcnt)
	{
#ifdef DEBUG
		fprintf(stderr, "Detected popcnt.\n");
#endif
	}

	ycmd_globals.have_popcnt = __builtin_cpu_supports("cmov");
	if (ycmd_globals.have_cmov)
	{
#ifdef DEBUG
		fprintf(stderr, "Detected cmov.\n");
#endif
	}

#ifdef USE_LIBGCRYPT
	if (!gcry_check_version("1.7.3"))
	{
		fprintf(stderr, "Libgcrypt init failed.\n");
		exit(-1);
	}
	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	//gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif

	ycmd_generate_secret_raw(ycmd_globals.secret_key_raw);
	ycmd_globals.secret_key_base64 = strdup(ycmd_generate_secret_base64(ycmd_globals.secret_key_raw));
#ifdef DEBUG
	fprintf(stderr, "HMAC secret is: %s\n", ycmd_globals.secret_key_base64);
#endif

	ne_sock_init();

	int tries = 3;
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

//generates a compile_commands.json for the clang completer
//returns 1 on success
int bear_generate(char *project_path)
{
#ifdef DEBUG
	fprintf(stderr, "Entered bear_generate\n");
#endif
	char file_path[PATH_MAX];
	char command[PATH_MAX*2];
	int ret = -1;

	snprintf(file_path, PATH_MAX, "%s/compile_commands.json", project_path);

	if (access(file_path, F_OK) == 0)
	{
		;//statusline(HUSH, "Using previously generated compile_commands.json file.");
		ret = 0;
	}
	else
	{
		statusline(HUSH, "Please wait.  Generating a compile_commands.json file.");
		snprintf(command, PATH_MAX*2, "cd \"%s\"; make clean > /dev/null", project_path);
		system(command);

		snprintf(command, PATH_MAX*2, "cd \"%s\"; bear make > /dev/null", project_path);
		ret = system(command);
		full_refresh();
		draw_all_subwindows();

		if (ret == 0)
		{
			statusline(HUSH, "Sucessfully generated a compile_commands.json file.");
			//usleep(1000000);
		}
		else
		{
			statusline(HUSH, "Failed generating a compile_commands.json file.");
			//usleep(1000000);
		}
	}
	blank_statusbar();

#ifdef DEBUG
	fprintf(stderr, "bear_generate ret is %d\n", ret);
#endif
	return ret == 0;
}

//generate a compile_commands.json for projects using the ninja build system
//returns 1 on success 0 on failure;
int ninja_compdb_generate(char *project_path)
{
#ifdef DEBUG
	fprintf(stderr, "Entered ninja_compdb_generate\n");
#endif
	//try ninja
	char command[PATH_MAX*2];

	char ninja_build_path[PATH_MAX];
	char *_ninja_build_path = getenv("NINJA_BUILD_PATH");
	if (_ninja_build_path && strcmp(_ninja_build_path, "(null)") != 0)
	{
#ifdef DEBUG
		fprintf(stderr,"ninja_build_path is not null\n");
#endif
		snprintf(ninja_build_path,PATH_MAX,"%s",_ninja_build_path);
	}
	else
	{
#ifdef DEBUG
		fprintf(stderr,"ninja_build_path is null\n");
#endif
		ninja_build_path[0] = 0;
	}

#ifdef DEBUG
	fprintf(stderr,"ninja find\n");
#endif
	snprintf(command, PATH_MAX*2, "find \"%s\" -maxdepth 1 -name \"*.ninja\" > /dev/null", ninja_build_path);
        int ret = system(command);

	if (ret != 0)
	{
#ifdef DEBUG
		fprintf(stderr,"No Ninja files found skipping.\n");
#endif
	}
	else
	{
		char ninja_build_targets[PATH_MAX];
		char *_ninja_build_targets = getenv("NINJA_BUILD_TARGETS");
		if (_ninja_build_targets && strcmp(_ninja_build_targets, "(null)") != 0)
		{
#ifdef DEBUG
			fprintf(stderr,"ninja_build_targets is not null\n");
#endif
			snprintf(ninja_build_targets,PATH_MAX,"%s",_ninja_build_targets);
		}
		else
		{
#ifdef DEBUG
			fprintf(stderr,"ninja_build_targets is null\n");
#endif
			ninja_build_targets[0] = 0;
		}

		snprintf(command,PATH_MAX*2, "cd \"%s\";\"%s\" -t compdb %s > %s/compile_commands.json", ninja_build_path, NINJA_PATH, ninja_build_targets, project_path);
		ret = system(command);
		full_refresh();
		draw_all_subwindows();
		if (ret == 0)
		{
#ifdef DEBUG
			fprintf(stderr,"Ninja compdb generated compile_commands.json success.\n");
#endif
		}
		else
		{
#ifdef DEBUG
			fprintf(stderr,"Ninja compdb generated compile_commands.json failed.\n");
#endif
		}
	}
	return ret == 0;
}

void get_project_path(char *path_project)
{
	char *ycmg_project_path = getenv("YCMG_PROJECT_PATH");
	if (ycmg_project_path && strcmp(ycmg_project_path, "(null)") != 0)
	{
#ifdef DEBUG
		fprintf(stderr,"ycmg_project_path is not null\n");
#endif
		snprintf(path_project, PATH_MAX, "%s", ycmg_project_path);
	}
	else
	{
#ifdef DEBUG
		fprintf(stderr,"ycmg_project_path is null\n");
#endif
		getcwd(path_project, PATH_MAX);
	}
}

//precondition: path_project must be populated first from get_project_path()
void get_extra_conf_path(char *path_project, char *path_extra_conf)
{
	snprintf(path_extra_conf, PATH_MAX, "%s/.ycm_extra_conf.py", path_project);
}

//generates a .ycm_extra_conf.py for the c family completer
//language must be: c, c++, objective-c, objective-c++
void ycm_generate(char *filepath, char *content)
{
	char path_project[PATH_MAX];
	char path_extra_conf[PATH_MAX];
	char command[PATH_MAX*2];
	char flags[PATH_MAX];

	get_project_path(path_project);

#ifdef ENABLE_YCM_GENERATOR
	char *ycmg_flags = getenv("YCMG_FLAGS");
	if (!ycmg_flags || strcmp(ycmg_flags,"(null)") == 0)
	{
#ifdef DEBUG
		fprintf(stderr,"ycmg_flags is null\n");
#endif
		flags[0] = 0;
	}
	else
	{
#ifdef DEBUG
		fprintf(stderr,"ycmg_flags is not null\n");
#endif
		snprintf(flags, PATH_MAX, "%s",ycmg_flags);
	}
#endif

	get_extra_conf_path(path_project, path_extra_conf);

	//generate bear's json first because ycm-generator deletes the Makefiles
#ifdef ENABLE_BEAR
	if (!bear_generate(path_project))
#endif
#ifdef ENABLE_NINJA
		ninja_compdb_generate(path_project); //handle ninja build system.
#else
		;
#endif

	if (access(path_extra_conf, F_OK) == 0)
	{
		;//statusline(HUSH, "Using previously generated .ycm_extra_conf.py.");
		//usleep(3000000);
	}
	else
	{
#ifdef ENABLE_YCM_GENERATOR
		statusline(HUSH, "Please wait.  Generating a .ycm_extra_conf.py file.");
		snprintf(command, PATH_MAX*2, "\"%s\" \"%s\" -f %s \"%s\" >/dev/null", YCMG_PYTHON_PATH, YCMG_PATH, flags, path_project);
#ifdef DEBUG
		fprintf(stderr, command);
#endif
		int ret = system(command);
		if (ret == 0)
		{
			statusline(HUSH, "Sucessfully generated a .ycm_extra_conf.py file.");
			//usleep(3000000);

#if defined(ENABLE_BEAR) || defined(ENABLE_NINJA)
			snprintf(command, PATH_MAX*2, "sed -i -e \"s|compilation_database_folder = ''|compilation_database_folder = '%s'|g\" \"%s\"", path_project, path_extra_conf);
			int ret2 = system(command);
			if (ret2 == 0)
			{
				statusline(HUSH, "Patching .ycm_extra_conf.py file with compile_commands.json was a success.");
				//usleep(3000000);
			}
			else
			{
				statusline(HUSH, "Failed patching .ycm_extra_conf.py with compile_commands.json.");
				//usleep(3000000);
			}
#endif

			char language[10];
			if (strstr(filepath,".mm"))
				sprintf(language, "objective-c++");
			else if (strstr(filepath,".m"))
				sprintf(language, "objective-c");
			else if (strstr(filepath,".cpp") || strstr(filepath,".C") || strstr(filepath,".cxx") || strstr(filepath,".cc"))
				sprintf(language, "c++");
			else if (strstr(filepath,".c"))
				sprintf(language, "c");
			else if (strstr(filepath,".hpp") || strstr(filepath,".hh"))
				sprintf(language, "c++");
			else if (strstr(filepath,".h"))
			{
				if (strstr(content, "using namespace") || strstr(content, "iostream") || strstr(content, "\tclass ") || strstr(content, " class ")
					|| strstr(content, "private:") || strstr(content, "public:") || strstr(content, "protected:"))
					sprintf(language, "c++");
				else
					sprintf(language, "c");
			}

			//inject clang includes to find stdio.h and others
			//caching disabled because of problems
/* unescaped version for testing in bash
V=$(echo | clang -v -E -x c - |& sed  -r  -e ':a' -e 'N' -e '$!ba' -e "s|.*#include <...> search starts here:[ \\n]+(.*)[ \\n]+End of search list.\\n.*|\\1|g"  -e "s|[ \\n]+|\\n|g" | tac);V=$(echo -e $V | sed -r -e "s|[ \\n]+|\',\\n    \'-isystem\','|g");
sed -e "s|'do_cache': True|'do_cache': False|g" -e "s|'-I.'|'-isystem','$(echo $V)','-I.'|g" ../.ycm_extra_conf.py
*/
			snprintf(command, PATH_MAX*2,
				"V=$(echo | clang -v -E -x %s - |& sed  -r  -e ':a' -e 'N' -e '$!ba' -e \"s|.*#include <...> search starts here:[ \\n]+(.*)[ \\n]+End of search list.\\n.*|\\1|g\" -e \"s|[ \\n]+|\\n|g\" | tac);"
				"V=$(echo -e $V | sed -r -e \"s|[ \\n]+|\',\\n    \'-isystem\','|g\");"
				"sed -i -e \"s|'do_cache': True|'do_cache': False|g\" -e \"s|'-I.'|'-isystem','$(echo -e $V)','-I.'|g\" \"%s\"",
				language, path_extra_conf);
#ifdef DEBUG
			fprintf(stderr, command);
#endif
			ret2 = system(command);
			if (ret2 == 0)
			{
				statusline(HUSH, "Patching .ycm_extra_conf.py file with clang includes was a success.");
				//usleep(3000000);
			}
			else
			{
				statusline(HUSH, "Failed patching .ycm_extra_conf.py with clang includes.");
				//usleep(3000000);
			}
		}
		else
		{
			statusline(HUSH, "Failed to generate a .ycm_extra_conf.py file.");
			//usleep(3000000);
		}
#endif
	}
	blank_statusbar();
}

char *ycmd_create_default_json()
{
	if (ycmd_globals.core_version == 39)
		return ycmd_create_default_json_core_version_39();
	else if (ycmd_globals.core_version == 43)
		return ycmd_create_default_json_core_version_43();
	else if (ycmd_globals.core_version == 45 || ycmd_globals.core_version == 46 || ycmd_globals.core_version == 47)
		return ycmd_create_default_json_core_version_44();
}

//needs to be freed
char *ycmd_create_default_json_core_version_44()
{
	// Structure same as 44 https://github.com/ycm-core/ycmd/blob/6f2f818364bb5c52f60e720741ff583bf77b4cd5/ycmd/default_settings.json
	// Structure same as 45 https://github.com/ycm-core/ycmd/blob/2ee41000a28fb6b2ae00985c231896b6d072af86/ycmd/default_settings.json
	// Structure same as 46 https://github.com/ycm-core/ycmd/blob/5f1e71240949ef9e6a64f47fa17ab63d1ec50a4c/ycmd/default_settings.json
	// Structure same as 47 (20230611 [live snapshot]) https://github.com/ycm-core/ycmd/blob/33922510b354bae0561b5de886d0d0767ed8822a/ycmd/default_settings.json
	char *_json = "{"
		"  \"filepath_completion_use_working_dir\": 0,"
		"  \"auto_trigger\": 1,"
		"  \"min_num_of_chars_for_completion\": 2,"
		"  \"min_num_identifier_candidate_chars\": 0,"
		"  \"semantic_triggers\": {},"
		"  \"filetype_specific_completion_to_disable\": {"
		"    \"gitcommit\": 1"
		"  },"
		"  \"collect_identifiers_from_comments_and_strings\": 0,"
		"  \"max_num_identifier_candidates\": 10,"
		"  \"max_num_candidates\": 50,"
		"  \"max_num_candidates_to_detail\": -1,"
		"  \"extra_conf_globlist\": [],"
		"  \"global_ycm_extra_conf\": \"\","
		"  \"confirm_extra_conf\": 0,"
		"  \"max_diagnostics_to_display\": 30,"
		"  \"filepath_blacklist\": {"
		"    \"html\": 1,"
		"    \"jsx\": 1,"
		"    \"xml\": 1"
		"  },"
		"  \"auto_start_csharp_server\": 1,"
		"  \"auto_stop_csharp_server\": 1,"
		"  \"use_ultisnips_completer\": 1,"
		"  \"csharp_server_port\": 0,"
		"  \"hmac_secret\": \"HMAC_SECRET\","
		"  \"server_keep_logfiles\": 0,"
		"  \"python_binary_path\": \"YCMD_PYTHON_PATH\","
		"  \"language_server\": [],"
		"  \"java_jdtls_use_clean_workspace\": 1,"
		"  \"java_jdtls_workspace_root_path\": \"\","
		"  \"java_jdtls_extension_path\": [],"
		"  \"use_clangd\": 1,"
		"  \"clangd_binary_path\": \"CLANGD_PATH\","
		"  \"clangd_args\": [],"
		"  \"clangd_uses_ycmd_caching\": 1,"
		"  \"disable_signature_help\": 0,"
		"  \"gopls_binary_path\": \"GOPLS_PATH\","
		"  \"gopls_args\": [],"
		"  \"rust_toolchain_root\": \"RUST_TOOLCHAIN_PATH\","
		"  \"tsserver_binary_path\": \"TSSERVER_PATH\","
		"  \"roslyn_binary_path\": \"OMNISHARP_PATH\","
		"  \"mono_binary_path\": \"MONO_PATH\","
		"  \"java_binary_path\": \"JAVA_PATH\""
		"}";

	static char *json;
	json = strdup(_json);
	return json;
}

//needs to be freed
char *ycmd_create_default_json_core_version_43()
{
	// Structure same as https://github.com/ycm-core/ycmd/blob/ef48cfe1b63bcc07b88e537fb5b6d17b513e319c/ycmd/default_settings.json
	char *_json = "{"
		"  \"filepath_completion_use_working_dir\": 0,"
		"  \"auto_trigger\": 1,"
		"  \"min_num_of_chars_for_completion\": 2,"
		"  \"min_num_identifier_candidate_chars\": 0,"
		"  \"semantic_triggers\": {},"
		"  \"filetype_specific_completion_to_disable\": {"
		"    \"gitcommit\": 1"
		"  },"
		"  \"collect_identifiers_from_comments_and_strings\": 0,"
		"  \"max_num_identifier_candidates\": 10,"
		"  \"max_num_candidates\": 50,"
		"  \"max_num_candidates_to_detail\": -1,"
		"  \"extra_conf_globlist\": [],"
		"  \"global_ycm_extra_conf\": \"\","
		"  \"confirm_extra_conf\": 0,"
		"  \"max_diagnostics_to_display\": 30,"
		"  \"filepath_blacklist\": {"
		"    \"html\": 1,"
		"    \"jsx\": 1,"
		"    \"xml\": 1"
		"  },"
		"  \"auto_start_csharp_server\": 1,"
		"  \"auto_stop_csharp_server\": 1,"
		"  \"use_ultisnips_completer\": 1,"
		"  \"csharp_server_port\": 0,"
		"  \"hmac_secret\": \"HMAC_SECRET\","
		"  \"server_keep_logfiles\": 0,"
		"  \"python_binary_path\": \"YCMD_PYTHON_PATH\","
		"  \"language_server\": [],"
		"  \"java_jdtls_use_clean_workspace\": 1,"
		"  \"java_jdtls_workspace_root_path\": \"\","
		"  \"java_jdtls_extension_path\": [],"
		"  \"use_clangd\": 1,"
		"  \"clangd_binary_path\": \"CLANGD_PATH\","
		"  \"clangd_args\": [],"
		"  \"clangd_uses_ycmd_caching\": 1,"
		"  \"disable_signature_help\": 0,"
		"  \"gopls_binary_path\": \"GOPLS_PATH\","
		"  \"gopls_args\": [],"
		"  \"rls_binary_path\": \"RLS_PATH\","
		"  \"rustc_binary_path\": \"RUSTC_PATH\","
		"  \"tsserver_binary_path\": \"TSSERVER_PATH\","
		"  \"roslyn_binary_path\": \"OMNISHARP_PATH\","
		"  \"mono_binary_path\": \"MONO_PATH\""
		"}";

	static char *json;
	json = strdup(_json);
	return json;
}

//needs to be freed
char *ycmd_create_default_json_core_version_39()
{
	// Structure same as https://github.com/ycm-core/ycmd/blob/813de203f3d04ed789a5616b8d4df872d8bb2b45/ycmd/default_settings.json
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
		"  \"max_num_candidates\": 50,"
		"  \"extra_conf_globlist\": [],"
		"  \"global_ycm_extra_conf\": \"\","
		"  \"confirm_extra_conf\": 0,"
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
		"  \"filepath_blacklist\": {"
		"    \"html\": 1,"
		"    \"jsx\": 1,"
		"    \"xml\": 1"
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
		"  \"python_binary_path\": \"YCMD_PYTHON_PATH\","
		"  \"java_jdtls_use_clean_workspace\": 1"
		"}";

	static char *json;
	json = strdup(_json);
	return json;
}

void ycmd_gen_extra_conf(char *filepath, char *content)
{
	char command[PATH_MAX*2];
	char cwd[PATH_MAX];

	getcwd(cwd, PATH_MAX);
#ifdef DEBUG
	fprintf(stderr,"ycmd_gen_extra_conf find\n");
#endif
	sprintf(command, "find \"%s\" -name \"*.mm\" -o -name \"*.m\" -o -name \"*.cpp\" -o -name \"*.C\" -o -name \"*.cxx\" -o -name \"*.c\" -o -name \"*.hpp\" -o -name \"*.h\" -o -name \"*.cc\" -o -name \"*.hh\" > /dev/null", cwd);
	int ret = system(command);

	if (ret == 0)
	{
#ifdef DEBUG
		fprintf(stderr, "Detected c family\n");
#endif
		ycm_generate(filepath, content);
		ycmd_globals.clang_completer = 1;
	}
	else
	{
#ifdef DEBUG
		fprintf(stderr, "Not c family\n");
#endif
		ycmd_globals.clang_completer = 0;
	}

}

void _ycmd_json_replace_file_data(char **json, char *filepath, char *content)
{
	if (filepath[0] != '/')
	{
		char abs_filepath[PATH_MAX];
		getcwd(abs_filepath, PATH_MAX);
		strcat(abs_filepath,"/");
		strcat(abs_filepath,filepath);
		string_replace_w(json, "FILEPATH", abs_filepath, 1);
	}
	else
		string_replace_w(json, "FILEPATH", filepath, 1);

	char *ft = _ycmd_get_filetype(filepath, content);
	string_replace_w(json, "FILETYPES", ft, 0);

	string_replace_w(json, "CONTENTS", content, 0);
}

void init_file_ready_to_parse_results(FILE_READY_TO_PARSE_RESULTS *frtpr)
{
	memset(frtpr, 0, sizeof(FILE_READY_TO_PARSE_RESULTS));
}

void destroy_file_ready_to_parse_results(FILE_READY_TO_PARSE_RESULTS *frtpr)
{
	if (frtpr->json_blob)
		free(frtpr->json_blob);
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

	snprintf(line_num, DIGITS_MAX, "%d", linenum);
#ifdef DEBUG
	fprintf(stderr, "ycmd_json_event_notification: line_num is : %s\n", line_num);
#endif
	snprintf(column_num, DIGITS_MAX, "%d", columnnum+(ycmd_globals.clang_completer?0:1));

	string_replace_w(&json, "COLUMN_NUM", column_num, 0);
	string_replace_w(&json, "EVENT_NAME", eventname, 0);

	string_replace_w(&json, "LINE_NUM", line_num, 0);

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
		ne_add_request_header(request, HTTP_HEADER_YCM_HMAC, ycmd_b64_hmac);
		ne_set_request_body_buffer(request, json, strlen(json));

#ifdef DEBUG
		fprintf(stderr,"Getting server response\n");
#endif

		int ret = ne_begin_request(request);
		if (strstr(eventname,"FileReadyToParse"))
		{
			destroy_file_ready_to_parse_results(&ycmd_globals.file_ready_to_parse_results);
			init_file_ready_to_parse_results(&ycmd_globals.file_ready_to_parse_results);
			ycmd_globals.file_ready_to_parse_results.status_code = status_code;
		}
		if (ret == NE_OK)
		{
			char *response = _ne_read_response_body_full(request);
			const char *hmac_remote = ne_get_response_header(request, HTTP_HEADER_YCM_HMAC);
			ne_end_request(request);

			//attacker could inject malicious code in fixit but user would see it
			char *hmac_local = ycmd_compute_response(response);

#ifdef DEBUG
			fprintf(stderr,"Server response: %s\n", response);
#endif

#ifdef DEBUG
			fprintf(stderr,"hmac_local is %s\n",hmac_local);
			fprintf(stderr,"hmac_remote is %s\n",hmac_remote);
#endif
//			if (!hmac_local || !hmac_remote || !ycmd_compare_hmac(hmac_remote, hmac_local)) //bugged
//				;
//			else
			{
				if (strstr(eventname,"FileReadyToParse"))
				{
					ycmd_globals.file_ready_to_parse_results.usable = 1;
					ycmd_globals.file_ready_to_parse_results.json_blob = strdup(response);
				}
			}

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
			fprintf(stderr, "Request is not success.  Discarding request.  Status code %d. (2)\n", ne_get_status(request)->klass);
#endif
			//ne_discard_response(request);
			break;
		}
#ifdef DEBUG
		fprintf(stderr, "readlen %zd\n",readlen);
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

//1 is valid, 0 is invalid
int ycmd_compare_hmac(const char *remote_hmac, char *local_hmac)
{
	if (strcmp(remote_hmac, local_hmac) == 0)
	{
#ifdef DEBUG
		fprintf(stderr,"Verified hmac.  Connection is not compromised.\n");
#endif
		return 1;
	}
	else
	{
#ifdef DEBUG
		fprintf(stderr,"Wrong hmac.  Possible compromised connection.\n");
#endif
		return 0;
	}
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

	snprintf(line_num, DIGITS_MAX, "%d", linenum);
	snprintf(column_num, DIGITS_MAX, "%d", columnnum+(ycmd_globals.clang_completer?0:1));

	string_replace_w(&json, "LINE_NUM", line_num, 0);
	string_replace_w(&json, "COLUMN_NUM", column_num, 0);
	string_replace_w(&json, "COMPLETER_TARGET", completertarget, 0);

	_ycmd_json_replace_file_data(&json, filepath, content);

#ifdef DEBUG
	fprintf(stderr, "json body in ycmd_req_completions_suggestions: %s\n", json);
#endif

	struct funcstruct *func = allfuncs;

	while(func)
	{
		if (func && (func->menus == MCODECOMPLETION))
			break;
		func = func->next;
	}

	int status_code = 0;
	ne_request *request;
	request = ne_request_create(ycmd_globals.session, method, path);
	{
		ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,0);

		ne_add_request_header(request,"content-type","application/json");
		char *ycmd_b64_hmac = ycmd_compute_request(method, path, json);
		ne_add_request_header(request, HTTP_HEADER_YCM_HMAC, ycmd_b64_hmac);
		ne_set_request_body_buffer(request, json, strlen(json));

		int ret = ne_begin_request(request);
		status_code = ne_get_status(request)->code;
		if (ret == NE_OK)
		{
			char *response_body = _ne_read_response_body_full(request);

#ifdef DEBUG
			fprintf(stderr,"response_body for ycmd_req_completions_suggestions is %s\n",response_body);
#endif

			const char *hmac_remote = ne_get_response_header(request, HTTP_HEADER_YCM_HMAC);
			ne_end_request(request);

			//attacker could inject malicious code into source code here but the user would see it.
			char *hmac_local = ycmd_compute_response(response_body);

#ifdef DEBUG
			fprintf(stderr,"hmac_local is %s\n",hmac_local);
			fprintf(stderr,"hmac_remote is %s\n",hmac_remote);
#endif

			if (!hmac_local || !hmac_remote || !ycmd_compare_hmac(hmac_remote, hmac_local))
				;
			else
			{

				//output should look like:
				//{"errors": [], "completion_start_column": 22, "completions": [{"insertion_text": "Wri", "extra_menu_info": "[ID]"}, {"insertion_text": "WriteLine", "extra_menu_info": "[ID]"}]}

				int found_cc_entry = 0;
				if (response_body && strstr(response_body, "completion_start_column"))
				{
#ifdef DEBUG
					fprintf(stderr,"server sent completion suggestions\n");
#endif
					const nx_json *pjson = nx_json_parse_utf8(response_body); //nx_json_parse_utf8 is destructive on response_body as intended

					const nx_json *completions = nx_json_get(pjson, "completions");
					int i = 0;
					int j = 0;
					size_t maximum = (((COLS + 40) / 20) * 2);

					for (i = 0; i < completions->length && j < maximum && j < 26 && func; i++, j++) //26 for 26 letters A-Z
					{
						const nx_json *candidate = nx_json_item(completions, i);
						const nx_json *insertion_text = nx_json_get(candidate, "insertion_text");
						if (insertion_text != NX_JSON_NULL) {
							if (func->desc != NULL)
								free((void *)func->desc);
							func->desc = strdup(insertion_text->text_value);
#ifdef DEBUG
							fprintf(stderr,">Added completion entry to nano toolbar: %s\n", insertion_text->text_value);
#endif
							found_cc_entry = 1;
						}
						func = func->next;
					}
					for (i = j; i < completions->length && i < maximum && i < 26 && func; i++, func = func->next)
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
			}

#ifdef DEBUG
			fprintf(stderr,"Server response (SUGGESTIONS): %s\n", response_body);
#endif

			if (response_body)
				free(response_body);

		}

	}
	ne_request_destroy(request);

	free(json);

#ifdef DEBUG
	fprintf(stderr, "Status code in ycmd_req_completions_suggestions is %d\n", status_code);
#endif

	return status_code == 200;
}

//1 is true, 0 is false
int is_c_family(char *ft)
{
	return !strcmp(ft,"cpp") || !strcmp(ft,"c") || !strcmp(ft,"objc") || !strcmp(ft,"objcpp");
}

void _do_completer_command(char *completercommand, COMPLETER_COMMAND_RESULTS *ccr)
{
#ifdef DEBUG
	fprintf(stderr,"Entered _do_completer_command for %s.\n", completercommand);
#endif
	char *content = get_all_content(openfile->filetop);

	char *ft2 = _ycmd_get_filetype(openfile->filename, content); //doesn't work for some reason if used with ycmd_req_run_completer_command
	char *ft = "filetype_default"; //works when passed to ycmd_req_run_completer_command

	//check server if it is compromised before sending sensitive source code
	int ready = ycmd_rsp_is_server_ready(ft);

	if (ycmd_globals.running && ready)
	{
		char path_project[PATH_MAX];
		char path_extra_conf[PATH_MAX];

		//loading required by the c family languages
		if (is_c_family(ft2))
		{
			ycmd_gen_extra_conf(openfile->filename, content);
#ifdef USE_YCM_GENERATOR
			get_project_path(path_project);
			get_extra_conf_path(path_project, path_extra_conf);
			ycmd_req_load_extra_conf_file(path_extra_conf);
#endif
		}

		int ret = ycmd_req_run_completer_command((long)openfile->current->lineno, openfile->current_x, openfile->filename, content, ft, completercommand, ccr);
		if (ret == 0)
		{
#ifdef DEBUG
			statusline(HUSH, "Completer command failed.");
#endif
		}
		else
		{
#ifdef DEBUG
			statusline(HUSH, "Completer command success.");
#endif
		}

		if (is_c_family(ft2))
			ycmd_req_ignore_extra_conf_file(path_extra_conf);
	}

	free(content);
}

void init_completer_command_results(COMPLETER_COMMAND_RESULTS *ccr)
{
	memset(ccr, 0, sizeof(COMPLETER_COMMAND_RESULTS));
}

void destroy_completer_command_results(COMPLETER_COMMAND_RESULTS *ccr)
{
	if (ccr->message)
		free(ccr->message);
	if (ccr->filepath)
		free(ccr->filepath);
	if (ccr->detailed_info)
		free(ccr->detailed_info);
	if (ccr->json_blob)
		free(ccr->json_blob);
}

//must call destroy_completer_command_results() aftr using it
void parse_completer_command_results(COMPLETER_COMMAND_RESULTS *ccr)
{
#ifdef DEBUG
	fprintf(stderr, "Entered parse_completer_command_results\n");
#endif
	if (!ccr->usable || ccr->status_code != 200)
	{
#ifdef DEBUG
		fprintf(stderr, "json blob not usable\n");
#endif
		return;
	}

	char *json_blob; //nxjson does inplace edits so back it up
	json_blob = strdup(ccr->json_blob);

	const nx_json *json = nx_json_parse_utf8(ccr->json_blob);

	if (json && ccr->usable)
	{
		const nx_json *n = nx_json_get(json, "message");
		if ( n->type != NX_JSON_NULL )
			ccr->message = strdup(n->text_value);

		n = nx_json_get(json, "filepath");
		if ( n->type != NX_JSON_NULL )
			ccr->filepath = strdup(n->text_value);

		n = nx_json_get(json, "line_num");
		if ( n->type != NX_JSON_NULL )
			ccr->line_num = n->int_value;

		n = nx_json_get(json, "column_num");
		if ( n->type != NX_JSON_NULL )
			ccr->column_num = n->int_value;

		n = nx_json_get(json, "detailed_info");
		if ( n->type != NX_JSON_NULL )
			ccr->detailed_info = strdup(n->text_value);

		nx_json_free(json);
	}

	ccr->json_blob = json_blob;
}

//1 on success, 0 on failure
void _do_goto(COMPLETER_COMMAND_RESULTS *ccr)
{
#ifdef DEBUG
	fprintf(stderr, "_do_goto names: ccr->filepath:%s  openfile->filename:%s\n", ccr->filepath, openfile->filename);
#endif

	if (strstr(ccr->filepath, openfile->filename))
	{
#ifdef DEBUG
		fprintf(stderr, "using same buffer: %s line_num:%d column_num:%d\n", ccr->filepath, ccr->line_num, ccr->column_num);
#endif
		//ycm treats tabs as one column.  nano treats a tab as many column.
		do_gotolinecolumn(ccr->line_num, 1, FALSE, FALSE);
		openfile->current_x = ccr->column_num-1;
	}
	else
	{
#ifdef DEBUG
		fprintf(stderr, "opening new buffer: %s line_num:%d column_num:%d\n", ccr->filepath, ccr->line_num, ccr->column_num);
#endif
#ifndef DISABLE_MULTIBUFFER
		SET(MULTIBUFFER);
#else
		//todo non multibuffer
#endif
		open_buffer(ccr->filepath, FALSE);
		prepare_for_display();
		do_gotolinecolumn(ccr->line_num, 1, FALSE, FALSE);
		openfile->current_x = ccr->column_num-1;
	}
	refresh_needed = TRUE;
}

void do_completer_command_gotoinclude(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_gotoinclude\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"GoToInclude\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		_do_goto(&ccr);
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

void do_completer_command_gotodeclaration(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_gotodeclaration\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"GoToDeclaration\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		_do_goto(&ccr);
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

void do_completer_command_gotodefinition(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_gotodefinition\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"GoToDefinition\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		_do_goto(&ccr);
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

void do_completer_command_gotodefinitionelsedeclaration(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_gotodefinition\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"GoToDefinitionElseDeclaration\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		//_do_goto(&ccr);
		//todo
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}


void do_completer_command_goto(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_goto\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"GoTo\"", &ccr);
	parse_completer_command_results(&ccr);
	char display_text[80]; //should be number of columns
	display_text[0] = 0;

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		//todo
		//_do_goto(&ccr);
		//[{"description": "Builtin instance BaseNewStr"}, {"description": "Builtin instance str"}, {"description": "Builtin instance NoneType"}, {"description": "Builtin instance unicode"}]

		const nx_json *json = nx_json_parse_utf8(ccr.json_blob);

		if (json)
		{
			const nx_json *a = json;
			int i;

			for (i=0; i < a->length; i++)
			{
				const nx_json *item = nx_json_item(a, i);
				const char *description = nx_json_get(item, "description")->text_value;
				//todo populate hotkeys with object
				snprintf(display_text, 80, "%s, %s", display_text, description);
			}

			nx_json_free(json);
		}
		statusline(HUSH, display_text);
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

void do_completer_command_gotoimprecise(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_gotoimprecise\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"GoToImprecise\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		_do_goto(&ccr);
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

void do_completer_command_gotoreferences(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_gotoreferences\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"GoToReferences\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		//todo
		//json array
		//[{"description": "return _SolutionTestCheckHeuristics( candidates, tokens, i )", "filepath": "/usr/lib64/python3.4/site-packages/ycmd/completers/cs/solutiondetection.py", "column_num": 14, "line_num": 92}, {"description": "def _SolutionTestCheckHeuristics", "filepath": "/usr/lib64/python3.4/site-packages/ycmd/completers/cs/solutiondetection.py", "column_num": 5, "line_num": 96}] 

		const nx_json *json = nx_json_parse_utf8(ccr.json_blob);

		if (json)
		{
			const nx_json *a = json;
			int i;

			for (i=0; i < a->length; i++)
			{
				const nx_json *item = nx_json_item(a, i);
				const char *description = nx_json_get(item, "description")->text_value;
				const char *filepath = nx_json_get(item, "filepath")->text_value;
				int column_num = nx_json_get(item, "column_num")->int_value;
				int line_num = nx_json_get(item, "line_num")->int_value;
				//todo populate hotkeys with object
			}

			nx_json_free(json);
		}
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

void do_completer_command_gotoimplementation(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_gotoimplementation\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"GoToImplementation\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		//{"filepath": "/var/tmp/portage/dev-dotnet/omnisharp-roslyn-9999.20170128/work/omnisharp-roslyn-b24c48f939dc3467514187184ff439f864ec6ad9/src/OmniSharp.DotNet/DotNetProjectSystem.cs", "column_num": 9, "line_num": 27}
		_do_goto(&ccr);
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

void do_completer_command_gotoimplementationelsedeclaration(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_gotoimplementationelsedeclaration\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"GoToImplementationElseDeclaration\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		//todo
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

/* Structure format prettyfied tag:1
{
   "fixits":[
      {
         "chunks":[
            {
               //solution section
               "range":{
                  "start":{
                     "filepath":"/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c",
                     "column_num":55,
                     "line_num":148
                  },
                  "end":{
                     "filepath":"/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c",
                     "column_num":57,
                     "line_num":148
                  }
               },
               "replacement_text":"%s"
            }
         ],
         //user dialog text
         "text":"/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c:148:62: warning: format specifies type 'int' but the argument has type 'char *' [-Wformat]",
         "location":{
            "filepath":"/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c",
            "column_num":62,
            "line_num":148
         }
      }
   ]
}

{
   "fixits":[
      {
         "chunks":[
            {
               //solution section
               "range":{
                  "start":{
                     "filepath":"/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c",
                     "column_num":16,
                     "line_num":135
                  },
                  "end":{
                     "filepath":"/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c",
                     "column_num":16,
                     "line_num":135
                  }
               },
               "replacement_text":";"
            }
         ],
         //user dialog text
         "text":"/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c:135:16: error: expected ';' at end of declaration",
         "location":{
            "filepath":"/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c",
            "column_num":16,
            "line_num":135
         }
      }
   ]
}

*/

//{"fixits": [{"chunks": [], "text": "", "location": {"filepath": "/var/tmp/portage/dev-dotnet/omnisharp-roslyn-9999.20170128/work/omnisharp-roslyn-b24c48f939dc3467514187184ff439f864ec6ad9/src/OmniSharp.DotNet/DotNetProjectSystem.cs", "column_num": 39, "line_num": 117}}]}
/*
{
   "fixits":[
      {
         "chunks":[

         ],
         "text":"",
         "location":{
            "filepath":"/var/tmp/portage/dev-dotnet/omnisharp-roslyn-9999.20170128/work/omnisharp-roslyn-b24c48f939dc3467514187184ff439f864ec6ad9/src/OmniSharp.DotNet/DotNetProjectSystem.cs",
            "column_num":39,
            "line_num":117
         }
      }
   ]
}
*/

void fixit_refresh(void)
{
	refresh_needed = FALSE;
}

void do_completer_command_fixit(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_fixit\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"FixIt\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		const nx_json *json = nx_json_parse_utf8(ccr.json_blob);


		//the server can only handle one at a time.  after that, it bombs out.

		if (json)
		{
			const nx_json *a_fixits = nx_json_get(json, "fixits");
			int i=0, j=0;

			//for (i=0; i < a_fixits->length; i++) //1 array element only supported
			if (a_fixits->length == 1)
			{
				const nx_json *item_fixit = nx_json_item(a_fixits, i);
				const nx_json *a_chunks = nx_json_get(item_fixit, "chunks");


				const nx_json *item_chunk, *range, *range_start, *range_end;
				const char *replacement_text = NULL;
				const char *fcrs_filepath;
				int fcrs_column_num, fcrs_line_num;

				const char *fcre_filepath;
				int fcre_column_num, fcre_line_num;;

				if (a_chunks != NX_JSON_NULL && a_chunks->length >= 1)
				{
					//see tag:1 on format
					//for (j=0; j < a_chunks->length; j++)
					if (a_chunks->length == 1) //1 array element only supported
					{
						item_chunk = nx_json_item(a_chunks, j);
						range = nx_json_get(item_chunk, "range");
						range_start = nx_json_get(range, "start");
						range_end = nx_json_get(range, "end");
						replacement_text = nx_json_get(item_chunk, "replacement_text")->text_value;

						fcrs_filepath = nx_json_get(range_start, "filepath")->text_value;
						fcrs_column_num = nx_json_get(range_start, "column_num")->int_value;
						fcrs_line_num = nx_json_get(range_start, "line_num")->int_value;

						fcre_filepath = nx_json_get(range_end, "filepath")->text_value;
						fcre_column_num = nx_json_get(range_end, "column_num")->int_value;
						fcre_line_num = nx_json_get(range_end, "line_num")->int_value;
					}
				}
				else
				{
					//see tag:2 on format
				}

				//user dialog text
				const char *text = nx_json_get(item_fixit, "text")->text_value;
				char prompt_msg[4096];
				snprintf(prompt_msg, 4096, "Apply fix It? %s", text);
				const nx_json *location = nx_json_get(item_fixit, "location");
				const char *fl_filepath = nx_json_get(location, "filepath")->text_value;
				int fl_column_num = nx_json_get(location, "column_num")->int_value;
				int fl_line_num = nx_json_get(location, "line_num")->int_value;

				//show prompt
				int ret = do_yesno_prompt(FALSE, prompt_msg);
				if (ret)
				{
					if (replacement_text && strlen(replacement_text))
					{
						//openfile->mark_set = 1; //assume flag was previously set
						do_gotolinecolumn(fcrs_line_num, 1, FALSE, FALSE); //nano column num means distance within a tab character.  ycmd column num means treat tabs as indivisible.
						openfile->current_x = fcrs_column_num-1; //nano treats current_x as 0 based and linenum as 1 based
#ifdef DEBUG
						fprintf(stderr, "start cursor: y=%d x=%d\n", fcrs_line_num, fcrs_column_num);
#endif
						do_mark(); //flip flag and unsets marker
						do_mark(); //flip flag and sets marker
						do_gotolinecolumn(fcre_line_num, 1, FALSE, FALSE);
						openfile->current_x = fcre_column_num-1;
#ifdef DEBUG
						fprintf(stderr, "end cursor: y=%d x=%d\n", fcrs_line_num, fcrs_column_num);
#endif
						cut_text(); //same function as (cut character) ^K in global.c
						inject((char*)replacement_text, strlen(replacement_text));
						statusline(HUSH, "Applied FixIt.");
					}
				}
				else
				{
					statusline(HUSH, "Canceled FixIt.");
				}
			}

			nx_json_free(json);
		}

	}

	bottombars(MMAIN);

	destroy_completer_command_results(&ccr);
}

void _do_completer_command_getdoc(char *command)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_getdoc\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command(command, &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
#ifdef DEBUG
		fprintf(stderr, "Dump to buffer:\n%s\n", ccr.detailed_info);
#endif

		char doc_filename[PATH_MAX];
		strcpy(doc_filename,"/tmp/nanoXXXXXX");
		int fdtemp = mkstemp(doc_filename);
#ifdef DEBUG
		fprintf(stderr, "tempname is %s\n", doc_filename);
#endif
		FILE *f = fdopen(fdtemp,"w+");
		fprintf(f, "%s", ccr.detailed_info);
		fclose(f);

#ifndef DISABLE_MULTIBUFFER
		SET(MULTIBUFFER);
#else
		//todo non multibuffer
#endif

		//do_output doesn't handle \n properly and displays it as ^@ so we do it this way
		open_buffer(doc_filename, TRUE);
		prepare_for_display();

		unlink(doc_filename);
	}

	bottombars(MMAIN);

	destroy_completer_command_results(&ccr);

	refresh_needed = TRUE;
}

void do_completer_command_getdoc(void)
{
	_do_completer_command_getdoc("\"GetDoc\"");
}

void do_completer_command_getdocimprecise(void)
{
	_do_completer_command_getdoc("\"GetDocImprecise\"");
}

void refactorrename_refresh(void)
{
	refresh_needed = TRUE;
}

void do_completer_command_refactorrename(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_refactorrename\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);

	char *cc_command = strdup("\"RefactorRename\",\"NEW_IDENTIFIER\"");

	int ret = do_prompt(MREFACTORRENAME, NULL,
#ifndef DISABLE_HISTORIES
		NULL,
#endif
		refactorrename_refresh, _("Rename identifier as"));

#ifdef DEBUG
	fprintf(stderr, "do_prompt return code %d\n", ret);
#endif

	if (ret == 0) //0 enter, -1 cancel
	{
		string_replace_w(&cc_command, "NEW_IDENTIFIER", answer, 0);

		statusline(HUSH, "Applying refactor rename...");

		_do_completer_command(cc_command, &ccr); //fixme needs additional arg and edit box widget

		parse_completer_command_results(&ccr);

		if (!ccr.usable || ccr.status_code != 200)
		{
			statusline(HUSH, "Refactor rename failed.");
		}
		else
		{
			statusline(HUSH, "Refactor rename thoughrout project success.");
		}

		destroy_completer_command_results(&ccr);
	}
	else
	{
		statusline(HUSH, "Canceled refactor rename.");
	}

	free(cc_command);

	bottombars(MMAIN);
}

void do_completer_command_gettype(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_gettype\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"GetType\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		statusline(HUSH, ccr.message);
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

void do_completer_command_gettypeimprecise(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_gettypeimprecise\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"GetTypeImprecise\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		statusline(HUSH, ccr.message);
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

void do_completer_command_reloadsolution(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_reloadsolution\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"ReloadSolution\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		statusline(HUSH, "Reloaded solution.");
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

void do_completer_command_restartserver(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_restartserver\n");
#endif
	char *_completercommand = "[\"RestartServer','LANG\"]";
	char *completercommand = strdup(_completercommand);

	//code is expanded for performance and memory reasons

	char *content = get_all_content(openfile->filetop);
	//char *ft = _ycmd_get_filetype(openfile->filename, content);
	char *ft = "filetype_default";
	string_replace_w(&completercommand, "LANG", ft, 0);

	//check server if it is compromised before sending sensitive source code
	int ready = ycmd_rsp_is_server_ready(ft);

	if (ycmd_globals.running && ready)
	{
		char path_project[PATH_MAX];
		char path_extra_conf[PATH_MAX];

		//loading required by the c family languages
		if (is_c_family(ft))
		{
			ycmd_gen_extra_conf(openfile->filename, content);
#ifdef USE_YCM_GENERATOR
			get_project_path(path_project);
			get_extra_conf_path(path_project, path_extra_conf);
			ycmd_req_load_extra_conf_file(path_extra_conf);
#endif
		}

		COMPLETER_COMMAND_RESULTS ccr;
		init_completer_command_results(&ccr);
		ycmd_req_run_completer_command((long)openfile->current->lineno, openfile->current_x, openfile->filename, content, ft, completercommand, &ccr);

		if (is_c_family(ft))
			ycmd_req_ignore_extra_conf_file(path_extra_conf);

		parse_completer_command_results(&ccr);

		if (!ccr.usable || ccr.status_code != 200)
		{
			statusline(HUSH, "Reloaded fail.");
		}
		else
		{
			statusline(HUSH, "Restarted solution.");
		}

		destroy_completer_command_results(&ccr);
	}

	free(completercommand);

	free(content);

	bottombars(MMAIN);
}

void do_completer_command_gototype(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_gototype\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"GoToType\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		_do_goto(&ccr);
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

void do_completer_command_clearcompliationflagcache(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_clearcompliationflagcache\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"ClearCompilationFlagCache\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
		bottombars(MMAIN);
	}
	else
	{
		statusline(HUSH, "Clear compliation flag cached performed.");
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

void do_completer_command_getparent(void)
{
#ifdef DEBUG
	fprintf(stderr, "Tapped do_completer_command_getparent\n");
#endif
	COMPLETER_COMMAND_RESULTS ccr;
	init_completer_command_results(&ccr);
	_do_completer_command("\"GetParent\"", &ccr);
	parse_completer_command_results(&ccr);

	if (!ccr.usable || ccr.status_code != 200)
	{
		statusline(HUSH, "Completer command failed.");
	}
	else
	{
		statusline(HUSH, ccr.message);
	}

	destroy_completer_command_results(&ccr);

	bottombars(MMAIN);
}

void do_completer_command_solutionfile(void)
{
	//todo

}

/*
JSON structure sample for each completer command not mentioned by the official docs:

GetParent (c lang)
{"message": "ycmd_init()"}

ClearCompilationFlagCache (c lang)
null

GetTypeImprecise (c lang)
{"message": "unsigned long (const char *)"}

GetType (c lang)
{"message": "char [8192]"}

FixIt (cs)
{"fixits": []}
{"fixits": [{"chunks": [], "text": "", "location": {"filepath": "/var/tmp/portage/dev-dotnet/omnisharp-roslyn-9999.20170128/work/omnisharp-roslyn-b24c48f939dc3467514187184ff439f864ec6ad9/src/OmniSharp.DotNet/DotNetProjectSystem.cs", "column_num": 39, "line_num": 117}}]}
{"fixits": [{"chunks": [{"range": {"start": {"filepath": "/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c", "column_num": 12, "line_num": 114}, "end": {"filepath": "/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c", "column_num": 12, "line_num": 114}}, "replacement_text": ";"}], "text": "/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c:114:12: error: expected ';' after return statement", "location": {"filepath": "/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c", "column_num": 12, "line_num": 114}}]}
{"fixits": [{"chunks": [{"range": {"start": {"filepath": "/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c", "column_num": 55, "line_num": 148}, "end": {"filepath": "/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c", "column_num": 57, "line_num": 148}}, "replacement_text": "%s"}], "text": "/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c:148:62: warning: format specifies type 'int' but the argument has type 'char *' [-Wformat]", "location": {"filepath": "/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/ycmd.c", "column_num": 62, "line_num": 148}}]}

GoToImprecise (c lang)
{"filepath": "/usr/include/string.h", "column_num": 15, "line_num": 394}

GoToInclude (c lang)
{"filepath": "/var/tmp/portage/app-editors/nano-ycmd-9999.20170205/work/nano-ycmd-052b4866f3b24caeed877ae6f017f422d1443ed9/src/proto.h", "column_num": 1, "line_num": 1}

GoToDeclaration (c lang)
{"filepath": "/usr/include/string.h", "column_num": 15, "line_num": 394}

GoToDeclaration (python)
{"filepath": "/usr/lib64/python3.4/site-packages/ycmd/completers/cs/solutiondetection.py", "column_num": 5, "line_num": 96}

GoToDefinition (python)
{"filepath": "/usr/lib64/python3.4/site-packages/ycmd/completers/cs/solutiondetection.py", "column_num": 5, "line_num": 96}

GoToImplementation (cs)
{"filepath": "/var/tmp/portage/dev-dotnet/omnisharp-roslyn-9999.20170128/work/omnisharp-roslyn-b24c48f939dc3467514187184ff439f864ec6ad9/src/OmniSharp.DotNet/DotNetProjectSystem.cs", "column_num": 9, "line_num": 27}

GoTo (python)
[{"description": "Builtin instance BaseNewStr"}, {"description": "Builtin instance str"}, {"description": "Builtin instance NoneType"}, {"description": "Builtin instance unicode"}]

GetDoc (python)
{"detailed_info": "\n---\n\n---\n\n---\n"}

GetDoc (C#)
{"detailed_info": "static void Thread.Sleep(int millisecondsTimeout);"}


GoToReferences (python)
[{"description": "return _SolutionTestCheckHeuristics( candidates, tokens, i )", "filepath": "/usr/lib64/python3.4/site-packages/ycmd/completers/cs/solutiondetection.py", "column_num": 14, "line_num": 92}, {"description": "def _SolutionTestCheckHeuristics", "filepath": "/usr/lib64/python3.4/site-packages/ycmd/completers/cs/solutiondetection.py", "column_num": 5, "line_num": 96}] 

*/

//Supported completer_command list: https://github.com/Valloric/YouCompleteMe

//most require line_num and column_num to implicitly work

//Goes to header
//GoToInclude
//c, cpp, objc, objcpp

//Goes to declaration of symbol
//GoToDeclaration
//c, cpp, objc, objcpp, cs, go, python, rustx, go

//Goes to the definition of the symbol
//GoToDefinition
//c, cpp, objc, objcpp, cs, go, javascript, python, rustx, typescript, go

//Go to whatever is sensible. symbol definition first then declration as fallback.  goes to header in c family or implementation in csharp
//GoTo
//c, cpp, objc, objcpp, cs, go, javascript, python, rustx, go

//Faster goto but without compile
//GoToImprecise
//c, cpp, objc, objcpp

//Gets a list of references in the project
//GoToReferences
//javascript, python, typescript

//Goes to implementation non-interface (abstract class
//GoToImplementation
//cs

//Go to implementation else go to declaration
//GoToImplementationElseDeclaration
//cs

//Applies trivial fixes to the problem
//It just spits the most recent one, one at a time, instead of all at once on demand.  It might need poll.
//FixIt
//c, cpp, objc, objcpp, cs

//Shows documentation
//GetDoc
//c, cpp, objc, objcpp, cs, python, typescript, javascript, rust

//Applies rename of identifier to multiple files
//RefactorRename <newname>
//javascript, typescript

//Displays the type
//GetType
//javascript, typescript, cs, c, cpp, objc, objcpp

//Faster version of GetType
//GetTypeImprecise
//c, cpp, objc, objcpp

//Clear cache and reload all files
//ReloadSolution
//cs

//no documentation
//GoToType
//typescript

//Restarts the semantic engine.  For java you can specify the binary
//RestartServer <lang>
//python, typescript, javascript, go

//no documentation
//command_arguments
//python

//Clears and reloads the function FlagsForFile from .ycm_extra_conf.py file
//ClearCompilationFlagCache
//c, cpp, objc, objcpp

//Applies to classes... basically gets the class of a method or an field
//GetParent
//c, cpp, objc, objcpp

//more advanced completer sub commands per completer engine
//completercommand expects a json array without dangling comma.  it should be one of the above GoTo{...}, FixIt, Get{...}, ....  Quotes also needs to be escaped so it would look like [\"FixIt\"].


int ycmd_req_run_completer_command(int linenum, int columnnum, char *filepath, char *content, char *completertarget, char *completercommand, COMPLETER_COMMAND_RESULTS *ccr)
{
#ifdef DEBUG
	fprintf(stderr, "Entering ycmd_req_run_completer_command()\n");
#endif

	char *method = "POST";
	char *path = "/run_completer_command";

	//todo handle without string replace
	char *_json = "{"
		"        \"line_num\": LINE_NUM,"
		"        \"column_num\": COLUMN_NUM,"
		"        \"filepath\": \"FILEPATH\","
		"        \"command_arguments\": [COMMAND_ARGUMENTS],"
		"        \"completer_target\": \"COMPLETER_TARGET\","
		"        \"file_data\": {"
		"		\"FILEPATH\": {"
		"                \"filetypes\": [\"FILETYPES\"],"
		"                \"contents\": \"CONTENTS\""
		"        	}"
		"	 }"
		"}";


	char *json;
	json = strdup(_json);

	char line_num[DIGITS_MAX];
	char column_num[DIGITS_MAX];

	snprintf(line_num, DIGITS_MAX, "%d", linenum);
	snprintf(column_num, DIGITS_MAX, "%d", columnnum+(ycmd_globals.clang_completer?0:1));

	string_replace_w(&json, "LINE_NUM", line_num, 0);
	string_replace_w(&json, "COLUMN_NUM", column_num, 0);
	string_replace_w(&json, "COMPLETER_TARGET", completertarget, 0);
	string_replace_w(&json, "COMMAND_ARGUMENTS", completercommand, 0);

	_ycmd_json_replace_file_data(&json, filepath, content);

#ifdef DEBUG
	fprintf(stderr, "json body in ycmd_req_run_completer_command: %s\n", json);
#endif

	int status_code = 0;
	ne_request *request;
	request = ne_request_create(ycmd_globals.session, method, path);
	{
		ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,0);
		char *response_body = NULL;

		ne_add_request_header(request,"content-type","application/json");
		char *ycmd_b64_hmac = ycmd_compute_request(method, path, json);
		ne_add_request_header(request, HTTP_HEADER_YCM_HMAC, ycmd_b64_hmac);
		ne_set_request_body_buffer(request, json, strlen(json));

		int ret = ne_begin_request(request);
		status_code = ne_get_status(request)->code;
		ccr->status_code = status_code; //sometimes the subservers will throw exceptions so capture that
		if (ret == NE_OK)
		{
			response_body = _ne_read_response_body_full(request);

			const char *hmac_remote = ne_get_response_header(request, HTTP_HEADER_YCM_HMAC);
			ne_end_request(request);

			//attacker could inject malicious code into source code here but the user would see it.
			char *hmac_local = ycmd_compute_response(response_body);

#ifdef DEBUG
			fprintf(stderr,"hmac_local is %s\n",hmac_local);
			fprintf(stderr,"hmac_remote is %s\n",hmac_remote);
#endif

#ifdef DEBUG
			fprintf(stderr,"Server response for ycmd_req_run_completer_command: %s %zd\n", response_body, strlen(response_body));
#endif


			if (!hmac_local || !hmac_remote || !ycmd_compare_hmac(hmac_remote, hmac_local))
				;
			else
			{
				ccr->json_blob = strdup(response_body);
#ifdef DEBUG
				fprintf(stderr,"Setting usable COMPLETER_COMMAND_RESULTS flag\n");
#endif
				ccr->usable = 1;
			}
		}
		else
		{
#ifdef DEBUG
			fprintf(stderr,"ne_begin_request was negative\n");
#endif
		}

		if (response_body)
			free(response_body);
	}
	ne_request_destroy(request);

	free(json);

#ifdef DEBUG
	fprintf(stderr, "Status code in ycmd_req_run_completer_command is %d\n", status_code);
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
		ne_add_request_header(request, HTTP_HEADER_YCM_HMAC, ycmd_b64_hmac);

		int ret = ne_begin_request(request);
		if (ret == NE_OK)
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
	char *_path = "/healthy";
	char *path;
	path = strdup(_path);

	char *_body = "include_subservers=VALUE";
	char *body;
	body = strdup(_body);

	if (include_subservers)
		string_replace_w(&path, "VALUE", "1", 0);
	else
		string_replace_w(&path, "VALUE", "0", 0);

	int status_code = 0;
	ne_request *request;
	request = ne_request_create(ycmd_globals.session, method, path);
	{
		ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,1);
		char *ycmd_b64_hmac = ycmd_compute_request(method, path, body);
		ne_add_request_header(request, HTTP_HEADER_YCM_HMAC, ycmd_b64_hmac);
		ne_set_request_body_buffer(request, body, strlen(body));

		int ret = ne_begin_request(request);
		if (ret == NE_OK)
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

	free(path);
	free(body);

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
	char *_path = "/ready";
	char *path;
	path = strdup(_path);
	char *_body = "subserver=FILE_TYPE";
	char *body;
	body = strdup(_body);

	string_replace_w(&body, "FILE_TYPE", filetype, 0);

#ifdef DEBUG
	fprintf(stderr,"ycmd_rsp_is_server_ready path is %s\n",path);
#endif

	int status_code = 0;
	int not_compromised = 1;

	ne_request *request;
	request = ne_request_create(ycmd_globals.session, method, path);
	{
		ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,1);
		char *ycmd_b64_hmac = ycmd_compute_request(method, path, body);
		ne_add_request_header(request, HTTP_HEADER_YCM_HMAC, ycmd_b64_hmac);
		ne_set_request_body_buffer(request, body, strlen(body));

		int ret = ne_begin_request(request);
		if (ret == NE_OK)
		{
			char *response_body = _ne_read_response_body_full(request);
			const char *hmac_remote = ne_get_response_header(request, HTTP_HEADER_YCM_HMAC);
			ne_end_request(request);

#ifdef DEBUG
			fprintf(stderr, "Server response: %s\n", response_body); //should just say: true
#endif

			//attacker could steal source code beyond this point
			char *hmac_local = ycmd_compute_response(response_body);

#ifdef DEBUG
			fprintf(stderr,"hmac_local is %s\n",hmac_local);
			fprintf(stderr,"hmac_remote is %s\n",hmac_remote);
#endif

			not_compromised = ycmd_compare_hmac(hmac_remote, hmac_local);

			free(response_body);
		}

		status_code = ne_get_status(request)->code;
	}
	ne_request_destroy(request);

	free(path);
	free(body);

#ifdef DEBUG
	fprintf(stderr, "Status code in ycmd_rsp_is_server_ready is %d\n", status_code);
#endif

	return status_code == 200 && not_compromised;
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

	snprintf(line_num, DIGITS_MAX, "%d", linenum);
	snprintf(column_num, DIGITS_MAX, "%d", columnnum+(ycmd_globals.clang_completer?0:1));

	string_replace_w(&json, "LINE_NUM", line_num, 0);
	string_replace_w(&json, "COLUMN_NUM", column_num, 0);

	_ycmd_json_replace_file_data(&json, filepath, content);

	int status_code = 0;
	ne_request *request;
	request = ne_request_create(ycmd_globals.session, method, path);
	{
		ne_add_request_header(request,"content-type","application/json");
		if (strcmp(method, "POST") == 0)
		{
			ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,0);
			char *ycmd_b64_hmac = ycmd_compute_request(method, path, json);
			ne_add_request_header(request, HTTP_HEADER_YCM_HMAC, ycmd_b64_hmac);
		}
		else
		{
			ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,1);
		}

		ne_set_request_body_buffer(request, json, strlen(json));

		int ret = ne_begin_request(request);
		if (ret == NE_OK)
		{
			char *response_body = _ne_read_response_body_full(request);
			ne_end_request(request);

#ifdef DEBUG
			fprintf(stderr, "Server response: %s",response_body);
#endif
			free(response_body);
		}

		status_code = ne_get_status(request)->code;
	}
	ne_request_destroy(request);

	free(json);

#ifdef DEBUG
	fprintf(stderr, "Status code in _ycmd_req_simple_request is %d\n", status_code);
#endif

	return status_code == 200;
}

//get the list completer commands available for the completer target
int ycmd_req_defined_subcommands(int linenum, int columnnum, char *filepath, char *content, char *completertarget, DEFINED_SUBCOMMANDS_RESULTS *dsr)
{
#ifdef DEBUG
	fprintf(stderr, "Entering defined_subcommands()\n");
#endif

	char *method = "POST";
	char *path = "/defined_subcommands";

	//todo handle without string replace
	char *_json = "{"
		"        \"line_num\": LINE_NUM,"
		"        \"column_num\": COLUMN_NUM,"
		"        \"filepath\": \"FILEPATH\","
		"        \"completer_target\": \"COMPLETER_TARGET\","
		"        \"file_data\": {"
		"		\"FILEPATH\": {"
		"                \"filetypes\": [\"FILETYPES\"],"
		"                \"contents\": \"CONTENTS\""
		"        	}"
		"	 }"
		"}";


	char *json;
	json = strdup(_json);

	char line_num[DIGITS_MAX];
	char column_num[DIGITS_MAX];

	snprintf(line_num, DIGITS_MAX, "%d", linenum);
	snprintf(column_num, DIGITS_MAX, "%d", columnnum+(ycmd_globals.clang_completer?0:1));

	string_replace_w(&json, "LINE_NUM", line_num, 0);
	string_replace_w(&json, "COLUMN_NUM", column_num, 0);
	string_replace_w(&json, "COMPLETER_TARGET", completertarget, 0);

	_ycmd_json_replace_file_data(&json, filepath, content);

#ifdef DEBUG
	fprintf(stderr, "json body in ycmd_req_defined_subcommands: %s\n", json);
#endif

	int status_code = 0;
	ne_request *request;
	request = ne_request_create(ycmd_globals.session, method, path);
	{
		ne_set_request_flag(request,NE_REQFLAG_IDEMPOTENT,0);
		char *response_body = NULL;

		ne_add_request_header(request,"content-type","application/json");
		char *ycmd_b64_hmac = ycmd_compute_request(method, path, json);
		ne_add_request_header(request, HTTP_HEADER_YCM_HMAC, ycmd_b64_hmac);
		ne_set_request_body_buffer(request, json, strlen(json));

		int ret = ne_begin_request(request);
		status_code = ne_get_status(request)->code;
		dsr->status_code = status_code; //sometimes the subservers will throw exceptions so capture that
		if (ret == NE_OK)
		{
			response_body = _ne_read_response_body_full(request);

			const char *hmac_remote = ne_get_response_header(request, HTTP_HEADER_YCM_HMAC);
			ne_end_request(request);

			//attacker could inject malicious code into source code here but the user would see it.
			char *hmac_local = ycmd_compute_response(response_body);

#ifdef DEBUG
			fprintf(stderr,"hmac_local is %s\n",hmac_local);
			fprintf(stderr,"hmac_remote is %s\n",hmac_remote);
#endif

#ifdef DEBUG
			fprintf(stderr,"Server response for ycmd_req_defined_subcommands: %s %zd\n", response_body, strlen(response_body));
#endif


			if (!hmac_local || !hmac_remote || !ycmd_compare_hmac(hmac_remote, hmac_local))
				;
			else
			{
				dsr->json_blob = strdup(response_body);
#ifdef DEBUG
				fprintf(stderr,"Setting usable COMPLETER_COMMAND_RESULTS flag\n");
#endif
				dsr->usable = 1;
			}
		}
		else
		{
#ifdef DEBUG
			fprintf(stderr,"ne_begin_request was negative\n");
#endif
		}

		if (response_body)
			free(response_body);
	}
	ne_request_destroy(request);

	free(json);

#ifdef DEBUG
	fprintf(stderr, "Status code in ycmd_req_defined_subcommands is %d\n", status_code);
#endif

	return status_code == 200;
}




//filepath should be the .ycm_extra_conf.py file
//should load before parsing
void ycmd_req_load_extra_conf_file(char *filepath)
{
#ifdef DEBUG
	fprintf(stderr, "Entering ycmd_req_load_extra_conf_file()\n");
#endif
	char *method = "POST";
	char *path = "/load_extra_conf_file";

	_ycmd_req_simple_request(method, path, 0, 0, filepath, "");
}

//filepath should be the .ycm_extra_conf.py file
void ycmd_req_ignore_extra_conf_file(char *filepath)
{
#ifdef DEBUG
	fprintf(stderr, "Entering ycmd_req_ignore_extra_conf_file()\n");
#endif
	char *method = "POST";
	char *path = "/ignore_extra_conf_file";

	_ycmd_req_simple_request(method, path, 0, 0, filepath, "");
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
	destroy_file_ready_to_parse_results(&ycmd_globals.file_ready_to_parse_results);

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

	string_replace_w(&ycmd_globals.json, "HMAC_SECRET", ycmd_globals.secret_key_base64, 0);
	if (ycmd_globals.core_version == 39) {
		string_replace_w(&ycmd_globals.json, "GOCODE_PATH", GOCODE_PATH, 0);
		string_replace_w(&ycmd_globals.json, "GODEF_PATH", GODEF_PATH, 0);
		string_replace_w(&ycmd_globals.json, "RUST_SRC_PATH", RUST_SRC_PATH, 0);
		string_replace_w(&ycmd_globals.json, "RACERD_PATH", RACERD_PATH, 0);
	} else if (ycmd_globals.core_version == 43) {
		string_replace_w(&ycmd_globals.json, "CLANGD_PATH", CLANGD_PATH, 0);
		string_replace_w(&ycmd_globals.json, "GOPLS_PATH", GOPLS_PATH, 0);
		string_replace_w(&ycmd_globals.json, "MONO_PATH", MONO_PATH, 0);
		string_replace_w(&ycmd_globals.json, "RLS_PATH", RLS_PATH, 0);
		string_replace_w(&ycmd_globals.json, "RUSTC_PATH", RUSTC_PATH, 0);
		string_replace_w(&ycmd_globals.json, "OMNISHARP_PATH", OMNISHARP_PATH, 0);
		string_replace_w(&ycmd_globals.json, "TSSERVER_PATH", TSSERVER_PATH, 0);
	} else if (ycmd_globals.core_version == 44 || ycmd_globals.core_version == 45 || ycmd_globals.core_version == 46 || ycmd_globals.core_version == 47) {
		string_replace_w(&ycmd_globals.json, "CLANGD_PATH", CLANGD_PATH, 0);
		string_replace_w(&ycmd_globals.json, "GOPLS_PATH", GOPLS_PATH, 0);
		string_replace_w(&ycmd_globals.json, "JAVA_PATH", JAVA_PATH, 0);
		string_replace_w(&ycmd_globals.json, "MONO_PATH", MONO_PATH, 0);
		string_replace_w(&ycmd_globals.json, "RUST_TOOLCHAIN_PATH", RUST_TOOLCHAIN_PATH, 0);
		string_replace_w(&ycmd_globals.json, "OMNISHARP_PATH", OMNISHARP_PATH, 0);
		string_replace_w(&ycmd_globals.json, "TSSERVER_PATH", TSSERVER_PATH, 0);
	}
	string_replace_w(&ycmd_globals.json, "YCMD_PYTHON_PATH", YCMD_PYTHON_PATH, 0);

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
		fprintf(stderr, "YCMD_PYTHON_PATH is %s\n",YCMD_PYTHON_PATH);
		fprintf(stderr, "YCMD_PATH is %s\n",YCMD_PATH);
		fprintf(stderr, "port_value %s\n", port_value);
		fprintf(stderr, "options_file_value %s\n", options_file_value);
		fprintf(stderr, "idle_suicide_seconds_value %s\n", idle_suicide_seconds_value);
		fprintf(stderr, "generated server command: %s %s %s %s %s %s %s %s\n", YCMD_PYTHON_PATH, YCMD_PATH, "--port", port_value, "--options_file", options_file_value, "--idle_suicide_seconds", idle_suicide_seconds_value);

		fprintf(stderr, "Child process is going to start the server...\n");
#endif

		//after execl executes, the server will delete the tmpfile
#ifdef DEBUG
		execl(YCMD_PYTHON_PATH, YCMD_PYTHON_PATH, ycmd_path, "--port", port_value, "--options_file", options_file_value, "--idle_suicide_seconds", idle_suicide_seconds_value, "--keep_logfiles", "--stdout", "/tmp/ynano2.txt", "--stderr", "/tmp/ynano.txt", NULL);
#else
		execl(YCMD_PYTHON_PATH, YCMD_PYTHON_PATH, ycmd_path, "--port", port_value, "--options_file", options_file_value, "--idle_suicide_seconds", idle_suicide_seconds_value, "--stdout", "/dev/null", "--stderr",  "/dev/null", NULL);
#endif

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

#ifdef DEBUG
	fprintf(stderr, "Parent process: checking if child PID is still alive...\n");
#endif
	if (waitpid(pid,0,WNOHANG) == 0)
	{
		statusline(HUSH, "Server just ran...");
#ifdef DEBUG
		fprintf(stderr,"ycmd server is up.\n");
#endif
		ycmd_globals.running = 1;
	}
	else
	{
		statusline(HUSH, "Server didn't ran...");
#ifdef DEBUG
		fprintf(stderr,"ycmd failed to load server.\n");
#endif
		ycmd_globals.running = 0;

		ycmd_stop_server();
		return;
	}

	statusline(HUSH, "Letting the server initialize.  Wait...");

	//give time for the server initialize
	usleep(1500000);

	statusline(HUSH, "Checking server health...");

	int i;
	int tries = 5;
	for (i = 0; i < tries && ycmd_globals.connected == 0; i++)
	{
#ifdef DEBUG
		fprintf(stderr, "Parent process: checking ycmd server health by communicating with it...\n");
#endif
		if (ycmd_rsp_is_healthy_simple())
		{
			statusline(HUSH, "Connected...");
#ifdef DEBUG
			fprintf(stderr,"Client can communicate with server.\n");
#endif
			ycmd_globals.connected = 1;
		}
		else
		{
			statusline(HUSH, "Connect failed...");
#ifdef DEBUG
			fprintf(stderr,"Client cannot communicate with server.  Retrying...\n");
#endif
			ycmd_globals.connected = 0;
			usleep(1000000);
		}
	}

	//load conf
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
	full_refresh();
	statusline(HUSH, "Please stop typing.  Clearing input buffer...");
	nodelay(stdscr, TRUE);  while (getch() != ERR); nodelay(stdscr, FALSE);
	full_refresh();
	statusline(HUSH, "Please stop typing.  Clearing input buffer...");

	usleep(1000000);
	fflush(stdin);

	full_refresh();
	statusline(HUSH, "Please stop typing.  Clearing input buffer...");
	nodelay(stdscr, TRUE); while (getch() != ERR); nodelay(stdscr, FALSE);
	full_refresh();
	draw_all_subwindows();

	statusline(HUSH, "Input buffer cleared.");
}

char *ycmd_generate_secret_base64(char *secret)
{
#ifdef USE_NETTLE
	static char b64_secret[BASE64_ENCODE_RAW_LENGTH(SECRET_KEY_LENGTH)];
	base64_encode_raw((unsigned char *)b64_secret, SECRET_KEY_LENGTH, (unsigned char *)secret);
#elif USE_OPENSSL
	BIO *b, *append;
	BUF_MEM *pp;
	b = BIO_new(BIO_f_base64());
	append = BIO_new(BIO_s_mem());
	b = BIO_push(b, append);

	BIO_set_flags(b, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b, secret, SECRET_KEY_LENGTH);
	BIO_flush(b);
	BIO_get_mem_ptr(b, &pp);

	static char b64_secret[80];
	memset(b64_secret, 0, 80);
	memcpy(b64_secret, pp->data, pp->length);
	BIO_free_all(b);
#elif USE_LIBGCRYPT
	//todo secure memory
	static char b64_secret[80];
        gchar *_b64_secret = g_base64_encode((unsigned char *)secret, SECRET_KEY_LENGTH);
	strncpy(b64_secret, _b64_secret, 80);
	free (_b64_secret);
#else
#error "You need to define a crypto library to use."
#endif

#ifdef DEBUG
	fprintf(stderr,"base64 secret is %s\n",b64_secret);
#endif
	return b64_secret;
}

char *ycmd_compute_request(char *method, char *path, char *body)
{
#ifdef DEBUG
	fprintf(stderr, "ycmd_compute_request entered\n");
#endif
#ifdef USE_NETTLE
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
#elif USE_OPENSSL
        unsigned char join[HMAC_SIZE*3];
        HMAC(EVP_sha256(), ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH,(unsigned char *) method,strlen(method), join, NULL);
        HMAC(EVP_sha256(), ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH,(unsigned char *) path,strlen(path), join+HMAC_SIZE, NULL);
        HMAC(EVP_sha256(), ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH,(unsigned char *) body,strlen(body), join+2*HMAC_SIZE, NULL);

        unsigned char *digest_join = HMAC(EVP_sha256(), ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH,(unsigned char *) join,HMAC_SIZE*3, NULL, NULL);

	BIO *b, *append;
	BUF_MEM *pp;
	b = BIO_new(BIO_f_base64());
	append = BIO_new(BIO_s_mem());
	b = BIO_push(b, append);

	BIO_set_flags(b, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b, digest_join, HMAC_SIZE);
	BIO_flush(b);
	BIO_get_mem_ptr(b, &pp);

	static char b64_request[80];
	memset(b64_request, 0, 80);
	memcpy(b64_request, pp->data, pp->length);
	BIO_free_all(b);
#elif USE_LIBGCRYPT
        unsigned char join[HMAC_SIZE*3];
	size_t length;

	gcry_mac_hd_t hd;
	gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, 0/*GCRY_MAC_FLAG_SECURE*/, NULL);
	gcry_mac_setkey(hd, ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH);

	gcry_mac_write(hd, method, strlen(method));
	length = HMAC_SIZE;
	gcry_mac_read(hd, join, &length);

	gcry_mac_reset(hd);

	gcry_mac_write(hd, path, strlen(path));
	length = HMAC_SIZE;
	gcry_mac_read(hd, join+HMAC_SIZE, &length);

	gcry_mac_reset(hd);

	gcry_mac_write(hd, body, strlen(body));
	length = HMAC_SIZE;
	gcry_mac_read(hd, join+2*HMAC_SIZE, &length);

	gcry_mac_reset(hd);

	unsigned char digest_join[HMAC_SIZE];
	gcry_mac_write(hd, join, HMAC_SIZE*3);
	length = HMAC_SIZE;
	gcry_mac_read(hd, digest_join, &length);

	gcry_mac_close(hd);

	//todo secure memory
	static char b64_request[80];
        gchar *_b64_request = g_base64_encode((unsigned char *)digest_join, HMAC_SIZE);
	strncpy(b64_request, _b64_request, 80);
	free (_b64_request);
#else
#error "You need to define a crypto library to use."
#endif

#ifdef DEBUG
	fprintf(stderr,"base64 hmac is %s\n",b64_request);
#endif
	return b64_request;
}

char *ycmd_compute_response(char *response_body)
{
#ifdef DEBUG
	fprintf(stderr, "ycmd_compute_response entered\n");
#endif
#ifdef USE_NETTLE
	static char hmac_response[HMAC_SIZE];
	struct hmac_sha256_ctx hmac_ctx;

	hmac_sha256_set_key(&hmac_ctx, SECRET_KEY_LENGTH, (unsigned char *)ycmd_globals.secret_key_raw);
	hmac_sha256_update(&hmac_ctx, strlen(response_body), (unsigned char *)response_body);
	hmac_sha256_digest(&hmac_ctx, HMAC_SIZE, (unsigned char *)hmac_response);

	static char b64_response[BASE64_ENCODE_RAW_LENGTH(HMAC_SIZE)];
	base64_encode_raw((unsigned char *)b64_response, HMAC_SIZE, (unsigned char *)hmac_response);
#elif USE_OPENSSL
        unsigned char *response_digest = HMAC(EVP_sha256(), ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH,(unsigned char *) response_body,strlen(response_body), NULL, NULL);

	BIO *b, *append;
	BUF_MEM *pp;
	b = BIO_new(BIO_f_base64());
	append = BIO_new(BIO_s_mem());
	b = BIO_push(b, append);

	BIO_set_flags(b, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b, response_digest, HMAC_SIZE);
	BIO_flush(b);
	BIO_get_mem_ptr(b, &pp);

	static char b64_response[80];
	memset(b64_response, 0, 80);
	memcpy(b64_response, pp->data, pp->length);
	BIO_free_all(b);
#elif USE_LIBGCRYPT
	gcry_mac_hd_t hd;
	gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, 0/*GCRY_MAC_FLAG_SECURE*/, NULL);
	gcry_mac_setkey(hd, ycmd_globals.secret_key_raw, SECRET_KEY_LENGTH);

	char response_digest[HMAC_SIZE];
	gcry_mac_write(hd, response_body, strlen(response_body));
	size_t length = HMAC_SIZE;
	gcry_mac_read(hd, response_digest, &length);

	gcry_mac_close(hd);

	//todo secure memory
	static char b64_response[80];
        gchar *_b64_response = g_base64_encode((unsigned char *)response_digest, HMAC_SIZE);
	strncpy(b64_response, _b64_response, 80);
	free (_b64_response);
#else
#error "You need to define a crypto library to use."
#endif

#ifdef DEBUG
	fprintf(stderr,"base64 hmac is %s\n",b64_response);
#endif
	return b64_response;
}

#if USE_OPENMP
//the final length measured can be like 197466 bytes for this file so simd and multicore seems reasonable to use versus the naive algorithm.
//use multicore and simd to count the number of start sequence
size_t _predict_new_json_escape_size_multicore(char **buffer)
{
	int i = 0;
	int len = strlen(*buffer);

	size_t outlen = 0;
	outlen = 1;
	size_t outlen_sum = 0;

	int stop = 0;
	int resume_i = 0;
	int resume_ii = 0; //used for initializing for loop initilizer variable because can have variable listed twice in pragma

	char *p = *buffer;

#ifdef DEBUG
	fprintf(stderr, "len=%d\n",len);
	fprintf(stderr, "before avx512 resume_ii=%d outlen_sum=%zd\n",resume_ii,outlen_sum);
#endif

#ifdef __AVX512__
	#pragma omp parallel for \
		default(none) \
		reduction(+:outlen,resume_i) \
		shared(p,len,stderr) \
		firstprivate(stop,resume_ii) \
		private(i)
	for (i = resume_ii; i < len; i+=64)
	{
		if (len-i <= 64)
		{
			stop = 1;
		}

		if (!stop)
		{
#ifdef DEBUG
			fprintf(stderr, "i=%d running multicore avx512 threadid=%d\n",i,omp_get_thread_num());
#endif

			//use simd to compare by chunks
			//sse doesn't have an lt

			//compare 64 at a time instead of 1 at a time

			__m512i chunk;
			memcpy(&chunk, i+p, 64);
			__mmask64 r0,r1,r2,r3,rf0,rf1,rf2,rf3,rf4;

			//check 2 byte sequences
			__m512i c0 = _mm512_set1_epi8('\\'); //5c
			__m512i c1 = _mm512_set1_epi8('\"'); //22
			__m512i c2 = _mm512_set1_epi8('/'); //2f
			r0 = _mm512_cmpeq_epi8_mask(chunk,c0);
			r1 = _mm512_cmpeq_epi8_mask(chunk,c1);
			r2 = _mm512_cmpeq_epi8_mask(chunk,c2);
			rf0 = r0 | r1 | r2; //final

			__m512i c3 = _mm512_set1_epi8('\b'); //08
			rf1 = _mm512_cmple_epu8_mask(c3,chunk);
			__m512i c4 = _mm512_set1_epi8('\r'); //0d
			rf2 = _mm512_cmple_epu8_mask(chunk,c4);
			rf3 = rf1 & rf2; //final

			int c;
			c = 0;
			__mmask64 result;
			result = rf0 | rf3;
			if (result)
			{
				c = __builtin_popcountll(result);
				outlen += c*2;
			}
			outlen += 64-c;

			//check 6 byte sequences
			__m512i c5 = _mm512_set1_epi8('\x01');
			rf1 = _mm512_cmple_epu8_mask(c3,chunk);
			__m512i c6 = _mm512_set1_epi8('\x1f');
			rf2 = _mm512_cmple_epu8_mask(chunk,c4);
			result = rf1 & rf2; //final

			c = 0;
			if (result)
			{
				c = __builtin_popcountll(result);
				outlen += c*6;
			}
			outlen += 64-c;

			resume_i+=64;

#ifdef DEBUG
			fprintf(stderr, "i=%d running multicore avx512 threadid=%d outlen=%zd\n",i,omp_get_thread_num(),outlen);
#endif
		}
	}
#endif

	if (resume_i)
		resume_ii+=resume_i;
	resume_i = 0;

	if (outlen)
		outlen_sum+=outlen;
	outlen = 0;


#ifdef DEBUG
	fprintf(stderr, "before avx2 resume_ii=%d outlen_sum=%zd\n",resume_ii, outlen_sum);
#endif
	assert(outlen_sum>=resume_ii);

	stop = 0;

#ifdef __AVX2__
	#pragma omp parallel for \
		default(none) \
		reduction(+:outlen,resume_i) \
		shared(p,len,stderr) \
		firstprivate(stop,resume_ii) \
		private(i)
	for (i = resume_ii; i < len; i+=32)
	{
		if (len-i <= 32)
		{
			stop = 1;
		}

		if (!stop)
		{
#ifdef DEBUG
			fprintf(stderr, "i=%d running multicore avx2 threadid=%d\n",i,omp_get_thread_num());
#endif

			//compare 32 at a time instead of 1 at a time
			__m256i chunk;
			memcpy(&chunk, i+p, 32);
			__mmask64 r0,r1,r2,r3,rf0,rf1,rf2,rf3,rf4;

			//avx2 doesn't support cmplt <
			//since avx2 doesn't support < or <= we have to use logical eqivalence to get the same effect
			// 1 <= 2 <= 3 which is logically equivalent to 1 <= 2 && 2 <= 3
			//is logical equivalent and consistent as 3>= 2 && 2 >= 1
			// 3 >= 2 >= 1

			//check 2 byte sequences
			__m256i c0 = _mm256_set1_epi8('\\'); //5c
			__m256i c1 = _mm256_set1_epi8('\"'); //22
			__m256i c2 = _mm256_set1_epi8('/'); //2f
			r0 = _mm256_cmpeq_epi8(chunk,c0);
			r1 = _mm256_cmpeq_epi8(chunk,c1);
			r2 = _mm256_cmpeq_epi8(chunk,c2);
			rf0 = _mm256_or_si256(r0, r1);
			rf0 = _mm256_or_si256(rf0, r2); //final

			__m256i c3 = _mm256_set1_epi8('\r'); //0d
			r0 = _mm256_cmpgt_epi8(c3,chunk);
			r1 = _mm256_cmpeq_epi8(c3,chunk);
			rf1 = _mm256_or_si256(r0,r1);
			__m256i c4 = _mm256_set1_epi8('\b'); //08
			r2 = _mm256_cmpgt_epi8(chunk,c4);
			r3 = _mm256_cmpeq_epi8(chunk,c4);
			rf2 = _mm256_or_si256(r2,r3);
			rf3 = _mm256_and_si256(rf1,rf2); //final

			rf0 = _mm256_or_si256(rf0, rf3); //final final

			int c;
			c = 0;
			int result;
			result = _mm256_movemask_epi8(rf0);
			if (result)
			{
				c = __builtin_popcount(result);
				outlen += c*2;
			}
			outlen += 32-c;

			//check 6 byte sequences
			__m256i c5 = _mm256_set1_epi8('\x1f');
			rf1 = _mm256_cmpgt_epi8(c3,chunk);
			__m256i c6 = _mm256_set1_epi8('\x01');
			rf2 = _mm256_cmpgt_epi8(chunk,c4);
			rf0 = _mm256_and_si256(rf1, rf2); //final

			c = 0;
			result = _mm256_movemask_epi8(rf0);
			if (result)
			{
				c = __builtin_popcount(result);
				outlen += c*6;
			}
			outlen += 32-c;

			resume_i+=32;

#ifdef DEBUG
			fprintf(stderr, "i=%d running multicore avx2 threadid=%d outlen=%zd\n",i,omp_get_thread_num(),outlen);
#endif

		}
	}
#endif

	if (resume_i)
		resume_ii+=resume_i;
	resume_i = 0;

	if (outlen)
		outlen_sum+=outlen;
	outlen = 0;


#ifdef DEBUG
	fprintf(stderr, "before sse2 resume_i=%d outlen_sum=%zd\n",resume_i,outlen_sum);
#endif
	assert(outlen_sum>=resume_ii);

	stop = 0;

#ifdef __SSE2__
	#pragma omp parallel for \
		default(none) \
		reduction(+:outlen,resume_i) \
		shared(p,len,stderr) \
		firstprivate(stop,resume_ii) \
		private(i)
	for (i = resume_ii; i < len; i+=16)
	{
		if (len-i <= 16)
		{
			stop = 1;
		}

		if (!stop)
		{
#ifdef DEBUG
			fprintf(stderr, "i=%d running multicore sse2 threadid=%d\n", i, omp_get_thread_num());
#endif

			//compare 16 at a time instead of 1 at a time
			__m128i chunk;
			memcpy(&chunk, i+p, 16);
			__m128i r0,r1,r2,r3,rf0,rf1,rf2,rf3;

			//check 2 byte sequences
			__m128i c0 = _mm_set1_epi8('\\'); //5c
			__m128i c1 = _mm_set1_epi8('\"'); //22
			__m128i c2 = _mm_set1_epi8('/'); //2f
			r0 = _mm_cmpeq_epi8(chunk,c0); //x == backslash
			r1 = _mm_cmpeq_epi8(chunk,c1); //x == "
			r2 = _mm_cmpeq_epi8(chunk,c2); //x == .
			rf0 = _mm_or_si128(r0,r1); // x == \\ || x == \"
			rf0 = _mm_or_si128(rf0,r2); //final // x == \\ || x == \" || x == .

			__m128i c3 = _mm_set1_epi8('\b'); //08
			r0 = _mm_cmplt_epi8(c3,chunk); //\b < x
			r1 = _mm_cmpeq_epi8(c3,chunk); //\b = x
			rf1 = _mm_or_si128(r0,r1); //\b <= x
			__m128i c4 = _mm_set1_epi8('\r'); //0d
			r2 = _mm_cmplt_epi8(chunk,c4); //x < \r
			r3 = _mm_cmpeq_epi8(chunk,c4); //x = \r
			rf2 = _mm_or_si128(r2,r3); // x <= \r
			rf3 = _mm_and_si128(rf1,rf2); //final \b <= x && x <= \r
			rf0 = _mm_and_si128(rf0,rf3); //final

			int c;
			c = 0;
			int result;
			result = _mm_movemask_epi8(rf0);
			if (result)
			{
				c = __builtin_popcount(result); //count bits set
				outlen += c*2;
#ifdef DEBUG
				fprintf(stderr, "i=%d running multicore sse2 threadid=%d matches: c=%d result=%08x (2)\n", i, omp_get_thread_num(),c, result);
#endif
			}
			outlen += 16-c;

			//check 6 byte sequences
			__m128i c5 = _mm_set1_epi8('\x01');
			r0 = _mm_cmplt_epi8(c5,chunk); //\x01 < x
			r1 = _mm_cmpeq_epi8(c5,chunk); //\x01 = x
			rf1 = _mm_or_si128(r0,r1); // \x01 <= x
			__m128i c6 = _mm_set1_epi8('\x1f');
			r2 = _mm_cmplt_epi8(chunk,c6); //x < \x1f
			r3 = _mm_cmpeq_epi8(chunk,c6); //x = \x1f
			rf2 = _mm_or_si128(r2,r3); //x <= \x1f
			rf0 = _mm_and_si128(rf1,rf2); //final \x01 <= x && x <= \x1f

			c = 0;
			result = _mm_movemask_epi8(rf0);
			if (result)
			{
				c = __builtin_popcount(result);
				outlen += c*6;
#ifdef DEBUG
				fprintf(stderr, "i=%d running multicore sse2 threadid=%d matches: c=%d result=%08x (3)\n", i, omp_get_thread_num(),c,result);
#endif
			}
			outlen += 16-c;

			resume_i+=16;
		}
	}
#endif

	if (resume_i)
		resume_ii+=resume_i;
	resume_i = 0;

	if (outlen)
		outlen_sum+=outlen;
	outlen = 0;

#ifdef DEBUG
	//outlen_sum >= resume_ii
	fprintf(stderr, "before mmx resume_ii=%d outlen_sum=%zd\n",resume_ii, outlen_sum);
#endif
	assert(outlen_sum>=resume_ii);

	stop = 0;
	int have_sse = ycmd_globals.have_sse;

	//i = resume_i;
#ifdef __MMX__
	#pragma omp parallel for \
		default(none) \
		reduction(+:outlen,resume_i) \
		shared(p,len,stderr,have_sse) \
		firstprivate(stop,resume_ii) \
		private(i)
	for (i = resume_ii; i < len; i+=8)
	{
		if (len-i <= 8)
		{
			stop = 1;
		}

		if (!stop)
		{
#ifdef DEBUG
			fprintf(stderr, "i=%d running multicore mmx threadid=%d\n",i,omp_get_thread_num());
#endif

			//compare 8 at a time instead of 1

			//mmx doesn't have cmplt < so we have to make a logical equivalent one using cmpgt >
			//let c = 2
			//1 <= c <= 3 which is equivalent to 1 <= c && c <= 3
			//the logical equivalent one is
			//3 >= c >= 1 which is equivalent to 3 >= c && c >= 1 check by subsituting c=2
			//mmx
			//_mm_cmpgt_pi8
			//_mm_cmpeq_pi8
			__m64 chunk;
			memcpy(&chunk, i+p, 8);
			__m64 r0,r1,r2,r3,rf0,rf1,rf2,rf3,rf4;

			//check 2 byte sequences
			__m64 c0 = _mm_set1_pi8('\\');
			__m64 c1 = _mm_set1_pi8('\"');
			__m64 c2 = _mm_set1_pi8('/');
			r0 = _mm_cmpeq_pi8(chunk,c0);
			r1 = _mm_cmpeq_pi8(chunk,c1);
			r2 = _mm_cmpeq_pi8(chunk,c2);
			rf0 = _mm_or_si64(r0,r1);
			rf0 = _mm_or_si64(rf0,r2); //final


			__m64 c3 = _mm_set1_pi8('\r'); //0d
			r0 = _mm_cmpgt_pi8(c3,chunk);
			r1 = _mm_cmpeq_pi8(c3,chunk);
			rf1 = _mm_or_si64(r0,r1);
			__m64 c4 = _mm_set1_pi8('\b'); //08
			r2 = _mm_cmpgt_pi8(chunk,c4);
			r3 = _mm_cmpeq_pi8(chunk,c4);
			rf2 = _mm_or_si64(r2,r3);
			rf3 = _mm_and_si64(rf1,rf2); //final
			rf0 = _mm_or_si64(rf0,rf3); //final

			int c;
			int result;
			if (have_sse)
			{
				c = 0;
				result = _mm_movemask_pi8(rf0);
				if (result)
				{
					c = __builtin_popcount(result);
					outlen += c*2;
#ifdef DEBUG
					fprintf(stderr, "i=%d running multicore mmx threadid=%d matches: c=%d result=%04x (1)\n",i,omp_get_thread_num(),c, result);
#endif
				}
				outlen += 8-c; //sizeof(mmx register) - hamming weight
			}
			else
			{
				//we need to extract a bit per each 8 byte block so we don't over count
				c = 0;
				int result_x;
				result_x = _m_to_int(rf0);
				result_x = (result_x & 0x01010101);
				if (result_x)
				{
					c = __builtin_popcount(result_x);
					outlen += c*2;
#ifdef DEBUG
					fprintf(stderr, "i=%d running multicore mmx threadid=%d matches: c=%d result_x=%04x (1a)\n",i,omp_get_thread_num(),c, result_x);
#endif
				}
				outlen += 4-c; //sizeof((int32) low mmx register)) - hamming weight

				c = 0;
				rf0 = _m_psrlqi(rf0, 4);
				result_x = _m_to_int(rf0);
				result_x = (result_x & 0x01010101);
				if (result_x)
				{
					c = __builtin_popcount(result_x);
					outlen += c*2;
#ifdef DEBUG
					fprintf(stderr, "i=%d running multicore mmx threadid=%d matches: c=%d result_x=%04x (2)\n",i,omp_get_thread_num(),c, result_x);
#endif
				}
				outlen += 4-c; //sizeof((int32) high mmx register)) - hamming weight
			}

			//check 6 byte sequences
			__m64 c5 = _mm_set1_pi8('\x1f');
			r0 = _mm_cmpgt_pi8(c5,chunk);
			r1 = _mm_cmpeq_pi8(c5,chunk);
			rf1 = _mm_or_si64(r0,r1);
			__m64 c6 = _mm_set1_pi8('\x01');
			r2 = _mm_cmpgt_pi8(chunk,c6);
			r3 = _mm_cmpeq_pi8(chunk,c6);
			rf2 = _mm_or_si64(r2,r3);
			rf4 = _mm_and_si64(rf1,rf2); //final

			if (have_sse)
			{
				c = 0;
				result = _mm_movemask_pi8(rf4);
				if (result)
				{
					c = __builtin_popcount(result);
					outlen += c*2;
#ifdef DEBUG
					fprintf(stderr, "i=%d running multicore mmx threadid=%d matches: c=%d (1)\n",i,omp_get_thread_num(),c);
#endif
				}
				outlen += 8-c;
			}
			else
			{
				//we need to extract a bit per each 8 byte block so we don't over count
				c = 0;
				int result_x;
				result_x = _m_to_int(rf0);
				result_x = (result_x & 0x01010101);
				if (result_x)
				{
					c = __builtin_popcount(result_x);
					outlen += c*6;
#ifdef DEBUG
					fprintf(stderr, "i=%d running multicore mmx threadid=%d matches: c=%d (1a)\n",i,omp_get_thread_num(),c);
#endif
				}
				outlen += 4-c;

				c = 0;
				rf0 = _m_psrlqi(rf0, 4);
				result_x = _m_to_int(rf0);
				result_x = (result_x & 0x01010101);
				if (result_x)
				{
					int c = __builtin_popcount(result_x);
					outlen += c*6;
#ifdef DEBUG
					fprintf(stderr, "i=%d running multicore mmx threadid=%d matches: c=%d (2)\n",i,omp_get_thread_num(),c);
#endif
				}
				outlen += 4-c;
			}

			resume_i+=8;

#ifdef DEBUG
			fprintf(stderr, "i=%d running multicore mmx threadid=%d outlen=%zd\n",i,omp_get_thread_num(),outlen);
#endif
		}
	}
#endif

	if (resume_i)
		resume_ii+=resume_i;
	resume_i = 0;

	if (outlen)
		outlen_sum+=outlen;
	outlen = 0;

#ifdef DEBUG
	fprintf(stderr, "before naive resume_ii=%d outlen_sum=%zd\n",resume_ii, outlen_sum);
#endif
	assert(outlen_sum>=resume_ii);

	#pragma omp parallel for \
		default(none) \
		reduction(+:outlen,resume_i) \
		shared(p,len,stderr) \
		firstprivate(stop,resume_ii) \
		private(i)
	for (i = resume_ii; i < len; i++)
	{

#ifdef DEBUG
		fprintf(stderr, "i=%d running multicore byte checks threadid=%d\n",i,omp_get_thread_num());
#endif
		int matches = 0;
		char c = p[i];
		if (c == '\\' || ('\b' <= c && c <= '\r') || c == '\"' || c == '/') // \\   //escape already escape
		{
			outlen+=2;
			matches+=1;
		}
		else if (('\x01' <= c && c <= '\x1f') /* || p[i] == 0x7f delete char */) //escape control characters
		{
			outlen+=6;
			matches+=1;
		}
		else
		{
			outlen+=1;
			matches+=1;
		}

#ifdef DEBUG
		fprintf(stderr, "i=%d running multicore byte checks threadid=%d matches=%d\n",i,omp_get_thread_num(),matches);
#endif
		resume_i+=1;
	}

	if (resume_i)
		resume_ii+=resume_i;

	if (outlen)
		outlen_sum+=outlen;

#ifdef DEBUG
	fprintf(stderr, "final resume_ii=%d\n",resume_ii);
#endif

#ifdef DEBUG
	fprintf(stderr, "final length=%zd\n",outlen_sum);
#endif

	assert(outlen_sum>=resume_ii);

	return outlen_sum;
}
#endif

//naive version for unicore and non simd
//scopes out the new length so we can avoid the overhead of many calls to _expand or realloc
size_t _predict_new_json_escape_size_naive(char **buffer)
{
	int i = 0;
	int len = strlen(*buffer);

	size_t outlen;
	outlen = 1;

	char *p = *buffer;
	for (i = 0; i < len; i++)
	{
		char c = p[i];
		if (c == '\\' || ('\b' <= c && c <= '\r') || c == '\"' || c == '/') // \\   //escape already escape
		{
			outlen+=2;
		}
		else if (('\x01' <= c && c <= '\x1f') /* || p[i] == 0x7f delete char */) //escape control characters
		{
			outlen+=6;
		}
		else
		{
			outlen++;
		}
	}

	return outlen;
}

//gprof reports this function takes 33% time
//we don't use simd because the distance between collisions for the head of the sequence is very short with high probability so register size transfers via sse/avx for headless marked segments are rare
void escape_json(char **buffer)
{
#ifdef DEBUG
	fprintf(stderr, "Entered escape_json...\n");
#endif
	int i = 0;
	int len = strlen(*buffer);
	char *out;

	size_t new_length;

#if USE_OPENMP
	if (ycmd_globals.cpu_cores > 1)
		new_length = _predict_new_json_escape_size_multicore(buffer);
	else
#endif
		new_length = _predict_new_json_escape_size_naive(buffer);

	out = malloc(new_length);
	out[0] = '\0';

	int j = 0;
	char *p = *buffer;
	for (i = 0; i < len; i++)
	{
		char c = p[i];
		//reduce the number of comparisons because switch case in assembly is just test jump statements
		//the original had 34 case statements so 34 test instructions... currently have 9 test instructions with the if/else chain
		if (c == '\\') // \\   //escape already escape
		{
			memcpy(out+j, "\\\\", 2);
			j+=2;
		}
		else if ('\b' <= c && c <= '\r') // c escape sequences
		{
			char table[6] = {'b','t','n','v','f','r'};
			char tbuf[3];
			sprintf(tbuf, "\\%c", table[p[i]-0x08]);
			memcpy(out+j, tbuf, 2);
			j+=2;

		}
		else if (c == '\"')
		{
			memcpy(out+j, "\\\"", 2);
			j+=2;
		}
		else if (c == '/')
		{
			memcpy(out+j, "\\/", 2);
			j+=2;

		}
		else if (('\x01' <= c && c <= '\x1f') /* || p[i] == 0x7f delete char */) //escape control characters
		{
			char tbuf[8];
			sprintf(tbuf, "\\u00%02x", c);
			memcpy(out+j, tbuf, 6);
			j+=6;
		}
		else
		{
			out[j++] = c;
		}
	}
	out[j] = 0;

	*buffer=out;
	free(p);
}

//assemble the entire file of unsaved buffers
//consumer must free it
char *get_all_content(linestruct *filetop)
{
#ifdef DEBUG
	fprintf(stderr, "Assembling content...\n");
#endif
	char *buffer;
	buffer = NULL;

	linestruct *node;
	node = filetop;

	if (node == NULL)
	{
#ifdef DEBUG
		fprintf(stderr, "Node is null\n");
#endif
		return NULL;
	}

	buffer = malloc(strlen(node->data)+2);
	buffer[0] = 0;
	strcpy(buffer, node->data);
#ifdef DEBUG
	fprintf(stderr, "buffer is |%s| data is |%s|\n", buffer, node->data);
#endif
	node = node->next;

	while (node)
	{
#ifdef DEBUG
		fprintf(stderr, "looping in get_all_content\n");
#endif
		if (node->data == NULL)
			node = node->next;

		int ld = strlen(node->data);
		int lb = strlen(buffer);
		char *newbuffer = realloc(buffer, ld+lb+2);
		if (newbuffer == NULL) {
#ifdef DEBUG
			fprintf(stderr, "*newbuffer is null\n");
#endif
			break;
		}
		buffer = newbuffer;
#ifdef DEBUG
		fprintf(stderr, "node->data is |%s|\n", node->data);
#endif
		strcat(buffer, "\n");
		strcat(buffer, node->data);
#ifdef DEBUG
		fprintf(stderr, "buffer is |%s|\n", buffer);
#endif

		node = node->next;
	}

#ifdef DEBUG
	fprintf(stderr, "Content is: %s\n", buffer);
#endif
	escape_json(&buffer);

	return buffer;
}

char *_ycmd_get_filetype(char *filepath, char *content)
{
	static char type[20];
	type[0] = 0;
	if (strstr(filepath,".cs"))
		strcpy(type, "cs");
	else if (strstr(filepath,".go"))
		strcpy(type, "go");
	else if (strstr(filepath,".rs"))
		strcpy(type, "rust");
	else if (strstr(filepath,".mm"))
		strcpy(type, "objcpp");
	else if (strstr(filepath,".m"))
		strcpy(type, "objc");
	else if (strstr(filepath,".cpp") || strstr(filepath,".C") || strstr(filepath,".cxx") || strstr(filepath,".cc") )
		strcpy(type, "cpp");
	else if (strstr(filepath,".c"))
		strcpy(type, "c");
	else if (strstr(filepath,".hpp") || strstr(filepath,".hh") )
		strcpy(type, "cpp");
	else if (strstr(filepath,".h"))
	{
		if (strstr(content, "using namespace") || strstr(content, "iostream") || strstr(content, "\tclass ") || strstr(content, " class ")
			|| strstr(content, "private:") || strstr(content, "public:") || strstr(content, "protected:"))
			strcpy(type, "cpp");
		else
			strcpy(type, "c");
	}
	else if (strstr(filepath,".js"))
		strcpy(type, "javascript");
	else if (strstr(filepath,".py"))
		strcpy(type, "python");
	else if (strstr(filepath,".ts"))
		strcpy(type, "typescript");
	else
		strcpy(type, "filetype_default"); //try to quiet error.  it doesn't accept ''

	return type;
}

/*
Contents of ycm_json_event_notification -> ...simple_request...
Useful as a hinter for fixit support
Fix it alone only reports 1 result but FileReadyToParse reports many after parsing

[{"kind": "ERROR", "text": "'stddef.h' file not found", "ranges": [], "location": {"filepath": "/usr/include/stdio.h", "column_num": 11, "line_num": 33}, "location_extent": {"start": {"filepath": "/usr/include/stdio.h", "column_num": 11, "line_num": 33}, "end": {"filepath": "/usr/include/stdio.h", "column_num": 12, "line_num": 33}}, "fixit_available": false}, {"kind": "ERROR", "text": "'stddef.h' file not found", "ranges": [], "location": {"filepath": "/usr/include/_G_config.h", "column_num": 10, "line_num": 15}, "location_extent": {"start": {"filepath": "/usr/include/_G_config.h", "column_num": 10, "line_num": 15}, "end": {"filepath": "/usr/include/_G_config.h", "column_num": 11, "line_num": 15}}, "fixit_available": false}, {"kind": "ERROR", "text": "'stdarg.h' file not found", "ranges": [], "location": {"filepath": "/usr/include/libio.h", "column_num": 10, "line_num": 49}, "location_extent": {"start": {"filepath": "/usr/include/libio.h", "column_num": 10, "line_num": 49}, "end": {"filepath": "/usr/include/libio.h", "column_num": 11, "line_num": 49}}, "fixit_available": false}, {"kind": "ERROR", "text": "unknown type name 'size_t'", "ranges": [], "location": {"filepath": "/usr/include/libio.h", "column_num": 3, "line_num": 302}, "location_extent": {"start": {"filepath": "/usr/include/libio.h", "column_num": 3, "line_num": 302}, "end": {"filepath": "/usr/include/libio.h", "column_num": 9, "line_num": 302}}, "fixit_available": false}, {"kind": "ERROR", "text": "use of undeclared identifier 'size_t'; did you mean 'sizeof'?", "ranges": [], "location": {"filepath": "/usr/include/libio.h", "column_num": 67, "line_num": 305}, "location_extent": {"start": {"filepath": "/usr/include/libio.h", "column_num": 67, "line_num": 305}, "end": {"filepath": "/usr/include/libio.h", "column_num": 73, "line_num": 305}}, "fixit_available": true}, {"kind": "ERROR", "text": "reference to overloaded function could not be resolved; did you mean to call it?", "ranges": [{"start": {"filepath": "/usr/include/libio.h", "column_num": 66, "line_num": 305}, "end": {"filepath": "/usr/include/libio.h", "column_num": 74, "line_num": 305}}], "location": {"filepath": "/usr/include/libio.h", "column_num": 66, "line_num": 305}, "location_extent": {"start": {"filepath": "/usr/include/libio.h", "column_num": 66, "line_num": 305}, "end": {"filepath": "/usr/include/libio.h", "column_num": 67, "line_num": 305}}, "fixit_available": false}, {"kind": "ERROR", "text": "unknown type name 'size_t'", "ranges": [], "location": {"filepath": "/usr/include/libio.h", "column_num": 62, "line_num": 333}, "location_extent": {"start": {"filepath": "/usr/include/libio.h", "column_num": 62, "line_num": 333}, "end": {"filepath": "/usr/include/libio.h", "column_num": 68, "line_num": 333}}, "fixit_available": false}, {"kind": "ERROR", "text": "unknown type name 'size_t'", "ranges": [], "location": {"filepath": "/usr/include/libio.h", "column_num": 6, "line_num": 342}, "location_extent": {"start": {"filepath": "/usr/include/libio.h", "column_num": 6, "line_num": 342}, "end": {"filepath": "/usr/include/libio.h", "column_num": 12, "line_num": 342}}, "fixit_available": false}, {"kind": "ERROR", "text": "unknown type name 'size_t'", "ranges": [], "location": {"filepath": "/usr/include/libio.h", "column_num": 8, "line_num": 464}, "location_extent": {"start": {"filepath": "/usr/include/libio.h", "column_num": 8, "line_num": 464}, "end": {"filepath": "/usr/include/libio.h", "column_num": 18, "line_num": 464}}, "fixit_available": false}, {"kind": "ERROR", "text": "unknown type name '__gnuc_va_list'", "ranges": [], "location": {"filepath": "/usr/include/stdio.h", "column_num": 9, "line_num": 79}, "location_extent": {"start": {"filepath": "/usr/include/stdio.h", "column_num": 9, "line_num": 79}, "end": {"filepath": "/usr/include/stdio.h", "column_num": 19, "line_num": 79}}, "fixit_available": false}, {"kind": "ERROR", "text": "unknown type name 'size_t'; did you mean 'ssize_t'?", "ranges": [], "location": {"filepath": "/usr/include/stdio.h", "column_num": 35, "line_num": 319}, "location_extent": {"start": {"filepath": "/usr/include/stdio.h", "column_num": 35, "line_num": 319}, "end": {"filepath": "/usr/include/stdio.h", "column_num": 41, "line_num": 319}}, "fixit_available": true}, {"kind": "ERROR", "text": "unknown type name 'size_t'; did you mean 'ssize_t'?", "ranges": [], "location": {"filepath": "/usr/include/stdio.h", "column_num": 47, "line_num": 325}, "location_extent": {"start": {"filepath": "/usr/include/stdio.h", "column_num": 47, "line_num": 325}, "end": {"filepath": "/usr/include/stdio.h", "column_num": 53, "line_num": 325}}, "fixit_available": true}, {"kind": "ERROR", "text": "unknown type name 'size_t'; did you mean 'ssize_t'?", "ranges": [], "location": {"filepath": "/usr/include/stdio.h", "column_num": 20, "line_num": 337}, "location_extent": {"start": {"filepath": "/usr/include/stdio.h", "column_num": 20, "line_num": 337}, "end": {"filepath": "/usr/include/stdio.h", "column_num": 26, "line_num": 337}}, "fixit_available": true}, {"kind": "ERROR", "text": "unknown type name 'size_t'; did you mean 'ssize_t'?", "ranges": [], "location": {"filepath": "/usr/include/stdio.h", "column_num": 10, "line_num": 344}, "location_extent": {"start": {"filepath": "/usr/include/stdio.h", "column_num": 10, "line_num": 344}, "end": {"filepath": "/usr/include/stdio.h", "column_num": 16, "line_num": 344}}, "fixit_available": true}, {"kind": "ERROR", "text": "unknown type name '__gnuc_va_list'", "ranges": [], "location": {"filepath": "/usr/include/stdio.h", "column_num": 8, "line_num": 372}, "location_extent": {"start": {"filepath": "/usr/include/stdio.h", "column_num": 8, "line_num": 372}, "end": {"filepath": "/usr/include/stdio.h", "column_num": 18, "line_num": 372}}, "fixit_available": false}, {"kind": "ERROR", "text": "unknown type name '__gnuc_va_list'", "ranges": [], "location": {"filepath": "/usr/include/stdio.h", "column_num": 54, "line_num": 377}, "location_extent": {"start": {"filepath": "/usr/include/stdio.h", "column_num": 54, "line_num": 377}, "end": {"filepath": "/usr/include/stdio.h", "column_num": 64, "line_num": 377}}, "fixit_available": false}, {"kind": "ERROR", "text": "unknown type name '__gnuc_va_list'", "ranges": [], "location": {"filepath": "/usr/include/stdio.h", "column_num": 8, "line_num": 380}, "location_extent": {"start": {"filepath": "/usr/include/stdio.h", "column_num": 8, "line_num": 380}, "end": {"filepath": "/usr/include/stdio.h", "column_num": 18, "line_num": 380}}, "fixit_available": false}, {"kind": "ERROR", "text": "unknown type name 'size_t'; did you mean 'ssize_t'?", "ranges": [], "location": {"filepath": "/usr/include/stdio.h", "column_num": 44, "line_num": 386}, "location_extent": {"start": {"filepath": "/usr/include/stdio.h", "column_num": 44, "line_num": 386}, "end": {"filepath": "/usr/include/stdio.h", "column_num": 50, "line_num": 386}}, "fixit_available": true}, {"kind": "ERROR", "text": "unknown type name 'size_t'; did you mean 'ssize_t'?", "ranges": [], "location": {"filepath": "/usr/include/stdio.h", "column_num": 45, "line_num": 390}, "location_extent": {"start": {"filepath": "/usr/include/stdio.h", "column_num": 45, "line_num": 390}, "end": {"filepath": "/usr/include/stdio.h", "column_num": 51, "line_num": 390}}, "fixit_available": true}, {"kind": "WARNING", "text": "type specifier missing, defaults to 'int'", "ranges": [{"start": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}, "end": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}}], "location": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 46, "line_num": 597}, "location_extent": {"start": {"filepath": "", "column_num": 0, "line_num": 0}, "end": {"filepath": "", "column_num": 0, "line_num": 0}}, "fixit_available": false}, {"kind": "WARNING", "text": "type specifier missing, defaults to 'int'", "ranges": [{"start": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}, "end": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}}], "location": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 46, "line_num": 633}, "location_extent": {"start": {"filepath": "", "column_num": 0, "line_num": 0}, "end": {"filepath": "", "column_num": 0, "line_num": 0}}, "fixit_available": false}, {"kind": "WARNING", "text": "type specifier missing, defaults to 'int'", "ranges": [{"start": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}, "end": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}}], "location": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 45, "line_num": 634}, "location_extent": {"start": {"filepath": "", "column_num": 0, "line_num": 0}, "end": {"filepath": "", "column_num": 0, "line_num": 0}}, "fixit_available": false}, {"kind": "WARNING", "text": "type specifier missing, defaults to 'int'", "ranges": [{"start": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}, "end": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}}], "location": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 48, "line_num": 635}, "location_extent": {"start": {"filepath": "", "column_num": 0, "line_num": 0}, "end": {"filepath": "", "column_num": 0, "line_num": 0}}, "fixit_available": false}, {"kind": "WARNING", "text": "type specifier missing, defaults to 'int'", "ranges": [{"start": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}, "end": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}}], "location": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 48, "line_num": 649}, "location_extent": {"start": {"filepath": "", "column_num": 0, "line_num": 0}, "end": {"filepath": "", "column_num": 0, "line_num": 0}}, "fixit_available": false}, {"kind": "WARNING", "text": "type specifier missing, defaults to 'int'", "ranges": [{"start": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}, "end": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}}], "location": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 45, "line_num": 654}, "location_extent": {"start": {"filepath": "", "column_num": 0, "line_num": 0}, "end": {"filepath": "", "column_num": 0, "line_num": 0}}, "fixit_available": false}, {"kind": "WARNING", "text": "type specifier missing, defaults to 'int'", "ranges": [{"start": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}, "end": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}}], "location": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 46, "line_num": 656}, "location_extent": {"start": {"filepath": "", "column_num": 0, "line_num": 0}, "end": {"filepath": "", "column_num": 0, "line_num": 0}}, "fixit_available": false}, {"kind": "WARNING", "text": "type specifier missing, defaults to 'int'", "ranges": [{"start": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}, "end": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}}], "location": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 43, "line_num": 658}, "location_extent": {"start": {"filepath": "", "column_num": 0, "line_num": 0}, "end": {"filepath": "", "column_num": 0, "line_num": 0}}, "fixit_available": false}, {"kind": "WARNING", "text": "type specifier missing, defaults to 'int'", "ranges": [{"start": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}, "end": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}}], "location": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 46, "line_num": 717}, "location_extent": {"start": {"filepath": "", "column_num": 0, "line_num": 0}, "end": {"filepath": "", "column_num": 0, "line_num": 0}}, "fixit_available": false}, {"kind": "WARNING", "text": "type specifier missing, defaults to 'int'", "ranges": [{"start": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}, "end": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}}], "location": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 48, "line_num": 722}, "location_extent": {"start": {"filepath": "", "column_num": 0, "line_num": 0}, "end": {"filepath": "", "column_num": 0, "line_num": 0}}, "fixit_available": false}, {"kind": "WARNING", "text": "type specifier missing, defaults to 'int'", "ranges": [{"start": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}, "end": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 1, "line_num": 1}}], "location": {"filepath": "/usr/include/ncursesw/curses.h", "column_num": 47, "line_num": 748}, "location_extent": {"start": {"filepath": "", "column_num": 0, "line_num": 0}, "end": {"filepath": "", "column_num": 0, "line_num": 0}}, "fixit_available": false}]


[
   {
      "kind":"ERROR",
      "text":"'stddef.h' file not found",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/stdio.h",
         "column_num":11,
         "line_num":33
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/stdio.h",
            "column_num":11,
            "line_num":33
         },
         "end":{
            "filepath":"/usr/include/stdio.h",
            "column_num":12,
            "line_num":33
         }
      },
      "fixit_available":false
   },
   {
      "kind":"ERROR",
      "text":"'stddef.h' file not found",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/_G_config.h",
         "column_num":10,
         "line_num":15
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/_G_config.h",
            "column_num":10,
            "line_num":15
         },
         "end":{
            "filepath":"/usr/include/_G_config.h",
            "column_num":11,
            "line_num":15
         }
      },
      "fixit_available":false
   },
   {
      "kind":"ERROR",
      "text":"'stdarg.h' file not found",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/libio.h",
         "column_num":10,
         "line_num":49
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/libio.h",
            "column_num":10,
            "line_num":49
         },
         "end":{
            "filepath":"/usr/include/libio.h",
            "column_num":11,
            "line_num":49
         }
      },
      "fixit_available":false
   },
   {
      "kind":"ERROR",
      "text":"unknown type name 'size_t'",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/libio.h",
         "column_num":3,
         "line_num":302
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/libio.h",
            "column_num":3,
            "line_num":302
         },
         "end":{
            "filepath":"/usr/include/libio.h",
            "column_num":9,
            "line_num":302
         }
      },
      "fixit_available":false
   },
   {
      "kind":"ERROR",
      "text":"use of undeclared identifier 'size_t'; did you mean 'sizeof'?",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/libio.h",
         "column_num":67,
         "line_num":305
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/libio.h",
            "column_num":67,
            "line_num":305
         },
         "end":{
            "filepath":"/usr/include/libio.h",
            "column_num":73,
            "line_num":305
         }
      },
      "fixit_available":true
   },
   {
      "kind":"ERROR",
      "text":"reference to overloaded function could not be resolved; did you mean to call it?",
      "ranges":[
         {
            "start":{
               "filepath":"/usr/include/libio.h",
               "column_num":66,
               "line_num":305
            },
            "end":{
               "filepath":"/usr/include/libio.h",
               "column_num":74,
               "line_num":305
            }
         }
      ],
      "location":{
         "filepath":"/usr/include/libio.h",
         "column_num":66,
         "line_num":305
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/libio.h",
            "column_num":66,
            "line_num":305
         },
         "end":{
            "filepath":"/usr/include/libio.h",
            "column_num":67,
            "line_num":305
         }
      },
      "fixit_available":false
   },
   {
      "kind":"ERROR",
      "text":"unknown type name 'size_t'",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/libio.h",
         "column_num":62,
         "line_num":333
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/libio.h",
            "column_num":62,
            "line_num":333
         },
         "end":{
            "filepath":"/usr/include/libio.h",
            "column_num":68,
            "line_num":333
         }
      },
      "fixit_available":false
   },
   {
      "kind":"ERROR",
      "text":"unknown type name 'size_t'",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/libio.h",
         "column_num":6,
         "line_num":342
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/libio.h",
            "column_num":6,
            "line_num":342
         },
         "end":{
            "filepath":"/usr/include/libio.h",
            "column_num":12,
            "line_num":342
         }
      },
      "fixit_available":false
   },
   {
      "kind":"ERROR",
      "text":"unknown type name 'size_t'",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/libio.h",
         "column_num":8,
         "line_num":464
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/libio.h",
            "column_num":8,
            "line_num":464
         },
         "end":{
            "filepath":"/usr/include/libio.h",
            "column_num":18,
            "line_num":464
         }
      },
      "fixit_available":false
   },
   {
      "kind":"ERROR",
      "text":"unknown type name '__gnuc_va_list'",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/stdio.h",
         "column_num":9,
         "line_num":79
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/stdio.h",
            "column_num":9,
            "line_num":79
         },
         "end":{
            "filepath":"/usr/include/stdio.h",
            "column_num":19,
            "line_num":79
         }
      },
      "fixit_available":false
   },
   {
      "kind":"ERROR",
      "text":"unknown type name 'size_t'; did you mean 'ssize_t'?",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/stdio.h",
         "column_num":35,
         "line_num":319
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/stdio.h",
            "column_num":35,
            "line_num":319
         },
         "end":{
            "filepath":"/usr/include/stdio.h",
            "column_num":41,
            "line_num":319
         }
      },
      "fixit_available":true
   },
   {
      "kind":"ERROR",
      "text":"unknown type name 'size_t'; did you mean 'ssize_t'?",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/stdio.h",
         "column_num":47,
         "line_num":325
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/stdio.h",
            "column_num":47,
            "line_num":325
         },
         "end":{
            "filepath":"/usr/include/stdio.h",
            "column_num":53,
            "line_num":325
         }
      },
      "fixit_available":true
   },
   {
      "kind":"ERROR",
      "text":"unknown type name 'size_t'; did you mean 'ssize_t'?",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/stdio.h",
         "column_num":20,
         "line_num":337
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/stdio.h",
            "column_num":20,
            "line_num":337
         },
         "end":{
            "filepath":"/usr/include/stdio.h",
            "column_num":26,
            "line_num":337
         }
      },
      "fixit_available":true
   },
   {
      "kind":"ERROR",
      "text":"unknown type name 'size_t'; did you mean 'ssize_t'?",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/stdio.h",
         "column_num":10,
         "line_num":344
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/stdio.h",
            "column_num":10,
            "line_num":344
         },
         "end":{
            "filepath":"/usr/include/stdio.h",
            "column_num":16,
            "line_num":344
         }
      },
      "fixit_available":true
   },
   {
      "kind":"ERROR",
      "text":"unknown type name '__gnuc_va_list'",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/stdio.h",
         "column_num":8,
         "line_num":372
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/stdio.h",
            "column_num":8,
            "line_num":372
         },
         "end":{
            "filepath":"/usr/include/stdio.h",
            "column_num":18,
            "line_num":372
         }
      },
      "fixit_available":false
   },
   {
      "kind":"ERROR",
      "text":"unknown type name '__gnuc_va_list'",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/stdio.h",
         "column_num":54,
         "line_num":377
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/stdio.h",
            "column_num":54,
            "line_num":377
         },
         "end":{
            "filepath":"/usr/include/stdio.h",
            "column_num":64,
            "line_num":377
         }
      },
      "fixit_available":false
   },
   {
      "kind":"ERROR",
      "text":"unknown type name '__gnuc_va_list'",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/stdio.h",
         "column_num":8,
         "line_num":380
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/stdio.h",
            "column_num":8,
            "line_num":380
         },
         "end":{
            "filepath":"/usr/include/stdio.h",
            "column_num":18,
            "line_num":380
         }
      },
      "fixit_available":false
   },
   {
      "kind":"ERROR",
      "text":"unknown type name 'size_t'; did you mean 'ssize_t'?",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/stdio.h",
         "column_num":44,
         "line_num":386
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/stdio.h",
            "column_num":44,
            "line_num":386
         },
         "end":{
            "filepath":"/usr/include/stdio.h",
            "column_num":50,
            "line_num":386
         }
      },
      "fixit_available":true
   },
   {
      "kind":"ERROR",
      "text":"unknown type name 'size_t'; did you mean 'ssize_t'?",
      "ranges":[

      ],
      "location":{
         "filepath":"/usr/include/stdio.h",
         "column_num":45,
         "line_num":390
      },
      "location_extent":{
         "start":{
            "filepath":"/usr/include/stdio.h",
            "column_num":45,
            "line_num":390
         },
         "end":{
            "filepath":"/usr/include/stdio.h",
            "column_num":51,
            "line_num":390
         }
      },
      "fixit_available":true
   },
   {
      "kind":"WARNING",
      "text":"type specifier missing, defaults to 'int'",
      "ranges":[
         {
            "start":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            },
            "end":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            }
         }
      ],
      "location":{
         "filepath":"/usr/include/ncursesw/curses.h",
         "column_num":46,
         "line_num":597
      },
      "location_extent":{
         "start":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         },
         "end":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         }
      },
      "fixit_available":false
   },
   {
      "kind":"WARNING",
      "text":"type specifier missing, defaults to 'int'",
      "ranges":[
         {
            "start":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            },
            "end":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            }
         }
      ],
      "location":{
         "filepath":"/usr/include/ncursesw/curses.h",
         "column_num":46,
         "line_num":633
      },
      "location_extent":{
         "start":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         },
         "end":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         }
      },
      "fixit_available":false
   },
   {
      "kind":"WARNING",
      "text":"type specifier missing, defaults to 'int'",
      "ranges":[
         {
            "start":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            },
            "end":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            }
         }
      ],
      "location":{
         "filepath":"/usr/include/ncursesw/curses.h",
         "column_num":45,
         "line_num":634
      },
      "location_extent":{
         "start":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         },
         "end":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         }
      },
      "fixit_available":false
   },
   {
      "kind":"WARNING",
      "text":"type specifier missing, defaults to 'int'",
      "ranges":[
         {
            "start":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            },
            "end":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            }
         }
      ],
      "location":{
         "filepath":"/usr/include/ncursesw/curses.h",
         "column_num":48,
         "line_num":635
      },
      "location_extent":{
         "start":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         },
         "end":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         }
      },
      "fixit_available":false
   },
   {
      "kind":"WARNING",
      "text":"type specifier missing, defaults to 'int'",
      "ranges":[
         {
            "start":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            },
            "end":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            }
         }
      ],
      "location":{
         "filepath":"/usr/include/ncursesw/curses.h",
         "column_num":48,
         "line_num":649
      },
      "location_extent":{
         "start":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         },
         "end":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         }
      },
      "fixit_available":false
   },
   {
      "kind":"WARNING",
      "text":"type specifier missing, defaults to 'int'",
      "ranges":[
         {
            "start":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            },
            "end":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            }
         }
      ],
      "location":{
         "filepath":"/usr/include/ncursesw/curses.h",
         "column_num":45,
         "line_num":654
      },
      "location_extent":{
         "start":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         },
         "end":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         }
      },
      "fixit_available":false
   },
   {
      "kind":"WARNING",
      "text":"type specifier missing, defaults to 'int'",
      "ranges":[
         {
            "start":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            },
            "end":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            }
         }
      ],
      "location":{
         "filepath":"/usr/include/ncursesw/curses.h",
         "column_num":46,
         "line_num":656
      },
      "location_extent":{
         "start":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         },
         "end":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         }
      },
      "fixit_available":false
   },
   {
      "kind":"WARNING",
      "text":"type specifier missing, defaults to 'int'",
      "ranges":[
         {
            "start":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            },
            "end":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            }
         }
      ],
      "location":{
         "filepath":"/usr/include/ncursesw/curses.h",
         "column_num":43,
         "line_num":658
      },
      "location_extent":{
         "start":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         },
         "end":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         }
      },
      "fixit_available":false
   },
   {
      "kind":"WARNING",
      "text":"type specifier missing, defaults to 'int'",
      "ranges":[
         {
            "start":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            },
            "end":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            }
         }
      ],
      "location":{
         "filepath":"/usr/include/ncursesw/curses.h",
         "column_num":46,
         "line_num":717
      },
      "location_extent":{
         "start":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         },
         "end":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         }
      },
      "fixit_available":false
   },
   {
      "kind":"WARNING",
      "text":"type specifier missing, defaults to 'int'",
      "ranges":[
         {
            "start":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            },
            "end":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            }
         }
      ],
      "location":{
         "filepath":"/usr/include/ncursesw/curses.h",
         "column_num":48,
         "line_num":722
      },
      "location_extent":{
         "start":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         },
         "end":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         }
      },
      "fixit_available":false
   },
   {
      "kind":"WARNING",
      "text":"type specifier missing, defaults to 'int'",
      "ranges":[
         {
            "start":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            },
            "end":{
               "filepath":"/usr/include/ncursesw/curses.h",
               "column_num":1,
               "line_num":1
            }
         }
      ],
      "location":{
         "filepath":"/usr/include/ncursesw/curses.h",
         "column_num":47,
         "line_num":748
      },
      "location_extent":{
         "start":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         },
         "end":{
            "filepath":"",
            "column_num":0,
            "line_num":0
         }
      },
      "fixit_available":false
   }
]
*/

void ycmd_event_file_ready_to_parse(int columnnum, int linenum, char *filepath, linestruct *filetop)
{
	if (!ycmd_globals.connected)
		return;

#ifdef DEBUG
	fprintf(stderr,"ycmd_event_file_ready_to_parse called\n");
#endif

	char *content = get_all_content(filetop);
	char *ft = _ycmd_get_filetype(filepath, content);

	//check server if it is compromised before sending sensitive source code
	int ready = ycmd_rsp_is_server_ready(ft);

	if (ycmd_globals.running && ready)
	{
		char path_project[PATH_MAX];
		char path_extra_conf[PATH_MAX];

		if (is_c_family(ft))
		{
			ycmd_gen_extra_conf(filepath, content);
#ifdef USE_YCM_GENERATOR
			get_project_path(path_project);
			get_extra_conf_path(path_project, path_extra_conf);
			ycmd_req_load_extra_conf_file(path_extra_conf);
#endif
		}
		ycmd_json_event_notification(columnnum, linenum, filepath, "FileReadyToParse", content);
		ycmd_req_completions_suggestions(linenum, columnnum, filepath, content, "filetype_default");
		if (is_c_family(ft))
			ycmd_req_ignore_extra_conf_file(path_extra_conf);
	}
	free(content);
}

void ycmd_event_buffer_unload(int columnnum, int linenum, char *filepath, linestruct *filetop)
{
	if (!ycmd_globals.connected)
		return;

#ifdef DEBUG
	fprintf(stderr,"Entering ycmd_event_buffer_unload.\n");
#endif

	char *content = get_all_content(filetop);
	char *ft = _ycmd_get_filetype(filepath, content);

	//check server if it is compromised before sending sensitive source code
	int ready = ycmd_rsp_is_server_ready(ft);

	if (ycmd_globals.running && ready)
		ycmd_json_event_notification(columnnum, linenum, filepath, "BufferUnload", content);

	free(content);
}

void ycmd_event_buffer_visit(int columnnum, int linenum, char *filepath, linestruct *filetop)
{
	if (!ycmd_globals.connected)
		return;

#ifdef DEBUG
	fprintf(stderr,"Entering ycmd_event_buffer_visit.\n");
#endif

	char *content = get_all_content(filetop);
	char *ft = _ycmd_get_filetype(filepath, content);

	//check server if it is compromised before sending sensitive source code
	int ready = ycmd_rsp_is_server_ready(ft);

	if (ycmd_globals.running && ready)
		ycmd_json_event_notification(columnnum, linenum, filepath, "BufferVisit", content);

	free(content);
}

void ycmd_event_current_identifier_finished(int columnnum, int linenum, char *filepath, linestruct *filetop)
{
	if (!ycmd_globals.connected)
		return;

#ifdef DEBUG
	fprintf(stderr,"Entering ycmd_event_current_identifier_finished.\n");
#endif

	char *content = get_all_content(filetop);
	char *ft = _ycmd_get_filetype(filepath, content);

	//check server if it is compromised before sending sensitive source code
	int ready = ycmd_rsp_is_server_ready(ft);

	if (ycmd_globals.running && ready)
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
	struct funcstruct *func = allfuncs;

	while(func)
	{
		if (func && (func->menus == MCODECOMPLETION))
			break;
		func = func->next;
	}

	int nbackspaces = openfile->current_x-(ycmd_globals.apply_column-1);

	int i;
	int j;
	size_t maximum = (((COLS + 40) / 20) * 2);

	for (i = 'A', j = 0; j < maximum && i <= 'Z' && func; i++, j++, func = func->next)
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

				inject(func->desc,strlen(func->desc));

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

void do_end_code_completion(void)
{
	bottombars(MMAIN);
}

void do_end_completer_commands(void)
{
	bottombars(MMAIN);
}

void init_defined_subcommands_results(DEFINED_SUBCOMMANDS_RESULTS *dsr)
{
	memset(dsr, 0, sizeof(DEFINED_SUBCOMMANDS_RESULTS));
}

void destroy_defined_subcommands_results(DEFINED_SUBCOMMANDS_RESULTS *dsr)
{
        if (dsr->json_blob)
               	free(dsr->json_blob);
}

/*

cfamily
ValueError: Supported commands are:
ClearCompilationFlagCache
FixIt
GetDoc
GetDocImprecise
GetParent
GetType
GetTypeImprecise
GoTo
GoToDeclaration
GoToDefinition
GoToImprecise
GoToInclude

csharp
ValueError: Supported commands are:
FixIt
GetDoc
GetType
GoTo
GoToDeclaration
GoToDefinition
GoToDefinitionElseDeclaration
GoToImplementation
GoToImplementationElseDeclaration
ReloadSolution
RestartServer
SolutionFile

typescript
ValueError: Supported commands are:
GetDoc
GetType
GoToDefinition
GoToReferences
GoToType
RefactorRename
RestartServer

go
ValueError: Supported commands are:
GoTo
GoToDeclaration
GoToDefinition
RestartServer

js
ValueError: Supported commands are:
GetDoc
GetType
GoTo
GoToDefinition
GoToReferences
RefactorRename
RestartServer

python
ValueError: Supported commands are:
GetDoc
GoTo
GoToDeclaration
GoToDefinition
GoToReferences
RestartServer
*/

void do_completer_command_show(void)
{
#ifdef DEBUG
	fprintf(stderr,"Entered do_completer_command_show\n");
#endif
	keystruct *s;
	for (s = sclist; s != NULL; s = s->next)
		s->visibility = 0; //0 hidden, 1 visible

        char *content = get_all_content(openfile->filetop);
        char *ft = _ycmd_get_filetype(openfile->filename, content);

	//should cache
	DEFINED_SUBCOMMANDS_RESULTS dsr;
	init_defined_subcommands_results(&dsr);
	ycmd_req_defined_subcommands((long)openfile->current->lineno, openfile->current_x, openfile->filename, content, ft, &dsr);
	//should return something like: ["ClearCompilationFlagCache", "FixIt", "GetDoc", "GetDocImprecise", "GetParent", "GetType", "GetTypeImprecise", "GoTo", "GoToDeclaration", "GoToDefinition", "GoToImprecise", "GoToInclude"]

	if (dsr.usable && dsr.status_code == 200)
	{
		for (s = sclist; s != NULL; s = s->next)
		{
			if (s->func == do_completer_command_gotoinclude && strstr(dsr.json_blob,"\"GoToInclude\""))							s->visibility = 1;
			else if (s->func == do_completer_command_gotodeclaration && strstr(dsr.json_blob,"\"GoToDeclaration\"")) 					s->visibility = 1;
			else if (s->func == do_completer_command_gotodefinition && strstr(dsr.json_blob,"\"GoToDefinition\"")) 						s->visibility = 1;
			else if (s->func == do_completer_command_gotodefinitionelsedeclaration && strstr(dsr.json_blob,"\"GoToDefinitionElseDeclaration\"")) 		s->visibility = 1;
			else if (s->func == do_completer_command_goto && strstr(dsr.json_blob,"\"GoTo\"")) 								s->visibility = 1;
			else if (s->func == do_completer_command_gotoimprecise && strstr(dsr.json_blob,"\"GoToImprecise\"")) 						s->visibility = 1;
			else if (s->func == do_completer_command_gotoreferences && strstr(dsr.json_blob,"\"GoToReferences\"")) 						s->visibility = 1;
			else if (s->func == do_completer_command_gotoimplementation && strstr(dsr.json_blob,"\"GoToImplementation\"")) 					s->visibility = 1;
			else if (s->func == do_completer_command_gotoimplementationelsedeclaration && strstr(dsr.json_blob,"\"GoToImplementationElseDeclaration\"")) 	s->visibility = 1;
			else if (s->func == do_completer_command_fixit && strstr(dsr.json_blob,"\"FixIt\"")) 								s->visibility = 1;
			else if (s->func == do_completer_command_getdoc && strstr(dsr.json_blob,"\"GetDoc\"")) 								s->visibility = 1;
			else if (s->func == do_completer_command_getdocimprecise && strstr(dsr.json_blob,"\"GetDocImprecise\""))					s->visibility = 1;
			else if (s->func == do_completer_command_refactorrename && strstr(dsr.json_blob,"\"RefactorRename\"")) 						s->visibility = 1;
			else if (s->func == do_completer_command_gettype && strstr(dsr.json_blob,"\"GetType\"")) 							s->visibility = 1;
			else if (s->func == do_completer_command_gettypeimprecise && strstr(dsr.json_blob,"\"GetTypeImprecise\"")) 					s->visibility = 1;
			else if (s->func == do_completer_command_reloadsolution && strstr(dsr.json_blob,"\"ReloadSolution\"")) 						s->visibility = 1;
			else if (s->func == do_completer_command_restartserver && strstr(dsr.json_blob,"\"RestartServer\"")) 						s->visibility = 1;
			else if (s->func == do_completer_command_gototype && strstr(dsr.json_blob,"\"GoToType\"")) 							s->visibility = 1;
			else if (s->func == do_completer_command_clearcompliationflagcache && strstr(dsr.json_blob,"\"ClearCompilationFlagCache\"")) 			s->visibility = 1;
			else if (s->func == do_completer_command_getparent && strstr(dsr.json_blob,"\"GetParent\"")) 							s->visibility = 1;
			else if (s->func == do_completer_command_solutionfile && strstr(dsr.json_blob,"\"SolutionFile\""))						s->visibility = 1;

			if (s->func == ycmd_display_parse_results) s->visibility = 1;
		}
	}
	else
	{
		for (s = sclist; s != NULL; s = s->next)
			s->visibility = 1; //0 hidden, 1 visible
	}

	bottombars(MCOMPLETERCOMMANDS);

	destroy_defined_subcommands_results(&dsr);
	free(content);
}

void do_completer_refactorrename_apply(void)
{
	bottombars(MMAIN);
}

void do_completer_refactorrename_cancel(void)
{
	bottombars(MMAIN);
}

void ycmd_display_parse_results()
{
	if (!ycmd_globals.file_ready_to_parse_results.json_blob)
	{
		statusline(HUSH, "Parse results are not usable.");

		return;
	}

	char doc_filename[PATH_MAX];
	strcpy(doc_filename,"/tmp/nanoXXXXXX");
	int fdtemp = mkstemp(doc_filename);
#ifdef DEBUG
	fprintf(stderr, "tempname is %s\n", doc_filename);
#endif
	FILE *f = fdopen(fdtemp,"w+");
	//todo put id to make it easier to hash to object
	fprintf(f, "%s", ycmd_globals.file_ready_to_parse_results.json_blob);
	fclose(f);

	char command[PATH_MAX*5];
	snprintf(command, PATH_MAX*5, "cat \"%s\" | jq \"to_entries | map({name:.value, index:.key})\" > \"%s.t\"; mv \"%s.t\" \"%s\"", doc_filename, doc_filename, doc_filename, doc_filename);
	system(command);

#ifndef DISABLE_MULTIBUFFER
	SET(MULTIBUFFER);
#else
	//todo non multibuffer
#endif

	//do_output doesn't handle \n properly and displays it as ^@ so we do it this way
	open_buffer(doc_filename, FALSE);
	prepare_for_display();

	unlink(doc_filename);
}
