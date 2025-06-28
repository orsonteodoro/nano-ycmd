# Configuration for GNU nano - a small and user-friendly text editor
#
# Copyright (C) 1999-2011, 2013-2025 Free Software Foundation, Inc.
# Copyright (C) 2014, 2017 Mike Frysinger
#
# GNU nano is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License,
# or (at your option) any later version.
#
# GNU nano is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see https://www.gnu.org/licenses/.

AC_INIT([GNU nano], [8.4], [nano-devel@gnu.org], [nano])
AC_CONFIG_SRCDIR([src/nano.c])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([1.14])
AM_MAINTAINER_MODE([enable])
AC_CONFIG_HEADERS([config.h])

dnl Make sure the ONCE macros are available.

AC_PREREQ([2.69])

dnl Lie about gnulib features we don't use to speed up & shrink down.

gl_cv_func_printf_directive_n=yes
gl_cv_func_printf_infinite_long_double=yes
gl_cv_func_printf_long_double=yes
gl_cv_func_snprintf_directive_n=yes
gl_cv_glob_lists_symlinks=yes

dnl Checks for programs.

AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
gl_EARLY
gl_INIT
AC_PROG_LN_S
AC_SEARCH_LIBS([strerror], [cposix])
AC_SYS_LARGEFILE
PKG_PROG_PKG_CONFIG

dnl Internationalization macros.

AM_GNU_GETTEXT_VERSION([0.20])
AM_GNU_GETTEXT([external], [need-ngettext])
AM_CONDITIONAL(USE_NLS, test x$USE_NLS = xyes)

dnl Data location.

pkgdatadir=${datadir}/${PACKAGE}
AC_DEFINE_DIR([PKGDATADIR], [pkgdatadir], [Where data are placed to.])

dnl Whether this is a git repository.

AC_MSG_CHECKING([whether building from git])
if test -f "$srcdir/roll-a-release.sh" ; then
	AC_MSG_RESULT([yes])
	from_git=yes
else
	AC_MSG_RESULT([no])
	from_git=no
fi
AM_CONDITIONAL(BUILDING_FROM_GIT, test x$from_git = xyes)

dnl Checks for pkg-config and gettext when building from git.

if test x$from_git = xyes; then
	if test ! -f $(aclocal --print-ac-dir)/pkg.m4; then
		AC_MSG_ERROR([
  *** The pkg.m4 macros are missing.
  *** The pkg-config package needs to be installed when building from git.
  *** After fixing this problem, rerun ./autogen.sh.])
	fi
	if test "$ac_cv_path_MSGFMT" = ":"; then
		AC_MSG_ERROR([
  *** The msgfmt program is missing.
  *** The gettext package needs to be installed when building from git.])
	fi
fi

dnl Checks for header files.

AC_CHECK_HEADERS(libintl.h limits.h pwd.h termios.h sys/param.h)

dnl Checks for options.

AC_ARG_ENABLE(browser,
AS_HELP_STRING([--disable-browser], [Disable the built-in file browser]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_browser" != xyes; then
		enable_browser=no
	fi
fi
if test "x$enable_browser" != xno; then
	AC_DEFINE(ENABLE_BROWSER, 1, [Define this to enable the built-in file browser.])
fi

AC_ARG_ENABLE(color,
AS_HELP_STRING([--disable-color], [Disable color and syntax highlighting]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_color" = xyes; then
		if test "x$enable_nanorc" != xyes; then
			AC_MSG_ERROR([
  ***  --enable-color needs --enable-nanorc to work])
		fi
	else
		enable_color=no
	fi
fi
if test "x$enable_nanorc" = xno; then
	if test "x$enable_color" = xyes; then
		AC_MSG_ERROR([
  ***  --enable-color cannot work with --disable-nanorc])
	else
		# Disabling nanorc silently disables color support.
		enable_color=no
	fi
fi
if test "x$enable_color" != xno; then
	AC_DEFINE(ENABLE_COLOR, 1, [Define this to have syntax highlighting.])
	color_support=yes
fi

AC_ARG_ENABLE(comment,
AS_HELP_STRING([--disable-comment], [Disable the comment/uncomment function]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_comment" = xyes; then
		AC_MSG_ERROR([
  ***  --enable-comment cannot work with --enable-tiny])
	else
		enable_comment=no
	fi
fi
if test "x$enable_comment" != xno; then
	AC_DEFINE(ENABLE_COMMENT, 1, [Define this to enable the comment/uncomment function.])
fi

AC_ARG_ENABLE(extra,
AS_HELP_STRING([--disable-extra], [Disable the Easter egg]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_extra" != xyes; then
		enable_extra=no
	fi
fi
if test "x$enable_extra" != xno; then
	AC_DEFINE(ENABLE_EXTRA, 1, [Define this to have an Easter egg.])
fi

AC_ARG_ENABLE(formatter,
AS_HELP_STRING([--disable-formatter], [Disable the formatting tool]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_formatter" = xyes; then
		if test "x$enable_color" != xyes; then
			AC_MSG_ERROR([
  ***  --enable-formatter needs both --enable-color and --enable-nanorc to work])
		fi
	else
		enable_formatter=no
	fi
fi
if test "x$enable_color" = xno; then
	if test "x$enable_formatter" = xyes; then
		AC_MSG_ERROR([
  ***  --enable-formatter cannot work with --disable-color nor --disable-nanorc])
	else
		enable_formatter=no
	fi
fi
if test "x$enable_formatter" != xno; then
	AC_DEFINE(ENABLE_FORMATTER, 1, [Define this to have access to a formatter.])
fi

AC_ARG_ENABLE(help,
AS_HELP_STRING([--disable-help], [Disable the built-in help texts]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_help" = xyes; then
		if test "x$enable_multibuffer" != xyes; then
			AC_MSG_ERROR([
  ***  --enable-help needs --enable-multibuffer to work])
		fi
	else
		enable_help=no
	fi
fi
if test "x$enable_multibuffer" = xno; then
	if test "x$enable_help" = xyes; then
		AC_MSG_ERROR([
  ***  --enable-help cannot work with --disable-multibuffer])
	else
		# Disabling multibuffer silently disables the help texts.
		enable_help=no
	fi
fi
if test "x$enable_help" != xno; then
	AC_DEFINE(ENABLE_HELP, 1, [Define this to enable the Ctrl+G help texts.])
fi

AC_ARG_ENABLE(histories,
AS_HELP_STRING([--disable-histories], [Disable search and position histories]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_histories" != xyes; then
		enable_histories=no
	fi
fi
if test "x$enable_histories" != xno; then
	AC_DEFINE(ENABLE_HISTORIES, 1, [Define this to have search and position histories.])
fi

AC_ARG_ENABLE(justify,
AS_HELP_STRING([--disable-justify], [Disable the justify/unjustify functions]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_justify" != xyes; then
		enable_justify=no
	fi
fi
if test "x$enable_justify" != xno; then
	AC_DEFINE(ENABLE_JUSTIFY, 1, [Define this to have the routines for justifying.])
fi

AC_ARG_ENABLE(libmagic,
AS_HELP_STRING([--disable-libmagic], [Disable detection of file types via libmagic]))
if test "x$enable_libmagic" = xyes; then
	if test "x$enable_tiny" = xyes; then
		if test "x$enable_color" != xyes; then
			AC_MSG_ERROR([
  ***  --enable-libmagic needs both --enable-color and --enable-nanorc to work])
		fi
	fi
	if test "x$enable_color" = xno; then
		AC_MSG_ERROR([
  ***  --enable-libmagic cannot work with --disable-color nor --disable-nanorc])
	fi
fi

AC_ARG_ENABLE(linter,
AS_HELP_STRING([--disable-linter], [Disable the linting tool]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_linter" = xyes; then
		if test "x$enable_color" != xyes; then
			AC_MSG_ERROR([
  ***  --enable-linter needs both --enable-color and --enable-nanorc to work])
		fi
	else
		enable_linter=no
	fi
fi
if test "x$enable_color" = xno; then
	if test "x$enable_linter" = xyes; then
		AC_MSG_ERROR([
  ***  --enable-linter cannot work with --disable-color nor --disable-nanorc])
	else
		enable_linter=no
	fi
fi
if test "x$enable_linter" != xno; then
	AC_DEFINE(ENABLE_LINTER, 1, [Define this to have access to a linter.])
fi

AC_ARG_ENABLE(linenumbers,
AS_HELP_STRING([--disable-linenumbers], [Disable line numbering]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_linenumbers" != xyes; then
		enable_linenumbers=no
	fi
fi
if test "x$enable_linenumbers" != xno; then
	AC_DEFINE(ENABLE_LINENUMBERS, 1, [Define this to enable line numbering.])
fi

AC_ARG_ENABLE(mouse,
AS_HELP_STRING([--disable-mouse], [Disable mouse support]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_mouse" != xyes; then
		enable_mouse=no
	fi
fi
if test "x$enable_mouse" != xno; then
	AC_DEFINE(ENABLE_MOUSE, 1, [Define this to enable mouse support.])
fi

AC_ARG_ENABLE(multibuffer,
AS_HELP_STRING([--disable-multibuffer], [Disable multiple file buffers]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_multibuffer" != xyes; then
		enable_multibuffer=no
	fi
fi
if test "x$enable_multibuffer" != xno; then
	AC_DEFINE(ENABLE_MULTIBUFFER, 1, [Define this to enable multiple file buffers.])
fi

AC_ARG_ENABLE(nanorc,
AS_HELP_STRING([--disable-nanorc], [Disable the use of .nanorc files]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_nanorc" != xyes; then
		enable_nanorc=no
	fi
fi
if test "x$enable_nanorc" != xno; then
	AC_DEFINE(ENABLE_NANORC, 1, [Define this to enable the use of .nanorc files.])
	nanorc_support=yes
fi

AC_ARG_ENABLE(operatingdir,
AS_HELP_STRING([--disable-operatingdir], [Disable the setting of an operating directory]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_operatingdir" != xyes; then
		enable_operatingdir=no
	fi
fi
if test "x$enable_operatingdir" != xno; then
	AC_DEFINE(ENABLE_OPERATINGDIR, 1, [Define this to allow setting an operating directory (a chroot of sorts).])
fi

AC_ARG_WITH([safe-paths],
    [AS_HELP_STRING([--with-safe-paths=PATHS],
        [Specify safe paths (e.g., /usr/local;/usr/bin)])],
    [safe_paths="$withval"],
    [safe_paths=""])
AC_DEFINE_UNQUOTED([SAFE_PATHS], ["$safe_paths"], [Safe paths])

AC_ARG_ENABLE(speller,
AS_HELP_STRING([--disable-speller], [Disable the spell-checking tool]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_speller" != xyes; then
		enable_speller=no
	fi
fi
if test "x$enable_speller" != xno; then
	AC_DEFINE(ENABLE_SPELLER, 1, [Define this to have access to a spell checker.])
fi

AC_ARG_ENABLE(tabcomp,
AS_HELP_STRING([--disable-tabcomp], [Disable the tab-completion functions]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_tabcomp" != xyes; then
		enable_tabcomp=no
	fi
fi
if test "x$enable_tabcomp" != xno; then
	AC_DEFINE(ENABLE_TABCOMP, 1, [Define this to have tab completion for filenames and search strings.])
fi

AC_ARG_ENABLE(random,
AS_HELP_STRING([--enable-random], [Enable /dev/random for secret key generation]))
if test "x$enable_random" != xyes; then
	AC_DEFINE(USE_RANDOM, 1, [Define this to use /dev/random for secret key generation.])
fi

AC_ARG_ENABLE(wordcomp,
AS_HELP_STRING([--disable-wordcomp], [Disable the word-completion function]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_wordcomp" = xyes; then
		AC_MSG_ERROR([
  ***  --enable-wordcomp cannot work with --enable-tiny])
	else
		enable_wordcomp=no
	fi
fi
if test "x$enable_wordcomp" != xno; then
	AC_DEFINE(ENABLE_WORDCOMPLETION, 1, [Define this to enable the word-completion function.])
fi

AC_ARG_ENABLE(wrapping,
AS_HELP_STRING([--disable-wrapping], [Disable all hard-wrapping of text]))
if test "x$enable_tiny" = xyes; then
	if test "x$enable_wrapping" != xyes; then
		enable_wrapping=no
	fi
fi
if test "x$enable_wrapping" != xno; then
	AC_DEFINE(ENABLE_WRAPPING, 1, [Define this to have hard text wrapping.])
fi

AC_ARG_ENABLE([ycmd-popup],
	[AS_HELP_STRING([--enable-ycmd-popup], [Enable ycmd popup feature])],
	[enable_ycmd_popup=$enableval],
	[enable_ycmd_popup=yes])

if test "x$enable_ycmd_popup" = "xyes"; then
	AC_DEFINE([ENABLE_YCMD_POPUP], [1], [Define to 1 if ycmd popup feature is enabled])
fi

AC_ARG_ENABLE(debug,
AS_HELP_STRING([--enable-debug], [Enable debugging (disabled by default)]))
if test "x$enable_debug" = xyes; then
	AC_DEFINE(DEBUG, 1, [Define this to enable debug messages and abortion on failing asserts.])
else
	AC_DEFINE(NDEBUG, 1, [Shut up assert warnings :-)])
fi

AC_ARG_WITH([allocator],
  [AS_HELP_STRING([--with-allocator],
    [choose allocator (hardened_malloc, mimalloc-secure, libc)])],
  [allocator=$withval],
  [allocator=libc])
if test "x$allocator" = "xhardened_malloc" ; then
	AC_DEFINE(USE_HARDENED_MALLOC, 1, [Define this to use the hardened_malloc allocator.])
elif test "x$allocator" = "xmimalloc-secure" ; then
	AC_DEFINE(USE_MIMALLOC_SECURE, 1, [Define this to use the mimalloc-secure allocator.])
elif test "x$allocator" = "xlibc" ; then
	AC_DEFINE(USE_LIBC_MALLOC, 1, [Define this to use the insecure glibc/musl allocator.])
fi
AC_MSG_CHECKING([for allocator])
AC_MSG_RESULT([$allocator])

AC_ARG_VAR([BEAR_PATH],[Define the full path to bear for the Ninja build system support in ycmd (optional)])
AC_ARG_VAR([CLANGD_PATH],[Define the full path to clangd for C / C++ / Objective-C / Objective C++ language support in ycmd >=41 (optional, experimental)])
AC_ARG_VAR([GOCODE_PATH],[Define the full path to your gocode executable for Go language support in ycmd <42 (optional)])
AC_ARG_VAR([GODEF_PATH],[Define the full path to your godef executable for Go language support in ycmd <42 (optional)])
AC_ARG_VAR([GOPLS_PATH],[Define the full path to your gopls executable for Go language support in ycmd >=42 (optional)])
AC_ARG_VAR([JAVA_PATH],[Define the full path to your java executable for Java language support in ycmd >=44 (optional)])
AC_ARG_VAR([MONO_PATH],[Define the full path to your mono executable for CSharp language support in ycmd >=43 (optional)])
AC_ARG_VAR([NINJA_PATH],[Define the full path to ninja for projects that depend on the Ninja build system in ycmd (optional)])
AC_ARG_VAR([OMNISHARP_PATH],[Define the full path to your OmniSharp executable for CSharp language support in ycmd >=42 (optional)])
AC_ARG_VAR([RACERD_PATH],[Define the full path to the racerd for racerd for Rust language support in ycmd <42 (optional)])
AC_ARG_VAR([RLS_PATH],[Define the full path to the rls (Rust Language Server) executable for Rust language support in ycmd >=42 and <44 (optional)])
AC_ARG_VAR([RUST_SRC_PATH],[Define the full path to the Rust source code folder for Rust language support in ycmd <42 (optional)])
AC_ARG_VAR([RUST_TOOLCHAIN_PATH],[Define the full path to the Rust toolchain for Rust language support in ycmd >=44 (optional)])
AC_ARG_VAR([RUSTC_PATH],[Define the full path to the rustc executable for Rust language support in ycmd in ycmd >=42 and <44 (optional)])
AC_ARG_VAR([TSSERVER_PATH],[Define the full path to the tsserver executable for TypeScript language support in ycmd >=42 (optional)])
AC_ARG_VAR([YCMD_PATH],[Define the path to ycmd directory])
AC_ARG_VAR([YCMD_PYTHON_PATH],[Define the full path to your ycmd python executable for ycmd])
AC_ARG_VAR([YCMG_PATH],[Define the full path to YCM-Generator for C / C++ / Objective-C / Objective C++ language support in ycmd (optional)])
AC_ARG_VAR([YCMG_PYTHON_PATH],[Define the full path to your YCM-Generator python executable for ycmd (optional)])

AC_ARG_WITH(bear,AS_HELP_STRING([--with-bear], [Enable Bear support for ycmd.  Required for C / C++ / Objective-C / Objective C++ projects.  (optional)]))
AC_ARG_WITH(libgcrypt,AS_HELP_STRING([--with-libgcrypt], [Enable Libgcrypt support for ycmd]))
AC_ARG_WITH(nettle,AS_HELP_STRING([--with-nettle], [Enable Nettle support for ycmd]))
AC_ARG_WITH(ninja,AS_HELP_STRING([--with-ninja], [Enable Ninja support for ycmd.  Required for projects that rely on .ninja files.  (optional)]))
AC_ARG_WITH(openssl,AS_HELP_STRING([--with-openssl], [Enable OpenSSL support for ycmd]))
AC_ARG_WITH(safeclib,AS_HELP_STRING([--with-safeclib], [Enable safeclib support for ycmd]))

AC_CHECK_HEADERS(pthread.h)
if test "x$with_safeclib" = xyes; then
	AC_CHECK_HEADERS(pthread.h)
	PKG_CHECK_MODULES([SAFECLIB], [libsafec], [
		SAFECLIB_LIB=$SAFECLIB_LIBS
		CPPFLAGS="$SAFECLIB_CFLAGS $CPPFLAGS"
		SAFECLIB_LIB_NAME=safec
	], [:])
	AC_SUBST(SAFECLIB_CFLAGS)
	AC_SUBST(SAFECLIB_LIBS)
	have_safeclib=yes
	AC_MSG_CHECKING([for safeclib])
	AC_MSG_RESULT([yes])
	AC_MSG_CHECKING([for safeclib RSIZE_MAX_STR >= 128K])
	AC_RUN_IFELSE(
		[AC_LANG_PROGRAM(
			[[#include <safe_str_lib.h>]],
			[[if (RSIZE_MAX_STR < 131072) return 1; return 0;]]
		)],
		[AC_MSG_RESULT([yes])],
		[AC_MSG_ERROR([safeclib RSIZE_MAX_STR < 131072, needs to be rebuild with --enable-strmax=131072 or greater])],
		[AC_MSG_RESULT([cross-compiling; assuming OK])]
	)

	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <safeclib/safe_str_lib.h>
	#if RSIZE_MAX_STR < 1048576
	#error RSIZE_MAX_STR too small
	#endif]])],
	  [],
	  [AC_MSG_WARN([RSIZE_MAX_STR is less than 1MB (1048576). For full functionality, rebuild safeclib with --enable-strmax=10485760 to support 10MB files.])]
	)
else
	AC_MSG_CHECKING([for safeclib])
	AC_MSG_RESULT([no])
fi

# fallback - for compatibility (maximize availability but decrease security)
# fatal - for security-critical (decreased availability, immediately aborts on undefined behavior, full protection)
# return_error - for security (increased availability, but some protection)
AC_ARG_WITH([safeclib-error],
	[AS_HELP_STRING([--with-safeclib-error=TYPE],
		[Set Safe C error handling: fallback, fatal, return_error (default: fallback)])],
	[safeclib_error=$withval],
	[safeclib_error=fallback])

case "$safeclib_error" in
	fallback)
		AC_DEFINE([SAFECLIB_ERROR_HANDLING], [0], [Safe C error handling: 0=fallback])
		;;
	fatal)
		AC_DEFINE([SAFECLIB_ERROR_HANDLING], [1], [Safe C error handling: 1=fatal])
		;;
	return_error)
		AC_DEFINE([SAFECLIB_ERROR_HANDLING], [2], [Safe C error handling: 2=return_error])
		;;
	*)
		AC_MSG_ERROR([Invalid --with-safeclib-error value: $safeclib_error. Must be fallback, fatal, or return_error])
		;;
esac

AC_ARG_WITH(ycm-generator,AS_HELP_STRING([--with-ycm-generator], [Enable YCM-Generator support for ycmd.  Required for C / C++ / Objective-C / Objective C++ projects that use GNU Make, qmake, cmake.  (optional)]))
AC_ARG_ENABLE(ycmd,
  AS_HELP_STRING([--enable-ycmd], [Enable code completion support via ycmd])
)
have_ycmd=no
AC_DEFUN([AC_CHECK_YCMD_CORE_VERSION],[
	AC_MSG_CHECKING([for YCMD_PATH])
	if test -z "$1"; then
		AC_MSG_ERROR([The YCMD_PATH environmental variable must be set.])
	else
		AC_MSG_RESULT([$YCMD_PATH])
	fi
	AC_MSG_CHECKING([for CORE_VERSION])
	core_version_path=$(realpath "$1/../CORE_VERSION")
	if test -f "$core_version_path"; then
		AC_MSG_RESULT([$core_version_path])
	else
		AC_MSG_ERROR([Cannot find CORE_VERSION.])
	fi
	ycmd_core_version=$(cat "$core_version_path")
	ycmd_core_found=0
	AC_MSG_CHECKING([for ycmd CORE_VERSION])

# 48 https://github.com/ycm-core/ycmd/blob/99c068120c14257c236e1dcfbf55838e33ae141e/ycmd/default_settings.json # no change

# 47 https://github.com/ycm-core/ycmd/blob/671fee16bbaa5da3858108b3717b76bc833b3953/ycmd/default_settings.json # no change

# 46 https://github.com/ycm-core/ycmd/blob/18808eae493548f37c50e1e3e0b5607b5f94093d/ycmd/default_settings.json # no change

# adds max_num_candidates_to_detail, java_binary_path, rust_toolchain_root; removes rls_binary_path, rustc_binary_path
# 45 https://github.com/ycm-core/ycmd/blob/a9f616e24f4bc71cd0e7f227a41e8bc2640193fd/ycmd/default_settings.json

# adds mono_binary_path
# 44 https://github.com/ycm-core/ycmd/blob/ff428c9976c93e217cd3f502d92ea68ca2ac5210/ycmd/default_settings.json

# adds language_server, java_jdtls_workspace_root_path, java_jdtls_extension_path, use_clangd, clangd_binary_path, clangd_args, clangd_uses_ycmd_caching, disable_signature_help, gopls_binary_path, gopls_args, rls_binary_path, rustc_binary_path, tsserver_binary_path, roslyn_binary_path
# removes gocode_binary_path, godef_binary_path, rust_src_path, racerd_binary_path
# adds in filepath_blacklist { html, jsx, xml }
# removes in filepath_blacklist { tagbar, qf, notes, markdown, netrw, unite, text, vimwiki, pandoc, infolog, mail }
# 43 https://github.com/ycm-core/ycmd/blob/228adf91f5ea15cca837f3ccc85f4e55edfa1b4f/ycmd/default_settings.json

# 39 https://github.com/ycm-core/ycmd/blob/683cb5e51d9e2379903189d7be6b16cf7fe80e7e/ycmd/default_settings.json

	test $ycmd_core_version -eq 39 && ycmd_core_found=39
	test $ycmd_core_version -eq 43 && ycmd_core_found=43
	test $ycmd_core_version -eq 44 && ycmd_core_found=44
	test $ycmd_core_version -eq 45 && ycmd_core_found=45
	test $ycmd_core_version -eq 46 && ycmd_core_found=46
	test $ycmd_core_version -eq 47 && ycmd_core_found=47
	test $ycmd_core_version -eq 48 && ycmd_core_found=48
	if test $ycmd_core_found -gt 0; then
		AC_MSG_RESULT([$ycmd_core_version])
		AC_DEFINE_UNQUOTED([YCMD_CORE_VERSION], $ycmd_core_version, [Define this to set the ycmd server core version and to match the protocol version.])
	else
		AC_MSG_ERROR([Your CORE_VERSION ($ycmd_core_version) for ycmd is incompatible.  The CORE_VERSION needs to be either 39, 43, 44, 45, 46, 47, 48.])
	fi
])

AC_ARG_WITH([protocol],
  AS_HELP_STRING([--with-protocol=http|https], [Choose the protocol to use for ycmd.  For files with passwords use https. (default: http)]),
  [case "$withval" in
    http) YCMD_PROTOCOL="http" ;;
    https) YCMD_PROTOCOL="https" ;;
    *) AC_MSG_ERROR([Invalid protocol. Choose http or https.]) ;;
  esac],
  [YCMD_PROTOCOL="http"])

AC_ARG_WITH([host],
  AS_HELP_STRING([--with-host=HOST], [Specify the host to use (default: 127.0.0.1)]),
  [YCMD_HOST="$withval"],
  [YCMD_HOST="127.0.0.1"])

AC_ARG_WITH([port],
  AS_HELP_STRING([--with-port=PORT], [Specify the port to use (default: 8080)]),
  [YCMD_PORT="$withval"],
  [YCMD_PORT="0"])

AC_DEFINE_UNQUOTED([YCMD_PROTOCOL], ["$YCMD_PROTOCOL"], [The chosen protocol for ycmd])
AC_DEFINE_UNQUOTED([YCMD_HOST], ["$YCMD_HOST"], [The host to use for ycmd])
AC_DEFINE_UNQUOTED([YCMD_PORT], [$YCMD_PORT], [The port to use for ycmd])
AC_SUBST(YCMD_PROTOCOL)
AC_SUBST(YCMD_HOST)
AC_SUBST(YCMD_PORT)

if test "x$enable_ycmd" = xyes; then
	AC_CHECK_YCMD_CORE_VERSION([$YCMD_PATH])
	AC_MSG_CHECKING([for BEAR_PATH])
	AC_MSG_RESULT([$BEAR_PATH])
	AC_MSG_CHECKING([for CLANGD_PATH])
	AC_MSG_RESULT([$CLANGD_PATH])
	AC_MSG_CHECKING([for GOCODE_PATH])
	AC_MSG_RESULT([$GOCODE_PATH])
	AC_MSG_CHECKING([for GODEF_PATH])
	AC_MSG_RESULT([$GODEF_PATH])
	AC_MSG_CHECKING([for GOPLS_PATH])
	AC_MSG_RESULT([$GOPLS_PATH])
	AC_MSG_CHECKING([for JAVA_PATH])
	AC_MSG_RESULT([$JAVA_PATH])
	AC_MSG_CHECKING([for MONO_PATH])
	AC_MSG_RESULT([$MONO_PATH])
	AC_MSG_CHECKING([for NINJA_PATH])
	AC_MSG_RESULT([$NINJA_PATH])
	AC_MSG_CHECKING([for OMNISHARP_PATH])
	AC_MSG_RESULT([$OMNISHARP_PATH])
	AC_MSG_CHECKING([for RACERD_PATH])
	AC_MSG_RESULT([$RACERD_PATH])
	AC_MSG_CHECKING([for RLS_PATH])
	AC_MSG_RESULT([$RLS_PATH])
	AC_MSG_CHECKING([for RUST_SRC_PATH])
	AC_MSG_RESULT([$RUST_SRC_PATH])
	AC_MSG_CHECKING([for RUST_TOOLCHAIN_PATH])
	AC_MSG_RESULT([$RUST_TOOLCHAIN_PATH])
	AC_MSG_CHECKING([for RUSTC_PATH])
	AC_MSG_RESULT([$RUSTC_PATH])
	AC_MSG_CHECKING([for TSSERVER_PATH])
	AC_MSG_RESULT([$TSSERVER_PATH])
	AC_MSG_CHECKING([for YCMD_PATH])
	AC_MSG_RESULT([$YCMD_PATH])
	AC_MSG_CHECKING([for YCMD_PYTHON_PATH])
	AC_MSG_RESULT([$YCMD_PYTHON_PATH])
	AC_MSG_CHECKING([for YCMG_PATH])
	AC_MSG_RESULT([$YCMG_PATH])
	AC_MSG_CHECKING([for YCMG_PYTHON_PATH])
	AC_MSG_RESULT([$YCMG_PYTHON_PATH])

	PKG_CHECK_MODULES([GLIB], [glib-2.0], [
		GLIB_LIB=$GLIB_LIBS
		CPPFLAGS="$GLIB_CFLAGS $CPPFLAGS"
		GLIB_LIB_NAME=glib-2.0
	], [
		AC_MSG_ERROR([glib not found])
	])
	AC_SUBST(GLIB_CFLAGS)
	AC_SUBST(GLIB_LIBS)

	PKG_CHECK_MODULES([JANSSON], [jansson], [
		JANSSON_LIB=$JANSSON_LIBS
		CPPFLAGS="$JANSSON_CFLAGS $CPPFLAGS"
		JANSSON_LIB_NAME=jansson
	], [
		AC_MSG_ERROR([Jansson not found])
	])
	AC_SUBST(JANSSON_CFLAGS)
	AC_SUBST(JANSSON_LIBS)

	if test "x$with_openssl" = xyes; then
		PKG_CHECK_MODULES([OPENSSL], [openssl >= 3], [
			OPENSSL_LIB=$OPENSSL_LIBS
			CPPFLAGS="$OPENSSL_CFLAGS $CPPFLAGS"
			OPENSSL_LIB_NAME=openssl
		], [
			AC_MSG_ERROR([OpenSSL not found])
		])
		AC_SUBST(OPENSSL_CFLAGS)
		AC_SUBST(OPENSSL_LIBS)
		have_openssl=yes
	elif test "x$with_nettle" = xyes; then
		PKG_CHECK_MODULES([NETTLE], [nettle], [
			NETTLE_LIB=$NETTLE_LIBS
			CPPFLAGS="$NETTLE_CFLAGS $CPPFLAGS"
			NETTLE_LIB_NAME=nettle
		], [
			AC_MSG_ERROR([Nettle not found])
		])
		AC_SUBST(NETTLE_CFLAGS)
		AC_SUBST(NETTLE_LIBS)
		have_nettle=yes
	elif test "x$with_libgcrypt" = xyes; then
		AC_SEARCH_LIBS([gcry_mac_open], [gcrypt], [], [
			AC_MSG_ERROR([unable to find the gcry_mac_open() function])
		])
		have_libgcrypt=yes
	else
		AC_MSG_ERROR([You must choose a crypto library: libgcrypt, nettle, openssl])
	fi

	PKG_CHECK_MODULES([CURL], [libcurl], [
		CURL_LIB=$CURL_LIBS
		CPPFLAGS="$CURL_CFLAGS $CPPFLAGS"
		CURL_LIB_NAME=curl
	], [
		AC_MSG_ERROR([Curl not found])
	])
	AC_SUBST(CURL_CFLAGS)
	AC_SUBST(CURL_LIBS)

	AC_CHECK_LIB([curl], [curl_easy_init], [],
		[AC_MSG_ERROR([libcurl not found])])

	AC_CHECK_LIB([curl], [curl_global_sslset], [HAVE_CURL_SSL=yes], [HAVE_CURL_SSL=no])

	if test "$PROTOCOL" = "https" && test "$HAVE_CURL_SSL" = "no"; then
		AC_MSG_ERROR([https protocol requires libcurl with SSL/TLS support])
	fi

	AC_CHECK_FILE([$YCMD_PATH/hmac_utils.py], [ycmd_found=yes], [ycmd_found=no])
	AC_MSG_CHECKING([for YCMD_PATH/hmac_utils.py])
	if test "x$ycmd_found" = xno ; then
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([Your ycmd is possibly old or you haven't installed it or forgot to set the YCMD_PATH environmental variable to point to the path of ycmd])
	else
		AC_MSG_RESULT([yes])
		have_ycmd=yes
		AC_CHECK_YCMD_CORE_VERSION([$YCMD_PATH])
	fi

	AC_CHECK_FILE([$YCMD_PYTHON_PATH], [ycmd_python_found=yes], [ycmd_python_found=no])
	AC_MSG_CHECKING([for YCMD_PYTHON_PATH])
	if test "x$ycmd_python_found" = xno ; then
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([You must set the YCMD_PYTHON_PATH to your python executable or you may need to install python])
	else
		AC_MSG_RESULT([yes])
	fi

	if test "x$with_ycm_generator" = xyes; then
		AC_CHECK_FILE([$YCMG_PYTHON_PATH], [ycmg_python_found=yes], [ycmg_python_found=no])
		AC_MSG_CHECKING([for YCMG_PYTHON_PATH])
		if test "x$ycmg_python_found" = xno ; then
			AC_MSG_RESULT([no])
			AC_MSG_ERROR([You must set the YCMG_PYTHON_PATH to your python executable or you may need to install python])
		else
			AC_MSG_RESULT([yes])
		fi

		if test "x$with_bear" != xyes ; then
			if test "x$with_ninja" != xyes; then
				AC_MSG_ERROR([--with-ycm-generator requires you to set at least either --with-bear or --with-ninja.])
			fi
		fi

		if test "x$with_bear" = xyes; then
			AC_CHECK_FILE([$BEAR_PATH], [bear_found=yes], [bear_found=no])
			AC_MSG_CHECKING([for BEAR_PATH])
			if test "x$bear_found" = xno ; then
				AC_MSG_RESULT([no])
			else
				AC_MSG_RESULT([yes])
			fi
		fi

		if test "x$with_ninja" = xyes; then
			AC_CHECK_FILE([$NINJA_PATH], [ninja_found=yes], [ninja_found=no])
			AC_MSG_CHECKING([for NINJA_PATH])
			if test "x$bear_found" = xno ; then
				AC_MSG_RESULT([no])
			else
				AC_MSG_RESULT([yes])
			fi
		fi
	fi
fi
AM_CONDITIONAL([HAVE_BEAR], [test x$BEAR_PATH != x])
AM_CONDITIONAL([HAVE_CLANGD], [test x$CLANGD_PATH != x])
AM_CONDITIONAL([HAVE_GOCODE], [test x$GOCODE_PATH != x])
AM_CONDITIONAL([HAVE_GODEF], [test x$GODEF_PATH != x])
AM_CONDITIONAL([HAVE_GOPLS], [test x$GOPLS_PATH != x])
AM_CONDITIONAL([HAVE_LIBGCRYPT], [test x$have_libgcrypt = xyes])
AM_CONDITIONAL([HAVE_SAFECLIB], [test x$have_safeclib = xyes])
AM_CONDITIONAL([HAVE_JAVA], [test x$JAVA_PATH != x])
AM_CONDITIONAL([HAVE_MONO], [test x$MONO_PATH != x])
AM_CONDITIONAL([HAVE_NETTLE], [test x$have_nettle = xyes])
AM_CONDITIONAL([HAVE_NINJA], [test x$NINJA_PATH != x])
AM_CONDITIONAL([HAVE_OMNISHARP], [test x$OMNISHARP_PATH != x])
AM_CONDITIONAL([HAVE_OPENSSL], [test x$have_openssl = xyes])
AM_CONDITIONAL([HAVE_RACERD], [test x$RACERD_PATH != x])
AM_CONDITIONAL([HAVE_RLS], [test x$RLS_PATH != x])
AM_CONDITIONAL([HAVE_RUST_SRC], [test  x$RUST_SRC_PATH != x])
AM_CONDITIONAL([HAVE_RUSTC], [test x$RUSTC_PATH != x])
AM_CONDITIONAL([HAVE_RUST_TOOLCHAIN], [test x$RUST_TOOLCHAIN_PATH != x])
AM_CONDITIONAL([HAVE_TSSERVER], [test x$TSSERVER_PATH != x])
AM_CONDITIONAL([HAVE_YCMD], [test x$have_ycmd = xyes])
AM_CONDITIONAL([HAVE_YCMD_PYTHON], [test x$YCMD_PYTHON_PATH != x])
AM_CONDITIONAL([HAVE_YCMG], [test x$YCMG_PATH != x])
AM_CONDITIONAL([HAVE_YCMG_PYTHON], [test x$YCMG_PYTHON_PATH != x])
AM_CONDITIONAL([USE_BEAR], [test x$with_bear == xyes])
AM_CONDITIONAL([USE_HARDENED_MALLOC], [test x$allocator = xhardened_malloc])
AM_CONDITIONAL([USE_LIBC_MALLOC], [test x$allocator = xlibc])
AM_CONDITIONAL([USE_MIMALLOC_SECURE], [test x$allocator = xmimalloc-secure])
AM_CONDITIONAL([USE_NINJA], [test x$with_ninja == xyes])
AM_CONDITIONAL([USE_YCM_GENERATOR], [test x$with_ycm_generator = xyes])
AM_CONDITIONAL([USE_YCMD], [test x$enable_ycmd = xyes])


AC_ARG_ENABLE(tiny,
AS_HELP_STRING([--enable-tiny], [Disable features for the sake of size]))
if test "x$enable_tiny" = xyes; then
	AC_DEFINE(NANO_TINY, 1, [Define this to make the nano executable as small as possible.])
	if test "x$enable_libmagic" != xyes; then
		enable_libmagic=no
	fi
fi

AM_CONDITIONAL(USE_COLOR, test x$color_support = xyes)
AM_CONDITIONAL(USE_NANORC, test x$nanorc_support = xyes)

AC_MSG_CHECKING([whether to enable UTF-8 support])
AC_ARG_ENABLE(utf8, AS_HELP_STRING([--enable-utf8], [Enable UTF-8 support]))
AC_MSG_RESULT(${enable_utf8:-auto})

AC_ARG_ENABLE(altrcname,
AS_HELP_STRING([--enable-altrcname], [Specify an alternate rcfile name (default: .nanorc)]),
[if test x$enableval != no; then
	AC_DEFINE_UNQUOTED(RCFILE_NAME, "$enableval", [Specify an alternate rcfile name (default: .nanorc).]) rcfilename=$enableval
fi])

dnl Checks for functions.

if test "x$enable_utf8" != xno; then
	AC_CHECK_FUNCS(iswalpha iswalnum iswpunct mbstowcs wctomb)
fi

AC_CHECK_FUNCS_ONCE(chmod chown fchmod fchown flockfile funlockfile
                    fork fsync geteuid pipe wait waitpid)

dnl Checks for available flags.

AX_CHECK_COMPILE_FLAG([-Wall], [CFLAGS="$CFLAGS -Wall"], [], [])

dnl Checks for libraries.

if eval "test x$CURSES_LIB_NAME = x"; then
	if test "x$enable_utf8" != xno; then
		PKG_CHECK_MODULES([NCURSESW], [ncursesw], [
			CURSES_LIB=$NCURSESW_LIBS
			CPPFLAGS="$NCURSESW_CFLAGS $CPPFLAGS"
			CURSES_LIB_NAME=ncursesw
			CURSES_LIB_WIDE=yes
		], [:])
	else
		PKG_CHECK_MODULES([NCURSES], [ncurses], [
			CURSES_LIB=$NCURSES_LIBS
			CPPFLAGS="$NCURSES_CFLAGS $CPPFLAGS"
			CURSES_LIB_NAME=ncurses
		], [:])
	fi
fi

if eval "test x$CURSES_LIB_NAME = x"; then
	AC_CHECK_HEADERS(ncurses.h)

	if test "x$enable_utf8" != xno; then
		OLDLIBS="$LIBS"
		AC_CHECK_TOOL(NCURSESW_CONFIG, ncursesw5-config, no)
		if test "x$NCURSESW_CONFIG" != xno; then
			CURSES_LIB=`$NCURSESW_CONFIG --libs`
			LIBS="$CURSES_LIB $LIBS"
			CPPFLAGS="`$NCURSESW_CONFIG --cflags` $CPPFLAGS"
			AC_CHECK_LIB(ncursesw, wget_wch, [CURSES_LIB_NAME=ncursesw CURSES_LIB_WIDE=yes])
		else
			AC_CHECK_LIB(ncursesw, wget_wch, [CURSES_LIB="-lncursesw" CURSES_LIB_NAME=ncursesw CURSES_LIB_WIDE=yes])
		fi
		LIBS="$OLDLIBS"
	fi

	if eval "test x$CURSES_LIB_NAME = x"; then
		AC_CHECK_LIB(ncurses, initscr, [CURSES_LIB="-lncurses" CURSES_LIB_NAME=ncurses])
	fi
fi

if eval "test x$CURSES_LIB_NAME = x"; then
	AC_CHECK_HEADERS(curses.h)

	if test "x$enable_utf8" != xno; then
		AC_CHECK_LIB(curses, wget_wch, [CURSES_LIB="-lcurses" CURSES_LIB_NAME=curses CURSES_LIB_WIDE=yes])
	fi

	if eval "test x$CURSES_LIB_NAME = x"; then
		AC_CHECK_LIB(curses, initscr, [CURSES_LIB="-lcurses" CURSES_LIB_NAME=curses])
	fi
fi

if eval "test x$CURSES_LIB_NAME = x"; then
	AC_MSG_ERROR([
  *** No curses lib was found.  Please install the curses header files
  *** from libncurses-dev (Debian), ncurses-devel (Fedora), or similar.
  *** (Or install ncurses from https://ftp.gnu.org/gnu/ncurses/.)])
else
	AC_MSG_RESULT([  The curses library to be used is: $CURSES_LIB_NAME])
fi

AC_CHECK_LIB([$CURSES_LIB_NAME], [use_default_colors],
			 [AC_DEFINE(HAVE_USE_DEFAULT_COLORS, 1, [Define this if your curses library has the use_default_colors() function.])],
			 [], [$CURSES_LIB])
AC_CHECK_LIB([$CURSES_LIB_NAME], [set_escdelay],
			 [AC_DEFINE(HAVE_SET_ESCDELAY, 1, [Define this if your curses library has the set_escdelay() function.])],
			 [], [$CURSES_LIB])
AC_CHECK_LIB([$CURSES_LIB_NAME], [key_defined],
			 [AC_DEFINE(HAVE_KEY_DEFINED, 1, [Define this if your curses library has the key_defined() function.])],
			 [], [$CURSES_LIB])

LIBS="$LIBS $CURSES_LIB"

AC_SUBST(CURSES_LIB)

if test "x$enable_utf8" != xno && \
	test x$CURSES_LIB_WIDE = xyes && \
	test x$ac_cv_func_iswalpha = xyes && \
	test x$ac_cv_func_iswalnum = xyes && \
	test x$ac_cv_func_iswpunct = xyes && \
	test x$ac_cv_func_mbstowcs = xyes && \
	test x$ac_cv_func_wctomb = xyes; then
		AC_DEFINE(ENABLE_UTF8, 1, [Define this if your system has sufficient UTF-8 support.])
else
	if test "x$enable_utf8" = xyes; then
		AC_MSG_ERROR([
  *** UTF-8 support was requested, but insufficient support was
  *** detected in your curses and/or C libraries.  Please verify
  *** that both your curses library and your C library were built
  *** with wide-character support.])
	elif test "x$enable_utf8" != xno; then
		AC_MSG_WARN([
  *** Insufficient UTF-8 support was detected in your curses
  *** and/or C libraries.  If you want UTF-8 support, please
  *** verify that both your curses library and your C library
  *** were built with wide-character support.])
	fi
fi

AC_CACHE_CHECK([for enhanced regular expression flag], nano_cv_flag_reg_enhanced,
			   [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <regex.h>]],
												   [[
													 #ifndef REG_ENHANCED
													 error: No REG_ENHANCED support!
													 #endif
												   ]])],
								  [nano_cv_flag_reg_enhanced=yes],
								  [nano_cv_flag_reg_enhanced=no])])
dnl The bundled gnulib regex module doesn't support REG_ENHANCED.
if test "$ac_use_included_regex" = "yes"; then
	nano_cv_flag_reg_enhanced="no"
fi
if test "$nano_cv_flag_reg_enhanced" = "yes"; then
	nano_reg_extended="REG_EXTENDED | REG_ENHANCED"
else
	nano_reg_extended="REG_EXTENDED"
fi

AC_DEFINE_UNQUOTED(NANO_REG_EXTENDED, $nano_reg_extended,
				   [Flag(s) to use to get the full range of extended regular expressions])

if test x$color_support = xyes; then
	AC_MSG_CHECKING([whether _XOPEN_SOURCE_EXTENDED is needed])
	AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <curses.h>
int main(void)
{
	int testcolor = COLOR_WHITE;
	return 0;
}]])],
	AC_MSG_RESULT(no),
	AC_RUN_IFELSE([AC_LANG_SOURCE([[
#ifndef _XOPEN_SOURCE_EXTENDED
#define _XOPEN_SOURCE_EXTENDED 1
#endif
#include <curses.h>
int main(void)
{
	int testcolor = COLOR_WHITE;
	return 0;
}]])],
	AC_DEFINE(NEED_XOPEN_SOURCE_EXTENDED, 1, [Define this if you need the _XOPEN_SOURCE_EXTENDED macro for color support.])
	AC_MSG_RESULT(yes),
	AC_MSG_RESULT(not sure)
	AC_MSG_WARN([
  *** Couldn't successfully compile basic color test with or without
  *** _XOPEN_SOURCE_EXTENDED.  This build may not compile.  Consider
  *** configuring with --disable-color or installing ncurses.])),
	AC_MSG_WARN([
  *** Can't check need for _XOPEN_SOURCE_EXTENDED when cross-compiling.]))
fi

AS_IF([test "x$enable_libmagic" != "xno"], [
	AC_CHECK_HEADERS([magic.h])
	AC_CHECK_LIB(magic, magic_open)
	AC_CHECK_HEADERS([zlib.h])
	AC_CHECK_LIB(z, inflate)
])

# Check for groff html support.
AC_MSG_CHECKING([for HTML support in groff])
groff -t -mandoc -Thtml </dev/null >/dev/null
if test $? -ne 0 ; then
	AC_MSG_RESULT([no])
	AC_MSG_WARN([
  *** Will not generate HTML version of man pages.  Consider
  *** installing a newer version of groff with HTML support.])
	groff_html_support=no
else
	AC_MSG_RESULT([yes])
	groff_html_support=yes
fi
AM_CONDITIONAL(GROFF_HTML, test x$groff_html_support = xyes)

AC_CONFIG_FILES([
Makefile
doc/Makefile
doc/sample.nanorc
lib/Makefile
m4/Makefile
po/Makefile.in
src/Makefile
syntax/Makefile
])


AC_OUTPUT

make showinfo
