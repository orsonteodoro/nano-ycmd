AM_CFLAGS =
AM_CPPFLAGS = -DLOCALEDIR=\"$(localedir)\" -DSYSCONFDIR=\"$(sysconfdir)\" \
	-I$(top_builddir)/lib -I$(top_srcdir)/lib
AM_LDFLAGS =

if HAVE_YCMD

AM_CPPFLAGS += -DENABLE_YCMD -DYCMD_PATH=\"@YCMD_PATH@\" @GLIB_CFLAGS@
AM_CPPFLAGS += -DYCMD_PYTHON_PATH=\"@YCMD_PYTHON_PATH@\"

if HAVE_CLANGD
AM_CPPFLAGS += -DCLANGD_PATH=\"@CLANGD_PATH@\"
else
AM_CPPFLAGS += -DCLANGD_PATH=\"\"
endif

if HAVE_GOCODE
AM_CPPFLAGS += -DGOCODE_PATH=\"@GOCODE_PATH@\"
else
AM_CPPFLAGS += -DGOCODE_PATH=\"\"
endif

if HAVE_GODEF
AM_CPPFLAGS += -DGODEF_PATH=\"@GODEF_PATH@\"
else
AM_CPPFLAGS += -DGODEF_PATH=\"\"
endif

if HAVE_GOPLS
AM_CPPFLAGS += -DGOPLS_PATH=\"@GOPLS_PATH@\"
else
AM_CPPFLAGS += -DGOPLS_PATH=\"\"
endif

if HAVE_LIBGCRYPT
AM_CFLAGS += $(shell $(host)-libgcrypt-config --cflags)
AM_CPPFLAGS += -DUSE_LIBGCRYPT
LIBGCRYPT_LIBS = $(shell $(host)-libgcrypt-config --libs)
endif

if HAVE_JAVA
AM_CPPFLAGS += -DJAVA_PATH=\"@JAVA_PATH@\"
else
AM_CPPFLAGS += -DJAVA_PATH=\"\"
endif

if HAVE_MONO
AM_CPPFLAGS += -DMONO_PATH=\"@MONO_PATH@\"
else
AM_CPPFLAGS += -DMONO_PATH=\"\"
endif

if HAVE_NETTLE
AM_CFLAGS += @NETTLE_CFLAGS@
AM_CPPFLAGS += -DUSE_NETTLE
endif

if HAVE_NINJA
AM_CPPFLAGS += -DNINJA_PATH=\"@NINJA_PATH@\"
else
AM_CPPFLAGS += -DNINJA_PATH=\"\"
endif

if HAVE_OPENSSL
AM_CFLAGS += @OPENSSL_CFLAGS@
AM_CPPFLAGS += -DUSE_OPENSSL
endif

if HAVE_OMNISHARP
AM_CPPFLAGS += -DOMNISHARP_PATH=\"@OMNISHARP_PATH@\"
else
AM_CPPFLAGS += -DOMNISHARP_PATH=\"\"
endif

if HAVE_RACERD
AM_CPPFLAGS += -DRACERD_PATH=\"@RACERD_PATH@\"
else
AM_CPPFLAGS += -DRACERD_PATH=\"\"
endif

if HAVE_RLS
AM_CPPFLAGS += -DRLS_PATH=\"@RLS_PATH@\"
else
AM_CPPFLAGS += -DRLS_PATH=\"\"
endif

if HAVE_RUST_SRC
AM_CPPFLAGS += -DRUST_SRC_PATH=\"@RUST_SRC_PATH@\"
else
AM_CPPFLAGS += -DRUST_SRC_PATH=\"\"
endif

if HAVE_RUST_TOOLCHAIN
AM_CPPFLAGS += -DRUST_TOOLCHAIN_PATH=\"@RUST_TOOLCHAIN_PATH@\"
else
AM_CPPFLAGS += -DRUST_TOOLCHAIN_PATH=\"\"
endif

if HAVE_RUSTC
AM_CPPFLAGS += -DRUSTC_PATH=\"@RUSTC_PATH@\"
else
AM_CPPFLAGS += -DRUSTC_PATH=\"\"
endif

if HAVE_SAFECLIB
AM_CFLAGS += @SAFECLIB_CFLAGS@
AM_CPPFLAGS += -DUSE_SAFECLIB
endif

if HAVE_TSSERVER
AM_CPPFLAGS += -DTSSERVER_PATH=\"@TSSERVER_PATH@\"
else
AM_CPPFLAGS += -DTSSERVER_PATH=\"\"
endif

if HAVE_YCMG
AM_CPPFLAGS += -DYCMG_PATH=\"@YCMG_PATH@\" -DYCMG_PYTHON_PATH=\"@YCMG_PYTHON_PATH@\"
endif

if USE_BEAR
AM_CPPFLAGS += -DENABLE_BEAR=1
endif

if USE_NINJA
AM_CPPFLAGS += -DENABLE_NINJA=1
endif

if USE_YCM_GENERATOR
AM_CPPFLAGS += -DENABLE_YCM_GENERATOR=1
endif

endif

CLEANFILES = revision.h

if BUILDING_FROM_GIT
SOMETHING = "REVISION \"`git describe --tags 2>/dev/null`\""
else
SOMETHING = "PLAINBUILD \"from tarball\""
endif

nano.o: revision.h
winio.o: revision.h

# Always run the commands in this rule.  But update the target
# only when the revision actually changed.
revision.h: FORCE
	@[ -f $@ ] || touch $@
	@! git describe >/dev/null 2>&1 || \
			echo "#define $(SOMETHING)" | cmp -s $@ - || \
			echo "#define $(SOMETHING)" > $@
FORCE:

bin_PROGRAMS = 	nano
nano_SOURCES = \
		definitions.h \
		prototypes.h \
		browser.c \
		chars.c \
		completion_ui.c \
		color.c \
		cut.c \
		files.c \
		global.c \
		help.c \
		history.c \
		ld_preload.c \
		move.c \
		nano.c \
		prompt.c \
		rcfile.c \
		safe_wrapper.c \
		search.c \
		text.c \
		utils.c \
		winio.c

if USE_YCMD
nano_SOURCES += \
		ycmd.c
endif

nano_LDADD = $(top_builddir)/lib/libgnu.a @LIBINTL@ \
		$(GETRANDOM_LIB) $(CLOCK_TIME_LIB) $(LIBTHREAD)

if USE_HARDENED_MALLOC
nano_LDADD += -lhardened_malloc
endif

if USE_MIMALLOC_SECURE
nano_LDADD += -lmimalloc-secure
endif

if USE_YCMD
nano_LDADD += @CURL_LIBS@
endif

if HAVE_NETTLE
nano_LDADD += @NETTLE_LIBS@
endif

if HAVE_OPENSSL
nano_LDADD += @OPENSSL_LIBS@
endif

if HAVE_LIBGCRYPT
nano_LDADD += @GLIB_LIBS@
nano_LDFLAGS = $(LIBGCRYPT_LIBS)
endif

if HAVE_SAFECLIB
nano_LDADD += @SAFECLIB_LIBS@
endif

if HAVE_YCMD
nano_LDADD += @GLIB_LIBS@
nano_LDADD += @JANSSON_LIBS@
endif

nano_LDADD += @crypto_libs@

install-exec-hook:
	cd $(DESTDIR)$(bindir) && rm -f rnano && $(LN_S) nano rnano
uninstall-hook:
	cd $(DESTDIR)$(bindir) && rm -f rnano
