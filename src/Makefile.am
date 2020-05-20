AM_CPPFLAGS = -DLOCALEDIR=\"$(localedir)\" -DSYSCONFDIR=\"$(sysconfdir)\" \
	-I$(top_builddir)/lib -I$(top_srcdir)/lib

if HAVE_YCMD

AM_CPPFLAGS += -DENABLE_YCMD -DYCMD_PATH=\"@YCMD_PATH@\" @GLIB_CFLAGS@
AM_CFLAGS =
AM_CPPFLAGS += -DYCMD_PYTHON_PATH=\"@YCMD_PYTHON_PATH@\"
AM_LDFLAGS = -lnxjson

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

if HAVE_NETTLE
AM_CFLAGS += @NETTLE_CFLAGS@
AM_CPPFLAGS += -DUSE_NETTLE
endif

if HAVE_NINJA
AM_CPPFLAGS += -DUSE_NINJA=1 -DNINJA_PATH=\"@NINJA_PATH@\"
else
AM_CPPFLAGS += -DNINJA_PATH=\"\"
endif

if HAVE_OPENMP
AM_CFLAGS += -fopenmp -DUSE_OPENMP
AM_LDFLAGS += -lomp
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

if HAVE_RUSTC
AM_CPPFLAGS += -DRUSTC_PATH=\"@RUSTC_PATH@\"
else
AM_CPPFLAGS += -DRUSTC_PATH=\"\"
endif

if HAVE_TSSERVER
AM_CPPFLAGS += -DTSSERVER_PATH=\"@TSSERVER_PATH@\"
else
AM_CPPFLAGS += -DTSSERVER_PATH=\"\"
endif

if HAVE_YCMG
AM_CPPFLAGS += -DYCMG_PATH=\"@YCMG_PATH@\" -DYCMG_PYTHON_PATH=\"@YCMG_PYTHON_PATH@\"
endif

endif

CLEANFILES = revision.h

if BUILDING_FROM_GIT
SOMETHING = "REVISION \"`git describe --tags 2>/dev/null`\""
else
SOMETHING = "NOTHING \"from tarball\""
endif

nano.o: revision.h
winio.o: revision.h

# Always run the commands in this rule.  But update the target
# only when the revision actually changed.
revision.h: FORCE
	@[ -f $@ ] || touch $@
	@echo "#define $(SOMETHING)" | cmp -s $@ - || \
			echo "#define $(SOMETHING)" > $@
FORCE:

bin_PROGRAMS = 	nano
nano_SOURCES =	browser.c \
		chars.c \
		color.c \
		cut.c \
		files.c \
		global.c \
		help.c \
		history.c \
		move.c \
		nano.c \
		nano.h \
		prompt.c \
		proto.h \
		rcfile.c \
		search.c \
		text.c \
		utils.c \
		ycmd.c \
		winio.c

nano_LDADD = @LIBINTL@ $(top_builddir)/lib/libgnu.a \
		$(LIB_CLOCK_GETTIME) $(LIBTHREAD)

nano_LDADD += @NEON_LIBS@

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
if HAVE_YCMD
nano_LDADD += @GLIB_LIBS@
endif

install-exec-hook:
	cd $(DESTDIR)$(bindir) && rm -f rnano && $(LN_S) nano rnano
uninstall-hook:
	cd $(DESTDIR)$(bindir) && rm -f rnano
