AM_CPPFLAGS = -DLOCALEDIR=\"$(localedir)\" -DSYSCONFDIR=\"$(sysconfdir)\"

if HAVE_YCMD
AM_CPPFLAGS += -DENABLE_YCMD -DYCMD_PATH=\"@YCMD_PATH@\" @GLIB_CFLAGS@
AM_CFLAGS = -I../third_party/pixelbeat.org
AM_CPPFLAGS += -DPYTHON_PATH=\"@PYTHON_PATH@\"
AM_LDFLAGS = -L../third_party/pixelbeat.org
if HAVE_NETTLE
AM_CFLAGS += @NETTLE_CFLAGS@
AM_CPPFLAGS += -DUSE_NETTLE
endif
if HAVE_OPENSSL
AM_CFLAGS += @OPENSSL_CFLAGS@
AM_CPPFLAGS += -DUSE_OPENSSL
endif

endif

if HAVE_GOCODE
AM_CPPFLAGS += -DGOCODE_PATH=\"@GOCODE_PATH@\"
endif

if HAVE_GODEF
AM_CPPFLAGS += -DGODEF_PATH=\"@GODEF_PATH@\"
endif

if HAVE_RUST_SRC
AM_CPPFLAGS += -DRUST_SRC_PATH=\"@RUST_SRC_PATH@\"
endif

if HAVE_RACERD
AM_CPPFLAGS += -DRACERD_PATH=\"@RACERD_PATH@\"
endif

CLEANFILES = revision.h

if BUILDING_FROM_GIT
SOMETHING = "REVISION \"$(shell git describe --tags 2>/dev/null)\""
else
SOMETHING = "NOTHING \"from tarball\""
endif

nano.o: revision.h
winio.o: revision.h

revision.h: update_revision
	@[ -f $@ ] || touch $@
	@echo "#define $(SOMETHING)" | cmp -s $@ - || \
	echo "#define $(SOMETHING)" > $@

.PHONY: update_revision

bin_PROGRAMS = 	nano
nano_SOURCES =	browser.c \
		chars.c \
		color.c \
		cut.c \
		files.c \
		global.c \
		help.c \
		move.c \
		nano.c \
		nano.h \
		nxjson.c \
		prompt.c \
		proto.h \
		rcfile.c \
		search.c \
		text.c \
		utils.c \
		ycmd.c \
		winio.c

nano_LDADD = @GLIB_LIBS@ @LIBINTL@ @NEON_LIBS@
if HAVE_NETTLE
nano_LDADD += @NETTLE_LIBS@
endif
if HAVE_OPENSSL
nano_LDADD += @OPENSSL_LIBS@ @GLIB_LIBS@
endif
if HAVE_YCMD
nano_LDADD += @GLIB_LIBS@ -lstring_replace
endif


install-exec-hook:
	cd $(DESTDIR)$(bindir) && rm -f rnano && $(LN_S) nano rnano
uninstall-hook:
	cd $(DESTDIR)$(bindir) && rm -f rnano
