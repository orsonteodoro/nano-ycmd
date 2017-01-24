AUTOMAKE_OPTIONS = gnu no-dependencies

SUBDIRS =

if HAVE_YCMD
SUBDIRS += third_party
endif

SUBDIRS += doc m4 po src

if USE_COLOR
SUBDIRS += syntax
endif


EXTRA_DIST = ChangeLog.1999-2006 ChangeLog.2007-2015 \
		IMPROVEMENTS README.GIT nano.spec

ACLOCAL_AMFLAGS = -I m4
