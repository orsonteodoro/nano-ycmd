SUBDIRS =

if HAVE_YCMD
SUBDIRS += pixelbeat.org
endif

.PHONY: subdirs $(SUBDIRS)

all: subdirs

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@
