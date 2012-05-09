NULL =

INCLUDES = \
	-I$(top_srcdir) \
	-DADCLI_UNSTABLE_API \
	$(NULL)

incdir = $(includedir)/adcli-1/adcli

inc_HEADERS = \
	adcli.h

MODULE_SRCS = \
	adenroll.c \
	$(inc_HEADERS)

lib_LTLIBRARIES = \
	libadcli.la

libadcli_la_LDFLAGS = \
	-no-undefined \
	-version-info $(ADCLI_LT_RELEASE) \
	-export-symbols-regex '^adcli_'

libadcli_la_SOURCES = $(MODULE_SRCS)
libadcli_la_LIBADD = $(LTLIBINTL)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = adcli-1.pc

EXTRA_DIST = \
	adcli-1.pc.in
