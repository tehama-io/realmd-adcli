include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_srcdir) \
	-DADCLI_UNSTABLE_API \
	$(NULL)

incdir = $(includedir)/adcli-1/adcli

inc_HEADERS = \
	adcli.h \
	adconn.h \
	adenroll.h \
	adutil.h \
	$(NULL)

MODULE_SRCS = \
	adconn.c adconn.h \
	addnssrv.c \
	adenroll.c \
	adprivate.h \
	adutil.c adutil.h \
	$(inc_HEADERS)

lib_LTLIBRARIES = \
	libadcli.la

libadcli_la_LDFLAGS = \
	-no-undefined \
	-version-info $(ADCLI_LT_RELEASE) \
	-export-symbols-regex '^adcli_'

libadcli_la_SOURCES = $(MODULE_SRCS)

libadcli_la_cflags = \
	$(KRB5_CFLAGS) \
	$(LBAP_CFLAGS) \
	$(NULL)

libadcli_la_LIBADD = \
	$(LTLIBINTL) \
	$(KRB5_LIBS) \
	$(LDAP_LIBS) \
	$(NULL)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libadcli-1.pc

EXTRA_DIST = \
	libadcli-1.pc.in
