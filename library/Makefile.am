include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_srcdir) \
	-DADCLI_UNSTABLE_API \
	$(NULL)

MODULE_SRCS = \
	adcli.h \
	adconn.c adconn.h \
	adenroll.c adenroll.h \
	adldap.c \
	adkrb5.c \
	adprivate.h \
	adutil.c adutil.h \
	getsrvinfo.c getsrvinfo.h \
	$(inc_HEADERS)

noinst_LTLIBRARIES = \
	libadcli.la

libadcli_la_SOURCES = $(MODULE_SRCS)

libadcli_la_CFLAGS = \
	$(KRB5_CFLAGS) \
	$(LBAP_CFLAGS) \
	$(NULL)

libadcli_la_LIBADD = \
	$(LTLIBINTL) \
	$(KRB5_LIBS) \
	$(LDAP_LIBS) \
	$(NULL)

CLEANFILES = \
	*.gcno \
	*.gcda \
	$(NULL)
