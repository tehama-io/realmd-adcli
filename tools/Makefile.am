include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/library \
	-DKRB5_CONFIG=\""$(sysconfdir)/krb5.conf"\" \
	$(NULL)

sbin_PROGRAMS =  \
	adcli \
	$(NULL)

adcli_SOURCES = \
	computer.c \
	entry.c \
	info.c \
	tools.c tools.h \
	$(NULL)

adcli_LDADD = \
	$(top_builddir)/library/libadcli.la \
	$(KRB5_LIBS) \
	$(LDAP_LIBS) \
	$(NULL)

CLEANFILES = \
	*.gcno \
	*.gcda \
	$(NULL)
