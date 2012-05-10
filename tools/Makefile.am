include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/library \
	$(NULL)

sbin_PROGRAMS =  \
	ad-enroll \
	$(NULL)

ad_enroll_LDADD = \
	$(top_builddir)/library/libadcli.la \
	$(KRB5_LIBS) \
	$(LDAP_LIBS) \
	$(NULL)
