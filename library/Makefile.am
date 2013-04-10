include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_srcdir) \
	-DADCLI_UNSTABLE_API \
	-DHOST_TRIPLET=\"$(host_triplet)\" \
	$(NULL)

MODULE_SRCS = \
	adcli.h \
	adattrs.c adattrs.h \
	adconn.c adconn.h \
	addisco.c addisco.h \
	adenroll.c adenroll.h \
	adentry.c adentry.h \
	adldap.c \
	adkrb5.c \
	adprivate.h \
	adutil.c adutil.h \
	seq.c seq.h

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

check_PROGRAMS = \
	test-seq \
	test-util \
	test-ldap \
	test-attrs \
	$(NULL)

test_seq_SOURCES = seq.c test.c test.h
test_seq_CFLAGS = -DSEQ_TESTS

test_util_SOURCES = adutil.c $(test_seq_SOURCES)
test_util_CFLAGS = -DUTIL_TESTS

test_ldap_SOURCES = adldap.c adconn.c adkrb5.c addisco.c $(test_util_SOURCES)
test_ldap_CFLAGS = -DLDAP_TESTS
test_ldap_LDADD = $(KRB5_LIBS) $(LDAP_LIBS)

test_attrs_SOURCES = adattrs.c $(test_ldap_SOURCES)
test_attrs_CFLAGS = -DATTRS_TESTS
test_attrs_LDADD = $(test_ldap_LDADD)

TESTS = $(check_PROGRAMS)

MEMCHECK_ENV = $(TEST_RUNNER) valgrind --error-exitcode=80 --quiet --trace-children=yes

LEAKCHECK_ENV = $(TEST_RUNNER) valgrind --error-exitcode=81 --quiet --leak-check=yes

memcheck: all
	make $(AM_MAKEFLAGS) TESTS_ENVIRONMENT="$(MEMCHECK_ENV)" check-TESTS

leakcheck: all
	make $(AM_MAKEFLAGS) TESTS_ENVIRONMENT="$(LEAKCHECK_ENV)" check-TESTS

all-local: $(check_PROGRAMS)

CLEANFILES = \
	*.gcno \
	*.gcda \
	$(NULL)
