AC_PREREQ(2.61)

AC_INIT([libadcli],
	[0.1],
	[https://example.com/need/a/bugzilla],
	[libadcli],
	[http://example.com/website.html])

AC_USE_SYSTEM_EXTENSIONS

# ------------------------------------------------------------------------------
# libadcli libtool versioning
# CURRENT : REVISION : AGE
#   +1    :     0    : +1   == new interface that does not break old one.
#   +1    :     0    :  0   == removed an interface. Breaks old apps.
#    ?    :    +1    :  ?   == internal changes that doesn't break anything.

ADCLI_CURRENT=0
ADCLI_REVISION=0
ADCLI_AGE=0

# ------------------------------------------------------------------------------

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.10])
AM_SANITY_CHECK
AM_MAINTAINER_MODE([enable])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)

LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O

# -------------------------------------------------------------------
# Kerberos

if test "$KRB5_LIBS" != ""; then
	KRB5_PASSED_LIBS=$KRB5_LIBS
fi

if test "$KRB5_CFLAGS" != ""; then
	KRB5_PASSED_CFLAGS=$KRB5_CFLAGS
fi

AC_PATH_PROG(KRB5_CONFIG, krb5-config)
AC_MSG_CHECKING(for working krb5-config)
if test -x "$KRB5_CONFIG"; then
	KRB5_CFLAGS="`$KRB5_CONFIG --cflags`"
	KRB5_LIBS="`$KRB5_CONFIG --libs`"

	# Linking failures, so try this
	AC_CHECK_LIB(krb5support, krb5int_labeled_open, KRB5_LIBS="$KRB5_LIBS -lkrb5support")

	AC_MSG_RESULT(yes)
else
	if test "$KRB5_PASSED_LIBS" = ""; then
		AC_MSG_ERROR(no. Please install MIT kerberos devel package)
	fi
fi

if test "$KRB5_PASSED_LIBS" != ""; then
	KRB5_LIBS=$KRB5_PASSED_LIBS
fi

if test "$KRB5_PASSED_CFLAGS" != ""; then
	KRB5_CFLAGS=$KRB5_PASSED_CFLAGS
fi

AC_ARG_VAR([KRB5_CFLAGS], [C compiler flags for kerberos, overriding krb5-config])dnl
AC_ARG_VAR([KRB5_LIBS], [linker flags for kerberos, overriding krb5-config])dnl

AC_SUBST(KRB5_CFLAGS)
AC_SUBST(KRB5_LIBS)


# -------------------------------------------------------------------
# LDAP

LDAP_LIBS=""

AC_CHECK_LIB(ldap, ldap_search)
AC_CHECK_LIB(lber, ber_pvt_opt_on)
AC_CHECK_HEADERS(ldap.h)
AC_CHECK_LIB(resolv, res_query, LDAP_LIBS="-lresolv")

LDAP_LIBS="$LDAP_LIBS -lldap -llber"
LDAP_CFLAGS=""

AC_SUBST(LDAP_LIBS)
AC_SUBST(LDAP_CFLAGS)

# --------------------------------------------------------------------
# GTK Doc

dnl check for tools
AC_PATH_PROG([GTKDOC_CHECK],[gtkdoc-check])
AC_PATH_PROGS([GTKDOC_REBASE],[gtkdoc-rebase],[true])
AC_PATH_PROG([GTKDOC_MKPDF],[gtkdoc-mkpdf])
AC_PATH_PROG([GTKDOC_SCAN],[gtkdoc-scan])

dnl for overriding the documentation installation directory
AC_ARG_WITH([html-dir],
	AS_HELP_STRING([--with-html-dir=PATH], [path to installed docs]),,
	               [with_html_dir='${datadir}/gtk-doc/html'])
HTML_DIR="$with_html_dir"
AC_SUBST([HTML_DIR])

dnl enable/disable documentation building
AC_ARG_ENABLE([gtk-doc],
	AS_HELP_STRING([--enable-gtk-doc],
	               [use gtk-doc to build documentation [[default=no]]]),,
              [enable_gtk_doc=no])

if test x$enable_gtk_doc = xyes; then
	if test -z "$GTKDOC_SCAN"; then
		AC_MSG_ERROR([gtk-doc not installed and --enable-gtk-doc requested])
	fi
fi

AC_MSG_CHECKING([whether to build gtk-doc documentation])
AC_MSG_RESULT($enable_gtk_doc)

dnl enable/disable output formats
AC_ARG_ENABLE([gtk-doc-html],
	AS_HELP_STRING([--enable-gtk-doc-html],
	               [build documentation in html format [[default=yes]]]),,
	          [enable_gtk_doc_html=yes])
AC_ARG_ENABLE([gtk-doc-pdf],
	AS_HELP_STRING([--enable-gtk-doc-pdf],
	               [build documentation in pdf format [[default=no]]]),,
              [enable_gtk_doc_pdf=no])

if test -z "$GTKDOC_MKPDF"; then
	enable_gtk_doc_pdf=no
fi

AM_CONDITIONAL(ENABLE_GTK_DOC, [test x$enable_gtk_doc = xyes])
AM_CONDITIONAL(GTK_DOC_BUILD_HTML, [test x$enable_gtk_doc_html = xyes])
AM_CONDITIONAL(GTK_DOC_BUILD_PDF, [test x$enable_gtk_doc_pdf = xyes])
AM_CONDITIONAL(GTK_DOC_USE_LIBTOOL, [test -n "$LIBTOOL"])
AM_CONDITIONAL(GTK_DOC_USE_REBASE, [test -n "$GTKDOC_REBASE"])

# --------------------------------------------------------------------
# Compilation and linking options

AC_MSG_CHECKING([for debug mode])
AC_ARG_ENABLE(debug,
              AC_HELP_STRING([--enable-debug=no/default/yes],
              [Turn on or off debugging]))

if test "$enable_debug" != "no"; then
	AC_DEFINE_UNQUOTED(WITH_DEBUG, 1, [Print debug output])
	AC_DEFINE_UNQUOTED(_DEBUG, 1, [In debug mode])
	CFLAGS="$CFLAGS -g"
fi

if test "$enable_debug" = "yes"; then
	debug_status="yes (-g, -O0, debug output)"
	CFLAGS="$CFLAGS -O0"
elif test "$enable_debug" = "no"; then
	debug_status="no (no debug output, NDEBUG)"
	AC_DEFINE_UNQUOTED(NDEBUG, 1, [Disable glib assertions])
else
	debug_status="default (-g, debug output)"
fi

AC_MSG_RESULT($debug_status)

AC_MSG_CHECKING(for more warnings)
if test "$GCC" = "yes"; then
	CFLAGS="$CFLAGS \
		-Wall -Wstrict-prototypes -Wmissing-declarations \
		-Wmissing-prototypes -Wnested-externs -Wpointer-arith \
		-Wdeclaration-after-statement -Wformat=2 -Winit-self \
		-Waggregate-return -Wno-missing-format-attribute"

	for option in -Wmissing-include-dirs -Wundef; do
		SAVE_CFLAGS="$CFLAGS"
		CFLAGS="$CFLAGS $option"
		AC_MSG_CHECKING([whether gcc understands $option])
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])],
				  [has_option=yes],
				  [has_option=no])
		AC_MSG_RESULT($has_option)
		if test $has_option = no; then
			CFLAGS="$SAVE_CFLAGS"
		fi
	done
else
	AC_MSG_RESULT(no)
fi

AC_ARG_ENABLE(strict,
              [AS_HELP_STRING([--enable-strict], [Strict code compilation])]
             )

AC_MSG_CHECKING([build strict])

if test "$enable_strict" = "yes"; then
	CFLAGS="$CFLAGS -Werror"
	AC_DEFINE_UNQUOTED(WITH_STRICT, 1, [More strict checks])
	strict_status="yes (-Werror, fatals)"
else
	strict_status="no"
fi

AC_MSG_RESULT($strict_status)

AC_MSG_CHECKING([whether to build with gcov testing])
AC_ARG_ENABLE([coverage],
		[AS_HELP_STRING([--enable-coverage], [Whether to enable coverage testing ])],
		[],
		[enable_coverage=no])

AC_MSG_RESULT([$enable_coverage])

if test "$enable_coverage" = "yes"; then
	if test "$GCC" != "yes"; then
		AC_MSG_ERROR(Coverage testing requires GCC)
	fi

	AC_PATH_PROG(GCOV, gcov, no)
	if test "$GCOV" = "no" ; then
		AC_MSG_ERROR(gcov tool is not available)
	fi

	AC_PATH_PROG(LCOV, lcov, no)
	if test "$LCOV" = "no" ; then
		AC_MSG_ERROR(lcov tool is not installed)
	fi

	AC_PATH_PROG(GENHTML, genhtml, no)
	if test "$GENHTML" = "no" ; then
		AC_MSG_ERROR(lcov's genhtml tool is not installed)
	fi

	CFLAGS="$CFLAGS -O0 -g -fprofile-arcs -ftest-coverage"
	LDFLAGS="$LDFLAGS -lgcov"
fi

AM_CONDITIONAL([WITH_COVERAGE], [test "$enable_coverage" = "yes"])
AC_SUBST(LCOV)
AC_SUBST(GCOV)
AC_SUBST(GENHTML)

# ---------------------------------------------------------------------

ADCLI_LT_RELEASE=$ADCLI_CURRENT:$ADCLI_REVISION:$ADCLI_AGE
AC_SUBST(ADCLI_LT_RELEASE)

AC_CONFIG_FILES([Makefile
	doc/version.xml
	library/libadcli-1.pc
	library/Makefile
	tools/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([build options:
    Host:                            $host
    Debug build:                     $debug_status
    Strict build:                    $strict_status
])
