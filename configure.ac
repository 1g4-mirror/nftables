AC_INIT([nftables], [1.1.3], [netfilter-devel@vger.kernel.org])
AC_DEFINE([RELEASE_NAME], ["Commodore Bullmoose #4"], [Release name])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects
        tar-pax no-dist-gzip dist-xz 1.6])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_HEADERS([config.h])

AC_ARG_ENABLE([debug],
	      AS_HELP_STRING([--disable-debug], [Disable debugging symbols]),
	      [], [enable_debug=yes])
AM_CONDITIONAL([BUILD_DEBUG], [test "x$enable_debug" != xno])

AC_ARG_ENABLE([man-doc],
	      AS_HELP_STRING([--disable-man-doc], [Disable man page documentation]),
	      [], [enable_man_doc=yes])
AM_CONDITIONAL([BUILD_MAN], [test "x$enable_man_doc" = "xyes" ])

# Checks for programs.
AC_PROG_CC

AC_USE_SYSTEM_EXTENSIONS

AC_PROG_MKDIR_P
AC_PROG_INSTALL
AC_PROG_SED
AC_PROG_LEX([noyywrap])
AC_PROG_YACC

if test -z "$ac_cv_prog_YACC" -a ! -f "${srcdir}/src/parser_bison.c"
then
        echo "*** Error: No suitable bison/yacc found. ***"
        echo "    Please install the 'bison' package."
        exit 1
fi
if test -z "$ac_cv_prog_LEX" -a ! -f "${srcdir}/src/scanner.c"
then
        echo "*** Error: No suitable flex/lex found. ***"
        echo "    Please install the 'flex' package."
        exit 1
fi

AM_PROG_AR
LT_INIT([disable-static])
AC_EXEEXT
CHECK_GCC_FVISIBILITY

AS_IF([test "x$enable_man_doc" = "xyes"], [
       AC_CHECK_PROG(A2X, [a2x], [a2x], [no])
       AS_IF([test "$A2X" = "no" -a ! -f "${srcdir}/doc/nft.8"],
	     [AC_MSG_ERROR([a2x not found, please install asciidoc, or pass --disable-man-doc])])
])

PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.4])
PKG_CHECK_MODULES([LIBNFTNL], [libnftnl >= 1.2.9])

AC_ARG_WITH([mini-gmp], [AS_HELP_STRING([--with-mini-gmp],
            [Use builtin mini-gmp (for embedded builds)])],
	    [], [with_mini_gmp=no])
AS_IF([test "x$with_mini_gmp" != xyes], [
AC_CHECK_LIB([gmp],[__gmpz_init], , AC_MSG_ERROR([No suitable version of libgmp found]))
])
AM_CONDITIONAL([BUILD_MINIGMP], [test "x$with_mini_gmp" = xyes])

AC_ARG_WITH([cli], [AS_HELP_STRING([--without-cli],
            [disable interactive CLI (libreadline, editline or linenoise support)])],
            [], [with_cli=editline])

AS_IF([test "x$with_cli" = xreadline], [
AC_CHECK_LIB([readline], [readline], ,
	     AC_MSG_ERROR([No suitable version of libreadline found]))
AC_DEFINE([HAVE_LIBREADLINE], [1], [])
],
      [test "x$with_cli" = xlinenoise], [
AC_CHECK_LIB([linenoise], [linenoise], ,
	     AC_MSG_ERROR([No suitable version of linenoise found]))
AC_DEFINE([HAVE_LIBLINENOISE], [1], [])
],
      [test "x$with_cli" = xeditline], [
AC_CHECK_LIB([edit], [readline], ,
	     AC_MSG_ERROR([No suitable version of libedit found]))
AC_DEFINE([HAVE_LIBEDIT], [1], [])
],
      [test "x$with_cli" != xno], [
AC_MSG_ERROR([unexpected CLI value: $with_cli])
])
AM_CONDITIONAL([BUILD_CLI], [test "x$with_cli" != xno])

AC_ARG_WITH([xtables], [AS_HELP_STRING([--with-xtables],
            [Use libxtables for iptables interaction])],
	    [], [with_xtables=no])
AS_IF([test "x$with_xtables" != xno], [
PKG_CHECK_MODULES([XTABLES], [xtables >= 1.6.1])
AC_DEFINE([HAVE_LIBXTABLES], [1], [0])
])
AM_CONDITIONAL([BUILD_XTABLES], [test "x$with_xtables" = xyes])

AC_ARG_WITH([json], [AS_HELP_STRING([--with-json],
            [Enable JSON output support])],
	    [], [with_json=no])
AS_IF([test "x$with_json" != xno], [
AC_CHECK_LIB([jansson], [json_object], ,
	AC_MSG_ERROR([No suitable version of libjansson found]))
AC_DEFINE([HAVE_LIBJANSSON], [1], [Define if you have libjansson])
])
AM_CONDITIONAL([BUILD_JSON], [test "x$with_json" != xno])

AC_CHECK_DECLS([getprotobyname_r, getprotobynumber_r, getservbyport_r], [], [], [[
#include <netdb.h>
]])

AC_CONFIG_FILES([					\
		Makefile				\
		libnftables.pc				\
		])
AC_OUTPUT

echo "
nft configuration:
  cli support:			${with_cli}
  enable debugging symbols:	${enable_debug}
  use mini-gmp:			${with_mini_gmp}
  enable man page:              ${enable_man_doc}
  libxtables support:		${with_xtables}
  json output support:          ${with_json}"
