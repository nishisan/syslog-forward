#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([syslog-forward], [0.1],[lucas.nishimura@gmail.com])
AM_INIT_AUTOMAKE(syslog-forward, 0.1)
AC_CONFIG_SRCDIR([src/server.c])
AC_CONFIG_HEADERS([config.h lib/libconfig/ac_config.h])

AH_TEMPLATE(_GNU_SOURCE)
AC_DEFINE(_GNU_SOURCE)

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL


AM_PROG_LEX
if test Z"$LEX" != Zflex; then
cat <<EOF
*******************************************************************
You do not seem to have flex. While flex is not required to build
libconfig, you may need it to regenerate the lexer if you change
the scanner.l file. Flex 2.5.33 or newer is recommended.
*******************************************************************
EOF
fi

AC_PROG_YACC
if test Z"$YACC" != "Zbison -y"; then
cat <<EOF
*******************************************************************
You do not seem to have bison. While bison is not required to build
libconfig, you may need it to regenerate the parser if you change
the grammar.y file.
*******************************************************************
EOF
fi


# Checks for libraries.
AC_SEARCH_LIBS([pcap_open_live], pcap, ,
               [echo;echo -e "\a";
                 echo '*** libpcap library is missing; udp-forward will not build. ***'
                  echo;echo])

AC_SEARCH_LIBS([config_init], config, ,
               [echo;echo -e "\a";
                 echo '*** libconfig library is missing; udp-forward will not build. ***'
                  echo;echo])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h sys/socket.h unistd.h pcap.h libconfig.h unistd.h stdint.h xlocale.h])
AC_C_CONST

# Checks for typedefs, structures, and compiler characteristics.


AC_CHECK_FUNCS([newlocale uselocale freelocale])

dnl Package options

docxx=yes

AC_ARG_ENABLE(cxx,
AS_HELP_STRING([--disable-cxx], [Disable building of the C++ library]),
[if test "$enableval" = "no"; then docxx="no"; fi],
[
AC_PROG_CXX
docxx=yes
]
)


AM_CONDITIONAL(BUILDCXX, test x$docxx = xyes)

dnl Check for MinGW. Workaround for libtool's DLL_EXPORT stupidity.

case "$target" in
  *-*-cygwin* | *-*-mingw*)
    gnuwin=yes;;
esac

AM_CONDITIONAL(GNU_WIN, test x$gnuwin = xyes)



# Checks for library functions.

AC_OUTPUT(
          Makefile 
          src/Makefile
          lib/Makefile
          lib/libconfig/Makefile 
          lib/libconfig/libconfig.pc
          lib/libconfig/libconfig++.pc
          )
