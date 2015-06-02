#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([syslog-forward], [0.1],[lucas.nishimura@gmail.com])
AM_INIT_AUTOMAKE(syslog-forward, 0.1)
AC_CONFIG_SRCDIR([src/server.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_SEARCH_LIBS([pcap_open_live], pcap, ,
               [echo;echo -e "\a";
                 echo '*** pcap library is missing; doormand will not build. ***'
                  echo;echo])
# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h sys/socket.h unistd.h pcap.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_OUTPUT(Makefile src/Makefile)
