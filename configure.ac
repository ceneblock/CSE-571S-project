#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.72])
AC_INIT([CSE-571S],[0.0.1],[ceneblock@wustl.edu])
AC_CONFIG_SRCDIR([src/main.cpp])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_TESTDIR([tests])
AC_CONFIG_FILES([ Makefile
                  src/Makefile
		  preload/Makefile
                ])
#AC_CONFIG_FILES([
#                 Makefile 
#                 tests/Makefile
#                 src/Makefile 
#                 libs/Makefile
#                 libs/libevents/Makefile
#                 libs/libjson/Makefile
#                 libs/libschedule/Makefile
#                 ]
#                )
#Muk up the CFLAGS variable
: ${CXXFLAGS="-g"}

#AC_ARG_ENABLE([async-exec],
#              [AS_HELP_STRING([--disable-async-exec],
#              [disable asynchronous execution @<:@default: no@:>@])],
#              [async_exec=${enableval}],
#              [async_exec=yes])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT
LT_LANG([C++])

AC_LANG([C++])
AC_CONFIG_MACRO_DIRS([m4])

AC_ENABLE_SHARED
AC_DISABLE_STATIC
#LT_INIT([libtool])

# Checks for libraries.
#AX_CXX_COMPILE_STDCXX_17([ext],[mandatory])

# Checks for header files.
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([vector])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([arpa/nameser.h])
AC_CHECK_HEADERS([resolv.h])

#Should be in POSIX fstat(3p)
AC_CHECK_HEADERS([sys/stat.h])

AC_CHECK_HEADERS([sqlite3.h],
  [], [have_SQLITE3_h=no]
)
if test "x$have_SQLITE3_h" = xno; then
    AC_MSG_ERROR([
        -----------------------------------------------
         Unable to find sqlite3 dev on this system.

         Check with your distribution on how to install
         this.

         Source Code can be found here:
         https://sqlite.org/download.html
         -----------------------------------------------
        ])
else
  LIBS+='-lsqlite3 '
fi

#TODO: --with-preload-lib AC_ARG_ENABLE 
#Then we can do all of this if the user wants to build thedirectory
PKG_CHECK_MODULES([LIBCONFIG], [libconfig])

#Enable arguments
AC_ARG_WITH([config-file-path], 
	    [AS_HELP_STRING([--with-config-file-path=@<:@DIR@:>@], 
            [specify the location of the safe hosts])],
            [config_file_location=${withval}],
            [config_file_location="/etc/safe_hosts.conf"])

if test "x${config_file_location}" != "x/etc/safe_hosts.conf"; then
  AC_MSG_RESULT([using config file path ${config_file_location}])
else
  AC_MSG_RESULT([using default config file path ${config_file_location}])
fi
AC_DEFINE_UNQUOTED([SAFE_HOSTS_PATH], ["${config_file_location}"], [The path to safe-hosts.conf])
# Checks for typedefs, structures, and compiler characteristics.


# Checks for library functions.

#AC_SEARCH_LIBS([pthread_setaffinity_np], [pthread],
#               [have_pthread_setaffinity=yes])
#
#if test "x${have_pthread_setaffinity}" = xyes; then
#  AC_CHECK_HEADERS([pthread.h], [], [have_pthreads_h=no])
#  if test "x$have_pthreads_h" = xno; then
#    AC_MSG_ERROR([
#        -----------------------------------------------
#         Unable to find pthreads.h on this system.
#
#         This probably means you aren't running a 
#         POSIX like OS or have those libraries. Check 
#         with your OS's documentation for more 
#         information.
#         -----------------------------------------------
#        ])
#  fi
#
#  else
#  AC_MSG_ERROR([
#      -----------------------------------------------
#       Unable to find pthread_attr_setaffinity_np(3) 
#       on this system.
#
#       This probably means you aren't running a 
#       compatible version of glibc. Check with
#       your OS's documentation for more information.
#       -----------------------------------------------
#      ])
#fi

#AX_CXX_CHECK_LIB(SenseHat, [SenseHat],
#               [have_SenseHat=yes], [have_SenseHat=no])
#
#if test "x$have_SenseHat" = xno; then
#    AC_MSG_ERROR([
#        -----------------------------------------------
#         Unable to find SenseHat on this system.
#
#         Check with your distribution on how to install
#         this.
#
#         Source Code can be found here:
#         https://github.com/PhilippeSimier/SenseHat
#         -----------------------------------------------
#        ])
#  fi

AC_OUTPUT

cat << EOF
-------------------------------------------------

${PACKAGE_NAME} Version ${PACKAGE_VERSION}

Prefix: '${prefix}'.
Compiler: '${CXX} ${CXXFLAGS} ${CPPFLAGS}'
Libraries: '${LIBS} ${LIBCONFIG_LIBS} ${APR_LIBS} ${APR_UTIL_LIBS}'

Package features:

  Now type 'make @<:@<target>@:>@'
    where the optional <target> is:
      all                - build all binaries
      install            - install everything
      check              - runs the tests
--------------------------------------------------
EOF
