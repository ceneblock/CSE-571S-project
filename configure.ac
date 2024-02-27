#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([CSE-571S], [0.0.1], [ceneblock@wustl.edu])
AC_CONFIG_SRCDIR([src/main.cpp])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_TESTDIR([tests])
AC_CONFIG_FILES([ Makefile
                  src/Makefile
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

# Checks for libraries.
AX_CXX_COMPILE_STDCXX_17([ext],[mandatory])

# Checks for header files.
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([vector])
AC_CHECK_HEADERS([tuple])
AC_CHECK_HEADERS([csignal])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([arpa/nameser.h])
AC_CHECK_HEADERS([resolv.h])

#Should be in POSIX fstat(3p)
AC_CHECK_HEADERS([sys/stat.h])

#This is actually a prereq to SenseHat so if you have SenseHat, then you should
#have this..
#AC_CHECK_HEADERS([RTIMULib.h], [], [have_RTIMUL_h=no])
#if test "x$have_RTIMUL_h" = xno; then
#    AC_MSG_ERROR([
#        -----------------------------------------------
#         Unable to find RTIMULib on this system.
#
#         Check with your distribution on how to install
#         this.
#
#         Source Code can be found here:
#         https://github.com/RPi-Distro/RTIMULib
#         -----------------------------------------------
#        ])
#  else
#    LIBS+='-lRTIMULib '
#  fi
#
#AC_CHECK_HEADERS([SenseHat.h], [], [have_SenseHat_h=no])
#if test "x$have_SenseHat_h" = xno; then
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
#    else
#      LIBS+='-lSenseHat '
#    fi
#
#AC_CHECK_HEADERS([sys/epoll.h], [], [have_epoll=no])
#if test "x${have_epoll}" = xno; then
#  AC_MSG_ERROR([
#      -----------------------------------------------
#       Unable to find epoll on this system.
#       epoll is Linux exclusive, FreeBSD uses kqueue.
#
#       If you'd like to port to FreeBSD then please
#       submit a pull request.
#      -----------------------------------------------
#      ])
#fi
#
#AC_CHECK_HEADERS([rapidjson/document.h], [], [have_rapidjson=no])
#if test "x${have_rapidjson}" = xno; then
#  AC_MSG_ERROR([
#      -----------------------------------------------
#       Unable to find rapidjson dev on this system.
#       Check with your distribution on how to install
#       rapidjson.
#
#       Source code for rapidjson can be found at:
#           https://github.com/Tencent/rapidjson
#      -----------------------------------------------
#      ])
#fi

#Enable arguments
#AC_ARG_WITH([kernel-headers], 
#            [AS_HELP_STRING([--with-kernel-headers=@<:@DIR@:>@], 
#            [specify the location of kernel headers])],
#            [kernel_headers_location=${withval}],
#            [kernel_headers_location=no])
#
#AC_MSG_NOTICE([Header location ${kernel_headers_location}])
#if test "x$kernel_headers_location}" != xno; then
#  CPPFLAGS+="${kernel_headers_location}"
#fi
#
## Checks for specific function declarations
#AC_CHECK_FUNCS([sched_setaffinity], [], [have_setaffinity=no])
#if test "x${have_setaffinity}" = xno; then
#  AC_MSG_ERROR([
#      -----------------------------------------------
#       Unable to find sched_setaffinity(2) on this 
#       system.
#
#       This probably means you aren't running Linux 
#       or have kernel headers installed. Check with
#       your OS's documentation for more information.
#
#       On FreeBSD, this might be done with 
#       cpuset(2). If you'd like to port to FreeBSD,
#       then please submit a pull request.
#       -----------------------------------------------
#      ])
#fi

# Checks for typedefs, structures, and compiler characteristics.


# Checks for library functions.
PKG_CHECK_MODULES([GTEST], [gtest_main])

#PKG_CHECK_MODULES([APR], [apr-1])
#PKG_CHECK_MODULES([APR_UTIL], [apr-util-1])

                
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
Libraries: '${LIBS} ${GTEST_LIBS} ${APR_LIBS} ${APR_UTIL_LIBS}'

Package features:

  Now type 'make @<:@<target>@:>@'
    where the optional <target> is:
      all                - build all binaries
      install            - install everything
      check              - runs the tests
--------------------------------------------------
EOF
