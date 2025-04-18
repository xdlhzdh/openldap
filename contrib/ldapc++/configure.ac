dnl $OpenLDAP$

dnl Copyright 2000-2024 The OpenLDAP Foundation. All Rights Reserved.
dnl COPYING RESTRICTIONS APPLY, see COPYRIGHT file

dnl Process this file with autoconf to produce a configure script.

AC_COPYRIGHT([[Copyright 2000-2024 The OpenLDAP Foundation. All rights reserved.
Restrictions apply, see COPYRIGHT and LICENSE files.]])
AC_REVISION([$Id: 2301b679cf9abbd19de02c85ece6e712e070107a $])
AC_INIT([ldapcpplib],[ ],[http://www.openldap.org/its/ ])
AC_CONFIG_SRCDIR(src/LDAPConnection.h)
AM_INIT_AUTOMAKE(foreign)
AC_CONFIG_HEADERS([src/config.h])

eval `$ac_aux_dir/version.sh`
if test -z "$OL_CPP_API_RELEASE"; then
        AC_MSG_ERROR([could not determine version])
fi

VERSION=$OL_CPP_API_RELEASE
OPENLDAP_CPP_API_VERSION=$OL_CPP_API_VERSION
AC_SUBST(VERSION)
AC_SUBST(OPENLDAP_CPP_API_VERSION)
dnl Checks for programs.
AC_PROG_INSTALL
dnl AC_PROG_CC
AC_PROG_CXX
dnl AC_PROG_RANLIB
dnl AC_DISABLE_SHARED([])
LT_INIT
dnl AC_PROG_MAKE_SET
AC_ARG_ENABLE(debug,[  --enable-debug],[
	CXXFLAGS="-g -O0 -Wall"
    AC_DEFINE(WITH_DEBUG,[],[Define to 1 ot enable debug logging])
	],
)

AC_ARG_WITH(libldap,[  --with-libldap=DIR          Path to the libldap library [/usr/local/lib]],[
	LIBS="-L$with_libldap $LIBS "	
	],[
	LIBS="-L/usr/local/lib $LIBS "	
	]
)

AC_ARG_WITH(ldap-includes,[  --with-ldap-includes=DIR    Path to the libldap include files [/usr/local/include]],[
	CPPFLAGS="-I$with_ldap_includes $CPPFLAGS "	
	],[
	CPPFLAGS="-I/usr/local/include $CPPFLAGS "
	]
)
dnl Checks for libraries.
AC_CHECK_LIB(resolv,main)
AC_CHECK_LIB(lber,ber_strdup,[
dnl NOOP
        :
    ],[
        echo "        didn't find ber_strdup in liblber !";
        echo "        Check for the right version (>= 2.0) of the OpenLDAP libraries";
        echo "        or try the --with-libldap option.";
        exit
    ])
AC_CHECK_LIB(ldap,ldap_add_ext,[
dnl NOOP
        :
    ],[
        echo "        didn't find ldap_add_ext in libldap !";
        echo "        Check for the right version (>= 2.0) of the OpenLDAP libraries";
        echo "        or try the --with-libldap option.";
        exit
    ],[
    -llber
    ])
dnl Checks for header files.
AC_CHECK_HEADERS(termios.h ldap.h)
AC_EGREP_HEADER(ldap_add_ext,ldap.h,[
dnl NOOP
        :
    ],[
        echo "        didn't find ldap_add_ext in ldap.h!";
        echo "        Check for the right version (>= 2.0) of the OpenLDAP includes";
        echo "        or try --with-ldap-includes option.";
        exit
    ])
AC_CHECK_HEADER(lber.h)
AC_EGREP_HEADER(ber_strdup,lber.h,[
dnl NOOP
        :
    ],[
        echo "        didn't find ber_strdup in lber.h!";
        echo "        Check for the right version (>= 2.0) of the OpenLDAP includes";
        echo "        or try --with-ldap-includes option.";
        exit
    ])

dnl Checks for typedefs, structures, and compiler characteristics.

dnl Checks for library functions.

AC_CONFIG_FILES([Makefile src/Makefile examples/Makefile])
AC_OUTPUT
