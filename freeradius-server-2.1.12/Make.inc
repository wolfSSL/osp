# -*- makefile -*-
# Make.inc.in
#
# Version:	$Id$
#

# Location of files.
prefix		= /usr/local
exec_prefix	= ${prefix}
sysconfdir	= ${prefix}/etc
localstatedir	= ${prefix}/var
libdir		= ${exec_prefix}/lib
bindir		= ${exec_prefix}/bin
sbindir		= ${exec_prefix}/sbin
docdir		= ${datadir}/doc/freeradius
mandir		= ${datarootdir}/man
datadir		= ${datarootdir}
dictdir		= $(datadir)/freeradius
logdir		= ${localstatedir}/log/radius
includedir	= ${prefix}/include
raddbdir	= ${sysconfdir}/raddb
radacctdir	= ${logdir}/radacct
top_builddir	= /home/lealem/osp_fork/freeradius-server-2.1.12
top_build_prefix=/home/lealem/osp_fork/freeradius-server-2.1.12/
top_srcdir	= /home/lealem/osp_fork/freeradius-server-2.1.12
datarootdir	= ${prefix}/share

MAKE		= /usr/bin/make
CC		= gcc
RANLIB		= ranlib
INCLUDE		=
CFLAGS		= $(INCLUDE) -g -O2 -Wall -D_GNU_SOURCE -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS -DNDEBUG
CPPFLAGS	= 
LIBPREFIX	= lib
EXEEXT		= 

LIBTOOL		= /usr/bin/libtool
ACLOCAL		= aclocal
AUTOCONF	= autoconf
AUTOHEADER	= autoheader
INSTALL		= ${top_builddir}/install-sh -c
INSTALL_PROGRAM	= ${INSTALL}
INSTALL_DATA	= ${INSTALL} -m 644
INSTALL_SCRIPT	= ${INSTALL_PROGRAM}
INSTALLSTRIP	= 

LCRYPT		= -lcrypt
LIBS		= -lnsl -lresolv  -lpthread
LDFLAGS		= 

LOGDIR		= ${logdir}
RADDBDIR	= ${raddbdir}
RUNDIR		= ${localstatedir}/run/radiusd
SBINDIR		= ${sbindir}
RADIR		= ${radacctdir}
LIBRADIUS	= $(top_builddir)/src/lib/$(LIBPREFIX)freeradius-radius.la

LIBLTDL		= -lltdl
INCLTDL		= 
LTDL_SUBDIRS	= 

USE_SHARED_LIBS	= yes
USE_STATIC_LIBS = yes
STATIC_MODULES	= 

USE_SSL		= 
OPENSSL_LIBS	= 
OPENSSL_INCLUDE = -DNO_OPENSSL
CYASSL_LIBS	= 
CYASSL_INCLUDE  = -DNO_CYASSL

LIBREADLINE	= 

#
#  SQL driver defines
#
SQL_ODBC_LIBS = @ODBC_LIBS@
SQL_ODBC_INCLUDE = @ODBC_INCLUDE@

RADIUSD_MAJOR_VERSION	= 2
RADIUSD_MINOR_VERSION	= 1.12
RADIUSD_VERSION		= 2.1.12

MODULES			=  rlm_acctlog rlm_acct_unique rlm_always rlm_attr_filter rlm_attr_rewrite rlm_chap rlm_checkval rlm_copy_packet rlm_counter rlm_dbm rlm_detail rlm_digest rlm_eap rlm_exec rlm_expiration rlm_expr rlm_fastusers rlm_files rlm_ippool rlm_krb5 rlm_ldap rlm_linelog rlm_logintime rlm_mschap rlm_ns_mta_md5 rlm_otp rlm_pam rlm_pap rlm_passwd rlm_perl rlm_preprocess rlm_python rlm_radutmp rlm_realm rlm_soh rlm_sql rlm_sqlcounter rlm_sqlippool rlm_sql_log rlm_unix rlm_policy rlm_dynamic_clients rlm_replicate
HOSTINFO		= x86_64-unknown-linux-gnu

ifneq ($(WITH_OPENSSL_MD5),)
LIBRADIUS_WITH_OPENSSL = 1
CFLAGS += -DWITH_OPENSSL_MD5
endif

ifneq ($(WITH_OPENSSL_SHA1),)
LIBRADIUS_WITH_OPENSSL = 1
CFLAGS += -DWITH_OPENSSL_SHA1
endif

ifneq ($(LIBRADIUS_WITH_OPENSSL),)
ifeq ($(OPENSSL_LIBS),)
$(error OPENSSL_LIBS must be define in order to use WITH_OPENSSL_*)
else
LIBRADIUS += $(OPENSSL_LIBS)
endif
endif

#  http://clang.llvm.org/StaticAnalysis.html
#
#  $ make SCAN=/path/to/checker/ 
#
ifneq ($(SCAN),)
CC		:= $(SCAN)/scan-build gcc -DFR_SCAN_BUILD
LIBTOOL		:= 
endif
