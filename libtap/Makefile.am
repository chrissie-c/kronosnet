#
# Copyright (C) 2010-2018 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk


SYMFILE			= libtap_exported_syms

EXTRA_DIST		= $(SYMFILE) tap_updown_bad tap_updown_good api-test-coverage

sources			= libtap.c

libversion		= 1:0:0

AM_CFLAGS		+= $(PTHREAD_CFLAGS)
LIBS			= $(PTHREAD_LIBS)

if BUILD_LIBTAP

include_HEADERS		= libtap.h

pkgconfigdir		= $(libdir)/pkgconfig

pkgconfig_DATA		= libtap.pc

lib_LTLIBRARIES		= libtap.la

libtap_la_SOURCES	= $(sources)

EXTRA_libtap_la_DEPENDENCIES	= $(SYMFILE)

libtap_la_LDFLAGS	= $(AM_LDFLAGS) \
			  -Wl,-version-script,$(srcdir)/$(SYMFILE) \
			  -version-info $(libversion)

TESTS			= $(check_PROGRAMS)

noinst_PROGRAMS		= $(check_PROGRAMS)

check_PROGRAMS		= tap_test

check-local: check-api-test-coverage

check-api-test-coverage:
	chmod u+x $(top_srcdir)/libtap/api-test-coverage
	$(top_srcdir)/libtap/api-test-coverage $(top_srcdir) $(top_builddir)

tap_test_SOURCES	= $(sources)

tap_test_CPPFLAGS	= -DTEST \
			  -DABSBUILDDIR=\"$(abs_builddir)\"

endif
