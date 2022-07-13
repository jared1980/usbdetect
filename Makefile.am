# SUBDIRS = src
# SUBDIRS = lib

lib_LTLIBRARIES = libarc_tethering.la
libarc_tethering_la_SOURCES = lib/libinotify.c
libarc_tethering_la_LDFLAGS = -version-info 0:0:0
libarc_tethering_la_CFLAGS = -ggdb -O0
include_HEADERS = lib/.h

bin_PROGRAMS = arc_tetheringd
arc_tetheringd_SOURCES = main/arc_tetheringd.c
arc_tetheringd_LDADD = libarc_tethering.la
arc_tetheringd_CFLAGS = -I$(top_srcdir)/lib -ggdb -O0
