# SUBDIRS = src
# SUBDIRS = lib

lib_LTLIBRARIES = libdhcpc.la
libdhcpc_la_SOURCES = lib/dhcpc.c
libdhcpc_la_LDFLAGS = -version-info 0:0:0
libdhcpc_la_CFLAGS = -ggdb -O0
include_HEADERS = lib/dhcpc.h

bin_PROGRAMS = arc_dhcp_option_catcher
arc_dhcp_option_catcher_SOURCES = main/main_dhcp_catcher.c
arc_dhcp_option_catcher_LDADD = libdhcpc.la
arc_dhcp_option_catcher_CFLAGS = -I$(top_srcdir)/lib -ggdb -O0
