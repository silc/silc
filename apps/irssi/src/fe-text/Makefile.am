bin_PROGRAMS = silc

include $(top_srcdir)/Makefile.defines.in

ADD_INCLUDES = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/silc/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	-I$(top_srcdir)/src/fe-common/silc/ \
	$(CURSES_INCLUDEDIR) \
	-DLOCALEDIR=\""$(datadir)/locale"\"

silc_DEPENDENCIES = @COMMON_LIBS@

LIBS = $(SILC_COMMON_LIBS)
silc_LDADD = \
	@COMMON_LIBS@ \
	@PERL_LINK_LIBS@ \
	@PERL_FE_LINK_LIBS@ \
	$(PROG_LIBS) \
        $(CURSES_LIBS) \
	-L../../../lib -lsilcclient

silc_SOURCES = \
        gui-entry.c \
	gui-expandos.c \
        gui-printtext.c \
        gui-readline.c \
        gui-windows.c \
	lastlog.c \
        mainwindows.c \
        mainwindow-activity.c \
        mainwindows-save.c \
        screen.c \
        statusbar.c \
        statusbar-items.c \
        textbuffer.c \
        textbuffer-commands.c \
        textbuffer-view.c \
        silc.c \
	module-formats.c

noinst_HEADERS = \
        gui-entry.h \
        gui-printtext.h \
        gui-readline.h \
        gui-windows.h \
        mainwindows.h \
        statusbar.h \
        screen.h \
        textbuffer.h \
        textbuffer-view.h \
	module.h \
	module-formats.h
