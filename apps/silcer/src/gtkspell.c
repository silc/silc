/* gtkspell - a spell-checking addon for GtkText
 * Copyright (c) 2000 Evan Martin.
 * vim: ts=4 sw=4
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <gtk/gtk.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>   
#include <stdio.h>    
#include <signal.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define GTKSPELL_USE_GNOME

#ifdef GTKSPELL_USE_GNOME
#include <gnome.h>
#endif /* GTKSPELL_USE_GNOME */

#include "gtkspell.h"

/* TODO:
 * handle dictionary changes
 * asynchronous lookups
 */

/* size of the text buffer used in various word-processing routines. */
#define BUFSIZE 1024
/* number of suggestions to display on each menu. */
#define MENUCOUNT 10
#define BUGEMAIL "gtkspell-devel@lists.sourceforge.net"

/* because we keep only one copy of the spell program running, 
 * all ispell-related variables can be static.  
 */
static pid_t spell_pid = -1;
static int fd_write[2] = {0}, fd_read[2] = {0};
static int signal_set_up = 0;

/* FIXME? */
static GdkColor highlight = { 0, 255*256, 0, 0 };

static void entry_insert_cb(GtkText *gtktext, 
		gchar *newtext, guint len, guint *ppos, gpointer d);
static void set_up_signal();

int gtkspell_running() {
	return (spell_pid > 0);
}

static void error_print(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "gtkspell: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/* functions to interface with pipe */
static void writetext(char *text) {
	write(fd_write[1], text, strlen(text));
}
static int readpipe(char *buf, int bufsize) {
	int len;
	len = read(fd_read[0], buf, bufsize-1);
	if (len < 0) {
		error_print("read: %s\n", strerror(errno));
		return -1;
	} else if (len == 0) {
		error_print("pipe closed.\n");
		return -1;
	} else if (len == bufsize-1) {
		error_print("buffer overflowed?\n");
	}

	buf[len] = 0;
	return len;
}
static int readline(char *buf) {
	return readpipe(buf, BUFSIZE);
}

static int readresponse(char *buf) {
	int len;
	len = readpipe(buf, BUFSIZE);

	/* all ispell responses of any reasonable length should end in \n\n.
	 * depending on the speed of the spell checker, this may require more
	 * reading. */
	if (len >= 2 && (buf[len-1] != '\n' || buf[len-2] != '\n')) {
		len += readpipe(buf+len, BUFSIZE-len);
	}

	/* now we can remove all of the the trailing newlines. */
	while (len > 0 && buf[len-1] == '\n')
		buf[--len] = 0;

	return len;
}


void gtkspell_stop() {
	if (gtkspell_running()) {
		kill(spell_pid, SIGHUP); 
		spell_pid = 0;
		close(fd_read[0]);
		close(fd_write[1]);
	}
}

int gtkspell_start(char *path, char * args[]) {
	int fd_error[2];
	char buf[BUFSIZE];

	if (gtkspell_running()) {
		error_print("gtkspell_start called while already running.\n");
		gtkspell_stop();
	}

	if (!signal_set_up) {
		set_up_signal();
		signal_set_up = 1;
	}

	pipe(fd_write);
	pipe(fd_read);
	pipe(fd_error);

	spell_pid = fork();
	if (spell_pid < 0) {
		error_print("fork: %s\n", strerror(errno));
		return -1;
	} else if (spell_pid == 0) {
		dup2(fd_write[0], 0);
		close(fd_write[0]);
		close(fd_write[1]);

		dup2(fd_read[1], 1);
		close(fd_read[0]);
		close(fd_read[1]);

		dup2(fd_error[1], 2);
		close(fd_error[0]);
		close(fd_error[1]);

		if (path == NULL) {
			if (execvp(args[0], args) < 0) 
				error_print("execvp('%s'): %s\n", args[0], strerror(errno));
		} else {
			if (execv(path, args) < 0) 
				error_print("execv('%s'): %s\n", path, strerror(errno));
		}
		/* if we get here, we failed.
		 * send some text on the pipe to indicate status.
		 */
		write(0, "!", 1); /* stdout _is_ the pipe. */

		_exit(0);
	} else {
		/* there are at least two ways to fail:
		 * - the exec() can fail
		 * - the exec() can succeed, but the program can dump the help screen
		 * we must check for both.
		 */
		fd_set rfds;
		struct timeval tv;
		
		close(fd_write[0]);
		close(fd_read[1]);

		FD_ZERO(&rfds);
		FD_SET(fd_error[0], &rfds);
		FD_SET(fd_read[0], &rfds);
		tv.tv_sec = 2;
		tv.tv_usec = 0;

		if (select(MAX(fd_error[0], fd_read[0])+1, 
					&rfds, NULL, NULL, &tv) < 0) {
			/* FIXME: is this needed? */
			error_print("Timed out waiting for spell command.\n");
			gtkspell_stop();
			return -1;
		}

		if (FD_ISSET(fd_error[0], &rfds)) { /* stderr readable? */
			error_print("Spell command printed on stderr -- probably failed.\n");
			gtkspell_stop();
			return -1;
		}

		/* we're done with stderr, now. */
		close(fd_error[0]);
		close(fd_error[1]);

		/* otherwise, fd_read[0] is set. */
		readline(buf);

		/* ispell should print something like this:
		 * @(#) International Ispell Version 3.1.20 10/10/95
		 * if it doesn't, it's an error. */
		if (buf[0] != '@') {
			gtkspell_stop();
			return -1;
		}
	}

	/* put ispell into terse mode.  
	 * this makes it not respond on correctly spelled words. */
	sprintf(buf, "!\n");
	writetext(buf);
	return 0;
}

static GList* misspelled_suggest(char *word) {
	char buf[BUFSIZE];
	char *newword;
	GList *l = NULL;
	int count;

	sprintf(buf, "^%s\n", word); /* guard against ispell control chars */
	writetext(buf);
	readresponse(buf);

	switch (buf[0]) { /* first char is ispell command. */
		case 0: /* no response: word is ok. */
			return NULL;
		case '&': /* misspelled, with suggestions */
			/* & <orig> <count> <ofs>: <miss>, <miss>, <guess>, ... */
			strtok(buf, " "); /* & */
			newword = strtok(NULL, " "); /* orig */
			l = g_list_append(l, g_strdup(newword));
			newword = strtok(NULL, " "); /* count */
			count = atoi(newword);
			strtok(NULL, " "); /* ofs: */

			while ((newword = strtok(NULL, ",")) != NULL) {
				int len = strlen(newword);
				if (newword[len-1] == ' ' || newword[len-1] == '\n') 
					newword[len-1] = 0;
				if (count == 0) {
					g_list_append(l, NULL); /* signal the "suggestions" */
				}
				/* add it to the list, skipping the initial space. */
				l = g_list_append(l, 
						g_strdup(newword[0] == ' ' ? newword+1 : newword));

				count--;
			}
			return l;

		case '#': /* misspelled, no suggestions */
		case '?': /* ispell is guessing. */
			/* # <orig> <ofs> */
			strtok(buf, " "); /* & */
			newword = strtok(NULL, " "); /* orig */
			l = g_list_append(l, g_strdup(newword));
			return l;
		default:
			error_print("Unsupported spell command '%c'.\n"
					"This is a bug; mail " BUGEMAIL " about it.\n", buf[0]);
			error_print("Input [%s]\nOutput [%s]\n", word, buf);

	}
	return NULL;
}

static int misspelled_test(char *word) {
	char buf[BUFSIZE];
	sprintf(buf, "^%s\n", word); /* guard against ispell control chars */
	writetext(buf);
	readresponse(buf);

	if (buf[0] == 0) {
		return 0;
	} else if (buf[0] == '&' || buf[0] == '#' || buf[0] == '?') {
		return 1;
	}
	
	error_print("Unsupported spell command '%c'.\n"
			"This is a bug; mail " BUGEMAIL " about it.\n", buf[0]);
	error_print("Input [%s]\nOutput [%s]\n", word, buf);
	return -1;
}

static gboolean iswordsep(char c) {
	return !isalpha(c) && c != '\'';
}

static gboolean get_word_from_pos(GtkText* gtktext, int pos, char* buf, 
		int *pstart, int *pend) {
	gint start, end;

	if (iswordsep(GTK_TEXT_INDEX(gtktext, pos))) return FALSE;

	for (start = pos; start >= 0; --start) {
		if (iswordsep(GTK_TEXT_INDEX(gtktext, start))) break;
	}
	start++;

	for (end = pos; end <= gtk_text_get_length(gtktext); end++) {
		if (iswordsep(GTK_TEXT_INDEX(gtktext, end))) break;
	}

	if (buf) {
		for (pos = start; pos < end; pos++) 
			buf[pos-start] = GTK_TEXT_INDEX(gtktext, pos);
		buf[pos-start] = 0;
	}

	if (pstart) *pstart = start;
	if (pend) *pend = end;

	return TRUE;
}

static gboolean get_curword(GtkText* gtktext, char* buf, 
		int *pstart, int *pend) {
	int pos = gtk_editable_get_position(GTK_EDITABLE(gtktext));
	return get_word_from_pos(gtktext, pos, buf, pstart, pend);
}

static void change_color(GtkText *gtktext, 
		int start, int end, GdkColor *color) {
	char *newtext = gtk_editable_get_chars(GTK_EDITABLE(gtktext), start, end);
	gtk_text_freeze(gtktext);
	gtk_signal_handler_block_by_func(GTK_OBJECT(gtktext), 
			GTK_SIGNAL_FUNC(entry_insert_cb), NULL);
	
	gtk_text_set_point(gtktext, start);
	gtk_text_forward_delete(gtktext, end-start);

	if (newtext && end-start > 0)
		gtk_text_insert(gtktext, NULL, color, NULL, newtext, end-start);

	gtk_signal_handler_unblock_by_func(GTK_OBJECT(gtktext), 
			GTK_SIGNAL_FUNC(entry_insert_cb), NULL);
	gtk_text_thaw(gtktext);
	g_free(newtext);
}

static gboolean check_at(GtkText *gtktext, int from_pos) {
	int start, end;
	char buf[BUFSIZE];

	if (!get_word_from_pos(gtktext, from_pos, buf, &start, &end)) {
		return FALSE;
	}

	if (misspelled_test(buf)) {
		if (highlight.pixel == 0) {
			/* add an entry for the highlight in the color map. */
			GdkColormap *gc = gtk_widget_get_colormap(GTK_WIDGET(gtktext));
			gdk_colormap_alloc_color(gc, &highlight, FALSE, TRUE);;
		}
		change_color(gtktext, start, end, &highlight);
		return TRUE;
	} else { 
		change_color(gtktext, start, end, 
				&(GTK_WIDGET(gtktext)->style->fg[0]));
		return FALSE;
	}
}

void gtkspell_check_all(GtkText *gtktext) {
	guint origpos;
	guint pos = 0;
	guint len;
	float adj_value;
	
	if (!gtkspell_running()) return;
	
	len = gtk_text_get_length(gtktext);

	adj_value = gtktext->vadj->value;
	gtk_text_freeze(gtktext);
	origpos = gtk_editable_get_position(GTK_EDITABLE(gtktext));
	while (pos < len) {
		while (pos < len && iswordsep(GTK_TEXT_INDEX(gtktext, pos)))
			pos++;
		while (pos < len && !iswordsep(GTK_TEXT_INDEX(gtktext, pos)))
			pos++;
		if (pos > 0)
			check_at(gtktext, pos-1);
	}
	gtk_text_thaw(gtktext);
	gtk_editable_set_position(GTK_EDITABLE(gtktext), origpos);
}

static void entry_insert_cb(GtkText *gtktext, 
		gchar *newtext, guint len, guint *ppos, gpointer d) {
	int origpos;

	if (!gtkspell_running()) return;

	gtk_signal_handler_block_by_func(GTK_OBJECT(gtktext),
									 GTK_SIGNAL_FUNC(entry_insert_cb),
									 NULL);
	gtk_text_insert(GTK_TEXT(gtktext), NULL,
			&(GTK_WIDGET(gtktext)->style->fg[0]), NULL, newtext, len);
	gtk_signal_handler_unblock_by_func(GTK_OBJECT(gtktext),
									 GTK_SIGNAL_FUNC(entry_insert_cb),
									 NULL);
	gtk_signal_emit_stop_by_name(GTK_OBJECT(gtktext), "insert-text");
	*ppos += len;

	origpos = gtk_editable_get_position(GTK_EDITABLE(gtktext));

	if (iswordsep(newtext[0])) {
		/* did we just end a word? */
		if (*ppos >= 2) check_at(gtktext, *ppos-2);

		/* did we just split a word? */
		if (*ppos < gtk_text_get_length(gtktext))
			check_at(gtktext, *ppos+1);
	} else {
		/* check as they type, *except* if they're typing at the end (the most
		 * common case.
		 */
		if (*ppos < gtk_text_get_length(gtktext) && 
				!iswordsep(GTK_TEXT_INDEX(gtktext, *ppos)))
			check_at(gtktext, *ppos-1);
	}

	gtk_editable_set_position(GTK_EDITABLE(gtktext), origpos);
	gtk_editable_select_region(GTK_EDITABLE(gtktext), origpos, origpos);
}

static void entry_delete_cb(GtkText *gtktext,
		gint start, gint end, gpointer d) {
	int origpos;

	if (!gtkspell_running()) return;

	origpos = gtk_editable_get_position(GTK_EDITABLE(gtktext));
	check_at(gtktext, start-1);
	gtk_editable_set_position(GTK_EDITABLE(gtktext), origpos);
	gtk_editable_select_region(GTK_EDITABLE(gtktext), origpos, origpos);
	/* this is to *UNDO* the selection, in case they were holding shift
	 * while hitting backspace. */
}

static void replace_word(GtkWidget *w, gpointer d) {
	int start, end;
	char *newword;
	char buf[BUFSIZE];

	/* we don't save their position, 
	 * because the cursor is moved by the click. */

	gtk_text_freeze(GTK_TEXT(d));

	gtk_label_get(GTK_LABEL(GTK_BIN(w)->child), &newword);
	get_curword(GTK_TEXT(d), buf, &start, &end);

	gtk_text_set_point(GTK_TEXT(d), end);
	gtk_text_backward_delete(GTK_TEXT(d), end-start);
	gtk_text_insert(GTK_TEXT(d), NULL, NULL, NULL, newword, strlen(newword));

	gtk_text_thaw(GTK_TEXT(d));
}

static GtkMenu *make_menu(GList *l, GtkText *gtktext) {
	GtkWidget *menu, *item;
	char *caption;
	menu = gtk_menu_new(); {
		caption = g_strdup_printf("Not in dictionary: %s", (char*)l->data);
		item = gtk_menu_item_new_with_label(caption);
		/* I'd like to make it so this item is never selectable, like
		 * the menu titles in the GNOME panel... unfortunately, the GNOME
		 * panel creates their own custom widget to do this! */
		gtk_widget_show(item);
		gtk_menu_append(GTK_MENU(menu), item);

		item = gtk_menu_item_new();
		gtk_widget_show(item);
		gtk_menu_append(GTK_MENU(menu), item);

		l = l->next;
		if (l == NULL) {
			item = gtk_menu_item_new_with_label("(no suggestions)");
			gtk_widget_show(item);
			gtk_menu_append(GTK_MENU(menu), item);
		} else {
			GtkWidget *curmenu = menu;
			int count = 0;
			do {
				if (l->data == NULL && l->next != NULL) {
					count = 0;
					curmenu = gtk_menu_new();
					item = gtk_menu_item_new_with_label("Other Possibilities...");
					gtk_widget_show(item);
					gtk_menu_item_set_submenu(GTK_MENU_ITEM(item), curmenu);
					gtk_menu_append(GTK_MENU(curmenu), item);
					l = l->next;
				} else if (count > MENUCOUNT) {
					count -= MENUCOUNT;
					item = gtk_menu_item_new_with_label("More...");
					gtk_widget_show(item);
					gtk_menu_append(GTK_MENU(curmenu), item);
					curmenu = gtk_menu_new();
					gtk_menu_item_set_submenu(GTK_MENU_ITEM(item), curmenu);
				}
				item = gtk_menu_item_new_with_label((char*)l->data);
				gtk_signal_connect(GTK_OBJECT(item), "activate",
						GTK_SIGNAL_FUNC(replace_word), gtktext);
				gtk_widget_show(item);
				gtk_menu_append(GTK_MENU(curmenu), item);
				count++;
			} while ((l = l->next) != NULL);
		}
	}
	return GTK_MENU(menu);
}

static void popup_menu(GtkText *gtktext, GdkEventButton *eb) {
	char buf[BUFSIZE];
	GList *list, *l;

	get_curword(gtktext, buf, NULL, NULL);

	list = misspelled_suggest(buf);
	if (list != NULL) {
		gtk_menu_popup(make_menu(list, gtktext), NULL, NULL, NULL, NULL,
				eb->button, eb->time);
		for (l = list; l != NULL; l = l->next)
			g_free(l->data);
		g_list_free(list);
	}
}

/* ok, this is pretty wacky:
 * we need to let the right-mouse-click go through, so it moves the cursor, 
 * but we *can't* let it go through, because GtkText interprets rightclicks as
 * weird selection modifiers.
 *
 * so what do we do?  forge rightclicks as leftclicks, then popup the menu. 
 * HACK HACK HACK. 
 */
static gint button_press_intercept_cb(GtkText *gtktext, GdkEvent *e, gpointer d) {
	GdkEventButton *eb;
	gboolean retval;

	if (!gtkspell_running()) return FALSE;

	if (e->type != GDK_BUTTON_PRESS) return FALSE;
	eb = (GdkEventButton*) e;

	if (eb->button != 3) return FALSE;

	/* forge the leftclick */
	eb->button = 1;

	gtk_signal_handler_block_by_func(GTK_OBJECT(gtktext), 
			GTK_SIGNAL_FUNC(button_press_intercept_cb), d);
	gtk_signal_emit_by_name(GTK_OBJECT(gtktext), "button-press-event",
			e, &retval);
	gtk_signal_handler_unblock_by_func(GTK_OBJECT(gtktext), 
			GTK_SIGNAL_FUNC(button_press_intercept_cb), d);
	gtk_signal_emit_stop_by_name(GTK_OBJECT(gtktext), "button-press-event");

	/* now do the menu wackiness */
	popup_menu(gtktext, eb);
	return TRUE;
}

void gtkspell_uncheck_all(GtkText *gtktext) {
	int origpos;
	char *text;
	float adj_value;

	adj_value = gtktext->vadj->value;
	gtk_text_freeze(gtktext);
	origpos = gtk_editable_get_position(GTK_EDITABLE(gtktext));
	text = gtk_editable_get_chars(GTK_EDITABLE(gtktext), 0, -1);
	gtk_text_set_point(gtktext, 0);
	gtk_text_forward_delete(gtktext, gtk_text_get_length(gtktext));
	gtk_text_insert(gtktext, NULL, NULL, NULL, text, strlen(text));
	gtk_text_thaw(gtktext);

	gtk_editable_set_position(GTK_EDITABLE(gtktext), origpos);
	gtk_adjustment_set_value(gtktext->vadj, adj_value);
}

void gtkspell_attach(GtkText *gtktext) {
	gtk_signal_connect(GTK_OBJECT(gtktext), "insert-text",
		GTK_SIGNAL_FUNC(entry_insert_cb), NULL);
	gtk_signal_connect_after(GTK_OBJECT(gtktext), "delete-text",
		GTK_SIGNAL_FUNC(entry_delete_cb), NULL);
	gtk_signal_connect(GTK_OBJECT(gtktext), "button-press-event",
			GTK_SIGNAL_FUNC(button_press_intercept_cb), NULL);
}

void gtkspell_detach(GtkText *gtktext) {
	gtk_signal_disconnect_by_func(GTK_OBJECT(gtktext),
		GTK_SIGNAL_FUNC(entry_insert_cb), NULL);
	gtk_signal_disconnect_by_func(GTK_OBJECT(gtktext),
		GTK_SIGNAL_FUNC(entry_delete_cb), NULL);
	gtk_signal_disconnect_by_func(GTK_OBJECT(gtktext), 
			GTK_SIGNAL_FUNC(button_press_intercept_cb), NULL);

	gtkspell_uncheck_all(gtktext);
}

static void sigchld(int param) {
	if (gtkspell_running() &&
		(waitpid(spell_pid, NULL, WNOHANG) == spell_pid)) {
		spell_pid = 0;
	} else {
		/* a default SIGCHLD handler.
		 * what else to do here? */
		waitpid(-1, NULL, WNOHANG);
	}
}

static void set_up_signal() {
	struct sigaction sigact;
	memset(&sigact, 0, sizeof(struct sigaction));

	sigact.sa_handler = sigchld;
	sigaction(SIGCHLD, &sigact, NULL);
}
