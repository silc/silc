/* GtkUrl - A addon for GtkText that enables colored and clickable URLs
 * Copyright (C) 2001 Benedikt Roth <Benedikt.Roth@bratislav.de>  
 *   Based on code from 
 *   gtkspell - a spell-checking addon for GtkText
 *   Copyright (c) 2000 Evan Martin.
 * 
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

#define GTKURL_USE_GNOME

#include <gtk/gtk.h>
#ifdef GTKURL_USE_GNOME
#include <gnome.h>
#endif /* GTKURL_USE_GNOME */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "gtkurl.h"

/* FIXME? */
static GdkColor highlight = { 0, 0, 0, 255*256 };

enum {
  GTKURL_NO_URL,
  GTKURL_URL,
  GTKURL_HOST
};


static void entry_insert_cb(GtkText *gtktext, gchar *newtext, guint len, guint *ppos, gpointer d);
static void entry_delete_cb(GtkText *gtktext, gint start, gint end, gpointer d);
static gint button_press_intercept_cb(GtkText *gtktext, GdkEvent *e, gpointer d);

static void popup_menu(GtkText *gtktext, GdkEventButton *eb);
static GtkMenu *make_menu(gchar *url);

static gboolean visit_url_gnome_cb( GtkWidget *widget, gpointer *data);
static int my_poptParseArgvString(const char * s, int * argcPtr, char *** argvPtr);
static gboolean visit_url_cmd_cb( GtkWidget *widget, gpointer *data);

static gboolean check_at(GtkText *gtktext, gint from_pos);
static gchar *get_word_from_pos(GtkText* gtktext, gint pos, gint *pstart, gint *pend);
static gchar *get_curword(GtkText* gtktext, gint *pstart, gint *pend);

static void change_color(GtkText *gtktext, gint start, gint end, GdkColor *color);

static gboolean iswordsep(gchar c);
static gint is_url(gchar* word);



void gtkurl_attach(GtkText *gtktext)
{
   gtk_signal_connect(GTK_OBJECT(gtktext), "insert-text",
 		     GTK_SIGNAL_FUNC(entry_insert_cb), NULL);
   gtk_signal_connect_after(GTK_OBJECT(gtktext), "delete-text",
			    GTK_SIGNAL_FUNC(entry_delete_cb), NULL);
   gtk_signal_connect(GTK_OBJECT(gtktext), "button-press-event",
		      GTK_SIGNAL_FUNC(button_press_intercept_cb), NULL);
}


void gtkurl_detach(GtkText *gtktext)
{
  gtk_signal_disconnect_by_func(GTK_OBJECT(gtktext),
				GTK_SIGNAL_FUNC(entry_insert_cb), NULL);
  gtk_signal_disconnect_by_func(GTK_OBJECT(gtktext),
				GTK_SIGNAL_FUNC(entry_delete_cb), NULL);
  gtk_signal_disconnect_by_func(GTK_OBJECT(gtktext), 
				GTK_SIGNAL_FUNC(button_press_intercept_cb), NULL);
  
  gtkurl_uncheck_all(gtktext);
}


void gtkurl_check_all(GtkText *gtktext)
{
  guint origpos;
  guint pos = 0;
  guint len;
  float adj_value;

  len = gtk_text_get_length(gtktext);
  
  adj_value = gtktext->vadj->value;
  gtk_text_freeze(gtktext);
  origpos = gtk_editable_get_position(GTK_EDITABLE(gtktext));

  while (pos < len) 
    { 
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


void gtkurl_uncheck_all(GtkText *gtktext)
{
  gint origpos;
  gchar *text;
  gfloat adj_value;

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


static void entry_insert_cb(GtkText *gtktext, gchar *newtext, guint len, guint *ppos, gpointer d)
{
  gint origpos;

  gtk_signal_handler_block_by_func(GTK_OBJECT(gtktext),
				   GTK_SIGNAL_FUNC(entry_insert_cb), 
				   NULL );
  
  gtk_text_insert(GTK_TEXT(gtktext), NULL,
		  &(GTK_WIDGET(gtktext)->style->fg[0]), NULL, newtext, len);

  gtk_signal_handler_unblock_by_func(GTK_OBJECT(gtktext),
				     GTK_SIGNAL_FUNC(entry_insert_cb),
				     NULL);
  
  gtk_signal_emit_stop_by_name(GTK_OBJECT(gtktext), "insert-text");
  *ppos += len;

  origpos = gtk_editable_get_position(GTK_EDITABLE(gtktext));

  if (iswordsep(newtext[0])) 
    {
      /* did we just end a word? */
      if (*ppos >= 2) check_at(gtktext, *ppos-2);
      
      /* did we just split a word? */
      if (*ppos < gtk_text_get_length(gtktext))
	check_at(gtktext, *ppos+1);
    } 
  else 
    {
      /* check as they type, *except* if they're typing at the end (the most
       * common case.
       */
      if (*ppos < gtk_text_get_length(gtktext) && !iswordsep(GTK_TEXT_INDEX(gtktext, *ppos)))
	check_at(gtktext, *ppos-1);
    }

  gtk_editable_set_position(GTK_EDITABLE(gtktext), origpos);
  gtk_editable_select_region(GTK_EDITABLE(gtktext), origpos, origpos);
}


static void entry_delete_cb(GtkText *gtktext, gint start, gint end, gpointer d)
{
  gint origpos;
  
  origpos = gtk_editable_get_position(GTK_EDITABLE(gtktext));
  check_at(gtktext, start-1);
  gtk_editable_set_position(GTK_EDITABLE(gtktext), origpos);
  gtk_editable_select_region(GTK_EDITABLE(gtktext), origpos, origpos);
  /* this is to *UNDO* the selection, in case they were holding shift
   * while hitting backspace. */
}


/* ok, this is pretty wacky:
 * we need to let the right-mouse-click go through, so it moves the cursor, 
 * but we *can't* let it go through, because GtkText interprets rightclicks as
 * weird selection modifiers.
 *
 * so what do we do?  forge rightclicks as leftclicks, then popup the menu. 
 * HACK HACK HACK. 
 */
static gint button_press_intercept_cb(GtkText *gtktext, GdkEvent *e, gpointer d)
{
  GdkEventButton *eb;
  gboolean retval;
  
  if (e->type != GDK_BUTTON_PRESS) return FALSE;
  eb = (GdkEventButton*) e;

  if (eb->button != 3)
    return FALSE;

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


static void popup_menu(GtkText *gtktext, GdkEventButton *eb)
{
  gchar *buf;
  
  buf = get_curword(gtktext, NULL, NULL);
  
  gtk_menu_popup(make_menu(buf), NULL, NULL, NULL, NULL,
		 eb->button, eb->time);
}


static GtkMenu *make_menu(gchar *url)
{
  GtkWidget *menu, *item;
  gchar *caption;
  gchar *s = "http://";
  gchar *cmd;

  switch( is_url(url) )
    {
    case GTKURL_URL:
      url = g_strdup_printf("%s", url);
      break;
    case GTKURL_HOST: 
      url = g_strdup_printf("%s%s", s, url);
      break;
    }	  

  menu = gtk_menu_new(); 
  
  caption = g_strdup_printf("%s", url);
  item = gtk_menu_item_new_with_label(caption);
  g_free(caption);
  gtk_widget_set_sensitive( GTK_WIDGET(item), FALSE);
  /* I'd like to make it so this item is never selectable, like
   * the menu titles in the GNOME panel... unfortunately, the GNOME
   * panel creates their own custom widget to do this! */
  gtk_widget_show(item);
  gtk_menu_append(GTK_MENU(menu), item);
  
  item = gtk_menu_item_new();
  gtk_widget_show(item);
  gtk_menu_append(GTK_MENU(menu), item);

#ifdef GTKURL_USE_GNOME
  item = gtk_menu_item_new_with_label(_("Open with GNOME URL Handler"));
  gtk_signal_connect(GTK_OBJECT(item), "activate", 
		     GTK_SIGNAL_FUNC(visit_url_gnome_cb), g_strdup(url) );
  gtk_menu_append(GTK_MENU(menu), item);
  gtk_widget_show(item);
#endif /* GTKURL_USE_GNOME */
    
  item = gtk_menu_item_new_with_label(_("Open with Netscape (Existing)"));
  cmd = g_strdup_printf("netscape -remote 'openURL(%s)'", url);
  gtk_signal_connect(GTK_OBJECT(item), "activate",
		     GTK_SIGNAL_FUNC(visit_url_cmd_cb), g_strdup(cmd) );
  g_free(cmd);
  gtk_menu_append(GTK_MENU(menu), item);
  gtk_widget_show(item);

  item = gtk_menu_item_new_with_label(_("Open with Netscape (New Window)"));
  cmd = g_strdup_printf("netscape -remote 'openURL(%s,new-window)'", url);
  gtk_signal_connect(GTK_OBJECT(item), "activate",
		     GTK_SIGNAL_FUNC(visit_url_cmd_cb), g_strdup(cmd) );
  g_free(cmd);
  gtk_menu_append(GTK_MENU(menu), item);
  gtk_widget_show(item);

  item = gtk_menu_item_new_with_label(_("Open with Netscape (Run New)"));
  cmd = g_strdup_printf("netscape %s", url);
  gtk_signal_connect(GTK_OBJECT(item), "activate",
		     GTK_SIGNAL_FUNC(visit_url_cmd_cb), g_strdup(cmd) );
  g_free(cmd);
  gtk_menu_append(GTK_MENU(menu), item);
  gtk_widget_show(item);

  g_free(url);
  
  return GTK_MENU(menu);
}


#ifdef GTKURL_USE_GNOME
static gboolean visit_url_gnome_cb( GtkWidget *widget, gpointer *data)
{
  gnome_url_show((gchar *) data);
  g_free(data);
  return(TRUE);
}
#endif /* GTKURL_USE_GNOME */


/* this is taken from gnome-libs 1.2.4 */
#define POPT_ARGV_ARRAY_GROW_DELTA 5

static int my_poptParseArgvString(const char * s, int * argcPtr, char *** argvPtr)
{
    char * buf, * bufStart, * dst;
    const char * src;
    char quote = '\0';
    int argvAlloced = POPT_ARGV_ARRAY_GROW_DELTA;
    char ** argv = malloc(sizeof(*argv) * argvAlloced);
    const char ** argv2;
    int argc = 0;
    int i, buflen;

    buflen = strlen(s) + 1;
    bufStart = buf = alloca(buflen);
    memset(buf, '\0', buflen);

    src = s;
    argv[argc] = buf;

    while (*src) {
	if (quote == *src) {
	    quote = '\0';
	} else if (quote) {
	    if (*src == '\\') {
		src++;
		if (!*src) {
		    free(argv);
		    return 1;
		}
		if (*src != quote) *buf++ = '\\';
	    }
	    *buf++ = *src;
	} else if (isspace(*src)) {
	    if (*argv[argc]) {
		buf++, argc++;
		if (argc == argvAlloced) {
		    argvAlloced += POPT_ARGV_ARRAY_GROW_DELTA;
		    argv = realloc(argv, sizeof(*argv) * argvAlloced);
		}
		argv[argc] = buf;
	    }
	} else switch (*src) {
	  case '"':
	  case '\'':
	    quote = *src;
	    break;
	  case '\\':
	    src++;
	    if (!*src) {
		free(argv);
		return 1;
	    }
	    /* fallthrough */
	  default:
	    *buf++ = *src;
	}

	src++;
    }

    if (strlen(argv[argc])) {
	argc++, buf++;
    }

    dst = malloc((argc + 1) * sizeof(*argv) + (buf - bufStart));
    argv2 = (void *) dst;
    dst += (argc + 1) * sizeof(*argv);
    memcpy(argv2, argv, argc * sizeof(*argv));
    argv2[argc] = NULL;
    memcpy(dst, bufStart, buf - bufStart);

    for (i = 0; i < argc; i++) {
	argv2[i] = dst + (argv[i] - bufStart);
    }

    free(argv);

    *argvPtr = (char **)argv2;	/* XXX don't change the API */
    *argcPtr = argc;

    return 0;
}


static gboolean visit_url_cmd_cb( GtkWidget *widget, gpointer *data)
{
  int pid;
  char **argv;
  int argc;

  if (my_poptParseArgvString ( (const char *)data, &argc, &argv) != 0)
    return -1;

  pid = fork ();
  if (pid == -1)
    return -1;
  if (pid == 0)
    {
      execvp (argv[0], argv);
      _exit (0);
    } else
      {
	free (argv);
	return pid;
      }
  
  g_free(data);

  return(TRUE);
}


static gboolean check_at(GtkText *gtktext, gint from_pos)
{
  gint start, end;
  gchar *buf;
  
  if ( ! (buf = get_word_from_pos(gtktext, from_pos, &start, &end)) ) 
      return FALSE;
  
  if ( is_url(buf) ) 
    {
      if (highlight.pixel == 0) 
	{
	  /* add an entry for the highlight in the color map. */
	  GdkColormap *gc = gtk_widget_get_colormap(GTK_WIDGET(gtktext));
	  gdk_colormap_alloc_color(gc, &highlight, FALSE, TRUE);;
	}
      change_color(gtktext, start, end, &highlight);
      return(TRUE);
    } 
  else 
    { 
      change_color(gtktext, start, end, &(GTK_WIDGET(gtktext)->style->fg[0]));
      return(FALSE);
    }
}


static gchar *get_word_from_pos(GtkText* gtktext, gint pos, gint *pstart, gint *pend)
{
  GString *word = g_string_new("");
  gint start, end;
  gchar ch;
  
  if (iswordsep(GTK_TEXT_INDEX(gtktext, pos))) 
    return(NULL);

  /* Get start and end position from the word */
  for (start = pos; start >= 0; --start) 
    if (iswordsep(GTK_TEXT_INDEX(gtktext, start))) 
      break;
  start++;
  
  for (end = pos; end < gtk_text_get_length(gtktext); end++) 
    if (iswordsep(GTK_TEXT_INDEX(gtktext, end)) )
      break;

  /* Be sure to not include punctation marks etc. */
  for ( ;end>start; end-- )
    {
      ch = GTK_TEXT_INDEX(gtktext, end-1); 
      if( isalpha(ch) || isdigit(ch) || ch == ':' )
	break;
    }

  /* Get the word (everyting between start and end */
  for (pos = start; pos < end; pos++)
    g_string_append_c( word, GTK_TEXT_INDEX(gtktext, pos) );

  if (pstart) 
    *pstart = start;
  if (pend) 
    *pend = end;
  
  return(word->str);
}


static gchar *get_curword(GtkText* gtktext, gint *pstart, gint *pend)
{
  gint pos = gtk_editable_get_position(GTK_EDITABLE(gtktext));
  return(get_word_from_pos(gtktext, pos, pstart, pend));
}


static void change_color(GtkText *gtktext, gint start, gint end, GdkColor *color)
{
  gchar *newtext;

  /* So we don't need spaces at the very end of the text */
  if ( end == gtk_text_get_length(GTK_TEXT(gtktext))+1 )
    end--;

  newtext = gtk_editable_get_chars(GTK_EDITABLE(gtktext), start, end);
    
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


static gboolean iswordsep(gchar c)
{
/* 	return !isalpha(c) && c != '\''; */
  return( isspace(c) );
}


static gint is_url(gchar* word)
{
     gint len;
     if (!word)
	  return GTKURL_NO_URL;

   len = strlen (word);

   if (!strncasecmp (word, "irc://", 6))
      return GTKURL_URL;

   if (!strncasecmp (word, "irc.", 4))
      return GTKURL_URL;

   if (!strncasecmp (word, "ftp.", 4))
      return GTKURL_URL;

   if (!strncasecmp (word, "ftp:", 4))
      return GTKURL_URL;

   if (!strncasecmp (word, "www.", 4))
      return GTKURL_URL;

   if (!strncasecmp (word, "http:", 5))
      return GTKURL_URL;

   if (!strncasecmp (word, "https:", 6))
      return GTKURL_URL;

   if (!strncasecmp (word + len - 4, ".org", 4))
      return GTKURL_HOST;

   if (!strncasecmp (word + len - 4, ".net", 4))
      return GTKURL_HOST;

   if (!strncasecmp (word + len - 4, ".com", 4))
      return GTKURL_HOST;

   if (!strncasecmp (word + len - 4, ".edu", 4))
      return GTKURL_HOST;

   return GTKURL_NO_URL;
}
