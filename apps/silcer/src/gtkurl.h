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

#ifndef __GTKSPELL_h__
#define __GTKSPELL_h__

BEGIN_GNOME_DECLS

#define GTKURL_VERSION "0.1"

/* Attach GtkURL to a GtkText Widget.
 * This enables URL-checking as you type and the popup menu.
 *
 * Arguments:
 *  - "text" is the widget to which GtkURL should attach.
 *
 * Example:
 *  GtkWidget *text;
 *  text = gtk_text_new(NULL, NULL); 
 *  gtk_text_set_editable(GTK_TEXT(text), TRUE);
 *  gtkurl_attach(GTK_TEXT(text));
 */  
void gtkurl_attach(GtkText *text);


/* Detach GtkUrl from a GtkText widget.
 * 
 * Arguments:
 *  - "text" is the widget from which GtkUrl should detach.
 */ 
void gtkurl_detach(GtkText *text);


/* Highlight all urls
 * Note that the popup menu will not work unless you gtkurl_attach().
 *
 * Arguments:
 *  - "text" is the widget to check.
 */
void gtkurl_check_all(GtkText *text);

/* Remove all of the highlighting from the widget.
 *
 * Arguments:
 *  - "text" is the widget to check.
 */
void gtkurl_uncheck_all(GtkText *gtktext);

END_GNOME_DECLS

#endif /* __GTKURL_H__ */
