/* gtkspell - a spell-checking addon for GtkText
 * Copyright (c) 2000 Evan Martin.
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

#ifndef __gtkspell_h__
#define __gtkspell_h__

BEGIN_GNOME_DECLS

/* PLEASE NOTE that this API is unstable and subject to change. */
#define GTKSPELL_VERSION "0.3.2"

extern int gtkspell_start(char *path, char *args[]);
/* Spawns the spell checking program.
 *
 * Arguments:
 *  - "path" should be the full path to the spell checking program, or NULL
 *    if you want to search the PATH for args[0].
 *  - "args" should be a array of arguments to the spell checking program.
 *    The first element should be the name of the program.
 *    You should give the argument to run the spell checking program in the
 *    "embedded" mode.  for ispell, this is "-a".
 *    The last element should be NULL.
 * Return:
 *  0 on success, and -1 on error.
 *
 * Example:
 *  char *args[] = { "ispell", "-a", NULL };
 *  if (gtkspell_start(NULL, args) < 0) {
 *  	fprintf(stderr, "Unable to start GtkSpell.\n");
 *  	return -1;
 *  }
 *
 */


extern void gtkspell_stop();
/* Stop the spellchecking program.
 * This kills the spell checker's process and frees memory.
 */

extern int gtkspell_running();
/* Is gtkspell running?
 *
 * Return:
 * 	nonzero if it running
 * 	zero if is not running
 *
 * Example:
 *  if (gtkspell_running())
 *  	printf("gtkspell is running.\n");
 */

extern void gtkspell_attach(GtkText *text);
/* Attach GtkSpell to a GtkText Widget.
 * This enables checking as you type and the popup menu.
 *
 * Arguments:
 *  - "text" is the widget to which GtkSpell should attach.
 *
 * Example:
 *  GtkWidget *text;
 *  text = gtk_text_new(NULL, NULL); 
 *  gtk_text_set_editable(GTK_TEXT(text), TRUE);
 *  gtkspell_attach(GTK_TEXT(text));
 */  

void gtkspell_detach(GtkText *gtktext);
/* Detach GtkSpell from a GtkText widget.
 * 
 * Arguments:
 *  - "text" is the widget from which GtkSpell should detach.
 * 
 */ 

void gtkspell_check_all(GtkText *gtktext);
/* Check and highlight the misspelled words.
 * Note that the popup menu will not work unless you gtkspell_attach().
 *
 * Arguments:
 *  - "text" is the widget to check.
 */

void gtkspell_uncheck_all(GtkText *gtktext);
/* Remove all of the highlighting from the widget.
 *
 * Arguments:
 *  - "text" is the widget to check.
 */

END_GNOME_DECLS

#endif /* __gtkspell_h__ */
