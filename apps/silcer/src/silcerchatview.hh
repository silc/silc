/*

  silcerchatview.hh 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  Code is mostly ripped from Gabber, thus code also copyrighted by:
  Copyright (C) 1999-2001 Dave Smith & Julian Missig
*/

#ifndef SILCERCHATVIEW_HH
#define SILCERCHATVIEW_HH

extern "C" {
#include "xtext.h"
}

#include <gtk/gtkframe.h>
#include <gtk/gtkvscrollbar.h>
#include <gtk--/container.h>
#include <gtk--/paned.h>
#include <gtk--/widget.h>

typedef const string COLOR_T;

COLOR_T BLACK       = "\0030";
COLOR_T WHITE       = "\0031";
COLOR_T BLUE        = "\0032";
COLOR_T GREEN       = "\0033";
COLOR_T RED         = "\0034";
COLOR_T YELLOWBROWN = "\0035";
COLOR_T PURPLE      = "\0036";
COLOR_T ORANGE      = "\0037";
COLOR_T YELLOW      = "\0038";
COLOR_T GREEN2      = "\0039";
COLOR_T AQUA        = "\00310";
COLOR_T LIGHTAQUA   = "\00311";
COLOR_T BLUE2       = "\00312";
COLOR_T PINK        = "\00313";
COLOR_T GREY        = "\00314";
COLOR_T LIGHTGREY   = "\00315";
COLOR_T BLUEMARKBACK= "\00316";
COLOR_T WHITEMARKFORE= "\00317";
COLOR_T WHITEFORE   = "\00318";
COLOR_T BLACKBACK   = "\00319";


class SilcerChatView
{
public:
  SilcerChatView(Gtk::Widget *owner, Gtk::Container *parent, 
		 gboolean indent = true);
  SilcerChatView(Gtk::Widget *owner, Gtk::Paned *parent, 
		 gboolean indent = true);
  ~SilcerChatView();
  void render(const string &message, const string &username, 
	      const string &timestamp, COLOR_T &delimiter_color);
  void render_error(const string &message, const string &error, 
		    const string &timestamp, COLOR_T &delimiter_color);
  void clearbuffer();
  string get_chars();
  GtkXText *_xtext;
  GtkFrame *_frmChat;
  GtkVScrollbar *_vsChat;

 protected:
  void print(const string &s);
  void print(const string &left, const string &right);
  void on_word_clicked(char* word, GdkEventButton *evt);
  static void _on_word_clicked_stub(GtkXText *xtext, char *word, 
				    GdkEventButton *evt, 
				    SilcerChatView *_this);
};

#endif /* SILCERCHATVIEW_HH */
