/*

  SilcerMainDlg.hh

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCERMAINDLG_HH
#define SILCERMAINDLG_HH

#include "silcerbasewin.hh"
#include "silcerchatview.hh"
#include <gnome--/color-picker.h>
#include <gtk--/spinbutton.h>
#include <gtk--/notebook.h>
#include <gtk--/text.h>

class SilcerMainDlg : public SilcerBaseDialog
{
public:
  SilcerMainDlg(void);
  ~SilcerMainDlg(void);

  // Print message to output box
  void print(const string message);
  void print(const string message, const string nickname);

protected:
  // Events
  gint InputBoxKeyPress(GdkEventKey *key);

private:
  SilcerChatView *_ChatView;
  GCompletion *_Completer;
  Gtk::HBox *_OutputBox;
  Gtk::Text *_InputBox;
  Gtk::Notebook *_Tab;
};

#endif /* SILCERMAINDLG */
