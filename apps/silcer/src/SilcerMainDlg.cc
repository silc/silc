/*

  SilcerMainDlg.cc 

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

#include "silcerapp.hh"
#include "silcerchatview.hh"
#include "SilcerMainDlg.hh"
#include "gtkspell.h"

#include <libgnomeui/gnome-window-icon.h>   
#include <libgnome/gnome-help.h>
#include <gtk--/style.h>
#include <gnome--/href.h>
#include <gtk--/text.h>
#include <gtk--/toolbar.h>
#include <gtk--/notebook.h>

static char *parse_command(const char *buffer)
{
  char *ret;
  char *cp = (char *)buffer;
  int len;

  len = strcspn((const char *)cp, " ");
  ret = silc_to_upper(cp + 1);
  ret[len - 1] = 0;
  return ret;
}

SilcerMainDlg::SilcerMainDlg(void) : SilcerBaseDialog("SilcerMainDlg")
{
  _thisWindow->realize();

  // Get intput box and set it for input
  _InputBox = getWidget<Gtk::Text>("SilcerMainDlgInputBox");
  _InputBox->key_press_event.connect(slot(this,
					  &SilcerMainDlg::InputBoxKeyPress));
  _Completer = g_completion_new(NULL);

  // Get output box and create new chat view box
  _OutputBox = getWidget<Gtk::HBox>("SilcerMainDlgOutputBox");
  _ChatView = new SilcerChatView(_thisWindow, _OutputBox, false);

  // Show only icons on toolbar
  getWidget<Gtk::Toolbar>("SilcerMainDlgToolbar")->
    set_style(GTK_TOOLBAR_ICONS);

  // Hide tabs, since they are not used currently!
  getWidget<Gtk::Notebook>("SilcerMainDlgTab")->set_show_tabs(false);

  _thisWindow->show();
}

SilcerMainDlg::~SilcerMainDlg(void)
{

}

void SilcerMainDlg::print(const string message)
{
  _ChatView->render(message, "", "", BLUE);
}

void SilcerMainDlg::print(const string message, const string nickname)
{
  _ChatView->render(message, nickname, "", BLUE2);
}

gint SilcerMainDlg::InputBoxKeyPress(GdkEventKey *key)
{
  string msg;

  switch (key->keyval) {
  case GDK_space:
    if (gtkspell_running())
      gtkspell_check_all(_InputBox->gtkobj());
    break;

  case GDK_Return:
  case GDK_KP_Enter:
    if (key->state & GDK_SHIFT_MASK) {
      key->state ^= GDK_SHIFT_MASK;
      return 0;
    }

    // Parse message to see whether it is command
    msg = _InputBox->get_chars(0, -1);
    if (msg.empty()) {
      _InputBox->delete_text(0, -1);
      gtk_signal_emit_stop_by_name(GTK_OBJECT(_InputBox->gtkobj()), 
				   "key_press_event");
      break;
    }

    if (msg.at(0) == '/') {
      // Command
      SilcClientCommand *cmd;
      SilcClientCommandContext ctx;
      char *tmpcmd;
      uint32 argc = 0;
      unsigned char **argv;
      uint32 *argv_lens, *argv_types;

      // Parse arguments
      tmpcmd = parse_command(msg.c_str());
      cmd = silc_client_command_find((const char *)tmpcmd);
      silc_free(tmpcmd);
      if (cmd == NULL)
	break;

      silc_parse_command_line((unsigned char *)msg.c_str(), &argv, &argv_lens,
			      &argv_types, &argc, cmd->max_args);

      ctx = silc_client_command_alloc();
      ctx->client = silc_client;
      ctx->conn = silc_client_conn;
      ctx->command = cmd;
      ctx->argc = argc;
      ctx->argv = argv;
      ctx->argv_lens = argv_lens;
      ctx->argv_types = argv_types;
      
      // Execute the command
      (*cmd->cb)(ctx, NULL);
    } else {
      // Channel message
      if (silc_client_conn->current_channel) {
	print(msg);
	silc_client_send_channel_message(silc_client, 
					 silc_client_conn,
					 silc_client_conn->current_channel, 
					 NULL,
					 0, (unsigned char *)msg.c_str(), 
					 msg.length(), TRUE);
      }
    }

    _InputBox->delete_text(0, -1);
    gtk_signal_emit_stop_by_name(GTK_OBJECT(_InputBox->gtkobj()), 
				 "key_press_event");
    break;

  case GDK_Tab:
    {
      // Word completion
      msg = _InputBox->get_chars(0, -1);

      if (!msg.empty()) {
	string lastword;

	// Search for the last whitespace
	string::size_type n = msg.find_last_of(" ");
	if (n != string::npos)
	  lastword = msg.substr(n+1);
	else
	  lastword = msg;
	
	// Try and autocomplete
	gchar *prefix;
	g_completion_complete(_Completer, (char*)lastword.c_str(), &prefix);
	if (prefix != NULL){
	  // Replace the last word in the message and update
	  if (n != string::npos)
	    msg.replace(msg.find_last_of(" ")+1, msg.length(), prefix);
	  else
	    msg = string(prefix);
	  g_free(prefix);
	  
	  // Update text
	  _InputBox->delete_text(0, -1);
	  _InputBox->insert(msg);
	}

	gtk_signal_emit_stop_by_name(GTK_OBJECT(_InputBox->gtkobj()), 
				     "key_press_event");
	return 1;
      }
    }
    break;

  default:
    break;
  }

  return 0;
}
