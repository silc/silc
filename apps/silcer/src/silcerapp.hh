/*

  silcerapp.hh 

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

#ifndef SILCERAPP_HH
#define SILCERAPP_HH

#include "SilcerMainDlg.hh"
#include "silcer_gladehelper.hh"

extern "C" {
#include "silcincludes.h"
#include "clientlibincludes.h"
}

#include <fstream>
#include <glade/glade-xml.h>
#include <sigc++/object_slot.h>
#include <gnome--/client.h>
#include <gnome--/main.h>

// Forward declarations
class SilcerApp;

// Global pointer for the application
extern SilcerApp *Silcer_App;

// Global pointer to the SILC Client Library object
extern SilcClient silc_client;
extern SilcClientConnection silc_client_conn;

// Silcer class
class SilcerApp : public SigC::Object
{
public:
  SilcerApp(int argc, char **argv);
  ~SilcerApp();

  SilcerMainDlg *_MainDialog;

  void run();
  void quit();
  GladeXML* load_resource(const char *name);
  GladeXML* load_resource(const char *name, const char *filename);

protected:
  gint silc_scheduler();

private:
  Gnome::Main _GnomeApp;
  Gnome::Client *_gclient;
  string _SourceDir;
  string _pix_path;
};

#endif /* SILCERAPP_HH */
