/*

  silcer.cc 

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

#include <fstream>
#include <glade/glade-xml.h>
#include <sigc++/object_slot.h>
#include <gnome--/client.h>
#include <gnome--/main.h>
#include <libgnome/gnome-i18n.h>
#include "silcerapp.hh"

int main (int argc, char** argv)
{
#ifdef ENABLE_LNS
  // Load translation
  bindtextdomain(ConfigManager::get_PACKAGE(), GNOMELOCALEDIR);
  textdomain(ConfigManager::get_PACKAGE());
#endif
  
  new SilcerApp(argc, argv);
  Silcer_App->run();

  return 0;
}
