/*

  silcer_gladehelper.hh 

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

#ifndef SILCER_GLADEHELPER_HH
#define SILCER_GLADEHELPER_HH

#include <glade/glade-xml.h>
#include <gtk/gtkobject.h>
#include <gtk--/base.h>

template<class T> T *SilcerGetWidget(GladeXML* obj, const char *name)
{
  T *widget = 
    static_cast<T *>(Gtk::wrap_auto((GtkObject *)
				    glade_xml_get_widget(obj, name)));
  if (!widget)
    g_error("Could not find widget `%s'", name);
  return widget;
}

#endif /* SILCER_GLADEHELPER_HH */
