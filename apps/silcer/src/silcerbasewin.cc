/*

  silcerbasewin.cc 

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

#include "silcerbasewin.hh"
#include "silcerapp.hh"

SilcerBaseWindow::SilcerBaseWindow(const char *widgetname)
{ 
  _thisGH = Silcer_App->load_resource(widgetname); 
  _thisWindow = SilcerGetWidget<Gtk::Window>(_thisGH, widgetname);
  reference();
}

void SilcerBaseWindow::set_dynamic()
{
  SigC::Object::set_dynamic();
  set_sink();
}

void SilcerBaseWindow::close()
{
  unreference();
}

SilcerBaseWindow::~SilcerBaseWindow()
{
  evtDestroy();
  _thisWindow->destroy();
  gtk_object_unref(GTK_OBJECT(_thisGH));
}

SilcerBaseDialog::SilcerBaseDialog(const char *widgetname, 
				   gboolean close_hides)
  : SilcerBaseWindow(widgetname)
{
  _thisDialog = static_cast<Gnome::Dialog*>(_thisWindow);
  _thisDialog->close_hides(close_hides);
  if (!close_hides)
    _thisDialog->close.connect(slot(this, &SilcerBaseDialog::on_Dialog_close));
}

gboolean SilcerBaseDialog::on_Dialog_close()
{
  _thisWindow->destroy();
  return true;
}

SilcerBaseWidget::SilcerBaseWidget(const char *widgetname, 
				   const char* filename)
{ 
  _thisGH = Silcer_App->load_resource(widgetname, filename); 
  _thisWidget = SilcerGetWidget<Gtk::Widget>(_thisGH, widgetname);
  reference();
}

void SilcerBaseWidget::set_dynamic()
{
  SigC::Object::set_dynamic();
  set_sink();
}

void SilcerBaseWidget::close()
{
  unreference();
}

SilcerBaseWidget::~SilcerBaseWidget()
{
  evtDestroy();
  _thisWidget->destroy();
  gtk_object_unref(GTK_OBJECT(_thisGH));
}
