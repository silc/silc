/*

  silcerbasewin.hh 

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

#ifndef SILCERBASEWIN_HH
#define SILCERBASEWIN_HH

#include "silcer_gladehelper.hh"

#include "silcincludes.h"
#include "silcclient.h"

#include <sigc++/signal_system.h>
#include <sigc++/object_slot.h>
#include <sigc++/marshal.h>
#include <glade/glade-xml.h>
#include <gtk--/box.h>
#include <gtk--/button.h>
#include <gtk--/checkbutton.h>
#include <gtk--/ctree.h>
#include <gtk--/entry.h>
#include <gtk--/eventbox.h>
#include <gtk--/frame.h>
#include <gtk--/label.h>
#include <gtk--/menuitem.h>
#include <gtk--/optionmenu.h>
#include <gtk--/text.h>
#include <gtk--/widget.h>
#include <gtk--/window.h>
#include <gnome--/dialog.h>
#include <gnome--/entry.h>
#include <gnome--/pixmap.h>
#include <gnome--/pixmapmenuitem.h>

using namespace SigC;

class SilcerBaseWindow : public SigC::Object
{
public:
  SilcerBaseWindow(const char *widgetname);
  virtual ~SilcerBaseWindow();

  void show() { _thisWindow->show(); }
  void hide() { _thisWindow->hide(); }
  virtual void close(); 
  // Object extender
  virtual void set_dynamic();
  // Destruction signal
  Signal0<void, Marshal<void> > evtDestroy;

protected:
  SilcerBaseWindow();
  // FIXME: Should make this function properly copy
  SilcerBaseWindow& operator=(const SilcerBaseWindow&) { return *this;}
  SilcerBaseWindow(const SilcerBaseWindow&) {}
  
public:
  // Helper functions

  Gtk::Button *getButton(const char *name)
  { return SilcerGetWidget<Gtk::Button>(_thisGH, name); }

  Gtk::CheckButton *getCheckButton(const char *name)
  { return SilcerGetWidget<Gtk::CheckButton>(_thisGH, name); }

  Gtk::CTree *getCTree(const char *name)
  { return SilcerGetWidget<Gtk::CTree>(_thisGH, name); }

  Gtk::Entry *getEntry(const char *name)
  { return SilcerGetWidget<Gtk::Entry>(_thisGH, name); }

  Gtk::EventBox *getEventBox(const char *name)
  { return SilcerGetWidget<Gtk::EventBox>(_thisGH, name); }

  Gtk::Frame *getFrame(const char *name)
  { return SilcerGetWidget<Gtk::Frame>(_thisGH, name); }

  Gtk::HBox *getHBox(const char *name)
  { return SilcerGetWidget<Gtk::HBox>(_thisGH, name); }

  Gnome::Entry *getGEntry(const char *name)
  { return SilcerGetWidget<Gnome::Entry>(_thisGH, name); }

  Gtk::Label *getLabel(const char *name)
  { return SilcerGetWidget<Gtk::Label>(_thisGH, name); }

  Gtk::MenuItem *getMenuItem(const char *name)
  { return SilcerGetWidget<Gtk::MenuItem>(_thisGH, name); }

  Gtk::OptionMenu *getOptionMenu(const char *name)
  { return SilcerGetWidget<Gtk::OptionMenu>(_thisGH, name); }

  Gnome::Pixmap *getPixmap(const char *name)
  { return SilcerGetWidget<Gnome::Pixmap>(_thisGH, name); }

  Gtk::PixmapMenuItem *getPixmapMenuItem(const char *name)
  { return SilcerGetWidget<Gtk::PixmapMenuItem>(_thisGH, name); }

  Gtk::Text *getText(const char *name)
  { return SilcerGetWidget<Gtk::Text>(_thisGH, name); }

  Gtk::VBox *getVBox(const char *name)
  { return SilcerGetWidget<Gtk::VBox>(_thisGH, name); }

  template <class T> T *getWidget(const char *name)
  { return SilcerGetWidget<T>(_thisGH, name); }

protected:
  Gtk::Window *_thisWindow;

private:
  GladeXML *_thisGH;
};

class SilcerBaseDialog : public SilcerBaseWindow
{
public:
  SilcerBaseDialog(const char *widgetname, gboolean close_hides = false);
  virtual ~SilcerBaseDialog() {}

protected:
  Gnome::Dialog *_thisDialog;
  gboolean on_Dialog_close();
};

class SilcerBaseWidget : public SigC::Object
{
public:
  SilcerBaseWidget(const char* widgetname, const char* filename);
  virtual ~SilcerBaseWidget();
  void show() { _thisWidget->show(); }
  void hide() { _thisWidget->hide(); }
  Gtk::Widget* get_this_widget() { return _thisWidget; }
  virtual void close(); 
  // Object extender
  virtual void set_dynamic();
  // Destruction signal
  Signal0<void, Marshal<void> > evtDestroy;
protected:
  SilcerBaseWidget();
  // FIXME: Should make this function properly copy
  SilcerBaseWidget& operator=(const SilcerBaseWidget&) { return *this;}
  SilcerBaseWidget(const SilcerBaseWidget&) {}
public:
  // Helper functions

  Gtk::Button *getButton(const char *name)
  { return SilcerGetWidget<Gtk::Button>(_thisGH, name); }

  Gtk::CheckButton *getCheckButton(const char *name)
  { return SilcerGetWidget<Gtk::CheckButton>(_thisGH, name); }

  Gtk::Entry *getEntry(const char *name)
  { return SilcerGetWidget<Gtk::Entry>(_thisGH, name); }

  Gtk::Label *getLabel(const char *name)
  { return SilcerGetWidget<Gtk::Label>(_thisGH, name); }

  Gtk::MenuItem *getMenuItem(const char *name)
  { return SilcerGetWidget<Gtk::MenuItem>(_thisGH, name); }

  Gtk::OptionMenu *getOptionMenu(const char *name)
  { return SilcerGetWidget<Gtk::OptionMenu>(_thisGH, name); }

  Gtk::PixmapMenuItem *getPixmapMenuItem(const char *name)
  { return SilcerGetWidget<Gtk::PixmapMenuItem>(_thisGH, name); }

  Gtk::Text *getText(const char *name)
  { return SilcerGetWidget<Gtk::Text>(_thisGH, name); }

  template <class T> T *getWidget(const char *name)
  { return SilcerGetWidget<T>(_thisGH, name); }

protected:
  Gtk::Widget *_thisWidget;

private:
  GladeXML *_thisGH;
};

#endif /* SILCERBASEWIN_HH */
