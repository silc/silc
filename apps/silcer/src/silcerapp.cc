/*

  silcerapp.cc 

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
#include "gtkspell.h"

#include <sys/utsname.h>
#include <glade/glade.h>
#include <libgnome/gnome-triggers.h>
#include <libgnome/gnome-util.h>
#include <libgnomeui/gnome-window-icon.h>
#include <gnome--/client.h>

#include "silcversion.h"

// Pointer to the application
SilcerApp *Silcer_App;
string package = "silcer";
string version = "1.0";

SilcClient silc_client;
SilcClientConnection silc_client_conn;

static int 
silc_create_key_pair(char *pkcs_name, int bits, char *path,
		     char *identifier, 
		     SilcPublicKey *ret_pub_key,
		     SilcPrivateKey *ret_prv_key)
{
  SilcPKCS pkcs;
  SilcPublicKey pub_key;
  SilcPrivateKey prv_key;
  SilcRng rng;
  unsigned char *key;
  SilcUInt32 key_len;
  char pkfile[256], prvfile[256];

  if (!pkcs_name || !path)
    return FALSE;

  if (!bits)
    bits = 1024;

  rng = silc_rng_alloc();
  silc_rng_init(rng);
  silc_rng_global_init(rng);

  /* Generate keys */
  silc_pkcs_alloc((const unsigned char *)pkcs_name, &pkcs);
  pkcs->pkcs->init(pkcs->context, bits, rng);

  /* Save public key into file */
  key = silc_pkcs_get_public_key(pkcs, &key_len);
  pub_key = silc_pkcs_public_key_alloc(pkcs->pkcs->name, identifier,
                                       key, key_len);
  *ret_pub_key = pub_key;

  memset(key, 0, sizeof(key_len));
  silc_free(key);

  /* Save private key into file */
  key = silc_pkcs_get_private_key(pkcs, &key_len);
  prv_key = silc_pkcs_private_key_alloc(pkcs->pkcs->name, key, key_len);
  *ret_prv_key = prv_key;

  memset(key, 0, sizeof(key_len));
  silc_free(key);

  silc_rng_free(rng);
  silc_pkcs_free(pkcs);

  return TRUE;
}

static
void silc_op_say(SilcClient client, SilcClientConnection conn, 
                 SilcClientMessageType type, char *msg, ...)
{
  va_list va;
  char *str;

  va_start(va, msg);
  str = g_strdup_vprintf(msg, va);
  Silcer_App->_MainDialog->print((string)str);
  g_free(str);
  va_end(va);
}

static
void silc_channel_message(SilcClient client, SilcClientConnection conn, 
			  SilcClientEntry sender, SilcChannelEntry channel, 
			  SilcMessageFlags flags, char *msg)
{
  Silcer_App->_MainDialog->print((string)msg, (string)sender->nickname);
}

static
void silc_private_message(SilcClient client, SilcClientConnection conn,
			  SilcClientEntry sender, SilcMessageFlags flags,
			  char *msg)
{
  Silcer_App->_MainDialog->print((string)msg);
}

static
void silc_notify(SilcClient client, SilcClientConnection conn, 
		 SilcNotifyType type, ...)
{
  va_list va;
  
  va_start(va, type);
  Silcer_App->_MainDialog->print((string)va_arg(va, char *));
  va_end(va);
}

static
void silc_connect(SilcClient client, SilcClientConnection conn, int success)
{
  silc_client_conn = conn;
}

static
void silc_disconnect(SilcClient client, SilcClientConnection conn)
{
  silc_client_conn = NULL;
}

static
void silc_auth_meth(SilcClient client, 
		    SilcClientConnection conn,
		    char *hostname, SilcUInt16 port,
		    SilcGetAuthMeth completion, void *context)
{
  completion(TRUE, SILC_AUTH_NONE, NULL, 0, context);
}

static
void silc_verify_public_key(SilcClient client, SilcClientConnection conn,
			    SilcSocketType conn_type, unsigned char *pk, 
			    SilcUInt32 pk_len, SilcSKEPKType pk_type,
			    SilcVerifyPublicKey completion, void *context)
{
  completion(TRUE, context);
}

static
void silc_command(SilcClient client, SilcClientConnection conn, 
		  SilcClientCommandContext cmd_context, int success,
		  SilcCommand command)
{

}

static
void silc_command_reply(SilcClient client, SilcClientConnection conn,
			SilcCommandPayload cmd_payload, int success,
			SilcCommand command, SilcCommandStatus status, ...)
{

}

/* SILC client operations */
SilcClientOperations ops = {
  silc_op_say,
  silc_channel_message,
  silc_private_message,
  silc_notify,
  silc_command,
  silc_command_reply,
  silc_connect,
  silc_disconnect,
  silc_auth_meth,
  silc_verify_public_key,
  NULL,
  NULL,
  NULL,
  NULL
};

SILC_TASK_CALLBACK(connect_client)
{
  SilcClient client = (SilcClient)context;
  silc_client_connect_to_server(client, 706, "silc.silcnet.org", NULL);
}

SilcerApp::SilcerApp(int argc, char **argv)
  : _GnomeApp(package, version, argc, argv),
  _gclient(Gnome::Client::master_client())
{
  // Save application pointer
  Silcer_App = this;

  // Initialize SILC stuff
  silc_debug = TRUE;
  silc_debug_hexdump = TRUE;
  silc_log_set_debug_string("*client*,*net*,*ske*");

  // Initialize SILC Client Library */
  silc_client = silc_client_alloc(&ops, NULL, NULL, "SILC-1.0-0.6.2");
  silc_client->realname = "Foo T. Bar";
  silc_client->username = "foobar";
  silc_client->hostname = "foo.bar.foobar.com";
  silc_cipher_register_default();
  silc_pkcs_register_default();
  silc_hash_register_default();
  silc_hmac_register_default();

  // XXXXX
  // In real application at this point it would be of course checked 
  // whether ~/.silc direectory or something exists and key pair exists.
  // If not then some firstsetup-wizard would be lauched that creates
  // the keypair.  In our example we'll always create a key pair. :(
  silc_create_key_pair("rsa", 1024, "kk", "UN=foobar, "
		       "HN=foo.bar.foobar.com", 
		       &silc_client->public_key, &silc_client->private_key);

  // We are ready to initialize the SILC Client library.
  silc_client_init(silc_client);

  // Setup SILC scheduler as timeout task. This will handle the SILC
  // client library every 50 milliseconds.  It will actually make the
  // SILC client work on background.
  Gnome::Main::timeout.connect(slot(this, &SilcerApp::silc_scheduler), 50);

  // XXXXX
  // This is now used to directly connect to silc.silcnet.org router
  // XXXXX
  silc_schedule_task_add(silc_client->schedule, 0, connect_client, 
			 silc_client, 0, 1, SILC_TASK_TIMEOUT, 
			 SILC_TASK_PRI_NORMAL); 

   // Initialize glade
  glade_gnome_init();

  // Locate glade files
  if (!g_file_exists(string(_SourceDir + "SilcerMainDlg.glade").c_str()))
    _SourceDir = "./";
  if (!g_file_exists(string(_SourceDir + "SilcerMainDlg.glade").c_str()))
    _SourceDir = "./ui/";
  if (!g_file_exists(string(_SourceDir + "SilcerMainDlg.glade").c_str()))
    _SourceDir = "./src/";
  if (!g_file_exists(string(_SourceDir + "SilcerMainDlg.glade").c_str())) {
    g_error("Could not find SilcerMainDlg.glade");
    exit(-1);
  }

  _MainDialog = new SilcerMainDlg();
}

SilcerApp::~SilcerApp()
{
  delete _MainDialog;
}

void SilcerApp::run()
{
  // Let the gnome app start processing messages
  Gnome::Main::run();
}

void SilcerApp::quit()
{
  // Stop gtk/gnome message loop
  Gnome::Main::quit();
  delete Silcer_App;
}

GladeXML *SilcerApp::load_resource(const char *name)
{
  return glade_xml_new(string(_SourceDir + name + ".glade").c_str(), name);
}

GladeXML *SilcerApp::load_resource(const char *name, const char *filename)
{
  return glade_xml_new(string(_SourceDir + filename + ".glade").c_str(), name);
}

gint SilcerApp::silc_scheduler()
{
  // Run the SILC client once, and return immediately.  This function
  // is called every 50 milliseconds by the Gnome main loop, to process
  // SILC stuff.  This function will read data, and write data to network,
  // etc.  Makes the client library tick! :)
  silc_client_run_one(silc_client);
  return 1;
}
