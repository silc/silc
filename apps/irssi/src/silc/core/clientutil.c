/*
 clientutil.c : irssi

    Copyright (C) 2000 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"

#include "silc-servers.h"

/* Verifies received public key. If user decides to trust the key it is
   saved as trusted server key for later use. If user does not trust the
   key this returns FALSE. */

int silc_client_verify_server_key(SILC_SERVER_REC *server,
				  unsigned char *pk, unsigned int pk_len,
				  SilcSKEPKType pk_type)
{
  char filename[256];
  char file[256];
  char *hostname, *fingerprint;
  struct stat st;

  hostname = server->connrec->address;

  if (pk_type != SILC_SKE_PK_TYPE_SILC) {
    //silc_say(client, "We don't support server %s key type", hostname);
    return FALSE;
  }

  memset(filename, 0, sizeof(filename));
  memset(file, 0, sizeof(file));
  snprintf(file, sizeof(file) - 1, "serverkey_%s_%d.pub", hostname,
	   server->connrec->port);
  snprintf(filename, sizeof(filename) - 1, "%s/.silc/serverkeys/%s", 
	   g_get_home_dir(), file);

  /* Check wheter this key already exists */
  if (stat(filename, &st) < 0) {

    fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
    /*silc_say(client, "Received server %s public key", hostname);
    silc_say(client, "Fingerprint for the server %s key is", hostname);
    silc_say(client, "%s", fingerprint);*/
    silc_free(fingerprint);

    /* Ask user to verify the key and save it */
    /*if (silc_client_ask_yes_no(client,
       "Would you like to accept the key (y/n)? "))*/
      {
	/* Save the key for future checking */
	silc_pkcs_save_public_key_data(filename, pk, pk_len, 
				       SILC_PKCS_FILE_PEM);
	return TRUE;
      }
  } else {
    /* The key already exists, verify it. */
    SilcPublicKey public_key;
    unsigned char *encpk;
    unsigned int encpk_len;

    /* Load the key file */
    if (!silc_pkcs_load_public_key(filename, &public_key, 
				   SILC_PKCS_FILE_PEM))
      if (!silc_pkcs_load_public_key(filename, &public_key, 
				     SILC_PKCS_FILE_BIN)) {
	fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
	/*silc_say(client, "Received server %s public key", hostname);
	silc_say(client, "Fingerprint for the server %s key is", hostname);
	silc_say(client, "%s", fingerprint);*/
	silc_free(fingerprint);
	/*silc_say(client, "Could not load your local copy of the server %s key",
		 hostname);
	if (silc_client_ask_yes_no(client, 
	   "Would you like to accept the key anyway (y/n)? "))*/
	  {
	    /* Save the key for future checking */
	    unlink(filename);
	    silc_pkcs_save_public_key_data(filename, pk, pk_len,
					   SILC_PKCS_FILE_PEM);
	    return TRUE;
	  }
	
	return FALSE;
      }
  
    /* Encode the key data */
    encpk = silc_pkcs_public_key_encode(public_key, &encpk_len);
    if (!encpk) {
      fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
      /*silc_say(client, "Received server %s public key", hostname);
      silc_say(client, "Fingerprint for the server %s key is", hostname);
      silc_say(client, "%s", fingerprint);*/
      silc_free(fingerprint);
      /*silc_say(client, "Your local copy of the server %s key is malformed",
	       hostname);
      if (silc_client_ask_yes_no(client,
         "Would you like to accept the key anyway (y/n)? "))*/
	{
	  /* Save the key for future checking */
	  unlink(filename);
	  silc_pkcs_save_public_key_data(filename, pk, pk_len,
					 SILC_PKCS_FILE_PEM);
	  return TRUE;
	}

      return FALSE;
    }

    if (memcmp(encpk, pk, encpk_len)) {
      fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
      /*silc_say(client, "Received server %s public key", hostname);
      silc_say(client, "Fingerprint for the server %s key is", hostname);
      silc_say(client, "%s", fingerprint);*/
      silc_free(fingerprint);
      /*silc_say(client, "Server %s key does not match with your local copy",
	       hostname);
      silc_say(client, "It is possible that the key has expired or changed");
      silc_say(client, "It is also possible that some one is performing "
	               "man-in-the-middle attack");*/
      
      /* Ask user to verify the key and save it */
      /*if (silc_client_ask_yes_no(client,
         "Would you like to accept the key anyway (y/n)? "))*/
	{
	  /* Save the key for future checking */
	  unlink(filename);
	  silc_pkcs_save_public_key_data(filename, pk, pk_len,
					 SILC_PKCS_FILE_PEM);
	  return TRUE;
	}

      //silc_say(client, "Will not accept server %s key", hostname);
      return FALSE;
    }

    /* Local copy matched */
    return TRUE;
  }

  //silc_say(client, "Will not accept server %s key", hostname);
  return FALSE;
}
