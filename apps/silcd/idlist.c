/*

  idlist.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * $Id$
 * $Log$
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Importet from internal CVS/Added Log headers.
 *
 *
 */

#include "serverincludes.h"
#include "idlist.h"

/* Adds a new server to the list. The pointer sent as argument is allocated
   and returned. */

void silc_idlist_add_server(SilcServerList **list, 
			    char *server_name, int server_type,
			    SilcServerID *id, SilcServerList *router,
			    SilcCipher send_key, SilcCipher receive_key,
			    SilcPKCS public_key, SilcHmac hmac, 
			    SilcServerList **new_idlist)
{
  SilcServerList *last, *idlist;

  SILC_LOG_DEBUG(("Adding new server to id list"));

  idlist = silc_calloc(1, sizeof(*idlist));
  if (idlist == NULL) {
    SILC_LOG_ERROR(("Could not allocate new server list object"));
    *new_idlist = NULL;
    return;
  }

  /* Set the pointers */
  idlist->server_name = server_name;
  idlist->server_type = server_type;
  idlist->id = id;
  idlist->router = router;
  idlist->send_key = send_key;
  idlist->receive_key = receive_key;
  idlist->public_key = public_key;
  idlist->hmac = hmac;
  idlist->next = idlist;
  idlist->prev = idlist;

  /* First on the list? */
  if (!*list) {
    *list = idlist;
    *new_idlist = idlist;
    return;
  }

  /* Add it to the list */
  last = (*list)->prev;
  last->next = idlist;
  (*list)->prev = idlist;
  idlist->next = (*list);
  idlist->prev = last;

  if (new_idlist)
    *new_idlist = idlist;
}

/* Adds a new client to the client list. This is called when new client 
   connection is accepted to the server. This adds all the relevant data 
   about the client and session with it to the list. This list is 
   referenced for example when sending message to the client. */

void silc_idlist_add_client(SilcClientList **list, char *nickname,
			    char *username, char *userinfo,
			    SilcClientID *id, SilcServerList *router,
			    SilcCipher send_key, SilcCipher receive_key,
			    SilcPKCS public_key, SilcHmac hmac, 
			    SilcClientList **new_idlist)
{
  SilcClientList *last, *idlist;

  SILC_LOG_DEBUG(("Adding new client to id list"));

  idlist = silc_calloc(1, sizeof(*idlist));
  if (idlist == NULL) {
    SILC_LOG_ERROR(("Could not allocate new client list object"));
    return;
  }

  /* Set the pointers */
  idlist->nickname = nickname;
  idlist->username = username;
  idlist->userinfo = userinfo;
  idlist->id = id;
  idlist->router = router;
  idlist->send_key = send_key;
  idlist->receive_key = receive_key;
  idlist->public_key = public_key;
  idlist->hmac = hmac;
  idlist->next = idlist;
  idlist->prev = idlist;

  /* First on the list? */
  if (!(*list)) {
    *list = idlist;
    if (new_idlist)
      *new_idlist = idlist;
    return;
  }

  /* Add it to the list */
  last = (*list)->prev;
  last->next = idlist;
  (*list)->prev = idlist;
  idlist->next = *list;
  idlist->prev = last;

  if (new_idlist)
    *new_idlist = idlist;
}

/* Free client entry.  This free's everything. */

void silc_idlist_del_client(SilcClientList **list, SilcClientList *entry)
{
  if (entry) {
    if (entry->nickname)
      silc_free(entry->nickname);
    if (entry->username)
      silc_free(entry->username);
    if (entry->userinfo)
      silc_free(entry->userinfo);
    if (entry->id)
      silc_free(entry->id);
    if (entry->send_key)
      silc_cipher_free(entry->send_key);
    if (entry->receive_key)
      silc_cipher_free(entry->receive_key);
    if (entry->public_key)
      silc_pkcs_free(entry->public_key);
    if (entry->hmac)
      silc_hmac_free(entry->hmac);
    if (entry->hmac_key) {
      memset(entry->hmac_key, 0, entry->hmac_key_len);
      silc_free(entry->hmac_key);
    }

    /* Last one in list? */
    if (*list == entry && entry->next == entry) {
      *list = NULL;
      silc_free(entry);
      return;
    }

    /* At the start of list? */
    if (*list == entry && entry->next != entry) {
      *list = entry->next;
      entry->next->prev = entry->prev;
      entry->prev->next = *list;
      silc_free(entry);
      return;
    }

    /* Remove from list */
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;
    silc_free(entry);
    return;
  }
}

SilcClientList *
silc_idlist_find_client_by_nickname(SilcClientList *list,
				    char *nickname,
				    char *server)
{
  SilcClientList *first, *entry;

  SILC_LOG_DEBUG(("Finding client by nickname"));

  if (!list)
    return NULL;

  first = entry = list;
  if (!strcmp(entry->nickname, nickname)) {
    SILC_LOG_DEBUG(("Found"));
    return entry;
  }
  entry = entry->next;

  while(entry != first) {
    if (!strcmp(entry->nickname, nickname)) {
      SILC_LOG_DEBUG(("Found"));
      return entry;
    }

    entry = entry->next;
  }

  return NULL;
}

SilcClientList *
silc_idlist_find_client_by_hash(SilcClientList *list,
				char *nickname, SilcHash md5hash)
{
  SilcClientList *first, *entry;
  unsigned char hash[16];

  SILC_LOG_DEBUG(("Finding client by nickname hash"));

  if (!list)
    return NULL;

  /* Make hash of the nickname */
  silc_hash_make(md5hash, nickname, strlen(nickname), hash);

  first = entry = list;
  if (entry && !SILC_ID_COMPARE_HASH(entry->id, hash)) {
    SILC_LOG_DEBUG(("Found"));
    return entry;
  }
  entry = entry->next;

  while(entry != first) {
    if (entry && !SILC_ID_COMPARE_HASH(entry->id, hash)) {
      SILC_LOG_DEBUG(("Found"));
      return entry;
    }

    entry = entry->next;
  }

  return NULL;
}

SilcClientList *
silc_idlist_find_client_by_id(SilcClientList *list, SilcClientID *id)
{
  SilcClientList *first, *entry;

  SILC_LOG_DEBUG(("Finding client by Client ID"));

  if (!list)
    return NULL;

  first = entry = list;
  if (entry && !SILC_ID_CLIENT_COMPARE(entry->id, id)) {
    SILC_LOG_DEBUG(("Found"));
    return entry;
  }
  entry = entry->next;

  while(entry != first) {
    if (entry && !SILC_ID_CLIENT_COMPARE(entry->id, id)) {
      SILC_LOG_DEBUG(("Found"));
      return entry;
    }

    entry = entry->next;
  }

  return NULL;
}

/* Adds new channel to the list. */

void silc_idlist_add_channel(SilcChannelList **list, 
			     char *channel_name, int mode,
			     SilcChannelID *id, SilcServerList *router,
			     SilcCipher channel_key,
			     SilcChannelList **new_idlist)
{
  SilcChannelList *last, *idlist;

  SILC_LOG_DEBUG(("Adding new channel to id list"));

  idlist = silc_calloc(1, sizeof(*idlist));
  if (idlist == NULL) {
    SILC_LOG_ERROR(("Could not allocate new channel list object"));
    return;
  }

  /* Set the pointers */
  idlist->channel_name = channel_name;
  idlist->mode = mode;
  idlist->id = id;
  idlist->router = router;
  idlist->channel_key = channel_key;
  idlist->next = idlist;
  idlist->prev = idlist;

  /* First on the list? */
  if (!*list) {
    *list = idlist;
    if (new_idlist)
      *new_idlist = idlist;
    return;
  }

  /* Add it to the list */
  last = (*list)->prev;
  last->next = idlist;
  (*list)->prev = idlist;
  idlist->next = (*list);
  idlist->prev = last;

  if (new_idlist)
    *new_idlist = idlist;
}

SilcChannelList *
silc_idlist_find_channel_by_id(SilcChannelList *list, SilcChannelID *id)
{
  SilcChannelList *first, *entry;

  SILC_LOG_DEBUG(("Finding channel by Channel ID"));

  if (!list)
    return NULL;

  first = entry = list;
  if (entry && !SILC_ID_CHANNEL_COMPARE(entry->id, id)) {
    SILC_LOG_DEBUG(("Found"));
    return entry;
  }
  entry = entry->next;

  while(entry != first) {
    if (entry && !SILC_ID_CHANNEL_COMPARE(entry->id, id)) {
      SILC_LOG_DEBUG(("Found"));
      return entry;
    }

    entry = entry->next;
  }

  return NULL;
}

/* Free channel entry.  This free's everything. */

void silc_idlist_del_channel(SilcChannelList **list, SilcChannelList *entry)
{
  if (entry) {
    if (entry->channel_name)
      silc_free(entry->channel_name);
    if (entry->id)
      silc_free(entry->id);
    if (entry->topic)
      silc_free(entry->topic);
    if (entry->channel_key)
      silc_cipher_free(entry->channel_key);
    if (entry->key) {
      memset(entry->key, 0, entry->key_len);
      silc_free(entry->key);
    }
    memset(entry->iv, 0, sizeof(entry->iv));

    if (entry->user_list_count)
      silc_free(entry->user_list);

    /* Last one in list? */
    if (*list == entry && entry->next == entry) {
      *list = NULL;
      silc_free(entry);
      return;
    }

    /* At the start of list? */
    if (*list == entry && entry->next != entry) {
      *list = entry->next;
      entry->next->prev = entry->prev;
      entry->prev->next = *list;
      silc_free(entry);
      return;
    }

    /* Remove from list */
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;
    silc_free(entry);
    return;
  }
}
