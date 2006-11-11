/*

  silcclient_entry.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCCLIENT_ENTRY_H
#define SILCCLIENT_ENTRY_H

#ifndef SILCCLIENT_H
#error "Do not include this header directly, include silcclient.h instead"
#endif

/****s* silcclient/SilcClientAPI/SilcClientEntry
 *
 * NAME
 *
 *    typedef struct SilcClientEntryStruct { ... } *SilcClientEntry;
 *
 * DESCRIPTION
 *
 *    This structure represents a client or a user in the SILC network.
 *    The local user has this structure also and it can be accessed from
 *    SilcClientConnection structure.  All other users in the SILC network
 *    that are accessed using the Client Library routines will have their
 *    own SilcClientEntry structure.  For example, when finding users by
 *    their nickname the Client Library returns this structure back to
 *    the application.  All strings in the structure are UTF-8 encoded.
 *
 *    Application may store its own pointer into the context pointer in
 *    this structure.
 *
 * NOTES
 *
 *    If application wants to store nickname or any of the other strings
 *    it should always duplicated them.
 *
 *    None of the string arrays are set if the first character is '\0'.
 *    All string arrays are always NULL terminated.
 *
 *    If application stores the SilcClientEntry it must always take
 *    a reference of it by calling silc_client_ref_client function.  The
 *    reference must be released after it is not needed anymore by calling
 *    silc_client_unref_client function.
 *
 * SOURCE
 */
struct SilcClientEntryStruct {
  char nickname[128 + 1];	     /* Nickname */
  char username[128 + 1];	     /* Username */
  char hostname[256 + 1];	     /* Hostname */
  char server  [256 + 1];	     /* SILC server name */
  char *realname;		     /* Realname (userinfo) */
  char *nickname_normalized;	     /* Normalized nickname */

  SilcClientID id;		     /* The Client ID */
  SilcUInt32 mode;	             /* User mode in SILC, see SilcUserMode */
  SilcPublicKey public_key;	     /* User's public key, may be NULL */
  SilcHashTable channels;	     /* Channels client has joined */
  SilcDList attrs;	             /* Requested Attributes (maybe NULL) */
  unsigned char fingerprint[20];     /* SHA-1 fingerprint of the public key */

  void *context;		     /* Application specific context */
  SilcClientEntryInternal internal;
};
/***/

/****s* silcclient/SilcClientAPI/SilcChannelEntry
 *
 * NAME
 *
 *    typedef struct SilcChannelEntryStruct { ... } *SilcChannelEntry;
 *
 * DESCRIPTION
 *
 *    This structure represents a channel in the SILC network.  All
 *    channels that the client are aware of or have joined in will be
 *    represented as SilcChannelEntry.  The structure includes information
 *    about the channel.  All strings in the structure are UTF-8 encoded.
 *
 * SOURCE
 */
struct SilcChannelEntryStruct {
  /* General information */
  char *channel_name;		             /* Channel name */
  SilcChannelID *id;			     /* Channel ID */
  SilcUInt32 mode;			     /* Channel mode, ChannelModes. */
  char *topic;				     /* Current topic, may be NULL */
  SilcPublicKey founder_key;		     /* Founder key, may be NULL */
  SilcUInt32 user_limit;		     /* User limit on channel */

  /* All clients that has joined this channel.  The key to the table is the
     SilcClientEntry and the context is SilcChannelUser context. */
  SilcHashTable user_list;

  /* Channel keys */
  SilcCipher channel_key;                    /* The channel key */
  unsigned char *key;			     /* Raw key data */
  SilcUInt32 key_len;		             /* Raw key data length */
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE]; /* Current IV */
  SilcHmac hmac;			     /* Current HMAC */

  /* Channel private keys */
  SilcDList private_keys;		     /* List of private keys or NULL */
  SilcChannelPrivateKey curr_key;	     /* Current private key */

  /* SilcChannelEntry status information */
  SilcDList old_channel_keys;
  SilcDList old_hmacs;
  SilcUInt16 resolve_cmd_ident;		     /* Command identifier when
						resolving this entry */

  /* Application specific data.  Application may set here whatever it wants. */
  void *context;
};
/***/

/****s* silcclient/SilcClientAPI/SilcServerEntry
 *
 * NAME
 *
 *    typedef struct SilcServerEntryStruct { ... } *SilcServerEntry
 *
 * DESCRIPTION
 *
 *    This structure represents a server in the SILC network.  All servers
 *    that the client is aware of and have for example resolved with
 *    SILC_COMMAND_INFO command have their on SilcServerEntry structure.
 *    All strings in the structure are UTF-8 encoded.
 *
 * SOURCE
 */
struct SilcServerEntryStruct {
  /* General information */
  char *server_name;			     /* Server name */
  char *server_info;			     /* Server info */
  SilcServerID *server_id;		     /* Server ID */
  SilcUInt16 resolve_cmd_ident;		     /* Command identifier when
					        resolving this entry */

  /* Application specific data.  Application may set here whatever it wants. */
  void *context;
};
/***/

/* SilcClientEntry routines */

/****f* silcclient/SilcClientAPI/SilcGetClientCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcGetClientCallback)(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          SilcStatus status,
 *                                          SilcDList clients,
 *                                          void *context);
 *
 * DESCRIPTION
 *
 *    Callback function given to various client search functions.  The
 *    found entries are allocated into the `clients' list.  The list must
 *    not be freed by the receiver, the library will free it later.  If the
 *    `clients' is NULL, no such clients exist in the SILC Network, and
 *    the `status' will include the error.
 *
 * NOTES
 *
 *    If the application stores any of the SilcClientEntry pointers from
 *    the `clients' list it must reference it with silc_client_ref_client
 *    function.
 *
 *    Application must not free the returned `clients' list.
 *
 ***/
typedef void (*SilcGetClientCallback)(SilcClient client,
				      SilcClientConnection conn,
				      SilcStatus status,
				      SilcDList clients,
				      void *context);

/****f* silcclient/SilcClientAPI/silc_client_ref_client
 *
 * SYNOPSIS
 *
 *    void silc_client_ref_client(SilcClient client,
 *                                SilcClientConnection conn,
 *                                SilcClientEntry client_entry);
 *
 * DESCRIPTION
 *
 *    Takes a reference of the client entry indicated by `client_entry'
 *    The reference must be released by calling silc_client_unref_client
 *    after it is not needed anymore.
 *
 ***/
void silc_client_ref_client(SilcClient client, SilcClientConnection conn,
			    SilcClientEntry client_entry);

/****f* silcclient/SilcClientAPI/silc_client_unref_client
 *
 * SYNOPSIS
 *
 *    void silc_client_unref_client(SilcClient client,
 *                                  SilcClientConnection conn,
 *                                  SilcClientEntry client_entry);
 *
 * DESCRIPTION
 *
 *    Releases the client entry reference indicated by `client_entry'.
 *
 ***/
void silc_client_unref_client(SilcClient client, SilcClientConnection conn,
			      SilcClientEntry client_entry);

/****f* silcclient/SilcClientAPI/silc_client_list_free
 *
 * SYNOPSIS
 *
 *    void silc_client_list_free(SilcClient client,
 *                               SilcClientConnection conn,
 *                               SilcDList client_list);
 *
 * DESCRIPTION
 *
 *    Free's client entry list that has been returned by various library
 *    routines.
 *
 ***/
void silc_client_list_free(SilcClient client, SilcClientConnection conn,
			   SilcDList client_list);

/****f* silcclient/SilcClientAPI/silc_client_get_clients
 *
 * SYNOPSIS
 *
 *    SilcUInt16 silc_client_get_clients(SilcClient client,
 *                                       SilcClientConnection conn,
 *                                       const char *nickname,
 *                                       const char *server,
 *                                       SilcGetClientCallback completion,
 *                                       void *context);
 *
 * DESCRIPTION
 *
 *    Finds client entry or entries by the `nickname' and `server'. The
 *    completion callback will be called when the client entries has been
 *    found.  After the server returns the client information it is cached
 *    and can be accesses locally at a later time.  The resolving is done
 *    with IDENTIFY command.  The `server' may be NULL.  Returns 0 on
 *    error and the command identifier used with the command otherwise.
 *
 * NOTES
 *
 *    This function is always asynchronous and resolves the client
 *    information from the server.  Thus, if you already know the client
 *    information then use the silc_client_get_client_by_id function to
 *    get the client entry since this function may be very slow and should
 *    be used only to initially get the client entries.
 *
 *    This function resolves only the relevant information (user's nickname
 *    and username).  It does not resolve for example user's real name,
 *    joined channel list or other information.  To resolve all the details
 *    use silc_client_get_clients_whois instead.
 *
 ***/
SilcUInt16 silc_client_get_clients(SilcClient client,
				   SilcClientConnection conn,
				   const char *nickname,
				   const char *server,
				   SilcGetClientCallback completion,
				   void *context);

/****f* silcclient/SilcClientAPI/silc_client_get_clients_whois
 *
 * SYNOPSIS
 *
 *    SilcUInt16
 *    silc_client_get_clients_whois(SilcClient client,
 *                                  SilcClientConnection conn,
 *                                  const char *nickname,
 *                                  const char *server,
 *                                  SilcBuffer attributes,
 *                                  SilcGetClientCallback completion,
 *                                  void *context);
 *
 * DESCRIPTION
 *
 *    Finds client entry or entries by the `nickname' and `server'. The
 *    completion callback will be called when the client entries has been
 *    found.  After the server returns the client information it is cached
 *    and can be accesses locally at a later time.  The resolving is done
 *    with WHOIS command.  The `server' may be NULL.  Returns 0 on error,
 *    and the command identifier used with the command otherwise.
 *
 *    If the `attributes' is non-NULL then the buffer includes Requested
 *    Attributes which can be used to fetch very detailed information
 *    about the user. If it is NULL then only normal WHOIS query is
 *    made (for more information about attributes see SilcAttribute).
 *    Caller may create the `attributes' with silc_client_attributes_request
 *    function.
 *
 * NOTES
 *
 *    The resolving is done with WHOIS command.  For this reason this
 *    command may take a long time because it resolves detailed user
 *    information.
 *
 ***/
SilcUInt16 silc_client_get_clients_whois(SilcClient client,
					 SilcClientConnection conn,
					 const char *nickname,
					 const char *server,
					 SilcBuffer attributes,
					 SilcGetClientCallback completion,
					 void *context);

/****f* silcclient/SilcClientAPI/silc_client_get_clients_local
 *
 * SYNOPSIS
 *
 *    SilcDList silc_client_get_clients_local(SilcClient client,
 *                                            SilcClientConnection conn,
 *                                            const char *nickname,
 *                                            const char *format);
 *
 * DESCRIPTION
 *
 *    Same as silc_client_get_clients function but does not resolve anything
 *    from the server.  This checks local cache and returns all matching
 *    clients from the local cache.  If none was found this returns NULL.
 *    The `nickname' is the real nickname of the client, and the `format'
 *    is the formatted nickname to find exact match from multiple found
 *    entries.  The format must be same as given in the SilcClientParams
 *    structure to the client library.  If the `format' is NULL all found
 *    clients by `nickname' are returned.  The caller must free the
 *    returned list by silc_client_list_free function.
 *
 * NOTES
 *
 *    If the application stores any of the SilcClientEntry pointers from
 *    the returned list it must reference it with silc_client_ref_client
 *    function.
 *
 *    Application must free the returned list with silc_client_list_free
 *    function.
 *
 ***/
SilcDList silc_client_get_clients_local(SilcClient client,
					SilcClientConnection conn,
					const char *nickname,
					const char *format);

/****f* silcclient/SilcClientAPI/silc_client_get_clients_by_channel
 *
 * SYNOPSIS
 *
 *    void silc_client_get_clients_by_channel(SilcClient client,
 *                                            SilcClientConnection conn,
 *                                            SilcChannelEntry channel,
 *                                            SilcGetClientCallback completion,
 *                                            void *context);
 *
 * DESCRIPTION
 *
 *    Gets client entries by the channel indicated by `channel'. Thus,
 *    it resovles the users currently on that channel. If all users are
 *    already resolved this returns the users from the channel. If the
 *    users are resolved only partially this resolves the complete user
 *    information. If no users are resolved on this channel at all, this
 *    calls USERS command to resolve all users on the channel. The `completion'
 *    will be called after the entries are available. When server returns
 *    the client information it will be cached and can be accessed locally
 *    at a later time.
 *
 *    This function can be used for example in SILC_COMMAND_JOIN command
 *    reply handling in application to resolve users on that channel.  It
 *    also can be used after calling silc_client_get_channel_resolve to
 *    resolve users on that channel.
 *
 * NOTES
 *
 *    The resolving is done with WHOIS command.  For this reason this
 *    command may take a long time because it resolves detailed user
 *    information.
 *
 ***/
void silc_client_get_clients_by_channel(SilcClient client,
					SilcClientConnection conn,
					SilcChannelEntry channel,
					SilcGetClientCallback completion,
					void *context);

/****f* silcclient/SilcClientAPI/silc_client_get_clients_by_list
 *
 * SYNOPSIS
 *
 *    void silc_client_get_clients_by_list(SilcClient client,
 *                                         SilcClientConnection conn,
 *                                         SilcUInt32 list_count,
 *                                         SilcBuffer client_id_list,
 *                                         SilcGetClientCallback completion,
 *                                         void *context);
 *
 * DESCRIPTION
 *
 *    Gets client entries by the list of client ID's `client_id_list'. This
 *    always resolves those client ID's it doesn't know about from the server.
 *    The `client_id_list' is a list of ID Payloads added one after other.
 *    JOIN command reply and USERS command reply for example returns this sort
 *    of list. The `completion' will be called after the entries are available.
 *    When server returns the client information it will be cached and can be
 *    accessed locally at a later time.  The resolving is done with WHOIS
 *    command.
 *
 * NOTES
 *
 *    If even after resolving some Client ID in the `client_id_list' is
 *    unknown it will be ignored and error is not returned.
 *
 ***/
void silc_client_get_clients_by_list(SilcClient client,
				     SilcClientConnection conn,
				     SilcUInt32 list_count,
				     SilcBuffer client_id_list,
				     SilcGetClientCallback completion,
				     void *context);

/****f* silcclient/SilcClientAPI/silc_client_get_client_by_id
 *
 * SYNOPSIS
 *
 *    SilcClientEntry silc_client_get_client_by_id(SilcClient client,
 *                                                 SilcClientConnection conn,
 *                                                 SilcClientID *client_id);
 *
 * DESCRIPTION
 *
 *    Find client entry by the client's ID.  Returns the entry or NULL
 *    if the entry was not found.  This checks the local cache and does
 *    not resolve anything from server.
 *
 * NOTES
 *
 *    The returned SilcClientEntry has been referenced by the library and
 *    the caller must call silc_client_unref_client after the entry is not
 *    needed anymore.
 *
 ***/
SilcClientEntry silc_client_get_client_by_id(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientID *client_id);

/****f* silcclient/SilcClientAPI/silc_client_get_client_by_id_resolve
 *
 * SYNOPSIS
 *
 *    void
 *    silc_client_get_client_by_id_resolve(SilcClient client,
 *                                         SilcClientConnection conn,
 *                                         SilcClientID *client_id,
 *                                         SilcBuffer attributes,
 *                                         SilcGetClientCallback completion,
 *                                         void *context);
 *
 * DESCRIPTION
 *
 *    Same as silc_client_get_client_by_id but will always resolve the
 *    information from the server. Use this only if you know that you
 *    do not have the entry and the only thing you know about the client
 *    is its ID. When server returns the client information it will be
 *    cache and can be accessed locally at a later time. The resolving
 *    is done by sending WHOIS command.
 *
 *    If the `attributes' is non-NULL then the buffer includes Requested
 *    Attributes which can be used to fetch very detailed information
 *    about the user. If it is NULL then only normal WHOIS query is
 *    made (for more information about attributes see SilcAttribute).
 *    Caller may create the `attributes' with silc_client_attributes_request
 *    function.
 *
 ***/
void silc_client_get_client_by_id_resolve(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientID *client_id,
					  SilcBuffer attributes,
					  SilcGetClientCallback completion,
					  void *context);

/****f* silcclient/SilcClientAPI/silc_client_del_client
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_del_client(SilcClient client, SilcClientConnection conn,
 *                                SilcClientEntry client_entry)
 *
 * DESCRIPTION
 *
 *    Removes client from local cache by the client entry indicated by
 *    the `client_entry'.  Returns TRUE if the deletion were successful.
 *
 ***/
SilcBool silc_client_del_client(SilcClient client, SilcClientConnection conn,
				SilcClientEntry client_entry);


#endif /* SILCCLIENT_ENTRY_H */
