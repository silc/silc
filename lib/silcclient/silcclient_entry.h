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
 *    Application may store its own pointer into the context pointer in
 *    this structure.
 *
 * NOTES
 *
 *    If application stores the SilcChannelEntry it must always take
 *    a reference of it by calling silc_client_ref_channel function.  The
 *    reference must be released after it is not needed anymore by calling
 *    silc_client_unref_channel function.
 *
 * SOURCE
 */
struct SilcChannelEntryStruct {
  char *channel_name;		     /* Channel name */
  char *topic;			     /* Current topic, may be NULL */
  SilcPublicKey founder_key;	     /* Founder key, may be NULL */
  SilcDList channel_pubkeys;	     /* Channel public keys, may be NULL */
  SilcChannelID id;		     /* Channel ID */
  SilcUInt32 mode;		     /* Channel mode, ChannelModes. */
  SilcUInt32 user_limit;	     /* User limit on channel */
  SilcHashTable user_list;	     /* Joined users.  Key to hash table is
					SilcClientEntry, context is
					SilcChannelUser. */

  void *context;		     /* Application specific context */
  SilcChannelEntryInternal internal;
};
/***/

/****s* silcclient/SilcClientAPI/SilcServerEntry
 *
 * NAME
 *
 *    typedef struct SilcServerEntryStruct { ... } *SilcServerEntry;
 *
 * DESCRIPTION
 *
 *    This structure represents a server in the SILC network.  All servers
 *    that the client is aware of and have for example resolved with
 *    SILC_COMMAND_INFO command have their on SilcServerEntry structure.
 *    Server's public key is present only if it has been retrieved using
 *    SILC_COMMAND_GETKEY command.  All strings in the structure are UTF-8
 *    encoded.
 *
 *    Application may store its own pointer into the context pointer in
 *    this structure.
 *
 * NOTES
 *
 *    If application stores the SilcServerEntry it must always take
 *    a reference of it by calling silc_client_ref_server function.  The
 *    reference must be released after it is not needed anymore by calling
 *    silc_client_unref_server function.
 *
 * SOURCE
 */
struct SilcServerEntryStruct {
  /* General information */
  char *server_name;		     /* Server name */
  char *server_info;		     /* Server info */
  SilcServerID id;		     /* Server ID */
  SilcPublicKey public_key;	     /* Server public key, may be NULL */

  void *context;		     /* Application specific context */
  SilcServerEntryInternal internal;
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
 *    `clients' is NULL, no such clients exist in the SILC network, and
 *    the `status' will include the error.  Each entry in the `clients'
 *    is SilcClientEntry.
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

/****f* silcclient/SilcClientAPI/silc_client_lock_client
 *
 * SYNOPSIS
 *
 *    void silc_client_lock_client(SilcClientEntry client_entry);
 *
 * DESCRIPTION
 *
 *    Acquires lock for the client entry indicate by `client_entry'.  When
 *    application wants to access `client_entry' it must lock the entry
 *    before reading any data from the `client_entry'.  The lock must be
 *    unlocked with silc_client_unlock_client.
 *
 *    The entry must be unlocked before calling any Client Library API
 *    functions where the entry is given as argument.
 *
 *    This function is not needed if application is not multithreaded
 *
 ***/
void silc_client_lock_client(SilcClientEntry client_entry);

/****f* silcclient/SilcClientAPI/silc_client_unlock_client
 *
 * SYNOPSIS
 *
 *    void silc_client_unlock_client(SilcClientEntry client_entry);
 *
 * DESCRIPTION
 *
 *    Releases the lock acquired with silc_client_lock_client.
 *
 ***/
void silc_client_unlock_client(SilcClientEntry client_entry);

/****f* silcclient/SilcClientAPI/silc_client_ref_client
 *
 * SYNOPSIS
 *
 *    SilcClientEntry
 *    silc_client_ref_client(SilcClient client,
 *                           SilcClientConnection conn,
 *                           SilcClientEntry client_entry);
 *
 * DESCRIPTION
 *
 *    Takes a reference of the client entry indicated by `client_entry'
 *    The reference must be released by calling silc_client_unref_client
 *    after it is not needed anymore.  Returns `client_entry'.
 *
 ***/
SilcClientEntry silc_client_ref_client(SilcClient client, 
				       SilcClientConnection conn,
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
 *    SilcUInt16
 *    silc_client_get_clients_by_list(SilcClient client,
 *                                    SilcClientConnection conn,
 *                                    SilcUInt32 list_count,
 *                                    SilcBuffer client_id_list,
 *                                    SilcGetClientCallback completion,
 *                                    void *context);
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
 *    Returns command identifier for the resolving.  It can be used to attach
 *    a pending command to it, if needed.  Returns 0 when no resolving was
 *    done or wasn't needed (completion is called before this returns).
 *
 * NOTES
 *
 *    If even after resolving some Client ID in the `client_id_list' is
 *    unknown it will be ignored and error is not returned.
 *
 ***/
SilcUInt16 silc_client_get_clients_by_list(SilcClient client,
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
 *    SilcUInt16
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
 *    Returns command identifier for the resolving.  It can be used to attach
 *    a pending command to it, if needed.  Returns 0 on error.
 *
 *    If the `attributes' is non-NULL then the buffer includes Requested
 *    Attributes which can be used to fetch very detailed information
 *    about the user. If it is NULL then only normal WHOIS query is
 *    made (for more information about attributes see SilcAttribute).
 *    Caller may create the `attributes' with silc_client_attributes_request
 *    function.
 *
 ***/
SilcUInt16
silc_client_get_client_by_id_resolve(SilcClient client,
				     SilcClientConnection conn,
				     SilcClientID *client_id,
				     SilcBuffer attributes,
				     SilcGetClientCallback completion,
				     void *context);

/* SilcChannelEntry routines */

/****f* silcclient/SilcClientAPI/SilcGetChannelCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcGetChannelCallback)(SilcClient client,
 *                                           SilcClientConnection conn,
 *                                           SilcStatus status,
 *                                           SilcDList channels,
 *                                           void *context);
 *
 * DESCRIPTION
 *
 *    Callback function given to various channel resolving functions.
 *    The found entries are included in the `channels' list and each entry
 *    in the list is SilcChannelEntry.  If `channels' is NULL then no such
 *    channel exist in the network and the `status' will indicate the error.
 *
 * NOTES
 *
 *    If the application stores any of the SilcChannelEntry pointers from
 *    the `channels' list it must reference it with silc_client_ref_channel
 *    function.
 *
 *    Application must not free the returned `channels' list.
 *
 ***/
typedef void (*SilcGetChannelCallback)(SilcClient client,
				       SilcClientConnection conn,
				       SilcStatus status,
				       SilcDList channels,
				       void *context);

/****f* silcclient/SilcClientAPI/silc_client_lock_channel
 *
 * SYNOPSIS
 *
 *    void silc_client_lock_channel(SilcChannelEntry channel_entry);
 *
 * DESCRIPTION
 *
 *    Acquires lock for the channel entry indicate by `channel_entry'.  When
 *    application wants to access `channel_entry' it must lock the entry
 *    before reading any data from the `channel_entry'.  The lock must be
 *    unlocked with silc_client_unlock_channel.
 *
 *    The entry must be unlocked before calling any Client Library API
 *    functions where the entry is given as argument.
 *
 *    This function is not needed if application is not multithreaded
 *
 ***/
void silc_client_lock_channel(SilcChannelEntry channel_entry);

/****f* silcclient/SilcClientAPI/silc_client_unlock_channel
 *
 * SYNOPSIS
 *
 *    void silc_client_unlock_channel(SilcChannelEntry channel_entry);
 *
 * DESCRIPTION
 *
 *    Releases the lock acquired with silc_client_lock_channel.
 *
 ***/
void silc_client_unlock_channel(SilcChannelEntry channel_entry);

/****f* silcclient/SilcClientAPI/silc_client_ref_channel
 *
 * SYNOPSIS
 *
 *    SilcChannelEntry
 *    silc_client_ref_channel(SilcClient client,
 *                            SilcClientConnection conn,
 *                            SilcChannelEntry channel_entry);
 *
 * DESCRIPTION
 *
 *    Takes a reference of the channel entry indicated by `channel_entry'
 *    The reference must be released by calling silc_client_unref_channel
 *    after it is not needed anymore.  Returns `channel_entry'.
 *
 ***/
SilcChannelEntry silc_client_ref_channel(SilcClient client, 
					 SilcClientConnection conn,
					 SilcChannelEntry channel_entry);

/****f* silcclient/SilcClientAPI/silc_client_unref_channel
 *
 * SYNOPSIS
 *
 *    void silc_client_unref_channel(SilcClient client,
 *                                   SilcClientConnection conn,
 *                                   SilcChannelEntry channel_entry);
 *
 * DESCRIPTION
 *
 *    Releases the channel entry reference indicated by `channel_entry'.
 *
 ***/
void silc_client_unref_channel(SilcClient client, SilcClientConnection conn,
			       SilcChannelEntry channel_entry);

/****f* silcclient/SilcClientAPI/silc_client_list_free_channel
 *
 * SYNOPSIS
 *
 *    void silc_client_list_free_channel(SilcClient client,
 *                                       SilcClientConnection conn,
 *                                       SilcDList channel_list);
 *
 * DESCRIPTION
 *
 *    Free's channel entry list that has been returned by various library
 *    routines.
 *
 ***/
void silc_client_list_free_channels(SilcClient client,
				    SilcClientConnection conn,
				    SilcDList channel_list);

/****f* silcclient/SilcClientAPI/silc_client_get_channel
 *
 * SYNOPSIS
 *
 *    SilcChannelEntry silc_client_get_channel(SilcClient client,
 *                                             SilcClientConnection conn,
 *                                             char *channel_name);
 *
 * DESCRIPTION
 *
 *    Finds entry for channel by the channel name. Returns the entry or NULL
 *    if the entry was not found. It is found only if the client is joined
 *    to the channel.  Use silc_client_get_channel_resolve or
 *    silc_client_get_channel_by_id_resolve to resolve channel that client
 *    is not joined.
 *
 * NOTES
 *
 *    The returned SilcChannelEntry has been referenced by the library and
 *    the caller must call silc_client_unref_channel after the entry is not
 *    needed anymore.
 *
 ***/
SilcChannelEntry silc_client_get_channel(SilcClient client,
					 SilcClientConnection conn,
					 char *channel_name);

/****f* silcclient/SilcClientAPI/silc_client_get_channel_resolve
 *
 * SYNOPSIS
 *
 *    void silc_client_get_channel_resolve(SilcClient client,
 *                                         SilcClientConnection conn,
 *                                         char *channel_name,
 *                                         SilcGetChannelCallback completion,
 *                                         void *context);
 *
 * DESCRIPTION
 *
 *    Resolves entry for channel by the channel name from the server.
 *    The resolving is done with IDENTIFY command. Note that users on
 *    the channel are not resolved at the same time. Use for example
 *    silc_client_get_clients_by_channel to resolve all users on a channel.
 *
 ***/
void silc_client_get_channel_resolve(SilcClient client,
				     SilcClientConnection conn,
				     char *channel_name,
				     SilcGetChannelCallback completion,
				     void *context);

/****f* silcclient/SilcClientAPI/silc_client_get_channel_by_id
 *
 * SYNOPSIS
 *
 *    SilcChannelEntry
 *    silc_client_get_channel_by_id(SilcClient client,
 *                                  SilcClientConnection conn,
 *                                  SilcChannelID *channel_id);
 *
 * DESCRIPTION
 *
 *    Finds channel entry by the channel ID. Returns the entry or NULL
 *    if the entry was not found.  This checks the local cache and does
 *    not resolve anything from server.
 *
 * NOTES
 *
 *    The returned SilcChannelEntry has been referenced by the library and
 *    the caller must call silc_client_unref_channel after the entry is not
 *    needed anymore.
 *
 ***/
SilcChannelEntry silc_client_get_channel_by_id(SilcClient client,
					       SilcClientConnection conn,
					       SilcChannelID *channel_id);

/****f* silcclient/SilcClientAPI/silc_client_get_channel_by_id_resolve
 *
 * SYNOPSIS
 *
 *    SilcUInt16
 *    silc_client_get_channel_by_id_resolve(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          SilcChannelID *channel_id,
 *                                          SilcGetClientCallback completion,
 *                                          void *context);
 *
 * DESCRIPTION
 *
 *    Resolves the channel information (its name mainly) from the server
 *    by the `channel_id'. Use this only if you know that you do not have
 *    the entry cached locally. The resolving is done with IDENTIFY command.
 *
 *    Returns command identifier for the resolving.  It can be used to attach
 *    a pending command to it, if needed.  Returns 0 on error.
 *
 *    Note that users on the channel are not resolved at the same time.
 *    Use for example silc_client_get_clients_by_channel to resolve all
 *    users on a channel.
 *
 ***/
SilcUInt16
silc_client_get_channel_by_id_resolve(SilcClient client,
				      SilcClientConnection conn,
				      SilcChannelID *channel_id,
				      SilcGetChannelCallback completion,
				      void *context);

/* SilcServerEntry routines */

/****f* silcclient/SilcClientAPI/SilcGetServerCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcGetServerCallback)(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          SilcStatus status,
 *                                          SilcDList servers,
 *                                          void *context);
 *
 * DESCRIPTION
 *
 *    Callback function given to various server resolving functions.
 *    The found entries are included in the `servers' list and each entry
 *    in the list is SilcServerEntry.  If `server' is NULL then no such
 *    server exist in the network and the `status' will indicate the error.
 *
 * NOTES
 *
 *    If the application stores any of the SilcServerEntry pointers from
 *    the `server' list it must reference it with silc_client_ref_server
 *    function.
 *
 *    Application must not free the returned `server' list.
 *
 ***/
typedef void (*SilcGetServerCallback)(SilcClient client,
				      SilcClientConnection conn,
				      SilcStatus status,
				      SilcDList servers,
				      void *context);

/****f* silcclient/SilcClientAPI/silc_client_lock_server
 *
 * SYNOPSIS
 *
 *    void silc_client_lock_server(SilcServerEntry server_entry);
 *
 * DESCRIPTION
 *
 *    Acquires lock for the server entry indicate by `server_entry'.  When
 *    application wants to access `server_entry' it must lock the entry
 *    before reading any data from the `server_entry'.  The lock must be
 *    unlocked with silc_client_unlock_server.
 *
 *    The entry must be unlocked before calling any Client Library API
 *    functions where the entry is given as argument.
 *
 *    This function is not needed if application is not multithreaded
 *
 ***/
void silc_client_lock_server(SilcServerEntry server_entry);

/****f* silcclient/SilcClientAPI/silc_client_unlock_server
 *
 * SYNOPSIS
 *
 *    void silc_client_unlock_server(SilcServerEntry server_entry);
 *
 * DESCRIPTION
 *
 *    Releases the lock acquired with silc_client_lock_server.
 *
 ***/
void silc_client_unlock_server(SilcServerEntry server_entry);

/****f* silcclient/SilcClientAPI/silc_client_ref_server
 *
 * SYNOPSIS
 *
 *    SilcServerEntry
 *    silc_client_ref_server(SilcClient client,
 *                           SilcClientConnection conn,
 *                           SilcServerEntry server_entry);
 *
 * DESCRIPTION
 *
 *    Takes a reference of the server entry indicated by `server_entry'
 *    The reference must be released by calling silc_client_unref_server
 *    after it is not needed anymore.  Returns `server_entry'.
 *
 ***/
SilcServerEntry silc_client_ref_server(SilcClient client, 
				       SilcClientConnection conn,
				       SilcServerEntry server_entry);

/****f* silcclient/SilcClientAPI/silc_client_unref_server
 *
 * SYNOPSIS
 *
 *    void silc_client_unref_server(SilcClient client,
 *                                  SilcClientConnection conn,
 *                                  SilcServerEntry server_entry);
 *
 * DESCRIPTION
 *
 *    Releases the server entry reference indicated by `server_entry'.
 *
 ***/
void silc_client_unref_server(SilcClient client, SilcClientConnection conn,
			      SilcServerEntry server_entry);

/****f* silcclient/SilcClientAPI/silc_client_list_free_server
 *
 * SYNOPSIS
 *
 *    void silc_client_list_free_server(SilcClient client,
 *                                      SilcClientConnection conn,
 *                                      SilcDList server_list);
 *
 * DESCRIPTION
 *
 *    Free's server entry list that has been returned by various library
 *    routines.
 *
 ***/
void silc_client_list_free_servers(SilcClient client,
				   SilcClientConnection conn,
				   SilcDList server_list);

/****f* silcclient/SilcClientAPI/silc_client_get_server
 *
 * SYNOPSIS
 *
 *    SilcServerEntry silc_client_get_server(SilcClient client,
 *                                           SilcClientConnection conn,
 *                                           char *server_name)
 *
 * DESCRIPTION
 *
 *    Finds entry for server by the server name. Returns the entry or NULL
 *    if the entry was not found.
 *
 ***/
SilcServerEntry silc_client_get_server(SilcClient client,
				       SilcClientConnection conn,
				       char *server_name);

/****f* silcclient/SilcClientAPI/silc_client_get_server_by_id
 *
 * SYNOPSIS
 *
 *    SilcServerEntry silc_client_get_server_by_id(SilcClient client,
 *                                                 SilcClientConnection conn,
 *                                                 SilcServerID *server_id);
 *
 * DESCRIPTION
 *
 *    Finds entry for server by the server ID. Returns the entry or NULL
 *    if the entry was not found.
 *
 ***/
SilcServerEntry silc_client_get_server_by_id(SilcClient client,
					     SilcClientConnection conn,
					     SilcServerID *server_id);

/****f* silcclient/SilcClientAPI/silc_client_get_server_by_id_resolve
 *
 * SYNOPSIS
 *
 *    SilcUInt16
 *    silc_client_get_server_by_id_resolve(SilcClient client,
 *                                         SilcClientConnection conn,
 *                                         SilcServerID *server_id,
 *                                         SilcGetServerCallback completion,
 *                                         void *context);
 *
 * DESCRIPTION
 *
 *    Resolves the server information by the `server_id'.  The resolved
 *    server is returned into the `completion' callback.
 *
 *    Returns command identifier for the resolving.  It can be used to attach
 *    a pending command to it, if needed.  Returns 0 on error.
 *
 ***/
SilcUInt16
silc_client_get_server_by_id_resolve(SilcClient client,
				     SilcClientConnection conn,
				     SilcServerID *server_id,
				     SilcGetServerCallback completion,
				     void *context);

#endif /* SILCCLIENT_ENTRY_H */
