/*

  id.h

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
/* These are important ID types used in SILC. SILC server creates these
   but SILC client has to handle these as well since these are used in
   packet sending and reception. However, client never creates these
   but it receives the correct ID's from server. Clients, servers and
   channels are identified by the these ID's.

   Note that these are currently IPv4 specific, although adding IPv6
   support is not a bad task and SILC protocol already supports IPv6.
*/

#ifndef ID_H
#define ID_H

#define SILC_ID_SERVER_LEN 	(64 / 8)
#define SILC_ID_CLIENT_LEN 	(128 / 8)
#define SILC_ID_CHANNEL_LEN 	(64 / 8)
#define CLIENTID_HASH_LEN       (88 / 8) /* Client ID's 88 bit MD5 hash */

/* SILC ID Types */
#define SILC_ID_NONE 0
#define SILC_ID_SERVER 1
#define SILC_ID_CLIENT 2
#define SILC_ID_CHANNEL 3

/* Type definition for the ID types. */
typedef unsigned short SilcIdType;

/* 
   64 bit SilcServerID structure:
   
   32 bit IP address
   16 bit port
   16 bit random number
*/
typedef struct {
  struct in_addr ip;				/* 32 bit IP */
  unsigned short port;				/* 16 bit port */
  unsigned short rnd;				/* 16 bit random number */
} SilcServerID;

/* 
   128 bit SilcClientID structure:

   32 bit ServerID IP address [bits 1-32]
    8 bit random number
   88 bit hash value from nickname
*/
typedef struct {
  struct in_addr ip;				/* 32 bit IP */
  unsigned char rnd;				/* 8 bit random number */
  unsigned char hash[CLIENTID_HASH_LEN];	/* 88 bit MD5 hash */
} SilcClientID;

/* 
   64 bit SilcChannel ID structure:

   32 bit Router's ServerID IP address [bits 1-32]
   16 bit Router's ServerID port [bits 33-48]
   16 bit random number
*/
typedef struct {
  struct in_addr ip;				/* 32 bit IP */
  unsigned short port;				/* 16 bit port */
  unsigned short rnd;				/* 16 bit random number */
} SilcChannelID;

/* Macros */

/* Compares two ID's */
#define SILC_ID_COMPARE(id1, id2, len) (memcmp(id1, id2, len))

/* Compares Channel ID's */
#define SILC_ID_CHANNEL_COMPARE(id1, id2) \
  SILC_ID_COMPARE(id1, id2, SILC_ID_CHANNEL_LEN)

/* Compares Client ID's */
#define SILC_ID_CLIENT_COMPARE(id1, id2) \
  SILC_ID_COMPARE(id1, id2, SILC_ID_CLIENT_LEN)

/* Compares Server ID's */
#define SILC_ID_SERVER_COMPARE(id1, id2) \
  SILC_ID_COMPARE(id1, id2, SILC_ID_SERVER_LEN)

/* Compares IP addresses from the ID's. */
#define SILC_ID_COMPARE_IP(id1, id2) \
  SILC_ID_COMPARE(id1, id2, 4)

/* Compare nickname hash from Client ID */
#define SILC_ID_COMPARE_HASH(id, _hash) \
  memcmp(id->hash, _hash, CLIENTID_HASH_LEN)

/* Prototypes */
unsigned char *silc_id_id2str(void *id, SilcIdType type);
void *silc_id_str2id(unsigned char *id, SilcIdType type);
unsigned int silc_id_get_len(SilcIdType type);

#endif
