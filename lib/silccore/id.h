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
*/

#ifndef ID_H
#define ID_H

/* The SILC ID Types */
#define SILC_ID_NONE 0
#define SILC_ID_SERVER 1
#define SILC_ID_CLIENT 2
#define SILC_ID_CHANNEL 3

/* Type definition for the ID types. */
typedef uint16 SilcIdType;

/* The ID Lenghts. These are IPv4 based and should be noted if used directly
   that these cannot be used with IPv6. */
#define SILC_ID_SERVER_LEN 	(64 / 8)
#define SILC_ID_CLIENT_LEN 	(128 / 8)
#define SILC_ID_CHANNEL_LEN 	(64 / 8)

#define CLIENTID_HASH_LEN       (88 / 8) /* Client ID's 88 bit MD5 hash */

/*
   SILC ID IP structure.

   Generic IP address structure to indicate either IPv4 or IPv6 address.
   This structure is used inside all SILC ID's. The true length of the
   ID depends of the length of the IP address.
*/
typedef struct {
  unsigned char data[16];	/* IP data (in MSB first order) */
  uint8 data_len;		/* Length of the data (4 or 16) */
} SilcIDIP;

/* 
   64 or 160 bit SilcServerID structure:
   
    n bit IP address
   16 bit port
   16 bit random number
*/
typedef struct {
  SilcIDIP ip;			/* n bit IP address */
  uint16 port;			/* 16 bit port */
  uint16 rnd;			/* 16 bit random number */
} SilcServerID;

/* 
   128 or 224 bit SilcClientID structure:

    n bit ServerID IP address [bits 1-32 or bits 1-128]
    8 bit random number
   88 bit hash value from nickname
*/
typedef struct {
  SilcIDIP ip;					/* n bit IP address */
  unsigned char rnd;				/* 8 bit random number */
  unsigned char hash[CLIENTID_HASH_LEN];	/* 88 bit MD5 hash */
} SilcClientID;

/* 
   64 or 160 bit SilcChannel ID structure:

    n bit Router's ServerID IP address [bits 1-32 or bits 1-128]
   16 bit Router's ServerID port [bits 33-48 or bits 129-144]
   16 bit random number
*/
typedef struct {
  SilcIDIP ip;					/* n bit IP address */
  uint16 port;					/* 16 bit port */
  uint16 rnd;					/* 16 bit random number */
} SilcChannelID;

/* Macros */

/* Compares two ID's. */
#define SILC_ID_COMPARE(id1, id2, len) (!memcmp(id1, id2, len))

/* Compares Client ID's */
#define SILC_ID_CLIENT_COMPARE(id1, id2) \
  SILC_ID_COMPARE(id1, id2, sizeof(SilcClientID))

/* Compares Server ID's */
#define SILC_ID_SERVER_COMPARE(id1, id2) \
  SILC_ID_COMPARE(id1, id2, sizeof(SilcServerID))

/* Compares Channel ID's */
#define SILC_ID_CHANNEL_COMPARE(id1, id2) \
  SILC_ID_COMPARE(id1, id2, sizeof(SilcChannelID))

/* Compares two ID's by type */
#define SILC_ID_COMPARE_TYPE(id1, id2, type)			\
  (type == SILC_ID_SERVER ? SILC_ID_SERVER_COMPARE(id1, id2) :	\
   type == SILC_ID_CLIENT ? SILC_ID_CLIENT_COMPARE(id1, id2) :	\
   SILC_ID_CHANNEL_COMPARE(id1, id2))

/* Compare nickname hash from Client ID */
#define SILC_ID_COMPARE_HASH(id, _hash) \
  memcmp(id->hash, _hash, CLIENTID_HASH_LEN)

/* Prototypes */
unsigned char *silc_id_id2str(void *id, SilcIdType type);
void *silc_id_str2id(unsigned char *id, uint32 id_len, SilcIdType type);
uint32 silc_id_get_len(void *id, SilcIdType type);
void *silc_id_dup(void *id, SilcIdType type);

#endif
