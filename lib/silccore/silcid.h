/****h* silccore/silcid.h
 *
 * NAME
 *
 * silcid.h
 *
 * COPYRIGHT
 *
 * Author: Pekka Riikonen <priikone@poseidon.pspt.fi>
 *
 * Copyright (C) 1997 - 2000 Pekka Riikonen
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * DESCRIPTION
 *
 * These are important ID types used in SILC. SILC server creates these
 * but SILC client has to handle these as well since these are used in
 * packet sending and reception. However, client never creates these
 * but it receives the correct ID's from server. Clients, servers and
 * channels are identified by the these ID's.
 *
 * The ID's are based on IP addresses. The IP address provides a good
 * way to distinguish the ID's from other ID's. The ID's supports both
 * IPv4 and IPv6.
 *
 ***/

#ifndef SILCID_H
#define SILCID_H

/****d* silccore/SilcIDAPI/SilcIdType
 *
 * NAME
 * 
 *    typedef uint16 SilcIdType;
 *
 * DESCRIPTION
 *
 *    SILC ID type definitions and the ID types.
 *
 * SOURCE
 */
typedef uint16 SilcIdType;

/* The SILC ID Types */
#define SILC_ID_NONE 0
#define SILC_ID_SERVER 1
#define SILC_ID_CLIENT 2
#define SILC_ID_CHANNEL 3
/***/

/* The ID Lenghts. These are IPv4 based and should be noted if used directly
   that these cannot be used with IPv6. */
#define SILC_ID_SERVER_LEN 	(64 / 8)
#define SILC_ID_CLIENT_LEN 	(128 / 8)
#define SILC_ID_CHANNEL_LEN 	(64 / 8)

#define CLIENTID_HASH_LEN       (88 / 8) /* Client ID's 88 bit MD5 hash */

/****s* silccore/SilcIDAPI/SilcIDIP
 *
 * NAME
 * 
 *    typedef struct { ... } SilcIDIP;
 *
 * DESCRIPTION
 *
 *    Generic IP address structure to indicate either IPv4 or IPv6 address.
 *    This structure is used inside all SILC ID's. The true length of the
 *    ID depends of the length of the IP address.
 *
 * SOURCE
 */
typedef struct {
  unsigned char data[16];	/* IP data (in MSB first order) */
  uint8 data_len;		/* Length of the data (4 or 16) */
} SilcIDIP;
/***/

/****s* silccore/SilcIDAPI/SilcServerID
 *
 * NAME
 * 
 *    typedef struct { ... } SilcServerID;
 *
 * DESCRIPTION
 *
 *    64 or 160 bit SilcServerID structure:
 *  
 *     n bit IP address
 *    16 bit port
 *    16 bit random number
 *
 * SOURCE
 */
typedef struct {
  SilcIDIP ip;			/* n bit IP address */
  uint16 port;			/* 16 bit port */
  uint16 rnd;			/* 16 bit random number */
} SilcServerID;
/***/

/****s* silccore/SilcIDAPI/SilcClientID
 *
 * NAME
 * 
 *    typedef struct { ... } SilcClientID;
 *
 * DESCRIPTION
 *
 *    128 or 224 bit SilcClientID structure:
 *
 *      n bit ServerID IP address [bits 1-32 or bits 1-128]
 *      8 bit random number
 *     88 bit hash value from nickname
 *
 * SOURCE
 */
typedef struct {
  SilcIDIP ip;					/* n bit IP address */
  unsigned char rnd;				/* 8 bit random number */
  unsigned char hash[CLIENTID_HASH_LEN];	/* 88 bit MD5 hash */
} SilcClientID;
/***/

/****s* silccore/SilcIDAPI/SilcChannelID
 *
 * NAME
 * 
 *    typedef struct { ... } SilcChannelID;
 *
 * DESCRIPTION
 *
 *    64 or 160 bit SilcChannel ID structure:
 *
 *     n bit Router's ServerID IP address [bits 1-32 or bits 1-128]
 *    16 bit Router's ServerID port [bits 33-48 or bits 129-144]
 *    16 bit random number
 *
 * SOURCE
 */
typedef struct {
  SilcIDIP ip;					/* n bit IP address */
  uint16 port;					/* 16 bit port */
  uint16 rnd;					/* 16 bit random number */
} SilcChannelID;
/***/

/* Macros */

/****d* silccore/SilcIDAPI/SILC_ID_COMPARE
 *
 * NAME
 * 
 *    #define SILC_ID_COMPARE ...
 *
 * DESCRIPTION
 *
 *    Compares two ID's. Returns TRUE if they match and FALSE if they do
 *    not.
 *
 * SOURCE
 */
#define SILC_ID_COMPARE(id1, id2, len) (!memcmp(id1, id2, len))
/***/

/****d* silccore/SilcIDAPI/SILC_ID_CLIENT_COMPARE
 *
 * NAME
 * 
 *    #define SILC_ID_CLIENT_COMPARE ...
 *
 * DESCRIPTION
 *
 *    Compares Client ID's. Returns TRUE if they match.
 *
 * SOURCE
 */
#define SILC_ID_CLIENT_COMPARE(id1, id2) \
  SILC_ID_COMPARE(id1, id2, sizeof(SilcClientID))
/***/

/****d* silccore/SilcIDAPI/SILC_ID_SERVER_COMPARE
 *
 * NAME
 * 
 *    #define SILC_ID_SERVER_COMPARE ...
 *
 * DESCRIPTION
 *
 *    Compares Server ID's. Returns TRUE if they match.
 *
 * SOURCE
 */
#define SILC_ID_SERVER_COMPARE(id1, id2) \
  SILC_ID_COMPARE(id1, id2, sizeof(SilcServerID))
/***/

/****d* silccore/SilcIDAPI/SILC_ID_CHANNEL_COMPARE
 *
 * NAME
 * 
 *    #define SILC_ID_CHANNEL_COMPARE ...
 *
 * DESCRIPTION
 *
 *    Compares Channel ID's. Returns TRUE if they match.
 *
 * SOURCE
 */
#define SILC_ID_CHANNEL_COMPARE(id1, id2) \
  SILC_ID_COMPARE(id1, id2, sizeof(SilcChannelID))
/***/

/****d* silccore/SilcIDAPI/SILC_ID_COMPARE_TYPE
 *
 * NAME
 * 
 *    #define SILC_ID_COMPARE_TYPE ...
 *
 * DESCRIPTION
 *
 *    Compares two ID's by type. Returns TRUE if they match.
 *
 * SOURCE
 */
#define SILC_ID_COMPARE_TYPE(id1, id2, type)			\
  (type == SILC_ID_SERVER ? SILC_ID_SERVER_COMPARE(id1, id2) :	\
   type == SILC_ID_CLIENT ? SILC_ID_CLIENT_COMPARE(id1, id2) :	\
   SILC_ID_CHANNEL_COMPARE(id1, id2))
/***/

/****d* silccore/SilcIDAPI/SILC_ID_COMPARE_HASH
 *
 * NAME
 * 
 *    #define SILC_ID_COMPARE_HASH ...
 *
 * DESCRIPTION
 *
 *    Compares the nickname hash of the Client ID. Returns TRUE if
 *    they match. Since the nickname hash is based on the nickname of
 *    the client this can be used to search the ID by nickname (taking
 *    the hash out of it) or using the hash from the ID.
 *
 * SOURCE
 */
#define SILC_ID_COMPARE_HASH(id1, id2) \
  (!memcmp((id1)->hash, (id2)->hash, CLIENTID_HASH_LEN))
/***/

/* Prototypes */

/****f* silccore/SilcIDAPI/silc_id_id2str
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_id_id2str(void *id, SilcIdType type);
 *
 * DESCRIPTION
 *
 *    Converts an ID of type `type' to data. This can be used to
 *    convert the ID's to data for inclusion in the packets.
 *
 ***/
unsigned char *silc_id_id2str(void *id, SilcIdType type);

/****f* silccore/SilcIDAPI/silc_id_str2id
 *
 * SYNOPSIS
 *
 *    void *silc_id_str2id(unsigned char *id, uint32 id_len, SilcIdType type);
 *
 * DESCRIPTION
 *
 *    Converts ID data string to an ID. This can be used to get the
 *    ID out of data that has been taken for example from packet.
 *
 ***/
void *silc_id_str2id(unsigned char *id, uint32 id_len, SilcIdType type);

/****f* silccore/SilcIDAPI/silc_id_get_len
 *
 * SYNOPSIS
 *
 *    uint32 silc_id_get_len(void *id, SilcIdType type);
 *
 * DESCRIPTION
 *
 *    Returns the true length of the ID of the type `type'.
 *
 ***/
uint32 silc_id_get_len(void *id, SilcIdType type);

/****f* silccore/SilcIDAPI/silc_id_dup
 *
 * SYNOPSIS
 *
 *    void *silc_id_dup(void *id, SilcIdType type);
 *
 * DESCRIPTION
 *
 *    Duplicates the ID of the type `type'. The caller must free the
 *    duplicated ID.
 *
 ***/
void *silc_id_dup(void *id, SilcIdType type);

#endif
