/*

  silcpacket.h

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

#ifndef SILCPACKET_H
#define SILCPACKET_H

/* Amount of bytes to be read from the socket connection at once. */
#define SILC_PACKET_READ_SIZE 16384

/* Default byte size of the packet. This can be set larger if this
   is not enough, we shall see. */
#define SILC_PACKET_DEFAULT_SIZE 2048

/* Header length without source and destination ID's. */
#define SILC_PACKET_HEADER_LEN 8 + 2

/* Minimum length of SILC Packet Header. This much is decrypted always
   when packet is received to be able to get all the relevant data out
   from the header. */
#define SILC_PACKET_MIN_HEADER_LEN 16 + 2

/* Maximum padding length */
#define SILC_PACKET_MAX_PADLEN 16

/* Minimum packet length */
#define SILC_PACKET_MIN_LEN (SILC_PACKET_HEADER_LEN + 1)

/* Maximum length of ID */
#define SILC_PACKET_MAX_ID_LEN 16

/* SILC packet type definition. For now, it is defined like this and I don't 
   expect it to change in any near future. If one byte as a packet type is 
   not enough we can, then, think something else. */
typedef unsigned char SilcPacketType;

/* SILC packet version type definition. */
typedef unsigned char SilcPacketVersion;

/* SILC packet flags type definition. */
typedef unsigned char SilcPacketFlags;

/* All defined packet flags */
#define SILC_PACKET_FLAG_NONE             0x00
#define SILC_PACKET_FLAG_PRIVMSG_KEY      0x01
#define SILC_PACKET_FLAG_BROADCAST        0x02
#define SILC_PACKET_FLAG_TUNNELED         0x04
/* Rest of flags still available
#define SILC_PACKET_FLAG_XXX              0x08
#define SILC_PACKET_FLAG_XXX              0x10
#define SILC_PACKET_FLAG_XXX              0x20
#define SILC_PACKET_FLAG_XXX              0x40
#define SILC_PACKET_FLAG_XXX              0x80
*/

/* 
   SILC packet context. 

   In packet sending this is filled and sent to silc_packet_assemble 
   which then uses it to assemble new packet. In packet reception pointer 
   to this context is sent to silc_packet_parse which parses the packet 
   and returns the relevant information to this structure. On packet 
   reception returned ID's are always the hash values of the ID's from 
   the packet. 

   Short description of the fields following:

   SilcBuffer buffer

       The data buffer.

   SilcPacketType type

       Type of the packet. Types are defined below.

   SilcPacketFlags flags

       Packet flags. Flags are defined above.

   unsigned char *src_id
   unsigned short src_id_len
   unsigned char src_id_type

       Source ID, its length and type. On packet reception retuned ID's
       are always the hash values of the ID's from the packet.

  unsigned char *dst_id;
  unsigned short dst_id_len;
  unsigned char src_id_type;

       Destination ID, its length and type. On packet reception retuned
       ID's are always the hash values of the ID's from the packet.

   SilcHash hash

       Pointer to allocated hash object. This must be MD5 hash object.
       This is used to calculate checksum of the packet.

*/
typedef struct {
  SilcBuffer buffer;
  SilcPacketType type;
  SilcPacketFlags flags;

  unsigned char *src_id;
  unsigned short src_id_len;
  unsigned char src_id_type;

  unsigned char *dst_id;
  unsigned short dst_id_len;
  unsigned char dst_id_type;

  unsigned short truelen;
  unsigned short padlen;

  /* For padding generation */
  SilcRng rng;

  /* Back pointers */
  void *context;
  SilcSocketConnection sock;

  /* Reference count for this context. The context is free'd only
     after the reference count is zero. */
  int users;
} SilcPacketContext;

/* 
   Silc Packet Parser context.

   This context is used in packet reception when silc_packet_receive_process
   function calls parser callback that performs the actual packet decryption
   and parsing. This context is sent as argument to the parser function.
   This context must be free'd by the parser callback function.

   Following description of the fields:

   SilcPacketContext *packet

       The actual packet received from the network. In this phase the
       context is not parsed, only the packet->buffer is allocated and
       it includes the raw packet data, which is encrypted.

   SilcSocketConnection sock

       The associated connection.

   SilcCipher cipher

       The cipher to be used in the decryption.

   SilcHmac hmac

       The HMAC to be used in the decryption.

   void *context

       User context that is sent to the silc_packet_receive_process
       function. This usually includes application and connection specific
       data.

*/

typedef struct {
  SilcPacketContext *packet;
  SilcSocketConnection sock;
  SilcCipher cipher;
  SilcHmac hmac;
  void *context;
} SilcPacketParserContext;

/* The parser callback function. */
typedef void (*SilcPacketParserCallback)(SilcPacketParserContext 
					 *parse_context);


/* SILC Packet types. */
#define SILC_PACKET_NONE		 0       /* NULL, never sent */
#define SILC_PACKET_DISCONNECT		 1	 /* Disconnection */
#define SILC_PACKET_SUCCESS		 2	 /* Success */
#define SILC_PACKET_FAILURE		 3	 /* Failure */
#define SILC_PACKET_REJECT		 4	 /* Rejected */
#define SILC_PACKET_NOTIFY               5       /* Notify message */
#define SILC_PACKET_ERROR                6       /* Error message */
#define SILC_PACKET_CHANNEL_MESSAGE	 7	 /* Message for channel */
#define SILC_PACKET_CHANNEL_KEY          8       /* Key of the channel */
#define SILC_PACKET_PRIVATE_MESSAGE      9       /* Private message */
#define SILC_PACKET_PRIVATE_MESSAGE_KEY  10      /* Private message key*/
#define SILC_PACKET_COMMAND              11      /* Command */
#define SILC_PACKET_COMMAND_REPLY        12      /* Reply to a command */
#define SILC_PACKET_KEY_EXCHANGE         13      /* Start of KE */
#define SILC_PACKET_KEY_EXCHANGE_1       14      /* KE1 */
#define SILC_PACKET_KEY_EXCHANGE_2       15      /* KE2 */
#define SILC_PACKET_CONNECTION_AUTH_REQUEST 16   /* Request of auth meth */
#define SILC_PACKET_CONNECTION_AUTH      17      /* Connectinon auth */
#define SILC_PACKET_NEW_ID               18      /* Sending new ID */
#define SILC_PACKET_NEW_ID_LIST          19      /* Sending list of them */
#define SILC_PACKET_NEW_CLIENT           20      /* Registering client */
#define SILC_PACKET_NEW_SERVER           21      /* Registering server */
#define SILC_PACKET_NEW_CHANNEL          22      /* Registering channel */
#define SILC_PACKET_NEW_CHANNEL_USER     23      /*   "" user on channel */
#define SILC_PACKET_NEW_CHANNEL_LIST     24      /* List of new channels */
#define SILC_PACKET_NEW_CHANNEL_USER_LIST 25     /* List of users on "" */
#define SILC_PACKET_REPLACE_ID           26      /* To replace old ID */
#define SILC_PACKET_REMOVE_ID            27      /* To remove ID */
#define SILC_PACKET_REMOVE_CHANNEL_USER  28      /* Remove user from channel */
#define SILC_PACKET_REKEY                29
#define SILC_PACKET_REKEY_DONE           30
#define SILC_PACKET_SET_MODE             31      /* Set mode */
#define SILC_PACKET_HEARTBEAT            32      /* Heartbeat */
/* #define SILC_PACKET_MAX               255 */

/* Macros */

/* Returns true length of the packet and padded length of the packet */
#define SILC_PACKET_LENGTH(__packet, __ret_truelen, __ret_padlen)	     \
do {									     \
  SILC_GET16_MSB((__ret_truelen), (__packet)->data);			     \
  (__ret_padlen) = (((__ret_truelen) - 2) +				     \
		    SILC_PACKET_MAX_PADLEN) & ~(SILC_PACKET_MAX_PADLEN - 1); \
} while(0)

/* Returns pad length of the packet */
#define SILC_PACKET_PADLEN(__packetlen)					 \
  SILC_PACKET_MAX_PADLEN - ((__packetlen) - 2) % SILC_PACKET_MAX_PADLEN;

/* Prototypes */
int silc_packet_write(int sock, SilcBuffer src);
int silc_packet_send(SilcSocketConnection sock, int force_send);
void silc_packet_encrypt(SilcCipher cipher, SilcHmac hmac, 
			 SilcBuffer buffer, unsigned int len);
void silc_packet_assemble(SilcPacketContext *ctx);
void silc_packet_send_prepare(SilcSocketConnection sock,
			      unsigned int header_len,
			      unsigned int padlen,
			      unsigned int data_len);
int silc_packet_read(int sock, SilcBuffer dest);
int silc_packet_receive(SilcSocketConnection sock);
int silc_packet_decrypt(SilcCipher cipher, SilcHmac hmac,
			SilcBuffer buffer, SilcPacketContext *packet);
void silc_packet_receive_process(SilcSocketConnection sock,
				 SilcCipher cipher, SilcHmac hmac,
				 SilcPacketParserCallback parser,
				 void *context);
SilcPacketType silc_packet_parse(SilcPacketContext *ctx);
SilcPacketType silc_packet_parse_special(SilcPacketContext *ctx);
SilcPacketContext *silc_packet_context_alloc();
SilcPacketContext *silc_packet_context_dup(SilcPacketContext *ctx);
void silc_packet_context_free(SilcPacketContext *ctx);

#endif
