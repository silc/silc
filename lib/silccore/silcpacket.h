/****h* silccore/silcpacket.h
 *
 * NAME
 *
 * silcpacket.h
 *
 * COPYRIGHT
 *
 * Author: Pekka Riikonen <priikone@poseidon.pspt.fi>
 *
 * Copyright (C) 1997 - 2001 Pekka Riikonen
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
 * Implementation of the packet routines for sending and receiving
 * SILC Packets. These includes the data sending routines and data
 * reading routines, encrypting and decrypting routines, packet assembling
 * and packet parsing routines.
 *
 ***/

#ifndef SILCPACKET_H
#define SILCPACKET_H

/* Amount of bytes to be read from the socket connection at once. */
#define SILC_PACKET_READ_SIZE 16384

/* Default byte size of the packet. */
#define SILC_PACKET_DEFAULT_SIZE 1024

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

/****d* silccore/SilcPacketAPI/SilcPacketType
 *
 * NAME
 * 
 *    typedef unsigned char SilcPacketType;
 *
 * DESCRIPTION
 *
 *    SILC packet type definition and all the packet types.
 *
 * SOURCE
 */
typedef unsigned char SilcPacketType;

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
#define SILC_PACKET_NEW_CLIENT           19      /* Client registering */
#define SILC_PACKET_NEW_SERVER           20      /* Server registering */
#define SILC_PACKET_NEW_CHANNEL          21      /* Channel registering */
#define SILC_PACKET_REKEY                22      /* Re-key start */
#define SILC_PACKET_REKEY_DONE           23      /* Re-key done */
#define SILC_PACKET_HEARTBEAT            24      /* Heartbeat */
#define SILC_PACKET_KEY_AGREEMENT        25      /* Key Agreement request */
#define SILC_PACKET_CELL_ROUTERS         26      /* Cell routers backup */

#define SILC_PACKET_PRIVATE              200     /* Private range start  */
#define SILC_PACKET_MAX                  255     /* RESERVED */
/***/

/****d* silccore/SilcPacketAPI/SilcPacketVersion
 *
 * NAME
 * 
 *    typedef unsigned char SilcPacketVersion;
 *
 * DESCRIPTION
 *
 *    SILC packet version type definition.
 *
 ***/
typedef unsigned char SilcPacketVersion;

/****d* silccore/SilcPacketAPI/SilcPacketFlags
 *
 * NAME
 * 
 *    typedef unsigned char SilcPacketFlags;
 *
 * DESCRIPTION
 *
 *    SILC packet flags type definition and all the packet flags.
 *
 * SOURCE
 */
typedef unsigned char SilcPacketFlags;

/* All defined packet flags */
#define SILC_PACKET_FLAG_NONE             0x00    /* No flags */
#define SILC_PACKET_FLAG_PRIVMSG_KEY      0x01	  /* Private message key */
#define SILC_PACKET_FLAG_LIST             0x02	  /* Packet is a list */
#define SILC_PACKET_FLAG_BROADCAST        0x04	  /* Packet is a broadcast */
/***/

/* Rest of flags still available
#define SILC_PACKET_FLAG_XXX              0x08
#define SILC_PACKET_FLAG_XXX              0x10
#define SILC_PACKET_FLAG_XXX              0x20
#define SILC_PACKET_FLAG_XXX              0x40
#define SILC_PACKET_FLAG_XXX              0x80
*/

/****s* silccore/SilcPacketAPI/SilcPacketContext
 *
 * NAME
 * 
 *    typedef struct { ... } SilcPacketContext;
 *
 * DESCRIPTION
 *
 *    In packet sending this is filled and sent to silc_packet_assemble 
 *    which then uses it to assemble new packet. In packet reception pointer 
 *    to this context is sent to silc_packet_parse which parses the packet 
 *    and returns the relevant information to this structure. On packet 
 *    reception returned ID's are always the hash values of the ID's from 
 *    the packet. 
 *
 *    Short description of the fields following:
 *
 *    SilcBuffer buffer
 *
 *      The data buffer.
 *
 *    SilcPacketType type
 *
 *      Type of the packet. Types are defined below.
 *
 *    SilcPacketFlags flags
 *
 *      Packet flags. Flags are defined above.
 *
 *    unsigned char *src_id
 *    uint16 src_id_len
 *    unsigned char src_id_type
 *
 *      Source ID, its length and type. On packet reception retuned ID's
 *      are always the hash values of the ID's from the packet.
 *
 *    unsigned char *dst_id;
 *    uint16 dst_id_len;
 *    unsigned char src_id_type;
 *
 *      Destination ID, its length and type. On packet reception retuned
 *      ID's are always the hash values of the ID's from the packet.
 *
 *    uint16 truelen
 *    uint16 padlen
 *
 *      The true lenght of the packet and the padded length of the packet.
 *      These may be set by the caller before calling any of the 
 *      silc_packet_* routines. If not provided the library will calculate
 *      the values.
 *
 *    in users;
 *
 *      Reference counter for this context. The context is freed only 
 *      after the reference counter hits zero. The counter is added
 *      calling silc_packet_context_dup and decreased by calling the
 *      silc_packet_context_free.
 *
 ***/
typedef struct {
  SilcBuffer buffer;
  SilcPacketType type;
  SilcPacketFlags flags;

  unsigned char *src_id;
  uint16 src_id_len;
  unsigned char src_id_type;

  unsigned char *dst_id;
  uint16 dst_id_len;
  unsigned char dst_id_type;

  uint16 truelen;
  uint16 padlen;

  /* Back pointers */
  void *context;
  SilcSocketConnection sock;

  int users;
} SilcPacketContext;

/****s* silccore/SilcPacketAPI/SilcPacketParserContext
 *
 * NAME
 * 
 *    typedef struct { ... } SilcPacketParserContext;
 *
 * DESCRIPTION
 *
 *    This context is used in packet reception when silc_packet_receive_process
 *    function calls parser callback that performs the actual packet decryption
 *    and parsing. This context is sent as argument to the parser function.
 *    This context must be free'd by the parser callback function.
 *
 *    Following description of the fields:
 *
 *    SilcPacketContext *packet
 *
 *      The actual packet received from the network. In this phase the
 *      context is not parsed, only the packet->buffer is allocated and
 *      it includes the raw packet data, which is encrypted.
 *
 *    SilcSocketConnection sock
 *
 *      The associated connection.
 *
 *    void *context
 *
 *      User context that is sent to the silc_packet_receive_process
 *      function. This usually includes application and connection specific
 *      data.
 *
 ***/
typedef struct {
  SilcPacketContext *packet;
  SilcSocketConnection sock;
  void *context;
} SilcPacketParserContext;

/****f* silccore/SilcPacketAPI/SilcPacketParserCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcPacketParserCallback)(SilcPacketParserContext 
 *                                             *parse_context);
 *
 * DESCRIPTION
 *
 *    This callback is given to the silc_packet_receive_process function.
 *    The callback is called by the library every time a packet is
 *    received from the network. After the packet has been decrypted
 *    and at least partially parsed it is passed to the application
 *    for further parsing using this callback and the SilcPacketParserContext
 *    context. The application receiving the SilcPacketParserContext
 *    must free it.
 *
 ***/
typedef void (*SilcPacketParserCallback)(SilcPacketParserContext 
					 *parse_context);

/****f* silccore/SilcPacketAPI/SilcPacketCheckDecrypt
 *
 * SYNOPSIS
 *
 *    typedef int (*SilcPacketCheckDecrypt)(SilcPacketType packet_type,
 *                                          SilcBuffer buffer,
 *                                          SilcPacketContext *packet,
 *                                          void *context);
 *
 * DESCRIPTION
 *
 *    This callback function relates to the checking whether the packet is
 *    normal packet or special packet and how it should be processed.  If
 *    the callback returns TRUE the packet is normal and FALSE if the packet
 *    is special and requires special procesing. Some of the packets in
 *    SILC are special (like channel message packets that are encrypted
 *    using channel specific keys) and requires special processing. That
 *    is the reason for this callback function.
 *
 *    The library will call this function if provided for the
 *    silc_packet_decrypt function. The `packet_type' is the type of
 *    packet received (this is also actually the first time application
 *    receives information of the received packet, next time it receives
 *    it is when the SilcPacketParserCallback function is called),
 *    the `buffer' is the raw packet data the `packet' the allocated
 *    SilcPacketContext that is filled when parsing the packet and `context'
 *    is application specific user context.
 *
 ***/
typedef int (*SilcPacketCheckDecrypt)(SilcPacketType packet_type,
				      SilcBuffer buffer,
				      SilcPacketContext *packet,
				      void *context);

/* Macros */

/****d* silccore/SilcPacketAPI/SILC_PACKET_LENGTH
 *
 * NAME
 * 
 *    #define SILC_PACKET_LENGTH ...
 *
 * DESCRIPTION
 *
 *    Returns true length of the packet and padded length of the packet.
 *    This is primarily used by the libary in packet parsing phase but
 *    the application may use it as well if needed.
 *
 * SOURCE
 */
#define SILC_PACKET_LENGTH(__packet, __ret_truelen, __ret_padlen)	     \
do {									     \
  SILC_GET16_MSB((__ret_truelen), (__packet)->data);			     \
  (__ret_padlen) = (((__ret_truelen) - 2) +				     \
		    SILC_PACKET_MAX_PADLEN) & ~(SILC_PACKET_MAX_PADLEN - 1); \
} while(0)
/***/

/****d* silccore/SilcPacketAPI/SILC_PACKET_PADLEN
 *
 * NAME
 * 
 *    #define SILC_PACKET_PADLEN ...
 *
 * DESCRIPTION
 *
 *    Returns the length of the padding in the packet. This is used
 *    by various library routines to determine needed padding length.
 *
 * SOURCE
 */
#define SILC_PACKET_PADLEN(__packetlen)					 \
  SILC_PACKET_MAX_PADLEN - ((__packetlen) - 2) % SILC_PACKET_MAX_PADLEN;
/***/

/* Prototypes */

/****f* silccore/SilcPacketAPI/silc_packet_write
 *
 * SYNOPSIS
 *
 *    int silc_packet_write(int sock, SilcBuffer src);
 *
 * DESCRIPTION
 *
 *    Writes data from encrypted buffer to the socket connection. If the
 *    data cannot be written at once, it will be written later with a timeout. 
 *    The data is written from the data section of the buffer, not from head
 *    or tail section. This automatically pulls the data section towards end
 *    after writing the data.
 *
 ***/
int silc_packet_write(int sock, SilcBuffer src);

/****f* silccore/SilcPacketAPI/silc_packet_send
 *
 * SYNOPSIS
 *
 *    int silc_packet_send(SilcSocketConnection sock, int force_send);
 *
 * DESCRIPTION
 *
 *    Actually sends the packet. This flushes the connections outgoing data
 *    buffer. If data is sent directly to the network this returns the bytes
 *    written, if error occured this returns -1 and if the data could not
 *    be written directly to the network at this time this returns -2, in
 *    which case the data should be queued by the caller and sent at some
 *    later time. If `force_send' is TRUE this attempts to write the data
 *    directly to the network, if FALSE, this returns -2.
 *
 ***/
int silc_packet_send(SilcSocketConnection sock, int force_send);

/****f* silccore/SilcPacketAPI/silc_packet_encrypt
 *
 * SYNOPSIS
 *
 *    void silc_packet_encrypt(SilcCipher cipher, SilcHmac hmac, 
 *                             SilcBuffer buffer, uint32 len);
 *
 * DESCRIPTION
 *
 *    Encrypts a packet. This also creates HMAC of the packet before 
 *    encryption and adds the HMAC at the end of the buffer. This assumes
 *    that there is enough free space at the end of the buffer to add the
 *    computed HMAC. This is the normal way of encrypting packets, if some
 *    other process of HMAC computing and encryption is needed this function
 *    cannot be used. 
 *
 ***/
void silc_packet_encrypt(SilcCipher cipher, SilcHmac hmac, 
			 SilcBuffer buffer, uint32 len);

/****f* silccore/SilcPacketAPI/silc_packet_assemble
 *
 * SYNOPSIS
 *
 *    void silc_packet_assemble(SilcPacketContext *ctx);
 *
 * DESCRIPTION
 *
 *    Assembles a new packet to be ready for send out. The buffer sent as
 *    argument must include the data to be sent and it must not be encrypted. 
 *    The packet also must have enough free space so that the SILC header
 *    and padding maybe added to the packet. The packet is encrypted after 
 *    this function has returned.
 *
 *    The buffer sent as argument should be something like following:
 *
 *    --------------------------------------------
 *    | head             | data           | tail |
 *    --------------------------------------------
 *    ^                  ^
 *    58 bytes           x bytes
 *
 *    So that the SILC header and 1 - 16 bytes of padding can fit to
 *    the buffer. After assembly the buffer might look like this:
 *
 *    --------------------------------------------
 *    | data                              |      |
 *    --------------------------------------------
 *    ^                                   ^
 *    Start of assembled packet
 *
 *    Packet construct is as follows (* = won't be encrypted):
 *
 *    n bytes       SILC Header
 *      2 bytes     Payload length  (*)
 *      1 byte      Flags
 *      1 byte      Packet type
 *      2 bytes     Source ID Length
 *      2 bytes     Destination ID Length
 *      1 byte      Source ID Type
 *      n bytes     Source ID
 *      1 byte      Destination ID Type
 *      n bytes     Destination ID
 *
 *    1 - 16 bytes    Padding
 *
 *    n bytes        Data payload
 *
 *    All fields in the packet will be authenticated by MAC. The MAC is
 *    not computed here, it must be computed separately before encrypting
 *    the packet.
 *
 ***/
void silc_packet_assemble(SilcPacketContext *ctx);

/****f* silccore/SilcPacketAPI/silc_packet_send_prepare
 *
 * SYNOPSIS
 *
 *    void silc_packet_send_prepare(SilcSocketConnection sock,
 *                                  uint32 header_len,
 *                                  uint32 padlen,
 *                                  uint32 data_len);
 *
 * DESCRIPTION
 *
 *    Prepare outgoing data buffer for packet sending. This moves the data
 *    area so that new packet may be added into it. If needed this allocates
 *    more space to the buffer. This handles directly the connection's
 *    outgoing buffer in SilcSocketConnection object.
 *
 ***/
void silc_packet_send_prepare(SilcSocketConnection sock,
			      uint32 header_len,
			      uint32 padlen,
			      uint32 data_len);

/****f* silccore/SilcPacketAPI/silc_packet_read
 *
 * SYNOPSIS
 *
 *    int silc_packet_read(int fd, SilcSocketConnection sock);
 *
 * DESCRIPTION
 *
 *    Reads data from the socket connection into the incoming data buffer.
 *    However, this does not parse the packet, it only reads some amount from
 *    the network. If there are more data available that can be read at a time
 *    the rest of the data will be read later with a timeout and only after
 *    that the packet is ready to be parsed. 
 *
 *    The destination buffer sent as argument must be initialized before 
 *    calling this function, and, the data section and the start of the tail
 *    section must be same. Ie. we add the read data to the tail section of
 *    the buffer hence the data section is the start of the buffer.
 *
 *    This returns amount of bytes read or -1 on error or -2 on case where
 *    all of the data could not be read at once.
 *
 ***/
int silc_packet_read(int fd, SilcSocketConnection sock);

/****f* silccore/SilcPacketAPI/silc_packet_receive
 *
 * SYNOPSIS
 *
 *    int silc_packet_receive(SilcSocketConnection sock);
 *
 * DESCRIPTION
 *
 *    Receives packet from network and reads the data into connection's
 *    incoming data buffer. If the data was read directly this returns the
 *    read bytes, if error occured this returns -1, if the data could not
 *    be read directly at this time this returns -2 in which case the data
 *    should be read again at some later time, or If EOF occured this returns
 *    0.
 *
 ***/
int silc_packet_receive(SilcSocketConnection sock);

/****f* silccore/SilcPacketAPI/silc_packet_decrypt
 *
 * SYNOPSIS
 *
 *    int silc_packet_decrypt(SilcCipher cipher, SilcHmac hmac,
 *                            SilcBuffer buffer, SilcPacketContext *packet,
 *                            SilcPacketCheckDecrypt check_packet,
 *                            void *context);
 *
 * DESCRIPTION
 *
 *    Decrypts a packet. This assumes that typical SILC packet is the
 *    packet to be decrypted and thus checks for normal and special SILC
 *    packets and can handle both of them. This also computes and checks
 *    the HMAC of the packet. If any other special or customized decryption
 *    processing is required this function cannot be used. This returns
 *    -1 on error, 0 when packet is normal packet and 1 when the packet
 *    is special and requires special processing. 
 *
 *    The `check_packet' is a callback funtion that this function will 
 *    call.  The callback relates to the checking whether the packet is
 *    normal packet or special packet and how it should be processed.  If
 *    the callback return TRUE the packet is normal and FALSE if the packet
 *    is special and requires special procesing.
 *
 ***/
int silc_packet_decrypt(SilcCipher cipher, SilcHmac hmac,
			SilcBuffer buffer, SilcPacketContext *packet,
			SilcPacketCheckDecrypt check_packet,
			void *context);

/****f* silccore/SilcPacketAPI/silc_packet_receive_process
 *
 * SYNOPSIS
 *
 *    void silc_packet_receive_process(SilcSocketConnection sock,
 *                                     SilcCipher cipher, SilcHmac hmac,
 *                                     SilcPacketParserCallback parser,
 *                                     void *context);
 *
 * DESCRIPTION
 *
 *    Processes the received data. This checks the received data and 
 *    calls parser callback that handles the actual packet decryption
 *    and parsing. If more than one packet was received this calls the
 *    parser multiple times. The parser callback will get context
 *    SilcPacketParserContext that includes the packet and the `context'
 *    sent to this function.
 *
 ***/
void silc_packet_receive_process(SilcSocketConnection sock,
				 SilcCipher cipher, SilcHmac hmac,
				 SilcPacketParserCallback parser,
				 void *context);

/****f* silccore/SilcPacketAPI/silc_packet_parse
 *
 * SYNOPSIS
 *
 *    SilcPacketType silc_packet_parse(SilcPacketContext *ctx);
 *
 * DESCRIPTION
 *
 *    Parses the packet. This is called when a whole packet is ready to be
 *    parsed. The buffer sent must be already decrypted before calling this 
 *    function. The len argument must be the true length of the packet. This 
 *    function returns the type of the packet. The data section of the 
 *    buffer is parsed, not head or tail sections.
 *
 ***/
SilcPacketType silc_packet_parse(SilcPacketContext *ctx);

/****f* silccore/SilcPacketAPI/silc_packet_parse_special
 *
 * SYNOPSIS
 *
 *    SilcPacketType silc_packet_parse_special(SilcPacketContext *ctx);
 *
 * DESCRIPTION
 *
 *    Perform special SILC Packet header parsing. This is required to some
 *    packet types that have the data payload encrypted with different key
 *    than the header area plus padding of the packet. Hence, this parses
 *    the header in a way that it does not take the data area into account
 *    and parses the header and padding area only.
 *
 ***/
SilcPacketType silc_packet_parse_special(SilcPacketContext *ctx);

/****f* silccore/SilcPacketAPI/silc_packet_context_alloc
 *
 * SYNOPSIS
 *
 *    SilcPacketContext *silc_packet_context_alloc();
 *
 * DESCRIPTION
 *
 *    Allocates a packet context. Packet contexts are used when 
 *    packets are assembled and parsed. The context is freed by the
 *    silc_packet_context_free function.
 *
 ***/
SilcPacketContext *silc_packet_context_alloc();

/****f* silccore/SilcPacketAPI/silc_packet_context_dup
 *
 * SYNOPSIS
 *
 *    SilcPacketContext *silc_packet_context_dup(SilcPacketContext *ctx);
 *
 * DESCRIPTION
 *
 *    Duplicates the packet context. It actually does not duplicate
 *    any data, instead a reference counter is increased.
 *
 ***/
SilcPacketContext *silc_packet_context_dup(SilcPacketContext *ctx);

/****f* silccore/SilcPacketAPI/silc_packet_context_free
 *
 * SYNOPSIS
 *
 *    void silc_packet_context_free(SilcPacketContext *ctx);
 *
 * DESCRIPTION
 *
 *    Frees the packet context. The context is actually freed when the
 *    reference counter hits zero.
 *
 ***/
void silc_packet_context_free(SilcPacketContext *ctx);

#endif
