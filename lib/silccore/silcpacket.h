/*

  silcpacket.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silccore/SilcPacketAPI
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

/* Default byte size of the packet. */
#define SILC_PACKET_DEFAULT_SIZE SILC_SOCKET_BUF_SIZE

/* Header length without source and destination ID's. */
#define SILC_PACKET_HEADER_LEN 10

/* Minimum length of SILC Packet Header. This much is decrypted always
   when packet is received to be able to get all the relevant data out
   from the header. */
#define SILC_PACKET_MIN_HEADER_LEN 16

/* Maximum padding length */
#define SILC_PACKET_MAX_PADLEN 128

/* Default padding length */
#define SILC_PACKET_DEFAULT_PADLEN 16

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
#define SILC_PACKET_RESUME_ROUTER        26      /* Backup router resume */
#define SILC_PACKET_FTP                  27      /* File Transfer */

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
 *    SilcUInt8 src_id_len
 *    unsigned char src_id_type
 *
 *      Source ID, its length and type. On packet reception retuned ID's
 *      are always the hash values of the ID's from the packet.
 *
 *    unsigned char *dst_id;
 *    SilcUInt8 dst_id_len;
 *    unsigned char src_id_type;
 *
 *      Destination ID, its length and type. On packet reception retuned
 *      ID's are always the hash values of the ID's from the packet.
 *
 *    SilcUInt16 truelen
 *    SilcUInt8 padlen
 *
 *      The true lenght of the packet and the padded length of the packet.
 *      These may be set by the caller before calling any of the 
 *      silc_packet_* routines. If not provided the library will calculate
 *      the values.
 *
 *    int users;
 *
 *      Reference counter for this context. The context is freed only 
 *      after the reference counter hits zero. The counter is added
 *      calling silc_packet_context_dup and decreased by calling the
 *      silc_packet_context_free.
 *
 *    SilcUInt32 sequence;
 *
 *      Packet sequence number.
 *
 ***/
typedef struct {
  SilcBuffer buffer;

  SilcUInt16 truelen;
  SilcPacketFlags flags;
  SilcPacketType type;
  SilcUInt8 padlen;

  unsigned char *src_id;
  SilcUInt8 src_id_len;
  SilcUInt8 src_id_type;

  unsigned char *dst_id;
  SilcUInt8 dst_id_len;
  SilcUInt8 dst_id_type;

  int users;
  bool long_pad;		/* Set to TRUE to use maximum padding
				   in packet (up to 256 bytes). */

  SilcUInt32 sequence;
} SilcPacketContext;

/****s* silccore/SilcPacketAPI/SilcPacketParserContext
 *
 * NAME
 * 
 *    typedef struct { ... } SilcPacketParserContext;
 *
 * DESCRIPTION
 *
 *    This context is used in packet reception when the function
 *    silc_packet_receive_process calls parser callback that performs
 *    the actual packet decryption and parsing. This context is sent as
 *    argument to the parser function. This context must be free'd by
 *    the parser callback function.
 *
 *    Following description of the fields:
 *
 *    SilcPacketContext *packet
 *
 *      The actual packet received from the network. In this phase the
 *      context is not parsed, only the packet->buffer is allocated and
 *      it includes the raw packet data, which is encrypted.
 *
 *    bool normal
 *
 *      Indicates whether the received packet is normal or special packet.
 *      If special the parsing process is special also.
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
  bool normal;
  SilcSocketConnection sock;
  void *context;
} SilcPacketParserContext;

/****f* silccore/SilcPacketAPI/SilcPacketParserCallback
 *
 * SYNOPSIS
 *
 *    typedef bool (*SilcPacketParserCallback)(SilcPacketParserContext 
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
 *    This returns TRUE if the library should continue packet processing
 *    (assuming there is more data to be processed), and FALSE if the
 *    upper layer does not want the library to continue but to leave the
 *    rest of the data is the packet queue untouched.  Application may
 *    want to do this for example if the cipher is not ready before 
 *    processing a certain packet.  In this case the application wants
 *    to recall the processing function with the correct cipher.
 *
 ***/
typedef bool (*SilcPacketParserCallback)(SilcPacketParserContext 
					 *parse_context, void *context);

/* Macros */

/****d* silccore/SilcPacketAPI/SILC_PACKET_LENGTH
 *
 * NAME
 * 
 *    #define SILC_PACKET_LENGTH ...
 *
 * DESCRIPTION
 *
 *    Returns true length of the packet. This is primarily used by the
 *    libary in packet parsing phase but the application may use it as
 *    well if needed.
 *
 * SOURCE
 */
#define SILC_PACKET_LENGTH(__packet, __ret_truelen, __ret_paddedlen)	\
do {									\
  SILC_GET16_MSB((__ret_truelen), (__packet)->data);			\
  (__ret_paddedlen) = (__ret_truelen) + (__packet)->data[4];		\
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
#define SILC_PACKET_PADLEN(__packetlen, __blocklen)		\
  SILC_PACKET_DEFAULT_PADLEN - (__packetlen) %			\
    ((__blocklen) ? (__blocklen) : SILC_PACKET_DEFAULT_PADLEN)
/***/

/****d* silccore/SilcPacketAPI/SILC_PACKET_PADLEN_MAX
 *
 * NAME
 * 
 *    #define SILC_PACKET_PADLEN_MAX ...
 *
 * DESCRIPTION
 *
 *    Returns the length of the padding up to the maximum length, which
 *    is 128 butes. This is used by various library routines to determine
 *    needed padding length.
 *
 * SOURCE
 */
#define SILC_PACKET_PADLEN_MAX(__packetlen)				\
  SILC_PACKET_MAX_PADLEN - (__packetlen) % SILC_PACKET_MAX_PADLEN
/***/

/* Prototypes */

/****f* silccore/SilcPacketAPI/silc_packet_send
 *
 * SYNOPSIS
 *
 *    int silc_packet_send(SilcSocketConnection sock, bool force_send);
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
int silc_packet_send(SilcSocketConnection sock, bool force_send);

/****f* silccore/SilcPacketAPI/silc_packet_encrypt
 *
 * SYNOPSIS
 *
 *    void silc_packet_encrypt(SilcCipher cipher, SilcHmac hmac, 
 *                             SilcBuffer buffer, SilcUInt32 len);
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
void silc_packet_encrypt(SilcCipher cipher, SilcHmac hmac, SilcUInt32 sequence,
			 SilcBuffer buffer, SilcUInt32 len);

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
void silc_packet_assemble(SilcPacketContext *ctx, SilcCipher cipher);

/****f* silccore/SilcPacketAPI/silc_packet_send_prepare
 *
 * SYNOPSIS
 *
 *    void silc_packet_send_prepare(SilcSocketConnection sock,
 *                                  SilcUInt32 header_len,
 *                                  SilcUInt32 padlen,
 *                                  SilcUInt32 data_len);
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
			      SilcUInt32 header_len,
			      SilcUInt32 padlen,
			      SilcUInt32 data_len);

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

/****f* silccore/SilcPacketAPI/silc_packet_receive_process
 *
 * SYNOPSIS
 *
 *    bool silc_packet_receive_process(SilcSocketConnection sock,
 *                                     bool local_is_router,
 *                                     SilcCipher cipher, SilcHmac hmac,
 *                                     SilcPacketParserCallback parser,
 *                                     void *parser_context);
 *
 * DESCRIPTION
 *
 *    Processes and decrypts the incoming data, and calls parser callback
 *    for each received packet that will handle the actual packet parsing.
 *    If more than one packet was received this calls the parser multiple
 *    times.  The parser callback will get context SilcPacketParserContext
 *    that includes the packet and the `parser_context' sent to this
 *    function. 
 *
 *    The `local_is_router' indicates whether the caller is router server
 *    in which case the receiving process of a certain packet types may
 *    be special.  Normal server and client must set it to FALSE.  The
 *    SilcPacketParserContext will indicate also whether the received
 *    packet was normal or special packet.
 *
 ***/
bool silc_packet_receive_process(SilcSocketConnection sock,
				 bool local_is_router,
				 SilcCipher cipher, SilcHmac hmac,
				 SilcUInt32 sequence,
				 SilcPacketParserCallback parser,
				 void *parser_context);

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
SilcPacketType silc_packet_parse(SilcPacketContext *ctx, SilcCipher cipher);

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
SilcPacketType silc_packet_parse_special(SilcPacketContext *ctx,
					 SilcCipher cipher);

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
SilcPacketContext *silc_packet_context_alloc(void);

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
