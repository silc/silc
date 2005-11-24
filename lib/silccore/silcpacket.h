/*

  silcpacket.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silccore/Packet Protocol Interface
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

/* XXX many of these could go to silcpacket_i.h */

/* Maximum packet length */
#define SILC_PACKET_MAX_LEN 0xffff

/* Maximum length of ID */
#define SILC_PACKET_MAX_ID_LEN 28

/****d* silccore/SilcPacketAPI/SilcPacketType
 *
 * NAME
 *
 *    typedef SilcUInt8 SilcPacketType;
 *
 * DESCRIPTION
 *
 *    SILC packet type definition and all the packet types.
 *
 * SOURCE
 */
typedef SilcUInt8 SilcPacketType;

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
#define SILC_PACKET_RESUME_CLIENT        28      /* Client resume */

#define SILC_PACKET_PRIVATE              200     /* Private range start  */
#define SILC_PACKET_MAX                  255     /* RESERVED */
/***/

/****d* silccore/SilcPacketAPI/SilcPacketFlags
 *
 * NAME
 *
 *    typedef SilcUInt8 SilcPacketFlags;
 *
 * DESCRIPTION
 *
 *    SILC packet flags type definition and all the packet flags.
 *
 * SOURCE
 */
typedef SilcUInt8 SilcPacketFlags;

/* All defined packet flags */
#define SILC_PACKET_FLAG_NONE             0x00    /* No flags */
#define SILC_PACKET_FLAG_PRIVMSG_KEY      0x01	  /* Private message key */
#define SILC_PACKET_FLAG_LIST             0x02	  /* Packet is a list */
#define SILC_PACKET_FLAG_BROADCAST        0x04	  /* Packet is a broadcast */
#define SILC_PACKET_FLAG_COMPRESSED       0x08    /* Payload is compressed */

/* Impelemntation specific flags */
#define SILC_PACKET_FLAG_LONG_PAD         0x10    /* Use maximum padding */
/***/

/****s* silccore/SilcPacketAPI/SilcPacketEngine
 *
 * NAME
 *
 *    typedef struct SilcPacketEngineStruct *SilcPacketEngine;
 *
 * DESCRIPTION
 *
 *    The packet engine context, allocated by silc_packet_engine_start.
 *    The engine is destroyed with silc_packet_engine_stop.
 *
 ***/
typedef struct SilcPacketEngineStruct *SilcPacketEngine;

/****s* silccore/SilcPacketAPI/SilcPacketStream
 *
 * NAME
 *
 *    typedef struct SilcPacketStreamStruct *SilcPacketStream;
 *
 * DESCRIPTION
 *
 *    The packet stream context, allocated by silc_packet_stream_create.
 *    The stream is destroyed with silc_packet_stream_destroy.
 *
 ***/
typedef struct SilcPacketStreamStruct *SilcPacketStream;

/****s* silccore/SilcPacketAPI/SilcPacket
 *
 * NAME
 *
 *    typedef struct SilcPacketStruct *SilcPacket;
 *
 * DESCRIPTION
 *
 *    The SilcPacket is returned by the packet engine in the SilcPacketReceive
 *    callback.  The application can parse the data payload from the
 *    SilcPacket.  Also packet type, flags, and sender and destination
 *    IDs are available.  The application must free the packet with the
 *    silc_packet_free function.
 *
 * SOURCE
 */
typedef struct SilcPacketStruct {
  struct SilcPacketStruct *next;
  SilcBufferStruct buffer;		 /* Packet data payload */
  unsigned char *src_id;		 /* Source ID */
  unsigned char *dst_id;		 /* Destination ID */
  unsigned int src_id_len  : 6;		 /* Source ID length */
  unsigned int src_id_type : 2;		 /* Source ID type */
  unsigned int dst_id_len  : 6;		 /* Destination ID length */
  unsigned int dst_id_type : 2;		 /* Destination ID type */
  SilcPacketType type;			 /* Packet type */
  SilcPacketFlags flags;		 /* Packet flags */
} *SilcPacket;
/***/

/****d* silcutil/SilcPacketAPI/SilcPacketError
 *
 * NAME
 *
 *    typedef enum { ... } SilcPacketError
 *
 * DESCRIPTION
 *
 *    Packet errors.  This is returned in the error callback.  If application
 *    needs the actual lower level stream error, it needs to retrieve it
 *    from the actual stream.
 *
 * SOURCE
 */
typedef enum {
  SILC_PACKET_ERR_READ,			 /* Error while reading */
  SILC_PACKET_ERR_WRITE,       		 /* Error while writing */
  SILC_PACKET_ERR_MAC_FAILED,     	 /* Packet MAC check failed */
  SILC_PACKET_ERR_DECRYPTION_FAILED,   	 /* Packet decryption failed */
  SILC_PACKET_ERR_MALFORMED,		 /* Packet is malformed */
  SILC_PACKET_ERR_NO_MEMORY,	 	 /* System out of memory */
} SilcPacketError;
/***/

/****f* silccore/SilcPacketAPI/SilcPacketReceiveCb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcPacketReceiveCb)(SilcPacketEngine engine,
 *                                        SilcPacketStream stream,
 *                                        SilcPacket packet,
 *                                        void *callback_context,
 *                                        void *app_context);
 *
 * DESCRIPTION
 *
 *    The packet receive callback is called by the packet engine when a new
 *    SILC Packet has arrived.  The application must free the returned
 *    SilcPacket with silc_packet_free.  This callback is set in the
 *    SilcPacketCallbacks structure.
 *
 ***/
typedef void (*SilcPacketReceiveCb)(SilcPacketEngine engine,
				    SilcPacketStream stream,
				    SilcPacket packet,
				    void *callback_context,
				    void *app_context);

/****f* silccore/SilcPacketAPI/SilcPacketEosCb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcPacketEosCb)(SilcPacketEngine engine,
 *                                    SilcPacketStream stream,
 *                                    void *callback_context,
 *                                    void *app_context);
 *
 * DESCRIPTION
 *
 *    The End Of Stream (EOS) callback, that is called by the packet engine
 *    when the underlaying stream has ended.  No more data can be sent to
 *    the stream or read from it.  The `stream' must be destroyed by
 *    calling the silc_packet_stream_destroy.  This callback is set in the
 *    SilcPacketCallbacks structure.
 *
 ***/
typedef void (*SilcPacketEosCb)(SilcPacketEngine engine,
				SilcPacketStream stream,
				void *callback_context,
				void *app_context);

/****f* silccore/SilcPacketAPI/SilcPacketErrorCb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcPacketErrorCb)(SilcPacketEngine engine,
 *                                      SilcPacketStream stream,
 *                                      SilcPacketError error,
 *                                      void *callback_context,
 *                                      void *app_context);
 *
 * DESCRIPTION
 *
 *    The error callback that is called by the packet engine if an error
 *    occurs.  The `error' will indicate the error.  This callback is set
 *    in the SilcPacketCallbacks structure.
 *
 ***/
typedef void (*SilcPacketErrorCb)(SilcPacketEngine engine,
				  SilcPacketStream stream,
				  SilcPacketError error,
				  void *callback_context,
				  void *app_context);

/****s* silccore/SilcPacketAPI/SilcPacketStream
 *
 * NAME
 *
 *    typedef struct SilcPacketStreamStruct *SilcPacketStream;
 *
 * DESCRIPTION
 *
 *    This structure is sent as argument to the silc_packet_engine_start
 *    function to set the callback functions for the packet engine.  The
 *    packet engine will call the callbacks when necessary.  Application
 *    must always be provided for the packet engine.
 *
 * SOURCE
 */
typedef struct {
  SilcPacketReceiveCb packet_receive;	 /* Called when packet is received */
  SilcPacketEosCb eos;		         /* Called on end of stream */
  SilcPacketErrorCb error;	         /* Called on an error */
} SilcPacketCallbacks;
/***/

/* Prototypes */

/****f* silccore/SilcPacketAPI/silc_packet_engine_start
 *
 * SYNOPSIS
 *
 *    SilcPacketEngine
 *    silc_packet_engine_start(SilcSchedule schedule, SilcRng rng, bool router,
 *                             SilcPacketCallbacks *callbacks,
 *                             void *callback_context);
 *
 * DESCRIPTION
 *
 *    Create new packet engine for processing incoming and outgoing packets.
 *    If `rng' is non-NULL that RNG will be used to create necessary random
 *    numbers during packet processing.  If NULL, Global RNG will be used.
 *    If `router' is  TRUE then the application is considered to be router
 *    server, and certain packets are handled differently.  Client and normal
 *    server must set it to FALSE.  The `callbacks' is a SilcPacketCallbacks
 *    structure provided by the caller which includes the callbacks that is
 *    called when for example packet is received, or end of stream is called
 *
 * NOTES
 *
 *    The packet engine is thread safe.  Also the `schedule' and `rng' are
 *    thread safe.  You can use one packet engine in multi threaded
 *    application.
 *
 ***/
SilcPacketEngine
silc_packet_engine_start(SilcSchedule schedule, SilcRng rng, bool router,
			 SilcPacketCallbacks *callbacks,
			 void *callback_context);

/****f* silccore/SilcPacketAPI/silc_packet_engine_stop
 *
 * SYNOPSIS
 *
 *    void silc_packet_engine_stop(SilcPacketEngine engine);
 *
 * DESCRIPTION
 *
 *    Stop the packet engine.  No new packets can be sent or received after
 *    calling this, and the `engine' will become invalid.
 *
 ***/
void silc_packet_engine_stop(SilcPacketEngine engine);

/****f* silccore/SilcPacketAPI/silc_packet_stream_create
 *
 * SYNOPSIS
 *
 *    SilcPacketStream silc_packet_stream_create(SilcPacketEngine engine,
 *                                               SilcStream stream);
 *
 * DESCRIPTION
 *
 *    Create new packet stream and use the `stream' as underlaying stream.
 *    Usually the `stream' would be a socket stream, but it can be any
 *    stream.  After this function returns, packets can immediately be
 *    sent to or received from the stream.
 *
 * NOTES
 *
 *    SilcPacketStream cannot be used with silc_stream_* routines (such as
 *    silc_stream_read and silc_stream_write) because of its special nature.
 *    Use the silc_packet_send and the silc_packet_send_ext to send packets.
 *    To read packets you will receive the packet receive callback from
 *    packet engine.  Destroy the stream with silc_packet_stream_destroy.
 *
 *    If you need to send only one type of SILC packets, then it is possible
 *    to create SILC Packet Streamer with silc_packet_streamer_create, which
 *    can be used with silc_stream_read and silc_stream_write.
 *
 *    The SilcPacketStream is not thread safe.  If you share same stream
 *    with multiple threads concurrency control need to be employed.  It
 *    is recommended to create new SilcPacketStream for every thread.
 *
 ***/
SilcPacketStream silc_packet_stream_create(SilcPacketEngine engine,
					   SilcStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_stream_destroy
 *
 * SYNOPSIS
 *
 *    void silc_packet_stream_destroy(SilcPacketStream stream);
 *
 * DESCRIPTION
 *
 *    Destroy packet stream and the underlaying stream.  This will also
 *    send end of stream to the underlaying stream.
 *
 ***/
void silc_packet_stream_destroy(SilcPacketStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_streamer_create
 *
 * SYNOPSIS
 *
 *    SilcStream silc_packet_streamer_create(SilcPacketStream stream,
 *                                           SilcPacketType packet_type,
 *                                           SilcPacketFlags packet_flags);
 *
 * DESCRIPTION
 *
 *    This function can be used to create a SILC Packet Streamer that will
 *    stream only one type of packet indicated by `packet_type' with packet
 *    flags `packet_flags'.  This is special purpose function as usually
 *    multiple different types of packets need to be sent in application.
 *    There are cases however when creating streamer is simpler and more
 *    efficient.  Cases such as file transfer stream or other data streams
 *    that only send and receive one type of packet.  While it would be
 *    possible to use silc_packet_send function to send packets it is
 *    more efficient to create the SILC Packet Streamer and use the
 *    silc_stream_read and silc_stream_write functions.
 *
 *    The encryption and decryption keys, and other information will be
 *    retrieved from the packet stream indicated by `stream', which must be
 *    created before creating the streamer.
 *
 * NOTES
 *
 *    The packet type that is assocated with the packet stream `stream' will
 *    only be available through the returned SilcStream.  That packet type
 *    will not be delivered to the packet callbacks.  To return to the
 *    normal operation destroy the streamer silc_packet_streamer_destroy.
 *
 ***/
SilcStream silc_packet_streamer_create(SilcPacketStream stream,
				       SilcPacketType packet_type,
				       SilcPacketFlags packet_flags);

/****f* silccore/SilcPacketAPI/silc_packet_streamer_destroy
 *
 * SYNOPSIS
 *
 *    void silc_packet_streamer_destroy(SilcStream stream);
 *
 * DESCRIPTION
 *
 *    Destroys the created packet streamer.  Use this function only for
 *    stream created with silc_packet_streamer_create.  The packet type
 *    that was associated with the streamer can be received in the packet
 *    callbacks after the streamer is destroyed.
 *
 ***/
void silc_packet_streamer_destroy(SilcStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_stream_get_stream
 *
 * SYNOPSIS
 *
 *    SilcStream silc_packet_stream_get_stream(SilcPacketStream stream);
 *
 * DESCRIPTION
 *
 *    Returns the actual stream that is associated with the packet stream
 *    `stream'.  The caller must not free the returned stream.  The returned
 *    stream is the same pointer that was set for silc_packet_stream_create.
 *    This function couled be used for example when an error callback is
 *    called by the packet engine to retrieve the actual lower level error
 *    from the stream.
 *
 ***/
SilcStream silc_packet_stream_get_stream(SilcPacketStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_stream_callbacks
 *
 * SYNOPSIS
 *
 *    void silc_packet_stream_callbacks(SilcPacketStream stream,
 *                                      SilcPacketCallbacks *callbacks,
 *                                      void *callback_context);
 *
 * DESCRIPTION
 *
 *    This is optional function which can be used to set specific callbacks
 *    for the packet stream indicated by `stream'.  If these are set then
 *    `callbacks' will be used instead of the ones set for the function
 *    silc_packet_engine_start.  To reset the normal behaviour call this
 *    function again with `callbacks' as NULL.  Note that the responsibility
 *    of handling end of stream, and error conditions moves to the layer
 *    calling this function since the original callbacks set in the
 *    silc_packet_engine_start will not be called.
 *
 ***/
void silc_packet_stream_callbacks(SilcPacketStream stream,
				  SilcPacketCallbacks *callbacks,
				  void *callback_context);

/****f* silccore/SilcPacketAPI/silc_packet_stream_ref
 *
 * SYNOPSIS
 *
 *    void silc_packet_stream_ref(SilcPacketStream stream);
 *
 * DESCRIPTION
 *
 *    Increase reference counter for the stream indicated by `stream'.  This
 *    can be used to take a reference for the stream.  To unreference the
 *    stream call silc_packet_stream_unref function.
 *
 ***/
void silc_packet_stream_ref(SilcPacketStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_stream_unref
 *
 * SYNOPSIS
 *
 *    void silc_packet_stream_unref(SilcPacketStream stream);
 *
 * DESCRIPTION
 *
 *    Decrease reference counter for the stream indicated by `stream'.  If
 *    the counter hits zero the stream will be destroyed automatically.
 *
 ***/
void silc_packet_stream_unref(SilcPacketStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_set_context
 *
 * SYNOPSIS
 *
 *    void silc_packet_set_context(SilcPacketStream stream, void *app_context);
 *
 * DESCRIPTION
 *
 *    Set an application specific context to the stream.  The context will
 *    be delivered to all callback functions, and it can be retrieved by
 *    calling silc_packet_get_context function as well.  Note that this is
 *    separate packet stream specific context, and not the same as
 *    `callback_context' in silc_packet_engine_start.  Both will be delivered
 *    to the callbacks.
 *
 ***/
void silc_packet_set_context(SilcPacketStream stream, void *app_context);

/****f* silccore/SilcPacketAPI/silc_packet_get_context
 *
 * SYNOPSIS
 *
 *    void *silc_packet_get_context(SilcPacketStream stream);
 *
 * DESCRIPTION
 *
 *    Returns the current set application context, or NULL if none is set.
 *
 ***/
void *silc_packet_get_context(SilcPacketStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_set_ciphers
 *
 * SYNOPSIS
 *
 *    void silc_packet_set_ciphers(SilcPacketStream stream, SilcCipher send,
 *                                 SilcCipher receive);
 *
 * DESCRIPTION
 *
 *    Set ciphers to be used to encrypt sent packets, and decrypt received
 *    packets.  This can be called multiple times to change the ciphers.
 *    In this case if old cipher is set it will be freed.  If ciphers are
 *    not set packets will not be encrypted or decrypted.
 *
 ***/
void silc_packet_set_ciphers(SilcPacketStream stream, SilcCipher send,
			     SilcCipher receive);

/****f* silccore/SilcPacketAPI/silc_packet_get_ciphers
 *
 * SYNOPSIS
 *
 *    bool silc_packet_get_ciphers(SilcPacketStream stream, SilcCipher *send,
 *                                 SilcCipher *receive);
 *
 * DESCRIPTION
 *
 *    Returns the pointers of current ciphers from the `stream'.  Returns
 *    FALSE if ciphers are not set.
 *
 ***/
bool silc_packet_get_ciphers(SilcPacketStream stream, SilcCipher *send,
			     SilcCipher *receive);

/****f* silccore/SilcPacketAPI/silc_packet_set_hmacs
 *
 * SYNOPSIS
 *
 *    void silc_packet_set_hmacs(SilcPacketStream stream, SilcHmac send,
 *                               SilcHmac receive);
 *
 * DESCRIPTION
 *
 *    Set HMACs to be used to create MACs for sent packets and to check
 *    MAC for received packets.  This can be called multiple times to change
 *    the HMACs.  In this case if old HMAC is set it will be freed.  If
 *    HMACs are not set MACs are not generated or verified for packets.
 *
 ***/
void silc_packet_set_hmacs(SilcPacketStream stream, SilcHmac send,
			   SilcHmac receive);

/****f* silccore/SilcPacketAPI/silc_packet_get_hmacs
 *
 * SYNOPSIS
 *
 *    bool silc_packet_get_hmacs(SilcPacketStream stream, SilcHmac *send,
 *                               SilcHmac *receive);
 *
 * DESCRIPTION
 *
 *    Returns the pointers of current HMACs from the `stream'.  Returns
 *    FALSE if HMACs are not set.
 *
 ***/
bool silc_packet_get_hmacs(SilcPacketStream stream, SilcHmac *send,
			   SilcHmac *receive);

/****f* silccore/SilcPacketAPI/silc_packet_set_ids
 *
 * SYNOPSIS
 *
 *    bool silc_packet_set_ids(SilcPacketStream stream,
 *                             SilcIdType src_id_type, const void *src_id
 *                             SilcIdType dst_id_type, const void *dst_id);
 *
 * DESCRIPTION
 *
 *    Set the source ID and destinaion ID to be used when sending packets to
 *    this packet stream.  The IDs to be used for a packet stream can be
 *    overridden when sending packets.  However, if the IDs do not ever change
 *    for the packet stream it is recommended they are set using this function.
 *    In this case they can be omitted when sending packets to the stream.
 *    It is also possible to set only source or destination ID.
 *
 ***/
bool silc_packet_set_ids(SilcPacketStream stream,
			 SilcIdType src_id_type, const void *src_id,
			 SilcIdType dst_id_type, const void *dst_id);

/****f* silccore/SilcPacketAPI/silc_packet_send
 *
 * SYNOPSIS
 *
 *    bool silc_packet_send(SilcPacketStream stream,
 *                          SilcPacketType type, SilcPacketFlags flags,
 *                          const unsigned char *data, SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Send `data' of length of `data_len' to the packet stream indicated by
 *    `stream'.  If ciphers and HMACs were set using silc_packet_set_ciphers
 *    and silc_packet_set_hmacs the packet will be encrypted and MAC will be
 *    generated for it.  If silc_packet_set_ids was used to set source and
 *    destination ID for the packet stream those IDs are used in the
 *    packet.  If IDs have not been set and they need to be provided then
 *    silc_packet_send_ext function should be used.  Otherwise, the packet
 *    will not have IDs set at all.
 *
 ***/
bool silc_packet_send(SilcPacketStream stream,
		      SilcPacketType type, SilcPacketFlags flags,
		      const unsigned char *data, SilcUInt32 data_len);

/****f* silccore/SilcPacketAPI/silc_packet_send_ext
 *
 * SYNOPSIS
 *
 *    bool
 *    silc_packet_send_ext(SilcPacketStream stream,
 *                         SilcPacketType type, SilcPacketFlags flags,
 *                         SilcIdType src_id_type, void *srd_id,
 *                         SilcIdType dst_id_type, void *dst_id,
 *                         const unsigned char *data, SilcUInt32 data_len,
 *                         SilcCipher cipher, SilcHmac hmac);
 *
 * DESCRIPTION
 *
 *    This function can be used to specificly set different parameters of
 *    the SILC packet to be sent to the stream indicated by `stream'.  This
 *    function can be used to set specific IDs, cipher and HMAC to be used
 *    in packet creation. If `truelen' is provided that value is put to the
 *    SILC packet's truelen field, if it is zero the routine will calculate
 *    the truelen field for the packet.  If `padlen' is provided that value
 *    will be the length of the padding for the packet, if zero the routine
 *    will calculate necessary amount of padding for the packet.  This
 *    function can be used when specific ciphers, HMACs and IDs has not been
 *    set for the stream, or setting them for the stream is not suitable.
 *
 ***/
bool silc_packet_send_ext(SilcPacketStream stream,
			  SilcPacketType type, SilcPacketFlags flags,
			  SilcIdType src_id_type, void *src_id,
			  SilcIdType dst_id_type, void *dst_id,
			  const unsigned char *data, SilcUInt32 data_len,
			  SilcCipher cipher, SilcHmac hmac);

/****f* silccore/SilcPacketAPI/silc_packet_free
 *
 * SYNOPSIS
 *
 *    void silc_packet_free(SilcPacketEngine engine, SilcPacket packet);
 *
 * DESCRIPTION
 *
 *    This function is used to free the SilcPacket pointer that application
 *    receives in the SilcPacketReceive callback.  Application must free
 *    the packet.
 *
 ***/
void silc_packet_free(SilcPacketEngine engine, SilcPacket packet);

#endif /* SILCPACKET_H */
