/*

  silcpacket.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006 Pekka Riikonen

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
 * The SILC secure binary packet protocol interface, provides interface for
 * sending and receiving SILC packets.  The interface provides a packet
 * engine, that can be used to receive packets from packet streams, and
 * routines for sending all kinds of SILC packets.
 *
 * The packet engine and packet stream are thread safe.  They can be safely
 * used in multi threaded environment.
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

#define SILC_PACKET_NONE		 0       /* RESERVED */
#define SILC_PACKET_ANY                  0
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
 *    silc_packet_free function if it takes it in for processing.
 *
 *    The `buffer' field contains the parsed packet payload and the start
 *    of the data area will point to the start of the packet payload.
 *
 *    The list pointer `next' can be used by the application to put the
 *    packet context in a list during processing, if needed.
 *
 * SOURCE
 */
typedef struct SilcPacketStruct {
  struct SilcPacketStruct *next;     /* List pointer, application may set */
  SilcPacketStream stream;	     /* Packet stream this packet is from */
  SilcBufferStruct buffer;	     /* Packet data payload */
  unsigned char *src_id;	     /* Source ID */
  unsigned char *dst_id;	     /* Destination ID */
  unsigned int src_id_len  : 6;	     /* Source ID length */
  unsigned int src_id_type : 2;	     /* Source ID type */
  unsigned int dst_id_len  : 6;	     /* Destination ID length */
  unsigned int dst_id_type : 2;	     /* Destination ID type */
  SilcPacketType type;		     /* Packet type */
  SilcPacketFlags flags;	     /* Packet flags */
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
 *    from the actual stream.  It can retrieve the underlaying stream from
 *    the packet stream by calling silc_packet_stream_get_stream function.
 *
 * SOURCE
 */
typedef enum {
  SILC_PACKET_ERR_READ,			 /* Error while reading */
  SILC_PACKET_ERR_WRITE,       		 /* Error while writing */
  SILC_PACKET_ERR_MAC_FAILED,     	 /* Packet MAC check failed */
  SILC_PACKET_ERR_DECRYPTION_FAILED,   	 /* Packet decryption failed */
  SILC_PACKET_ERR_UNKNOWN_SID,		 /* Unknown SID (with IV included) */
  SILC_PACKET_ERR_MALFORMED,		 /* Packet is malformed */
  SILC_PACKET_ERR_NO_MEMORY,	 	 /* System out of memory */
} SilcPacketError;
/***/

/****f* silccore/SilcPacketAPI/SilcPacketReceiveCb
 *
 * SYNOPSIS
 *
 *    typedef SilcBool (*SilcPacketReceiveCb)(SilcPacketEngine engine,
 *                                            SilcPacketStream stream,
 *                                            SilcPacket packet,
 *                                            void *callback_context,
 *                                            void *stream_context);
 *
 * DESCRIPTION
 *
 *    The packet receive callback is called by the packet engine when a new
 *    SILC Packet has arrived.  The application must free the returned
 *    SilcPacket with silc_packet_free if it takes the packet in for
 *    processing.  This callback is set in the SilcPacketCallbacks structure.
 *    The `callback_context' is the context set as argument in the
 *    silc_packet_engine_start function.  The `stream_context' is stream
 *    specific context that was set by calling silc_packet_set_context.
 *
 *    If the application takes the received packet `packet' into processing
 *    TRUE must be returned.  If FALSE is returned the packet engine will
 *    pass the packet to other packet processor, if one has been linked
 *    to the stream with silc_packet_stream_link function.  If no extra
 *    processor is linked the packet is dropped.
 *
 * EXAMPLE
 *
 *    SilcBool
 *    silc_foo_packet_receive_cb(SilcPacketEngine engine,
 *                               SilcPacketStream stream, SilcPacket packet,
 *                               void *callback_context, void *stream_context)
 *    {
 *      Application ctx = callback_context;
 *
 *      // If we're not up yet, let's not process the packet
 *      if (ctx->initialized == FALSE)
 *        return FALSE;
 *
 *      // Process the incoming packet...
 *      ...
 *
 *      // It's our packet now, no one else will get it
 *      return TRUE;
 *    }
 *
 ***/
typedef SilcBool (*SilcPacketReceiveCb)(SilcPacketEngine engine,
					SilcPacketStream stream,
					SilcPacket packet,
					void *callback_context,
					void *stream_context);

/****f* silccore/SilcPacketAPI/SilcPacketEosCb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcPacketEosCb)(SilcPacketEngine engine,
 *                                    SilcPacketStream stream,
 *                                    void *callback_context,
 *                                    void *stream_context);
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
				void *stream_context);

/****f* silccore/SilcPacketAPI/SilcPacketErrorCb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcPacketErrorCb)(SilcPacketEngine engine,
 *                                      SilcPacketStream stream,
 *                                      SilcPacketError error,
 *                                      void *callback_context,
 *                                      void *stream_context);
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
				  void *stream_context);

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
 *    silc_packet_engine_start(SilcRng rng, SilcBool router,
 *                             SilcPacketCallbacks *callbacks,
 *                             void *callback_context);
 *
 * DESCRIPTION
 *
 *    Create new packet engine for processing incoming and outgoing packets.
 *    If `router' is  TRUE then the application is considered to be router
 *    server, and certain packets are handled differently.  Client and normal
 *    server must set it to FALSE.  The `callbacks' is a SilcPacketCallbacks
 *    structure provided by the caller which includes the callbacks that is
 *    called when for example packet is received, or end of stream is called.
 *
 * NOTES
 *
 *    The packet engine is thread safe.  You can use one packet engine in
 *    multi threaded application.
 *
 ***/
SilcPacketEngine
silc_packet_engine_start(SilcRng rng, SilcBool router,
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
 *                                               SilcSchedule schedule,
 *                                               SilcStream stream);
 *
 * DESCRIPTION
 *
 *    Create new packet stream and use the `stream' as underlaying stream.
 *    Usually the `stream' would be a socket stream, but it can be any
 *    stream.  After this function returns, packets can immediately be
 *    sent to and received from the stream.
 *
 * NOTES
 *
 *    SilcPacketStream cannot be used with silc_stream_* routines (such as
 *    silc_stream_read and silc_stream_write) because of its special nature.
 *    Use the silc_packet_send and the silc_packet_send_ext to send packets.
 *    To read packets you will receive the packet receive callback from
 *    packet engine.  Destroy the stream with silc_packet_stream_destroy.
 *
 *    The SilcPacketStream is thread safe.  Same context can be safely used
 *    in multi threaded environment.
 *
 ***/
SilcPacketStream silc_packet_stream_create(SilcPacketEngine engine,
					   SilcSchedule schedule,
					   SilcStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_stream_add_remote
 *
 * SYNOPSIS
 *
 *    SilcPacketStream silc_packet_stream_add_remote(SilcPacketStream stream,
 *                                                   const char *remote_ip,
 *                                                   SilcUInt16 remote_port,
 *                                                   SilcPacket packet);
 *
 * DESCRIPTION
 *
 *    This function is used to add remote receivers in packet stream `stream'
 *    that has UDP/IP socket stream as the underlaying stream.  This function
 *    cannot be used with other type of streams.  This returns new packet
 *    stream context that can be used to send to and receive packets from
 *    the specified remote IP and remote port, or NULL on error.  The `stream'
 *    is the actual stream that is used to send and receive the data.
 *
 *    When the parent `stream' receives packets from remote IP address
 *    and port that does not have its own remote packet stream, it returns
 *    the packet to the packet callback set for `stream'.  The sender's
 *    IP address and port can then be retrieved by using the
 *    silc_packet_get_sender function and to create new packet stream by
 *    calling this function.  After that, all packets from that IP address
 *    and port will be received by the new packet stream.
 *
 *    If the `packet' is non-NULL it will be injected into the new packet
 *    stream as soon as the scheduler associated with `stream' schedules
 *    new tasks.  It can be used to inject an incoming packet to the stream.
 *
 *    This interface is for connectionless UDP streams.  If it is possible
 *    to create connected stream it should be done for performance reasons.
 *
 * EXAMPLE
 *
 *    // Create parent packet stream, it can receive packets from anywhere
 *    listener = silc_net_udp_connect("0.0.0.0", 500, NULL, 0, schedule);
 *    parent = silc_packet_stream_create(engine, schedule, listener);
 *
 *    ...
 *    // Received a packet to the parent stream, get the sender information.
 *    silc_packet_get_sender(packet, &ip, &port);
 *
 *    // Create new packet stream for this remote location.
 *    remote = silc_packet_stream_add_remote(parent, ip, port, packet);
 *
 ***/
SilcPacketStream silc_packet_stream_add_remote(SilcPacketStream stream,
					       const char *remote_ip,
					       SilcUInt16 remote_port,
					       SilcPacket packet);

/****f* silccore/SilcPacketAPI/silc_packet_stream_destroy
 *
 * SYNOPSIS
 *
 *    void silc_packet_stream_destroy(SilcPacketStream stream);
 *
 * DESCRIPTION
 *
 *    Destroy packet stream and the underlaying stream.  This will also
 *    close and destroy the underlaying stream.
 *
 ***/
void silc_packet_stream_destroy(SilcPacketStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_stream_set_router
 *
 * SYNOPSIS
 *
 *    void silc_packet_stream_set_router(SilcPacketStream stream);
 *
 * DESCRIPTION
 *
 *    When called sets the stream indicates by `stream' as SILC router
 *    connection stream.  This causes that certain packets are handled
 *    differently.  This must be called for router connection streams and
 *    must not be called for any other stream.
 *
 ***/
void silc_packet_stream_set_router(SilcPacketStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_stream_set_iv_included
 *
 * SYNOPSIS
 *
 *    void silc_packet_stream_set_iv_included(SilcPacketStream stream);
 *
 * DESCRIPTION
 *
 *    Sets an IV Included property for the stream indicated by `stream'.
 *    This means that the IV used in the encryption will be included in
 *    the resulted ciphertext.  This makes it possible to send and receive
 *    packets on unreliable network transport protocol, such as UDP/IP.
 *    This must be called if the underlaying stream in the `stream' is UDP
 *    stream.
 *
 *    When this is set to the stream the silc_packet_set_sid must be called
 *    to set new Security ID.  The Security ID will be included with the IV
 *    in the ciphertext.
 *
 ***/
void silc_packet_stream_set_iv_included(SilcPacketStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_stream_set_stream
 *
 * SYNOPSIS
 *
 *    void silc_packet_stream_set_stream(SilcPacketStream packet_stream,
 *                                       SilcStream stream,
 *                                       SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    This function may be used to change the underlaying stream in the
 *    packet stream indicated by `packet_stream'.  Note that the old
 *    stream will not be used after calling this function.  The caller is
 *    responsible destroying the old stream.
 *
 ***/
void silc_packet_stream_set_stream(SilcPacketStream packet_stream,
				   SilcStream stream,
				   SilcSchedule schedule);

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
 *    This function could be used for example when an error callback is
 *    called by the packet engine to retrieve the actual lower level error
 *    from the stream.
 *
 ***/
SilcStream silc_packet_stream_get_stream(SilcPacketStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_stream_link
 *
 * SYNOPSIS
 *
 *    SilcBool silc_packet_stream_link(SilcPacketStream stream,
 *                                     SilcPacketCallbacks *callbacks,
 *                                     void *callback_context,
 *                                     int priority, ...);
 *
 * DESCRIPTION
 *
 *    Links the packet processing callbacks indicated by `callbacks' into
 *    the packet stream indicated by `stream' with priority `priority' for
 *    the packet types given in the variable argument list.  This function
 *    can be used to link to the packet stream for specific packet types
 *    and receive them in the specified callbacks.  This way, a third party,
 *    for example some library may attach itself into the packet stream
 *    and receive and process certain packets.  The variable argument
 *    list is ended with -1.  To link to receive all packets use
 *    SILC_PACKET_ANY.
 *
 *    The default packet processing callbacks given as argument to the
 *    silc_packet_engine_start has the priority 0.  Any priority higher
 *    than 0 will then take precedence over the default callbacks.  Any
 *    priority lower than 0 (negative value) will be processed after the
 *    default callbacks.
 *
 *    Note that setting only the 'packet_receive' callback in the `callbacks'
 *    is required.
 *
 * EXAMPLE
 *
 *    // Link to this packet stream, with high priority, for
 *    // SILC_PACKET_CONNECTION_AUTH and SILC_PACKET_CONNECTION_AUTH_REQUEST
 *    // packets. We don't care about other packets.
 *    silc_packet_stream_link(stream, our_callbacks, our_context,
 *                            1000000, SILC_PACKET_CONNECTION_AUTH,
 *                            SILC_PACKET_CONNECTION_AUTH_REQUEST, -1);
 *
 ***/
SilcBool silc_packet_stream_link(SilcPacketStream stream,
				 SilcPacketCallbacks *callbacks,
				 void *callback_context,
				 int priority, ...);

/****f* silccore/SilcPacketAPI/silc_packet_stream_unlink
 *
 * SYNOPSIS
 *
 *    void silc_packet_stream_unlink(SilcPacketStream stream,
 *                                   SilcPacketCallbacks *callbacks,
 *                                   void *callback_context);
 *
 * DESCRIPTION
 *
 *    Unlinks the `callbacks' with `callback_context' from the packet stream
 *    indicated by `stream'.  This function must be called for the callbacks
 *    that was linked to `stream' when they are not needed anymore.
 *
 ***/
void silc_packet_stream_unlink(SilcPacketStream stream,
			       SilcPacketCallbacks *callbacks,
			       void *callback_context);

/****f* silccore/SilcPacketAPI/silc_packet_get_sender
 *
 * SYNOPSIS
 *
 *    SilcBool silc_packet_get_sender(SilcPacket packet,
 *                                    const char **sender_ip,
 *                                    SilcUInt16 *sender_port);
 *
 * DESCRIPTION
 *
 *    Returns the packet sender's IP address and port from UDP packet
 *    indicated by `packet'.  This can be called only from the packet
 *    callback to retrieve the information of the packet's sender.  Returns
 *    FALSE if the information is not available.
 *
 ***/
SilcBool silc_packet_get_sender(SilcPacket packet,
				const char **sender_ip,
				SilcUInt16 *sender_port);

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

/****f* silccore/SilcPacketAPI/silc_packet_get_engine
 *
 * SYNOPSIS
 *
 *    SilcPacketEngine silc_packet_get_engine(SilcPacketStream stream);
 *
 * DESCRIPTION
 *
 *    Returns the packet engine from the `stream'.
 *
 ***/
SilcPacketEngine silc_packet_get_engine(SilcPacketStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_set_context
 *
 * SYNOPSIS
 *
 *    void silc_packet_set_context(SilcPacketStream stream,
 *                                 void *stream_context);
 *
 * DESCRIPTION
 *
 *    Sets a stream specific context to the stream.  The context will
 *    be delivered to all callback functions, and it can be retrieved by
 *    calling silc_packet_get_context function as well.  Note that this is
 *    separate packet stream specific context, and not the same as
 *    `callback_context' in silc_packet_engine_start.  Both will be delivered
 *    to the callbacks, and this context as the `stream_context' argument.
 *
 ***/
void silc_packet_set_context(SilcPacketStream stream, void *stream_context);

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
 *    SilcBool silc_packet_get_ciphers(SilcPacketStream stream,
 *                                     SilcCipher *send,
 *                                     SilcCipher *receive);
 *
 * DESCRIPTION
 *
 *    Returns the pointers of current ciphers from the `stream'.  Returns
 *    FALSE if ciphers are not set.
 *
 ***/
SilcBool silc_packet_get_ciphers(SilcPacketStream stream, SilcCipher *send,
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
 *    SilcBool silc_packet_get_hmacs(SilcPacketStream stream, SilcHmac *send,
 *                                   SilcHmac *receive);
 *
 * DESCRIPTION
 *
 *    Returns the pointers of current HMACs from the `stream'.  Returns
 *    FALSE if HMACs are not set.
 *
 ***/
SilcBool silc_packet_get_hmacs(SilcPacketStream stream, SilcHmac *send,
			       SilcHmac *receive);

/****f* silccore/SilcPacketAPI/silc_packet_set_ids
 *
 * SYNOPSIS
 *
 *    SilcBool silc_packet_set_ids(SilcPacketStream stream,
 *                                 SilcIdType src_id_type, const void *src_id
 *                                 SilcIdType dst_id_type, const void *dst_id);
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
SilcBool silc_packet_set_ids(SilcPacketStream stream,
			     SilcIdType src_id_type, const void *src_id,
			     SilcIdType dst_id_type, const void *dst_id);

/****f* silccore/SilcPacketAPI/silc_packet_set_sid
 *
 * SYNOPSIS
 *
 *    SilcBool silc_packet_set_sid(SilcPacketStream stream, SilcUInt8 sid);
 *
 * DESCRIPTION
 *
 *    Sets new Security ID to the packet stream indicated by `stream'.  This
 *    is called only if the IV Included property was set to the stream
 *    by calling silc_packet_stream_set_iv_included.  This function sets
 *    new Security ID to the stream which is then included in the ciphertext
 *    of a packet.  The `sid' must be 0 when it is set for the very first
 *    time and must be increased by one after each rekey.  This function must
 *    be called every time new keys are added to the stream after a rekey.
 *
 *    If this function is called when the IV Included property has not been
 *    set to the stream the `sid' will be ignored.  Returns FALSE if the
 *    IV Included has not been set, TRUE otherwise.
 *
 ***/
SilcBool silc_packet_set_sid(SilcPacketStream stream, SilcUInt8 sid);

/****f* silccore/SilcPacketAPI/silc_packet_send
 *
 * SYNOPSIS
 *
 *    SilcBool silc_packet_send(SilcPacketStream stream,
 *                              SilcPacketType type, SilcPacketFlags flags,
 *                              const unsigned char *data,
 *                              SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Send `data' of length of `data_len' to the packet stream indicated by
 *    `stream'.  If ciphers and HMACs were set using silc_packet_set_ciphers
 *    and silc_packet_set_hmacs the packet will be encrypted and MAC will be
 *    computed for it.  If silc_packet_set_ids was used to set source and
 *    destination ID for the packet stream those IDs are used in the
 *    packet.  If IDs have not been set and they need to be provided then
 *    silc_packet_send_ext function should be used.  Otherwise, the packet
 *    will not have IDs set at all.  Returns FALSE if packet could not be
 *    sent.
 *
 ***/
SilcBool silc_packet_send(SilcPacketStream stream,
			  SilcPacketType type, SilcPacketFlags flags,
			  const unsigned char *data, SilcUInt32 data_len);

/****f* silccore/SilcPacketAPI/silc_packet_send_ext
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_packet_send_ext(SilcPacketStream stream,
 *                         SilcPacketType type, SilcPacketFlags flags,
 *                         SilcIdType src_id_type, void *srd_id,
 *                         SilcIdType dst_id_type, void *dst_id,
 *                         const unsigned char *data, SilcUInt32 data_len,
 *                         SilcCipher cipher, SilcHmac hmac);
 *
 * DESCRIPTION
 *
 *    Same as silc_packet_send but with this function different sending
 *    parameters can be sent as argument.  This function can be used to
 *    set specific IDs, cipher and HMAC to be used in packet sending,
 *    instead of the ones saved in the `stream'.  If any of the extra
 *    pointers are NULL, default values set to the stream will apply.
 *
 ***/
SilcBool silc_packet_send_ext(SilcPacketStream stream,
			      SilcPacketType type, SilcPacketFlags flags,
			      SilcIdType src_id_type, void *src_id,
			      SilcIdType dst_id_type, void *dst_id,
			      const unsigned char *data, SilcUInt32 data_len,
			      SilcCipher cipher, SilcHmac hmac);

/****f* silccore/SilcPacketAPI/silc_packet_send_va
 *
 * SYNOPSIS
 *
 *    SilcBool silc_packet_send_va(SilcPacketStream stream,
 *                                 SilcPacketType type,
 *                                 SilcPacketFlags flags, ...);
 *
 * DESCRIPTION
 *
 *    Same as silc_packet_send but takes the data in as variable argument
 *    formatted buffer (see silcbuffmt.h).  The arguments must be ended
 *    with SILC_STR_END.  Returns FALSE if packet could not be sent or
 *    the buffer could not be formatted.
 *
 * EXAMPLE
 *
 *    // Send NEW_CLIENT packet
 *    silc_packet_send_va(stream, SILC_PACKET_NEW_CLIENT, 0,
 *                        SILC_STR_UI_SHORT(username_len),
 *                        SILC_STR_DATA(username, username_len),
 *                        SILC_STR_UI_SHORT(realname_len),
 *                        SILC_STR_DATA(realname, realname_len),
 *                        SILC_STR_END);
 *
 ***/
SilcBool silc_packet_send_va(SilcPacketStream stream,
			     SilcPacketType type, SilcPacketFlags flags, ...);

/****f* silccore/SilcPacketAPI/silc_packet_send_va_ext
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_packet_send_va_ext(SilcPacketStream stream,
 *                            SilcPacketType type, SilcPacketFlags flags,
 *                            SilcIdType src_id_type, void *srd_id,
 *                            SilcIdType dst_id_type, void *dst_id,
 *                            SilcCipher cipher, SilcHmac hmac, ...);
 *
 * DESCRIPTION
 *
 *    Same as silc_packet_send_va but with this function different sending
 *    parameters can be sent as argument.  This function can be used to
 *    set specific IDs, cipher and HMAC to be used in packet sending,
 *    instead of the ones saved in the `stream'.  If any of the extra
 *    pointers are NULL, default values set to the stream will apply.
 *
 ***/
SilcBool silc_packet_send_va_ext(SilcPacketStream stream,
				 SilcPacketType type, SilcPacketFlags flags,
				 SilcIdType src_id_type, void *src_id,
				 SilcIdType dst_id_type, void *dst_id,
				 SilcCipher cipher, SilcHmac hmac, ...);

/****f* silccore/SilcPacketAPI/silc_packet_wait
 *
 * SYNOPSIS
 *
 *    void *silc_packet_wait_init(SilcPacketStream stream, ...);
 *
 * DESCRIPTION
 *
 *    Initializes a packet waiter for the packet stream `stream' and
 *    for the variable argument list of packet types.  The function
 *    silc_packet_wait can be used to block the thread until a packet
 *    has been received.  This function is used to initialize the waiting
 *    and to give the list of packet types that caller wish to receive.
 *    The variable argument list must end with -1.  To receive all
 *    packets use SILC_PACKET_ANY.  Returns a context that must be given
 *    to the silc_packet_wait function as argument.  Returns NULL on
 *    error.  To uninitialize the waiting call silc_packet_wait_uninit.
 *
 * NOTES
 *
 *    Note that packets may be available immediately after calling this
 *    function and they will be buffered, until silc_packet_wait is called.
 *
 * EXAMPLE
 *
 *    void *waiter;
 *
 *    // Will wait for private message packets
 *    waiter = silc_packet_wait_init(stream,
 *                                   SILC_PACKET_PRIVATE_MESSAGE, -1);
 *
 *
 ***/
void *silc_packet_wait_init(SilcPacketStream stream, ...);

/****f* silccore/SilcPacketAPI/silc_packet_wait
 *
 * SYNOPSIS
 *
 *    void silc_packet_wait_uninit(void *waiter, SilcPacketStream stream);
 *
 * DESCRIPTION
 *
 *    Uninitializes the waiting context.  This may be called also from
 *    another thread while other thread is waiting for packets.  This will
 *    inform the waiting thread to stop waiting.
 *
 ***/
void silc_packet_wait_uninit(void *waiter, SilcPacketStream stream);

/****f* silccore/SilcPacketAPI/silc_packet_wait
 *
 * SYNOPSIS
 *
 *    int silc_packet_wait(void *waiter, int timeout,
 *                         SilcPacket *return_packet)
 *
 * DESCRIPTION
 *
 *    A special function that can be used to wait for a packet to arrive.
 *    This function will block the calling process or thread until either
 *    a packet is received into the `return_packet' pointer or the specified
 *    timeout value `timeout', which is in milliseconds, will expire.  If
 *    the timeout is 0, no timeout exist.  Before calling this function the
 *    silc_packet_wait_init must be called.  The caller is responsible for
 *    freeing the returned packet with silc_packet_free.
 *
 *    This function can be used for example from a thread that wants to
 *    block until SILC packet has been received.
 *
 *    Returns 1 when packet was received, 0 if timeout occurred and -1 if
 *    error occurred.
 *
 * EXAMPLE
 *
 *    static int foo_read_data(FooContext c)
 *    {
 *      SilcPacket packet;
 *      void *waiter;
 *      ...
 *
 *      // Will wait for private message packets
 *      if (c->initialized == FALSE) {
 *        waiter = silc_packet_wait_init(stream,
 *                                       SILC_PACKET_PRIVATE_MESSAGE, -1);
 *        c->initialized = TRUE;
 *      }
 *
 *      ...
 *      // Wait here until private message packet is received
 *      if ((silc_packet_wait(waiter, 0, &packet)) < 0)
 *        return -1;
 *
 *      ... process packet ...
 *
 *      return 1;
 *    }
 *
 ***/
int silc_packet_wait(void *waiter, int timeout, SilcPacket *return_packet);

/****f* silccore/SilcPacketAPI/silc_packet_free
 *
 * SYNOPSIS
 *
 *    void silc_packet_free(SilcPacket packet);
 *
 * DESCRIPTION
 *
 *    This function is used to free the SilcPacket pointer that application
 *    receives in the SilcPacketReceive callback.  Application must free
 *    the packet if it takes it in to processing.
 *
 ***/
void silc_packet_free(SilcPacket packet);

#endif /* SILCPACKET_H */
