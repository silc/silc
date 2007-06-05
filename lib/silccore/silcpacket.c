/*

  silcpacket.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * Created: Fri Jul 25 18:52:14 1997
 */
/* $Id$ */

#include "silc.h"

/************************** Types and definitions ***************************/

/* Per scheduler (which usually means per thread) data.  We put per scheduler
   data here for accessing without locking.  SILC Schedule dictates that
   tasks are dispatched in one thread, hence the per scheduler context. */
typedef struct {
  SilcSchedule schedule;		 /* The scheduler */
  SilcPacketEngine engine;		 /* Packet engine */
  SilcDList inbufs;			 /* Data inbut buffer list */
  SilcUInt32 stream_count;		 /* Number of streams using this */
} *SilcPacketEngineContext;

/* Packet engine */
struct SilcPacketEngineStruct {
  SilcMutex lock;			 /* Engine lock */
  SilcRng rng;		                 /* RNG for engine */
  SilcHashTable contexts;		 /* Per scheduler contexts */
  SilcPacketCallbacks *callbacks;	 /* Packet callbacks */
  void *callback_context;		 /* Context for callbacks */
  SilcList streams;			 /* All streams in engine */
  SilcList packet_pool;       		 /* Free list for received packets */
  SilcHashTable udp_remote;		 /* UDP remote streams, or NULL */
  unsigned int local_is_router    : 1;
};

/* Packet processor context */
typedef struct SilcPacketProcessStruct {
  SilcPacketType *types;		 /* Packets to process */
  SilcPacketCallbacks *callbacks;	 /* Callbacks or NULL */
  void *callback_context;
  SilcInt32 priority;		         /* Priority */
} *SilcPacketProcess;

/* UDP remote stream tuple */
typedef struct {
  char *remote_ip;			 /* Remote IP address */
  SilcUInt16 remote_port;		 /* Remote port */
} *SilcPacketRemoteUDP;

/* Packet stream */
struct SilcPacketStreamStruct {
  struct SilcPacketStreamStruct *next;
  SilcPacketEngineContext sc;		 /* Per scheduler context */
  SilcStream stream;			 /* Underlaying stream */
  SilcMutex lock;			 /* Packet stream lock */
  SilcDList process;			 /* Packet processors, or NULL */
  SilcPacketRemoteUDP remote_udp;	 /* UDP remote stream tuple, or NULL */
  void *stream_context;			 /* Stream context */
  SilcBufferStruct outbuf;		 /* Out buffer */
  SilcBuffer inbuf;			 /* Inbuf from inbuf list or NULL */
  SilcCipher send_key[2];		 /* Sending key */
  SilcHmac send_hmac[2];		 /* Sending HMAC */
  SilcCipher receive_key[2];		 /* Receiving key */
  SilcHmac receive_hmac[2];		 /* Receiving HMAC */
  unsigned char *src_id;		 /* Source ID */
  unsigned char *dst_id;		 /* Destination ID */
  SilcUInt32 send_psn;			 /* Sending sequence */
  SilcUInt32 receive_psn;		 /* Receiving sequence */
  SilcAtomic8 refcnt;		         /* Reference counter */
  SilcUInt8 sid;			 /* Security ID, set if IV included */
  unsigned int src_id_len  : 6;
  unsigned int src_id_type : 2;
  unsigned int dst_id_len  : 6;
  unsigned int dst_id_type : 2;
  unsigned int is_router   : 1;		 /* Set if router stream */
  unsigned int destroyed   : 1;		 /* Set if destroyed */
  unsigned int iv_included : 1;          /* Set if IV included */
  unsigned int udp         : 1;          /* UDP remote stream */
};

/* Initial size of stream buffers */
#define SILC_PACKET_DEFAULT_SIZE  1024

/* Header length without source and destination ID's. */
#define SILC_PACKET_HEADER_LEN 10

/* Minimum length of SILC Packet Header. */
#define SILC_PACKET_MIN_HEADER_LEN 16
#define SILC_PACKET_MIN_HEADER_LEN_IV 32 + 1

/* Maximum padding length */
#define SILC_PACKET_MAX_PADLEN 128

/* Default padding length */
#define SILC_PACKET_DEFAULT_PADLEN 16

/* Minimum packet length */
#define SILC_PACKET_MIN_LEN (SILC_PACKET_HEADER_LEN + 1)

/* Returns true length of the packet. */
#define SILC_PACKET_LENGTH(__packetdata, __ret_truelen, __ret_paddedlen) \
do {									 \
  SILC_GET16_MSB((__ret_truelen), (__packetdata));			 \
  (__ret_paddedlen) = (__ret_truelen) + (SilcUInt8)(__packetdata)[4];	 \
} while(0)

/* Calculates the data length with given header length.  This macro
   can be used to check whether the data_len with header_len exceeds
   SILC_PACKET_MAX_LEN.  If it does, this returns the new data_len
   so that the SILC_PACKET_MAX_LEN is not exceeded.  If the data_len
   plus header_len fits SILC_PACKET_MAX_LEN the returned data length
   is the data_len given as argument. */
#define SILC_PACKET_DATALEN(data_len, header_len)			  \
  ((data_len + header_len) > SILC_PACKET_MAX_LEN ? 			  \
   data_len - ((data_len + header_len) - SILC_PACKET_MAX_LEN) : data_len)

/* Calculates the length of the padding in the packet. */
#define SILC_PACKET_PADLEN(__packetlen, __blocklen, __padlen)		    \
do {									    \
  __padlen = (SILC_PACKET_DEFAULT_PADLEN - (__packetlen) %		    \
	      ((__blocklen) ? (__blocklen) : SILC_PACKET_DEFAULT_PADLEN));  \
  if (__padlen < 8)							    \
    __padlen += ((__blocklen) ? (__blocklen) : SILC_PACKET_DEFAULT_PADLEN); \
} while(0)

/* Returns the length of the padding up to the maximum length, which
   is 128 bytes.*/
#define SILC_PACKET_PADLEN_MAX(__packetlen, __blocklen, __padlen)	   \
do {									   \
  __padlen = (SILC_PACKET_MAX_PADLEN - (__packetlen) % 			   \
	      ((__blocklen) ? (__blocklen) : SILC_PACKET_DEFAULT_PADLEN)); \
} while(0)

/* EOS callback */
#define SILC_PACKET_CALLBACK_EOS(s)					\
do {									\
  (s)->sc->engine->callbacks->eos((s)->sc->engine, s,			\
				  (s)->sc->engine->callback_context,	\
				  (s)->stream_context);			\
} while(0)

/* Error callback */
#define SILC_PACKET_CALLBACK_ERROR(s, err)				\
do {									\
  (s)->sc->engine->callbacks->error((s)->sc->engine, s, err,		\
				    (s)->sc->engine->callback_context,	\
				    (s)->stream_context);		\
} while(0)

static SilcBool silc_packet_dispatch(SilcPacket packet);
static void silc_packet_read_process(SilcPacketStream stream);
static inline SilcBool silc_packet_send_raw(SilcPacketStream stream,
					    SilcPacketType type,
					    SilcPacketFlags flags,
					    SilcIdType src_id_type,
					    unsigned char *src_id,
					    SilcUInt32 src_id_len,
					    SilcIdType dst_id_type,
					    unsigned char *dst_id,
					    SilcUInt32 dst_id_len,
					    const unsigned char *data,
					    SilcUInt32 data_len,
					    SilcCipher cipher,
					    SilcHmac hmac);

/************************ Static utility functions **************************/

/* Injects packet to new stream created with silc_packet_stream_add_remote. */

SILC_TASK_CALLBACK(silc_packet_stream_inject_packet)
{
  SilcPacket packet = context;
  SilcPacketStream stream = packet->stream;

  SILC_LOG_DEBUG(("Injecting packet %p to stream %p", packet, packet->stream));

  silc_mutex_lock(stream->lock);
  if (!stream->destroyed)
    silc_packet_dispatch(packet);
  silc_mutex_unlock(stream->lock);
  silc_packet_stream_unref(stream);
}

/* Write data to the stream.  Must be called with ps->lock locked.  Unlocks
   the lock inside this function, unless no_unlock is TRUE.  Unlocks always
   in case it returns FALSE. */

static inline SilcBool silc_packet_stream_write(SilcPacketStream ps,
						SilcBool no_unlock)
{
  SilcStream stream;
  SilcBool connected;
  int i;

  if (ps->udp)
    stream = ((SilcPacketStream)ps->stream)->stream;
  else
    stream = ps->stream;

  if (ps->udp && silc_socket_stream_is_udp(stream, &connected)) {
    if (!connected) {
      /* Connectionless UDP stream */
      while (silc_buffer_len(&ps->outbuf) > 0) {
	i = silc_net_udp_send(stream, ps->remote_udp->remote_ip,
			      ps->remote_udp->remote_port,
			      ps->outbuf.data, silc_buffer_len(&ps->outbuf));
	if (silc_unlikely(i == -2)) {
	  /* Error */
	  silc_buffer_reset(&ps->outbuf);
	  SILC_PACKET_CALLBACK_ERROR(ps, SILC_PACKET_ERR_WRITE);
	  return FALSE;
	}

	if (silc_unlikely(i == -1)) {
	  /* Cannot write now, write later. */
	  if (!no_unlock)
	    silc_mutex_unlock(ps->lock);
	  return TRUE;
	}

	/* Wrote data */
	silc_buffer_pull(&ps->outbuf, i);
      }

      silc_buffer_reset(&ps->outbuf);
      if (!no_unlock)
	silc_mutex_unlock(ps->lock);

      return TRUE;
    }
  }

  /* Write the data to the stream */
  while (silc_buffer_len(&ps->outbuf) > 0) {
    i = silc_stream_write(stream, ps->outbuf.data,
			  silc_buffer_len(&ps->outbuf));
    if (silc_unlikely(i == 0)) {
      /* EOS */
      silc_buffer_reset(&ps->outbuf);
      silc_mutex_unlock(ps->lock);
      SILC_PACKET_CALLBACK_EOS(ps);
      return FALSE;
    }

    if (silc_unlikely(i == -2)) {
      /* Error */
      silc_buffer_reset(&ps->outbuf);
      silc_mutex_unlock(ps->lock);
      SILC_PACKET_CALLBACK_ERROR(ps, SILC_PACKET_ERR_WRITE);
      return FALSE;
    }

    if (silc_unlikely(i == -1)) {
      /* Cannot write now, write later. */
      if (!no_unlock)
	silc_mutex_unlock(ps->lock);
      return TRUE;
    }

    /* Wrote data */
    silc_buffer_pull(&ps->outbuf, i);
  }

  silc_buffer_reset(&ps->outbuf);
  if (!no_unlock)
    silc_mutex_unlock(ps->lock);

  return TRUE;
}

/* Reads data from stream.  Must be called with ps->lock locked.  If this
   returns FALSE the lock has been unlocked.  If this returns packet stream
   to `ret_ps' its lock has been acquired and `ps' lock has been unlocked.
   It is returned if the stream is UDP and remote UDP stream exists for
   the sender of the packet. */

static inline SilcBool silc_packet_stream_read(SilcPacketStream ps,
					       SilcPacketStream *ret_ps)
{
  SilcStream stream = ps->stream;
  SilcBuffer inbuf;
  SilcBool connected;
  int ret;

  /* Get inbuf.  If there is already some data for this stream in the buffer
     we already have it.  Otherwise get the current one from list, it will
     include the data. */
  inbuf = ps->inbuf;
  if (!inbuf) {
    silc_dlist_start(ps->sc->inbufs);
    inbuf = silc_dlist_get(ps->sc->inbufs);
    if (!inbuf) {
      /* Allocate new data input buffer */
      inbuf = silc_buffer_alloc(SILC_PACKET_DEFAULT_SIZE * 65);
      if (!inbuf) {
        silc_mutex_unlock(ps->lock);
        return FALSE;
      }
      silc_buffer_reset(inbuf);
      silc_dlist_add(ps->sc->inbufs, inbuf);
    }
  }

  /* Make sure there is enough room to read */
  if (SILC_PACKET_DEFAULT_SIZE * 2 > silc_buffer_taillen(inbuf))
    silc_buffer_realloc(inbuf, silc_buffer_truelen(inbuf) +
			(SILC_PACKET_DEFAULT_SIZE * 2));

  if (silc_socket_stream_is_udp(stream, &connected)) {
    if (!connected) {
      /* Connectionless UDP stream, read one UDP packet */
      char remote_ip[64], tuple[64];
      int remote_port;
      SilcPacketStream remote;

      ret = silc_net_udp_receive(stream, remote_ip, sizeof(remote_ip),
				 &remote_port, inbuf->tail,
				 silc_buffer_taillen(inbuf));

      if (silc_unlikely(ret < 0)) {
	silc_mutex_unlock(ps->lock);
	if (ret == -1) {
	  /* Cannot read now, do it later. */
	  silc_buffer_pull(inbuf, silc_buffer_len(inbuf));
	  return FALSE;
	}

	/* Error */
	silc_buffer_reset(inbuf);
	SILC_PACKET_CALLBACK_ERROR(ps, SILC_PACKET_ERR_READ);
	return FALSE;
      }

      /* See if remote packet stream exist for this sender */
      silc_snprintf(tuple, sizeof(tuple), "%d%s", remote_port, remote_ip);
      silc_mutex_lock(ps->sc->engine->lock);
      if (silc_hash_table_find(ps->sc->engine->udp_remote, tuple, NULL,
			       (void *)&remote)) {
	silc_mutex_unlock(ps->sc->engine->lock);
	SILC_LOG_DEBUG(("UDP packet from %s:%d for stream %p", remote_ip,
			remote_port, remote));
	silc_mutex_unlock(ps->lock);
	silc_mutex_lock(remote->lock);
	*ret_ps = remote;
	return TRUE;
      }
      silc_mutex_unlock(ps->sc->engine->lock);

      /* Unknown sender */
      if (!ps->remote_udp) {
	ps->remote_udp = silc_calloc(1, sizeof(*ps->remote_udp));
	if (silc_unlikely(!ps->remote_udp)) {
	  silc_mutex_unlock(ps->lock);
	  SILC_PACKET_CALLBACK_ERROR(ps, SILC_PACKET_ERR_NO_MEMORY);
	  return FALSE;
	}
      }

      /* Save sender IP and port */
      silc_free(ps->remote_udp->remote_ip);
      ps->remote_udp->remote_ip = strdup(remote_ip);
      ps->remote_udp->remote_port = remote_port;

      silc_buffer_pull_tail(inbuf, ret);
      return TRUE;
    }
  }

  /* Read data from the stream */
  ret = silc_stream_read(stream, inbuf->tail, silc_buffer_taillen(inbuf));
  if (silc_unlikely(ret <= 0)) {
    silc_mutex_unlock(ps->lock);
    if (ret == 0) {
      /* EOS */
      silc_buffer_reset(inbuf);
      SILC_PACKET_CALLBACK_EOS(ps);
      return FALSE;
    }

    if (ret == -1) {
      /* Cannot read now, do it later. */
      silc_buffer_pull(inbuf, silc_buffer_len(inbuf));
      return FALSE;
    }

    /* Error */
    silc_buffer_reset(inbuf);
    SILC_PACKET_CALLBACK_ERROR(ps, SILC_PACKET_ERR_READ);
    return FALSE;
  }

  silc_buffer_pull_tail(inbuf, ret);
  return TRUE;
}

/* Our stream IO notifier callback. */

static void silc_packet_stream_io(SilcStream stream, SilcStreamStatus status,
				  void *context)
{
  SilcPacketStream remote = NULL, ps = context;

  silc_mutex_lock(ps->lock);

  if (silc_unlikely(ps->destroyed)) {
    silc_mutex_unlock(ps->lock);
    return;
  }

  switch (status) {
  case SILC_STREAM_CAN_READ:
    /* Reading is locked also with stream->lock because we may be reading
       at the same time other thread is writing to same underlaying stream. */
    SILC_LOG_DEBUG(("Reading data from stream %p, ps %p", ps->stream, ps));

    /* Read data from stream */
    if (!silc_packet_stream_read(ps, &remote))
      return;

    /* Now process the data */
    silc_packet_stream_ref(ps);
    if (!remote) {
      silc_packet_read_process(ps);
      silc_mutex_unlock(ps->lock);
    } else {
      silc_packet_read_process(remote);
      silc_mutex_unlock(remote->lock);
    }
    silc_packet_stream_unref(ps);
    break;

  case SILC_STREAM_CAN_WRITE:
    SILC_LOG_DEBUG(("Writing pending data to stream %p, ps %p",
		    ps->stream, ps));

    if (silc_unlikely(!silc_buffer_headlen(&ps->outbuf))) {
      silc_mutex_unlock(ps->lock);
      return;
    }

    /* Write pending data to stream */
    silc_packet_stream_write(ps, FALSE);
    break;

  default:
    silc_mutex_unlock(ps->lock);
    break;
  }
}

/* Allocate packet */

static SilcPacket silc_packet_alloc(SilcPacketEngine engine)
{
  SilcPacket packet;

  SILC_LOG_DEBUG(("Packet pool count %d",
		  silc_list_count(engine->packet_pool)));

  silc_mutex_lock(engine->lock);

  /* Get packet from freelist or allocate new one. */
  packet = silc_list_get(engine->packet_pool);
  if (!packet) {
    void *tmp;

    silc_mutex_unlock(engine->lock);

    packet = silc_calloc(1, sizeof(*packet));
    if (silc_unlikely(!packet))
      return NULL;

    SILC_LOG_DEBUG(("Allocating new packet %p", packet));

    tmp = silc_malloc(SILC_PACKET_DEFAULT_SIZE);
    if (silc_unlikely(!tmp)) {
      silc_free(packet);
      return NULL;
    }
    silc_buffer_set(&packet->buffer, tmp, SILC_PACKET_DEFAULT_SIZE);
    silc_buffer_reset(&packet->buffer);

    return packet;
  }

  SILC_LOG_DEBUG(("Get packet %p", packet));

  /* Delete from freelist */
  silc_list_del(engine->packet_pool, packet);

  silc_mutex_unlock(engine->lock);

  return packet;
}

/* UDP remote stream hash table destructor */

static void silc_packet_engine_hash_destr(void *key, void *context,
					  void *user_context)
{
  silc_free(key);
}

/* Per scheduler context hash table destructor */

static void silc_packet_engine_context_destr(void *key, void *context,
					     void *user_context)
{
  SilcPacketEngineContext sc = context;
  SilcBuffer buffer;

  silc_dlist_start(sc->inbufs);
  while ((buffer = silc_dlist_get(sc->inbufs))) {
    silc_buffer_clear(buffer);
    silc_buffer_free(buffer);
    silc_dlist_del(sc->inbufs, buffer);
  }

  silc_dlist_uninit(sc->inbufs);
  silc_free(sc);
}


/******************************** Packet API ********************************/

/* Allocate new packet engine */

SilcPacketEngine
silc_packet_engine_start(SilcRng rng, SilcBool router,
			 SilcPacketCallbacks *callbacks,
			 void *callback_context)
{
  SilcPacketEngine engine;
  SilcPacket packet;
  int i;
  void *tmp;

  SILC_LOG_DEBUG(("Starting new packet engine"));

  if (!callbacks)
    return NULL;
  if (!callbacks->packet_receive || !callbacks->eos || !callbacks->error)
    return NULL;

  engine = silc_calloc(1, sizeof(*engine));
  if (!engine)
    return NULL;

  engine->contexts = silc_hash_table_alloc(0, silc_hash_ptr, NULL, NULL, NULL,
					   silc_packet_engine_context_destr,
					   engine, TRUE);
  if (!engine->contexts) {
    silc_free(engine);
    return NULL;
  }

  engine->rng = rng;
  engine->local_is_router = router;
  engine->callbacks = callbacks;
  engine->callback_context = callback_context;
  silc_list_init(engine->streams, struct SilcPacketStreamStruct, next);
  silc_mutex_alloc(&engine->lock);

  /* Allocate packet free list */
  silc_list_init(engine->packet_pool, struct SilcPacketStruct, next);
  for (i = 0; i < 5; i++) {
    packet = silc_calloc(1, sizeof(*packet));
    if (!packet) {
      silc_packet_engine_stop(engine);
      return NULL;
    }

    tmp = silc_malloc(SILC_PACKET_DEFAULT_SIZE);
    if (!tmp) {
      silc_packet_engine_stop(engine);
      return NULL;
    }
    silc_buffer_set(&packet->buffer, tmp, SILC_PACKET_DEFAULT_SIZE);
    silc_buffer_reset(&packet->buffer);

    silc_list_add(engine->packet_pool, packet);
  }
  silc_list_start(engine->packet_pool);

  return engine;
}

/* Stop packet engine */

void silc_packet_engine_stop(SilcPacketEngine engine)
{
  SilcPacket packet;

  SILC_LOG_DEBUG(("Stopping packet engine"));

  if (!engine)
    return;

  /* Free packet free list */
  silc_list_start(engine->packet_pool);
  while ((packet = silc_list_get(engine->packet_pool))) {
    silc_buffer_purge(&packet->buffer);
    silc_free(packet);
  }

  silc_hash_table_free(engine->contexts);
  silc_mutex_free(engine->lock);
  silc_free(engine);
}

static const char *packet_error[] = {
  "Cannot read from stream",
  "Cannot write to stream",
  "Packet MAC failed",
  "Packet decryption failed",
  "Unknown SID",
  "Packet is malformed",
  "System out of memory",
};

/* Return packet error string */

const char *silc_packet_error_string(SilcPacketError error)
{
  if (error < SILC_PACKET_ERR_READ || error > SILC_PACKET_ERR_NO_MEMORY)
    return "";
  return packet_error[error];
}

/* Return list of packet streams in the engine */

SilcDList silc_packet_engine_get_streams(SilcPacketEngine engine)
{
  SilcDList list;
  SilcPacketStream ps;

  list = silc_dlist_init();
  if (!list)
    return NULL;

  silc_mutex_lock(engine->lock);
  silc_list_start(engine->streams);
  while ((ps = silc_list_get(engine->streams)))
    silc_dlist_add(list, ps);
  silc_mutex_unlock(engine->lock);

  return list;
}

/* Create new packet stream */

SilcPacketStream silc_packet_stream_create(SilcPacketEngine engine,
					   SilcSchedule schedule,
					   SilcStream stream)
{
  SilcPacketStream ps;
  SilcBuffer inbuf;
  void *tmp;

  SILC_LOG_DEBUG(("Creating new packet stream"));

  if (!engine || !stream)
    return NULL;

  ps = silc_calloc(1, sizeof(*ps));
  if (!ps)
    return NULL;

  ps->stream = stream;
  silc_atomic_init8(&ps->refcnt, 1);
  silc_mutex_alloc(&ps->lock);

  /* Allocate out buffer */
  tmp = silc_malloc(SILC_PACKET_DEFAULT_SIZE);
  if (!tmp) {
    silc_packet_stream_destroy(ps);
    return NULL;
  }
  silc_buffer_set(&ps->outbuf, tmp, SILC_PACKET_DEFAULT_SIZE);
  silc_buffer_reset(&ps->outbuf);

  /* Initialize packet procesors list */
  ps->process = silc_dlist_init();
  if (!ps->process) {
    silc_packet_stream_destroy(ps);
    return NULL;
  }

  silc_mutex_lock(engine->lock);

  /* Add per scheduler context */
  if (!silc_hash_table_find(engine->contexts, schedule, NULL,
			    (void *)&ps->sc)) {
    ps->sc = silc_calloc(1, sizeof(*ps->sc));
    if (!ps->sc) {
      silc_packet_stream_destroy(ps);
      silc_mutex_unlock(engine->lock);
      return NULL;
    }
    ps->sc->engine = engine;
    ps->sc->schedule = schedule;

    /* Allocate data input buffer */
    inbuf = silc_buffer_alloc(SILC_PACKET_DEFAULT_SIZE * 65);
    if (!inbuf) {
      silc_free(ps->sc);
      ps->sc = NULL;
      silc_packet_stream_destroy(ps);
      silc_mutex_unlock(engine->lock);
      return NULL;
    }
    silc_buffer_reset(inbuf);

    ps->sc->inbufs = silc_dlist_init();
    if (!ps->sc->inbufs) {
      silc_buffer_free(inbuf);
      silc_free(ps->sc);
      ps->sc = NULL;
      silc_packet_stream_destroy(ps);
      silc_mutex_unlock(engine->lock);
      return NULL;
    }
    silc_dlist_add(ps->sc->inbufs, inbuf);

    /* Add to per scheduler context hash table */
    if (!silc_hash_table_add(engine->contexts, schedule, ps->sc)) {
      silc_buffer_free(inbuf);
      silc_dlist_del(ps->sc->inbufs, inbuf);
      silc_free(ps->sc);
      ps->sc = NULL;
      silc_packet_stream_destroy(ps);
      silc_mutex_unlock(engine->lock);
      return NULL;
    }
  }
  ps->sc->stream_count++;

  /* Add the packet stream to engine */
  silc_list_add(engine->streams, ps);

  /* If this is UDP stream, allocate UDP remote stream hash table */
  if (!engine->udp_remote && silc_socket_stream_is_udp(stream, NULL))
    engine->udp_remote = silc_hash_table_alloc(0, silc_hash_string, NULL,
					       silc_hash_string_compare, NULL,
					       silc_packet_engine_hash_destr,
					       NULL, TRUE);

  silc_mutex_unlock(engine->lock);

  /* Set IO notifier callback.  This schedules this stream for I/O. */
  if (!silc_stream_set_notifier(ps->stream, schedule,
				silc_packet_stream_io, ps)) {
    SILC_LOG_DEBUG(("Cannot set stream notifier for packet stream"));
    silc_packet_stream_destroy(ps);
    return NULL;
  }

  return ps;
}

/* Add new remote packet stream for UDP packet streams */

SilcPacketStream silc_packet_stream_add_remote(SilcPacketStream stream,
					       const char *remote_ip,
					       SilcUInt16 remote_port,
					       SilcPacket packet)
{
  SilcPacketEngine engine = stream->sc->engine;
  SilcPacketStream ps;
  char *tuple;
  void *tmp;

  SILC_LOG_DEBUG(("Adding UDP remote %s:%d to packet stream %p",
		  remote_ip, remote_port, stream));

  if (!stream || !remote_ip || !remote_port)
    return NULL;

  if (!silc_socket_stream_is_udp(stream->stream, NULL)) {
    SILC_LOG_ERROR(("Stream is not UDP stream, cannot add remote IP"));
    return NULL;
  }

  ps = silc_calloc(1, sizeof(*ps));
  if (!ps)
    return NULL;
  ps->sc = stream->sc;

  silc_atomic_init8(&ps->refcnt, 1);
  silc_mutex_alloc(&ps->lock);

  /* Set the UDP packet stream as underlaying stream */
  silc_packet_stream_ref(stream);
  ps->stream = (SilcStream)stream;
  ps->udp = TRUE;

  /* Allocate out buffer */
  tmp = silc_malloc(SILC_PACKET_DEFAULT_SIZE);
  if (!tmp) {
    silc_packet_stream_destroy(ps);
    return NULL;
  }
  silc_buffer_set(&ps->outbuf, tmp, SILC_PACKET_DEFAULT_SIZE);
  silc_buffer_reset(&ps->outbuf);

  /* Initialize packet procesors list */
  ps->process = silc_dlist_init();
  if (!ps->process) {
    silc_packet_stream_destroy(ps);
    return NULL;
  }

  /* Add to engine with this IP and port pair */
  tuple = silc_format("%d%s", remote_port, remote_ip);
  silc_mutex_lock(engine->lock);
  if (!tuple || !silc_hash_table_add(engine->udp_remote, tuple, ps)) {
    silc_mutex_unlock(engine->lock);
    silc_packet_stream_destroy(ps);
    return NULL;
  }
  silc_mutex_unlock(engine->lock);

  /* Save remote IP and port pair */
  ps->remote_udp = silc_calloc(1, sizeof(*ps->remote_udp));
  if (!ps->remote_udp) {
    silc_packet_stream_destroy(ps);
    return NULL;
  }
  ps->remote_udp->remote_port = remote_port;
  ps->remote_udp->remote_ip = strdup(remote_ip);
  if (!ps->remote_udp->remote_ip) {
    silc_packet_stream_destroy(ps);
    return NULL;
  }

  if (packet) {
    /* Inject packet to the new stream */
    packet->stream = ps;
    silc_packet_stream_ref(ps);
    silc_schedule_task_add_timeout(silc_stream_get_schedule(stream->stream),
				   silc_packet_stream_inject_packet, packet,
				   0, 0);
  }

  return ps;
}

/* Destroy packet stream */

void silc_packet_stream_destroy(SilcPacketStream stream)
{
  SilcPacketEngine engine;

  if (!stream)
    return;

  if (silc_atomic_sub_int8(&stream->refcnt, 1) > 0) {
    stream->destroyed = TRUE;

    /* Close the underlaying stream */
    if (!stream->udp && stream->stream)
      silc_stream_close(stream->stream);
    return;
  }

  SILC_LOG_DEBUG(("Destroying packet stream %p", stream));

  if (!stream->udp) {
    /* Delete from engine */
    engine = stream->sc->engine;
    silc_mutex_lock(engine->lock);
    silc_list_del(engine->streams, stream);

    /* Remove per scheduler context, if it is not used anymore */
    if (stream->sc) {
      stream->sc->stream_count--;
      if (!stream->sc->stream_count)
	silc_hash_table_del(engine->contexts, stream->sc->schedule);
    }
    silc_mutex_unlock(engine->lock);

    /* Destroy the underlaying stream */
    if (stream->stream)
      silc_stream_destroy(stream->stream);
  } else {
    /* Delete from UDP remote hash table */
    char tuple[64];
    engine = stream->sc->engine;
    silc_snprintf(tuple, sizeof(tuple), "%d%s",
		  stream->remote_udp->remote_port,
		  stream->remote_udp->remote_ip);
    silc_mutex_lock(engine->lock);
    silc_hash_table_del(engine->udp_remote, tuple);
    silc_mutex_unlock(engine->lock);

    silc_free(stream->remote_udp->remote_ip);
    silc_free(stream->remote_udp);

    /* Unreference the underlaying packet stream */
    silc_packet_stream_unref((SilcPacketStream)stream->stream);
  }

  /* Clear and free buffers */
  silc_buffer_clear(&stream->outbuf);
  silc_buffer_purge(&stream->outbuf);

  if (stream->process) {
    SilcPacketProcess p;
    silc_dlist_start(stream->process);
    while ((p = silc_dlist_get(stream->process))) {
      silc_free(p->types);
      silc_free(p);
      silc_dlist_del(stream->process, p);
    }
    silc_dlist_uninit(stream->process);
  }

  /* Destroy ciphers and HMACs */
  if (stream->send_key[0])
    silc_cipher_free(stream->send_key[0]);
  if (stream->receive_key[0])
    silc_cipher_free(stream->receive_key[0]);
  if (stream->send_hmac[0])
    silc_hmac_free(stream->send_hmac[0]);
  if (stream->receive_hmac[0])
    silc_hmac_free(stream->receive_hmac[0]);
  if (stream->send_key[1])
    silc_cipher_free(stream->send_key[1]);
  if (stream->receive_key[1])
    silc_cipher_free(stream->receive_key[1]);
  if (stream->send_hmac[1])
    silc_hmac_free(stream->send_hmac[1]);
  if (stream->receive_hmac[1])
    silc_hmac_free(stream->receive_hmac[1]);

  /* Free IDs */
  silc_free(stream->src_id);
  silc_free(stream->dst_id);

  silc_atomic_uninit8(&stream->refcnt);
  silc_mutex_free(stream->lock);
  silc_free(stream);
}

/* Return TRUE if the stream is valid */

SilcBool silc_packet_stream_is_valid(SilcPacketStream stream)
{
  return stream->destroyed == FALSE;
}

/* Marks as router stream */

void silc_packet_stream_set_router(SilcPacketStream stream)
{
  stream->is_router = TRUE;
}

/* Mark to include IV in ciphertext */

void silc_packet_stream_set_iv_included(SilcPacketStream stream)
{
  stream->iv_included = TRUE;
}

/* Links `callbacks' to `stream' for specified packet types */

static SilcBool silc_packet_stream_link_va(SilcPacketStream stream,
					   SilcPacketCallbacks *callbacks,
					   void *callback_context,
					   int priority, va_list ap)
{
  SilcPacketProcess p, e;
  SilcInt32 packet_type;
  int i;

  SILC_LOG_DEBUG(("Linking callbacks %p to stream %p", callbacks, stream));

  if (!callbacks)
    return FALSE;
  if (!callbacks->packet_receive)
    return FALSE;

  p = silc_calloc(1, sizeof(*p));
  if (!p)
    return FALSE;

  p->priority = priority;
  p->callbacks = callbacks;
  p->callback_context = callback_context;

  silc_mutex_lock(stream->lock);

  if (!stream->process) {
    stream->process = silc_dlist_init();
    if (!stream->process) {
      silc_mutex_unlock(stream->lock);
      return FALSE;
    }
  }

  /* According to priority set the procesor to correct position.  First
     entry has the highest priority */
  silc_dlist_start(stream->process);
  while ((e = silc_dlist_get(stream->process)) != SILC_LIST_END) {
    if (p->priority > e->priority) {
      silc_dlist_insert(stream->process, p);
      break;
    }
  }
  if (!e)
    silc_dlist_add(stream->process, p);

  /* Get packet types to process */
  i = 1;
  while (1) {
    packet_type = va_arg(ap, SilcInt32);

    if (packet_type == SILC_PACKET_ANY)
      break;

    if (packet_type == -1)
      break;

    p->types = silc_realloc(p->types, sizeof(*p->types) * (i + 1));
    if (!p->types) {
      silc_mutex_unlock(stream->lock);
      return FALSE;
    }

    p->types[i - 1] = (SilcPacketType)packet_type;
    i++;
  }
  if (p->types)
    p->types[i - 1] = 0;

  silc_mutex_unlock(stream->lock);

  silc_packet_stream_ref(stream);

  return TRUE;
}

/* Links `callbacks' to `stream' for specified packet types */

SilcBool silc_packet_stream_link(SilcPacketStream stream,
				 SilcPacketCallbacks *callbacks,
				 void *callback_context,
				 int priority, ...)
{
  va_list ap;
  SilcBool ret;

  va_start(ap, priority);
  ret = silc_packet_stream_link_va(stream, callbacks, callback_context,
				   priority, ap);
  va_end(ap);

  return ret;
}

/* Unlinks `callbacks' from `stream'. */

void silc_packet_stream_unlink(SilcPacketStream stream,
			       SilcPacketCallbacks *callbacks,
			       void *callback_context)
{
  SilcPacketProcess p;

  SILC_LOG_DEBUG(("Unlinking callbacks %p from stream %p",
		  callbacks, stream));

  silc_mutex_lock(stream->lock);

  silc_dlist_start(stream->process);
  while ((p = silc_dlist_get(stream->process)) != SILC_LIST_END)
    if (p->callbacks == callbacks &&
	p->callback_context == callback_context) {
      silc_dlist_del(stream->process, p);
      silc_free(p->types);
      silc_free(p);
      break;
    }

  if (!silc_dlist_count(stream->process)) {
    silc_dlist_uninit(stream->process);
    stream->process = NULL;
  }

  silc_mutex_unlock(stream->lock);

  silc_packet_stream_unref(stream);
}

/* Returns TRUE if stream is UDP stream */

SilcBool silc_packet_stream_is_udp(SilcPacketStream stream)
{
  return stream->udp || silc_socket_stream_is_udp(stream->stream, NULL);
}

/* Return packet sender IP and port for UDP packet stream */

SilcBool silc_packet_get_sender(SilcPacket packet,
				const char **sender_ip,
				SilcUInt16 *sender_port)
{
  if (!packet->stream->remote_udp)
    return FALSE;

  *sender_ip = packet->stream->remote_udp->remote_ip;
  *sender_port = packet->stream->remote_udp->remote_port;

  return TRUE;
}

/* Reference packet stream */

void silc_packet_stream_ref(SilcPacketStream stream)
{
  silc_atomic_add_int8(&stream->refcnt, 1);
  SILC_LOG_DEBUG(("Stream %p, refcnt %d->%d", stream,
		  silc_atomic_get_int8(&stream->refcnt) - 1,
		  silc_atomic_get_int8(&stream->refcnt)));
}

/* Unreference packet stream */

void silc_packet_stream_unref(SilcPacketStream stream)
{
  SILC_LOG_DEBUG(("Stream %p, refcnt %d->%d", stream,
		  silc_atomic_get_int8(&stream->refcnt),
		  silc_atomic_get_int8(&stream->refcnt) - 1));
  if (silc_atomic_sub_int8(&stream->refcnt, 1) > 0)
    return;
  silc_atomic_add_int8(&stream->refcnt, 1);
  silc_packet_stream_destroy(stream);
}

/* Return engine */

SilcPacketEngine silc_packet_get_engine(SilcPacketStream stream)
{
  return stream->sc->engine;
}

/* Set application context for packet stream */

void silc_packet_set_context(SilcPacketStream stream, void *stream_context)
{
  silc_mutex_lock(stream->lock);
  stream->stream_context = stream_context;
  silc_mutex_unlock(stream->lock);
}

/* Return application context from packet stream */

void *silc_packet_get_context(SilcPacketStream stream)
{
  void *context;
  silc_mutex_lock(stream->lock);
  context = stream->stream_context;
  silc_mutex_unlock(stream->lock);
  return context;
}

/* Change underlaying stream */

void silc_packet_stream_set_stream(SilcPacketStream ps,
				   SilcStream stream)
{
  if (ps->stream)
    silc_stream_set_notifier(ps->stream, ps->sc->schedule, NULL, NULL);
  ps->stream = stream;
  silc_stream_set_notifier(ps->stream, ps->sc->schedule, silc_packet_stream_io,
			   ps);
}

/* Return underlaying stream */

SilcStream silc_packet_stream_get_stream(SilcPacketStream stream)
{
  return stream->stream;
}

/* Set keys. */

SilcBool silc_packet_set_keys(SilcPacketStream stream, SilcCipher send_key,
                              SilcCipher receive_key, SilcHmac send_hmac,
                              SilcHmac receive_hmac, SilcBool rekey)
{
  SILC_LOG_DEBUG(("Setting new keys to packet stream %p", stream));

  /* If doing rekey, send REKEY_DONE packet */
  if (rekey) {
    /* This will take stream lock. */
    if (!silc_packet_send_raw(stream, SILC_PACKET_REKEY_DONE, 0,
			      stream->src_id_type, stream->src_id,
			      stream->src_id_len, stream->dst_id_type,
			      stream->dst_id, stream->dst_id_len,
			      NULL, 0, stream->send_key[0],
			      stream->send_hmac[0]))
      return FALSE;

    /* Write the packet to the stream */
    if (!silc_packet_stream_write(stream, TRUE))
      return FALSE;
  } else {
    silc_mutex_lock(stream->lock);
  }

  /* In case IV Included is set, save the old keys */
  if (stream->iv_included) {
    if (stream->send_key[1] && send_key) {
      silc_cipher_free(stream->send_key[1]);
      stream->send_key[1] = stream->send_key[0];
    }
    if (stream->receive_key[1] && receive_key) {
      silc_cipher_free(stream->receive_key[1]);
      stream->receive_key[1] = stream->receive_key[0];
    }
    if (stream->send_hmac[1] && send_hmac) {
      silc_hmac_free(stream->send_hmac[1]);
      stream->send_hmac[1] = stream->send_hmac[0];
    }
    if (stream->receive_hmac[1] && receive_hmac) {
      silc_hmac_free(stream->receive_hmac[1]);
      stream->receive_hmac[1] = stream->receive_hmac[0];
    }
  } else {
    if (stream->send_key[0] && send_key)
      silc_cipher_free(stream->send_key[0]);
    if (stream->receive_key[0] && receive_key)
      silc_cipher_free(stream->receive_key[0]);
    if (stream->send_hmac[0] && send_hmac)
      silc_hmac_free(stream->send_hmac[0]);
    if (stream->receive_hmac[0] && receive_hmac)
      silc_hmac_free(stream->receive_hmac[0]);
  }

  /* Set keys */
  if (send_key)
    stream->send_key[0] = send_key;
  if (receive_key)
    stream->receive_key[0] = receive_key;
  if (send_hmac)
    stream->send_hmac[0] = send_hmac;
  if (receive_hmac)
    stream->receive_hmac[0] = receive_hmac;

  silc_mutex_unlock(stream->lock);
  return TRUE;
}

/* Return current ciphers from packet stream */

SilcBool silc_packet_get_keys(SilcPacketStream stream,
			      SilcCipher *send_key,
			      SilcCipher *receive_key,
			      SilcHmac *send_hmac,
			      SilcHmac *receive_hmac)
{
  if (!stream->send_key[0] && !stream->receive_key[0] &&
      !stream->send_hmac[0] && !stream->receive_hmac[0])
    return FALSE;

  silc_mutex_lock(stream->lock);

  if (send_key)
    *send_key = stream->send_key[0];
  if (receive_key)
    *receive_key = stream->receive_key[0];
  if (send_hmac)
    *send_hmac = stream->send_hmac[0];
  if (receive_hmac)
    *receive_hmac = stream->receive_hmac[0];

  silc_mutex_unlock(stream->lock);

  return TRUE;
}

/* Set SILC IDs to packet stream */

SilcBool silc_packet_set_ids(SilcPacketStream stream,
			     SilcIdType src_id_type, const void *src_id,
			     SilcIdType dst_id_type, const void *dst_id)
{
  SilcUInt32 len;
  unsigned char tmp[32];

  if (!src_id && !dst_id)
    return FALSE;

  SILC_LOG_DEBUG(("Setting new IDs to packet stream"));

  silc_mutex_lock(stream->lock);

  if (src_id) {
    silc_free(stream->src_id);
    if (!silc_id_id2str(src_id, src_id_type, tmp, sizeof(tmp), &len)) {
      silc_mutex_unlock(stream->lock);
      return FALSE;
    }
    stream->src_id = silc_memdup(tmp, len);
    if (!stream->src_id) {
      silc_mutex_unlock(stream->lock);
      return FALSE;
    }
    stream->src_id_type = src_id_type;
    stream->src_id_len = len;
  }

  if (dst_id) {
    silc_free(stream->dst_id);
    if (!silc_id_id2str(dst_id, dst_id_type, tmp, sizeof(tmp), &len)) {
      silc_mutex_unlock(stream->lock);
      return FALSE;
    }
    stream->dst_id = silc_memdup(tmp, len);
    if (!stream->dst_id) {
      silc_mutex_unlock(stream->lock);
      return FALSE;
    }
    stream->dst_id_type = dst_id_type;
    stream->dst_id_len = len;
  }

  silc_mutex_unlock(stream->lock);

  return TRUE;
}

/* Return IDs from the packet stream */

SilcBool silc_packet_get_ids(SilcPacketStream stream,
			     SilcBool *src_id_set, SilcID *src_id,
			     SilcBool *dst_id_set, SilcID *dst_id)
{
  if (src_id && stream->src_id)
    if (!silc_id_str2id2(stream->src_id, stream->src_id_len,
			 stream->src_id_type, src_id))
      return FALSE;

  if (stream->src_id && src_id_set)
    *src_id_set = TRUE;

  if (dst_id && stream->dst_id)
    if (!silc_id_str2id2(stream->dst_id, stream->dst_id_len,
			 stream->dst_id_type, dst_id))
      return FALSE;

  if (stream->dst_id && dst_id_set)
    *dst_id_set = TRUE;

  return TRUE;
}

/* Adds Security ID (SID) */

SilcBool silc_packet_set_sid(SilcPacketStream stream, SilcUInt8 sid)
{
  if (!stream->iv_included)
    return FALSE;

  SILC_LOG_DEBUG(("Set packet stream %p SID to %d", stream, sid));

  stream->sid = sid;
  return TRUE;
}

/* Free packet */

void silc_packet_free(SilcPacket packet)
{
  SilcPacketStream stream = packet->stream;

  SILC_LOG_DEBUG(("Freeing packet %p", packet));

  /* Check for double free */
  SILC_ASSERT(packet->stream != NULL);

  packet->stream = NULL;
  packet->src_id = packet->dst_id = NULL;
  silc_buffer_reset(&packet->buffer);

  silc_mutex_lock(stream->sc->engine->lock);

  /* Put the packet back to freelist */
  silc_list_add(stream->sc->engine->packet_pool, packet);
  if (silc_list_count(stream->sc->engine->packet_pool) == 1)
    silc_list_start(stream->sc->engine->packet_pool);

  silc_mutex_unlock(stream->sc->engine->lock);
}

/****************************** Packet Sending ******************************/

/* Prepare outgoing data buffer for packet sending.  Returns the
   pointer to that buffer into the `packet'. */

static inline SilcBool silc_packet_send_prepare(SilcPacketStream stream,
						SilcUInt32 totlen,
						SilcHmac hmac,
						SilcBuffer packet)
{
  unsigned char *oldptr;
  unsigned int mac_len = hmac ? silc_hmac_len(hmac) : 0;

  totlen += mac_len;

  /* Allocate more space if needed */
  if (silc_unlikely(silc_buffer_taillen(&stream->outbuf) < totlen)) {
    if (!silc_buffer_realloc(&stream->outbuf,
			     silc_buffer_truelen(&stream->outbuf) + totlen))
      return FALSE;
  }

  /* Pull data area for the new packet, and return pointer to the start of
     the data area and save the pointer in to the `packet'.  MAC is pulled
     later after it's computed. */
  oldptr = silc_buffer_pull_tail(&stream->outbuf, totlen);
  silc_buffer_set(packet, oldptr, totlen);
  silc_buffer_push_tail(packet, mac_len);

  return TRUE;
}

/* Increments counter when encrypting in counter mode. */

static inline void silc_packet_send_ctr_increment(SilcPacketStream stream,
						  SilcCipher cipher,
						  unsigned char *ret_iv)
{
  unsigned char *iv = silc_cipher_get_iv(cipher);
  SilcUInt32 pc1, pc2;

  /* Increment 64-bit packet counter */
  SILC_GET32_MSB(pc1, iv + 4);
  SILC_GET32_MSB(pc2, iv + 8);
  if (++pc2 == 0)
    ++pc1;
  SILC_PUT32_MSB(pc1, iv + 4);
  SILC_PUT32_MSB(pc2, iv + 8);

  /* Reset block counter */
  memset(iv + 12, 0, 4);

  /* If IV Included flag, return the 64-bit IV for inclusion in packet */
  if (stream->iv_included) {
    /* Get new nonce */
    ret_iv[0] = silc_rng_get_byte_fast(stream->sc->engine->rng);
    ret_iv[1] = ret_iv[0] + iv[4];
    ret_iv[2] = ret_iv[0] ^ ret_iv[1];
    ret_iv[3] = ret_iv[0] + ret_iv[2];
    SILC_PUT32_MSB(pc2, ret_iv + 4);
    SILC_LOG_HEXDUMP(("IV"), ret_iv, 8);

    /* Set new nonce to counter block */
    memcpy(iv + 4, ret_iv, 4);
  }

  SILC_LOG_HEXDUMP(("Counter Block"), iv, 16);
}

/* Internal routine to assemble outgoing packet.  Assembles and encryptes
   the packet.  The silc_packet_stream_write needs to be called to send it
   after this returns TRUE. */

static inline SilcBool silc_packet_send_raw(SilcPacketStream stream,
					    SilcPacketType type,
					    SilcPacketFlags flags,
					    SilcIdType src_id_type,
					    unsigned char *src_id,
					    SilcUInt32 src_id_len,
					    SilcIdType dst_id_type,
					    unsigned char *dst_id,
					    SilcUInt32 dst_id_len,
					    const unsigned char *data,
					    SilcUInt32 data_len,
					    SilcCipher cipher,
					    SilcHmac hmac)
{
  unsigned char tmppad[SILC_PACKET_MAX_PADLEN], iv[33], psn[4];
  int block_len = (cipher ? silc_cipher_get_block_len(cipher) : 0);
  int i, enclen, truelen, padlen = 0, ivlen = 0, psnlen = 0;
  SilcBool ctr;
  SilcBufferStruct packet;

  SILC_LOG_DEBUG(("Sending packet %s (%d) flags %d, src %d dst %d, "
		  "data len %d", silc_get_packet_name(type), stream->send_psn,
		  flags, src_id_type, dst_id_type, data_len));

  /* Get the true length of the packet. This is saved as payload length
     into the packet header.  This does not include the length of the
     padding. */
  data_len = SILC_PACKET_DATALEN(data_len, (SILC_PACKET_HEADER_LEN +
					    src_id_len + dst_id_len));
  enclen = truelen = (data_len + SILC_PACKET_HEADER_LEN +
		      src_id_len + dst_id_len);

  /* If using CTR mode, increment the counter */
  ctr = (cipher && silc_cipher_get_mode(cipher) == SILC_CIPHER_MODE_CTR);
  if (ctr) {
    silc_packet_send_ctr_increment(stream, cipher, iv + 1);

    /* If IV is included, the SID, IV and sequence number is added to packet */
    if (stream->iv_included && cipher) {
      psnlen = sizeof(psn);
      ivlen = 8 + 1;
      iv[0] = stream->sid;
    }
  } else {
    /* If IV is included, the SID, IV and sequence number is added to packet */
    if (stream->iv_included && cipher) {
      psnlen = sizeof(psn);
      ivlen = block_len + 1;
      iv[0] = stream->sid;
      memcpy(iv + 1, silc_cipher_get_iv(cipher), block_len);
    }
  }

  /* We automatically figure out the packet structure from the packet
     type and flags, and calculate correct length.  Private messages with
     private keys and channel messages are special packets as their
     payload is encrypted already. */
  if (type == SILC_PACKET_PRIVATE_MESSAGE &&
      flags & SILC_PACKET_FLAG_PRIVMSG_KEY) {
    /* Padding is calculated from header + IDs */
    if (!ctr)
      SILC_PACKET_PADLEN((SILC_PACKET_HEADER_LEN + src_id_len + dst_id_len +
			  psnlen), block_len, padlen);

    /* Length to encrypt, header + IDs + padding. */
    enclen = (SILC_PACKET_HEADER_LEN + src_id_len + dst_id_len +
	      padlen + psnlen);

  } else if (type == SILC_PACKET_CHANNEL_MESSAGE) {
    if (stream->sc->engine->local_is_router && stream->is_router) {
      /* Channel messages between routers are encrypted as normal packets.
	 Padding is calculated from true length of the packet. */
      if (!ctr)
	SILC_PACKET_PADLEN(truelen + psnlen, block_len, padlen);

      enclen += padlen + psnlen;
    } else {
      /* Padding is calculated from header + IDs */
      if (!ctr)
	SILC_PACKET_PADLEN((SILC_PACKET_HEADER_LEN + src_id_len + dst_id_len +
			    psnlen), block_len, padlen);

      /* Length to encrypt, header + IDs + padding. */
      enclen = (SILC_PACKET_HEADER_LEN + src_id_len + dst_id_len +
		padlen + psnlen);
    }
  } else {
    /* Padding is calculated from true length of the packet */
    if (flags & SILC_PACKET_FLAG_LONG_PAD)
      SILC_PACKET_PADLEN_MAX(truelen + psnlen, block_len, padlen);
    else if (!ctr)
      SILC_PACKET_PADLEN(truelen + psnlen, block_len, padlen);

    enclen += padlen + psnlen;
  }

  /* Remove implementation specific flags */
  flags &= ~(SILC_PACKET_FLAG_LONG_PAD);

  /* Get random padding */
  for (i = 0; i < padlen; i++) tmppad[i] =
    silc_rng_get_byte_fast(stream->sc->engine->rng);

  silc_mutex_lock(stream->lock);

  /* Get packet pointer from the outgoing buffer */
  if (silc_unlikely(!silc_packet_send_prepare(stream, truelen + padlen + ivlen
					      + psnlen, hmac, &packet))) {
    silc_mutex_unlock(stream->lock);
    return FALSE;
  }

  SILC_PUT32_MSB(stream->send_psn, psn);

  /* Create the packet.  This creates the SILC header, adds padding, and
     the actual packet data. */
  i = silc_buffer_format(&packet,
			 SILC_STR_DATA(iv, ivlen),
			 SILC_STR_DATA(psn, psnlen),
			 SILC_STR_UI_SHORT(truelen),
			 SILC_STR_UI_CHAR(flags),
			 SILC_STR_UI_CHAR(type),
			 SILC_STR_UI_CHAR(padlen),
			 SILC_STR_UI_CHAR(0),
			 SILC_STR_UI_CHAR(src_id_len),
			 SILC_STR_UI_CHAR(dst_id_len),
			 SILC_STR_UI_CHAR(src_id_type),
			 SILC_STR_DATA(src_id, src_id_len),
			 SILC_STR_UI_CHAR(dst_id_type),
			 SILC_STR_DATA(dst_id, dst_id_len),
			 SILC_STR_DATA(tmppad, padlen),
			 SILC_STR_DATA(data, data_len),
			 SILC_STR_END);
  if (silc_unlikely(i < 0)) {
    silc_mutex_unlock(stream->lock);
    return FALSE;
  }

  SILC_LOG_HEXDUMP(("Assembled packet, len %d", silc_buffer_len(&packet)),
		   silc_buffer_data(&packet), silc_buffer_len(&packet));

  /* Encrypt the packet */
  if (silc_likely(cipher)) {
    SILC_LOG_DEBUG(("Encrypting packet"));
    silc_cipher_set_iv(cipher, NULL);
    if (silc_unlikely(!silc_cipher_encrypt(cipher, packet.data + ivlen,
					   packet.data + ivlen, enclen,
					   NULL))) {
      SILC_LOG_ERROR(("Packet encryption failed"));
      silc_mutex_unlock(stream->lock);
      return FALSE;
    }
  }

  /* Compute HMAC */
  if (silc_likely(hmac)) {
    SilcUInt32 mac_len;

    /* MAC is computed from the entire encrypted packet data, and put
       to the end of the packet. */
    silc_hmac_init(hmac);
    silc_hmac_update(hmac, psn, sizeof(psn));
    silc_hmac_update(hmac, packet.data, silc_buffer_len(&packet));
    silc_hmac_final(hmac, packet.tail, &mac_len);
    silc_buffer_pull_tail(&packet, mac_len);
    stream->send_psn++;
  }

  return TRUE;
}

/* Sends a packet */

SilcBool silc_packet_send(SilcPacketStream stream,
			  SilcPacketType type, SilcPacketFlags flags,
			  const unsigned char *data, SilcUInt32 data_len)
{
  SilcBool ret;

  ret = silc_packet_send_raw(stream, type, flags,
			     stream->src_id_type,
			     stream->src_id,
			     stream->src_id_len,
			     stream->dst_id_type,
			     stream->dst_id,
			     stream->dst_id_len,
			     data, data_len,
			     stream->send_key[0],
			     stream->send_hmac[0]);

  /* Write the packet to the stream */
  return ret ? silc_packet_stream_write(stream, FALSE) : FALSE;
}

/* Sends a packet, extended routine */

SilcBool silc_packet_send_ext(SilcPacketStream stream,
			      SilcPacketType type, SilcPacketFlags flags,
			      SilcIdType src_id_type, void *src_id,
			      SilcIdType dst_id_type, void *dst_id,
			      const unsigned char *data, SilcUInt32 data_len,
			      SilcCipher cipher, SilcHmac hmac)
{
  unsigned char src_id_data[32], dst_id_data[32];
  SilcUInt32 src_id_len, dst_id_len;
  SilcBool ret;

  if (src_id)
    if (!silc_id_id2str(src_id, src_id_type, src_id_data,
			sizeof(src_id_data), &src_id_len))
      return FALSE;
  if (dst_id)
    if (!silc_id_id2str(dst_id, dst_id_type, dst_id_data,
			sizeof(dst_id_data), &dst_id_len))
      return FALSE;

  ret = silc_packet_send_raw(stream, type, flags,
			     src_id ? src_id_type : stream->src_id_type,
			     src_id ? src_id_data : stream->src_id,
			     src_id ? src_id_len : stream->src_id_len,
			     dst_id ? dst_id_type : stream->dst_id_type,
			     dst_id ? dst_id_data : stream->dst_id,
			     dst_id ? dst_id_len : stream->dst_id_len,
			     data, data_len,
			     cipher ? cipher : stream->send_key[0],
			     hmac ? hmac : stream->send_hmac[0]);

  /* Write the packet to the stream */
  return ret ? silc_packet_stream_write(stream, FALSE) : FALSE;
}

/* Sends packet after formatting the arguments to buffer */

SilcBool silc_packet_send_va(SilcPacketStream stream,
			     SilcPacketType type, SilcPacketFlags flags, ...)
{
  SilcBufferStruct buf;
  SilcBool ret;
  va_list va;

  va_start(va, flags);

  memset(&buf, 0, sizeof(buf));
  if (silc_buffer_format_vp(&buf, va) < 0) {
    va_end(va);
    return FALSE;
  }

  ret = silc_packet_send(stream, type, flags, silc_buffer_data(&buf),
			 silc_buffer_len(&buf));

  silc_buffer_purge(&buf);
  va_end(va);

  return ret;
}

/* Sends packet after formatting the arguments to buffer, extended routine */

SilcBool silc_packet_send_va_ext(SilcPacketStream stream,
				 SilcPacketType type, SilcPacketFlags flags,
				 SilcIdType src_id_type, void *src_id,
				 SilcIdType dst_id_type, void *dst_id,
				 SilcCipher cipher, SilcHmac hmac, ...)
{
  SilcBufferStruct buf;
  SilcBool ret;
  va_list va;

  va_start(va, hmac);

  memset(&buf, 0, sizeof(buf));
  if (silc_buffer_format_vp(&buf, va) < 0) {
    va_end(va);
    return FALSE;
  }

  ret = silc_packet_send_ext(stream, type, flags, src_id_type, src_id,
			     dst_id_type, dst_id, silc_buffer_data(&buf),
			     silc_buffer_len(&buf), cipher, hmac);

  silc_buffer_purge(&buf);
  va_end(va);

  return TRUE;
}

/***************************** Packet Receiving *****************************/

/* Checks MAC in the packet. Returns TRUE if MAC is Ok. */

static inline SilcBool silc_packet_check_mac(SilcHmac hmac,
					     const unsigned char *data,
					     SilcUInt32 data_len,
					     const unsigned char *packet_mac,
					     const unsigned char *packet_seq,
					     SilcUInt32 sequence)
{
  /* Check MAC */
  if (silc_likely(hmac)) {
    unsigned char mac[32], psn[4];
    SilcUInt32 mac_len;

    SILC_LOG_DEBUG(("Verifying MAC"));

    /* Compute HMAC of packet */
    silc_hmac_init(hmac);

    if (!packet_seq) {
      SILC_PUT32_MSB(sequence, psn);
      silc_hmac_update(hmac, psn, 4);
    } else
      silc_hmac_update(hmac, packet_seq, 4);

    silc_hmac_update(hmac, data, data_len);
    silc_hmac_final(hmac, mac, &mac_len);

    /* Compare the MAC's */
    if (silc_unlikely(memcmp(packet_mac, mac, mac_len))) {
      SILC_LOG_DEBUG(("MAC failed"));
      return FALSE;
    }

    SILC_LOG_DEBUG(("MAC is Ok"));
  }

  return TRUE;
}

/* Increments/sets counter when decrypting in counter mode. */

static inline void silc_packet_receive_ctr_increment(SilcPacketStream stream,
						     unsigned char *iv,
						     unsigned char *packet_iv)
{
  SilcUInt32 pc1, pc2;

  /* If IV Included flag, set the IV from packet to block counter. */
  if (stream->iv_included) {
    memcpy(iv + 4, packet_iv, 8);
  } else {
    /* Increment 64-bit packet counter. */
    SILC_GET32_MSB(pc1, iv + 4);
    SILC_GET32_MSB(pc2, iv + 8);
    if (++pc2 == 0)
      ++pc1;
    SILC_PUT32_MSB(pc1, iv + 4);
    SILC_PUT32_MSB(pc2, iv + 8);
  }

  /* Reset block counter */
  memset(iv + 12, 0, 4);

  SILC_LOG_HEXDUMP(("Counter Block"), iv, 16);
}

/* Decrypts SILC packet.  Handles both normal and special packet decryption.
   Return 0 when packet is normal and 1 when it it special, -1 on error. */

static inline int silc_packet_decrypt(SilcCipher cipher, SilcHmac hmac,
				      SilcUInt32 sequence, SilcBuffer buffer,
				      SilcBool normal)
{
  if (normal == TRUE) {
    if (silc_likely(cipher)) {
      /* Decrypt rest of the packet */
      SILC_LOG_DEBUG(("Decrypting the packet"));
      if (silc_unlikely(!silc_cipher_decrypt(cipher, buffer->data,
					     buffer->data,
					     silc_buffer_len(buffer), NULL)))
	return -1;
    }
    return 0;

  } else {
    /* Decrypt rest of the header plus padding */
    if (silc_likely(cipher)) {
      SilcUInt16 len;
      SilcUInt32 block_len = silc_cipher_get_block_len(cipher);

      SILC_LOG_DEBUG(("Decrypting the header"));

      /* Padding length + src id len + dst id len + header length - 16
	 bytes already decrypted, gives the rest of the encrypted packet */
      silc_buffer_push(buffer, block_len);
      len = (((SilcUInt8)buffer->data[4] + (SilcUInt8)buffer->data[6] +
	      (SilcUInt8)buffer->data[7] + SILC_PACKET_HEADER_LEN) -
	     block_len);
      silc_buffer_pull(buffer, block_len);

      if (silc_unlikely(len > silc_buffer_len(buffer))) {
	SILC_LOG_ERROR(("Garbage in header of packet, bad packet length, "
			"packet dropped"));
	return -1;
      }
      if (silc_unlikely(!silc_cipher_decrypt(cipher, buffer->data,
					     buffer->data, len, NULL)))
	return -1;
    }

    return 1;
  }
}

/* Parses the packet. This is called when a whole packet is ready to be
   parsed. The buffer sent must be already decrypted before calling this
   function. */

static inline SilcBool silc_packet_parse(SilcPacket packet)
{
  SilcBuffer buffer = &packet->buffer;
  SilcUInt8 padlen = (SilcUInt8)buffer->data[4];
  SilcUInt8 src_id_len, dst_id_len, src_id_type, dst_id_type;
  int ret;

  SILC_LOG_DEBUG(("Parsing incoming packet"));

  /* Parse the buffer.  This parses the SILC header of the packet. */
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_ADVANCE,
			     SILC_STR_OFFSET(6),
			     SILC_STR_UI_CHAR(&src_id_len),
			     SILC_STR_UI_CHAR(&dst_id_len),
			     SILC_STR_UI_CHAR(&src_id_type),
			     SILC_STR_END);
  if (silc_unlikely(ret == -1)) {
    if (!packet->stream->udp &&
	!silc_socket_stream_is_udp(packet->stream->stream, NULL))
      SILC_LOG_ERROR(("Malformed packet header, packet dropped"));
    return FALSE;
  }

  if (silc_unlikely(src_id_len > SILC_PACKET_MAX_ID_LEN ||
		    dst_id_len > SILC_PACKET_MAX_ID_LEN)) {
    if (!packet->stream->udp &&
	!silc_socket_stream_is_udp(packet->stream->stream, NULL))
      SILC_LOG_ERROR(("Bad ID lengths in packet (%d and %d)",
		      packet->src_id_len, packet->dst_id_len));
    return FALSE;
  }

  ret = silc_buffer_unformat(buffer,
			     SILC_STR_ADVANCE,
			     SILC_STR_DATA(&packet->src_id, src_id_len),
			     SILC_STR_UI_CHAR(&dst_id_type),
			     SILC_STR_DATA(&packet->dst_id, dst_id_len),
			     SILC_STR_OFFSET(padlen),
			     SILC_STR_END);
  if (silc_unlikely(ret == -1)) {
    if (!packet->stream->udp &&
	!silc_socket_stream_is_udp(packet->stream->stream, NULL))
      SILC_LOG_ERROR(("Malformed packet header, packet dropped"));
    return FALSE;
  }

  if (silc_unlikely(src_id_type > SILC_ID_CHANNEL ||
		    dst_id_type > SILC_ID_CHANNEL)) {
    if (!packet->stream->udp &&
	!silc_socket_stream_is_udp(packet->stream->stream, NULL))
      SILC_LOG_ERROR(("Bad ID types in packet (%d and %d)",
		      src_id_type, dst_id_type));
    return FALSE;
  }

  packet->src_id_len = src_id_len;
  packet->dst_id_len = dst_id_len;
  packet->src_id_type = src_id_type;
  packet->dst_id_type = dst_id_type;

  SILC_LOG_HEXDUMP(("Parsed packet, len %d", silc_buffer_headlen(buffer) +
		   silc_buffer_len(buffer)), buffer->head,
		   silc_buffer_headlen(buffer) + silc_buffer_len(buffer));

  SILC_LOG_DEBUG(("Incoming packet type: %d (%s)", packet->type,
		  silc_get_packet_name(packet->type)));

  return TRUE;
}

/* Dispatch packet to application.  Called with stream->lock locked.
   Returns FALSE if the stream was destroyed while dispatching a packet. */

static SilcBool silc_packet_dispatch(SilcPacket packet)
{
  SilcPacketStream stream = packet->stream;
  SilcPacketProcess p;
  SilcBool default_sent = FALSE;
  SilcPacketType *pt;

  /* Dispatch packet to all packet processors that want it */

  if (silc_likely(!stream->process)) {
    /* Send to default processor as no others exist */
    SILC_LOG_DEBUG(("Dispatching packet to default callbacks"));
    silc_mutex_unlock(stream->lock);
    if (silc_unlikely(!stream->sc->engine->callbacks->
		      packet_receive(stream->sc->engine, stream, packet,
				     stream->sc->engine->callback_context,
				     stream->stream_context)))
      silc_packet_free(packet);
    silc_mutex_lock(stream->lock);
    return stream->destroyed == FALSE;
  }

  silc_dlist_start(stream->process);
  while ((p = silc_dlist_get(stream->process)) != SILC_LIST_END) {

    /* If priority is 0 or less, we send to default processor first
       because default processor has 0 priority */
    if (!default_sent && p->priority <= 0) {
      SILC_LOG_DEBUG(("Dispatching packet to default callbacks"));
      default_sent = TRUE;
      silc_mutex_unlock(stream->lock);
      if (stream->sc->engine->callbacks->
	  packet_receive(stream->sc->engine, stream, packet,
			 stream->sc->engine->callback_context,
			 stream->stream_context)) {
	silc_mutex_lock(stream->lock);
	return stream->destroyed == FALSE;
      }
      silc_mutex_lock(stream->lock);
    }

    /* Send to processor */
    if (!p->types) {
      /* Send all packet types */
      SILC_LOG_DEBUG(("Dispatching packet to %p callbacks", p->callbacks));
      silc_mutex_unlock(stream->lock);
      if (p->callbacks->packet_receive(stream->sc->engine, stream, packet,
				       p->callback_context,
				       stream->stream_context)) {
	silc_mutex_lock(stream->lock);
	return stream->destroyed == FALSE;
      }
      silc_mutex_lock(stream->lock);
    } else {
      /* Send specific types */
      for (pt = p->types; *pt; pt++) {
	if (*pt != packet->type)
	  continue;
	SILC_LOG_DEBUG(("Dispatching packet to %p callbacks", p->callbacks));
	silc_mutex_unlock(stream->lock);
	if (p->callbacks->packet_receive(stream->sc->engine, stream, packet,
					 p->callback_context,
					 stream->stream_context)) {
	  silc_mutex_lock(stream->lock);
	  return stream->destroyed == FALSE;
	}
	silc_mutex_lock(stream->lock);
	break;
      }
    }
  }

  if (!default_sent) {
    /* Send to default processor as it has not been sent yet */
    SILC_LOG_DEBUG(("Dispatching packet to default callbacks"));
    silc_mutex_unlock(stream->lock);
    if (stream->sc->engine->callbacks->
	packet_receive(stream->sc->engine, stream, packet,
		       stream->sc->engine->callback_context,
		       stream->stream_context)) {
      silc_mutex_lock(stream->lock);
      return stream->destroyed == FALSE;
    }
    silc_mutex_lock(stream->lock);
  }

  /* If we got here, no one wanted the packet, so drop it */
  silc_packet_free(packet);
  return stream->destroyed == FALSE;
}

/* Process incoming data and parse packets.  Called with stream->lock
   locked. */

static void silc_packet_read_process(SilcPacketStream stream)
{
  SilcBuffer inbuf;
  SilcCipher cipher;
  SilcHmac hmac;
  SilcPacket packet;
  SilcUInt8 sid;
  SilcUInt16 packetlen;
  SilcUInt32 paddedlen, mac_len, block_len, ivlen, psnlen;
  unsigned char tmp[SILC_PACKET_MIN_HEADER_LEN], *header;
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE], *packet_seq = NULL;
  SilcBool normal;
  int ret;

  /* Get inbuf.  If there is already some data for this stream in the buffer
     we already have it.  Otherwise get the current one from list, it will
     include the data. */
  inbuf = stream->inbuf;
  if (!inbuf) {
    silc_dlist_start(stream->sc->inbufs);
    inbuf = silc_dlist_get(stream->sc->inbufs);
  }

  /* Parse the packets from the data */
  while (silc_buffer_len(inbuf) > 0) {
    ivlen = psnlen = 0;
    cipher = stream->receive_key[0];
    hmac = stream->receive_hmac[0];
    normal = FALSE;

    if (silc_unlikely(silc_buffer_len(inbuf) <
		      (stream->iv_included ? SILC_PACKET_MIN_HEADER_LEN_IV :
		       SILC_PACKET_MIN_HEADER_LEN))) {
      SILC_LOG_DEBUG(("Partial packet in queue, waiting for the rest"));
      silc_dlist_del(stream->sc->inbufs, inbuf);
      stream->inbuf = inbuf;
      return;
    }

    if (silc_likely(hmac))
      mac_len = silc_hmac_len(hmac);
    else
      mac_len = 0;

    /* Decrypt first block of the packet to get the length field out */
    if (silc_likely(cipher)) {
      block_len = silc_cipher_get_block_len(cipher);

      if (stream->iv_included) {
	/* SID, IV and sequence number is included in the ciphertext */
	sid = (SilcUInt8)inbuf->data[0];

	if (silc_cipher_get_mode(cipher) == SILC_CIPHER_MODE_CTR) {
	  /* Set the CTR mode IV from packet to counter block */
	  memcpy(iv, silc_cipher_get_iv(cipher), block_len);
	  silc_packet_receive_ctr_increment(stream, iv, inbuf->data + 1);
	  ivlen = 8 + 1;
	} else {
	  /* Get IV from packet */
	  memcpy(iv, inbuf->data + 1, block_len);
	  ivlen = block_len + 1;
	}
	psnlen = 4;

	/* Check SID, and get correct decryption key */
	if (sid != stream->sid) {
	  /* If SID is recent get the previous key and use it */
	  if (sid > 0 && stream->sid > 0 && stream->sid - 1 == sid &&
	      stream->receive_key[1] && !stream->receive_hmac[1]) {
	    cipher = stream->receive_key[1];
	    hmac = stream->receive_hmac[1];
	  } else {
	    /* The SID is unknown, drop rest of the data in buffer */
	    SILC_LOG_DEBUG(("Unknown Security ID %d in packet, expected %d",
			    sid, stream->sid));
	    silc_mutex_unlock(stream->lock);
	    SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_UNKNOWN_SID);
	    silc_mutex_lock(stream->lock);
	    goto out;
	  }
	}
      } else {
	memcpy(iv, silc_cipher_get_iv(cipher), block_len);

	/* If using CTR mode, increment the counter */
	if (silc_cipher_get_mode(cipher) == SILC_CIPHER_MODE_CTR)
	  silc_packet_receive_ctr_increment(stream, iv, NULL);
      }

      if (silc_cipher_get_mode(cipher) == SILC_CIPHER_MODE_CTR)
	silc_cipher_set_iv(cipher, NULL);
      silc_cipher_decrypt(cipher, inbuf->data + ivlen, tmp, block_len, iv);

      header = tmp;
      if (stream->iv_included) {
	/* Take sequence number from packet */
	packet_seq = header;
	header += 4;
      }
    } else {
      /* Unencrypted packet */
      block_len = SILC_PACKET_MIN_HEADER_LEN;
      header = inbuf->data;
    }

    /* Get packet length and full packet length with padding */
    SILC_PACKET_LENGTH(header, packetlen, paddedlen);

    /* Sanity checks */
    if (silc_unlikely(packetlen < SILC_PACKET_MIN_LEN)) {
      if (!stream->udp && !silc_socket_stream_is_udp(stream->stream, NULL))
	SILC_LOG_ERROR(("Received too short packet"));
      silc_mutex_unlock(stream->lock);
      SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_MALFORMED);
      silc_mutex_lock(stream->lock);
      memset(tmp, 0, sizeof(tmp));
      goto out;
    }

    if (silc_buffer_len(inbuf) < paddedlen + ivlen + mac_len) {
      SILC_LOG_DEBUG(("Received partial packet, waiting for the rest "
		      "(%d bytes)",
		      paddedlen + mac_len - silc_buffer_len(inbuf)));
      memset(tmp, 0, sizeof(tmp));
      silc_dlist_del(stream->sc->inbufs, inbuf);
      stream->inbuf = inbuf;
      return;
    }

    /* Check MAC of the packet */
    if (silc_unlikely(!silc_packet_check_mac(hmac, inbuf->data,
					     paddedlen + ivlen,
					     inbuf->data + ivlen +
					     paddedlen, packet_seq,
					     stream->receive_psn))) {
      silc_mutex_unlock(stream->lock);
      SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_MAC_FAILED);
      silc_mutex_lock(stream->lock);
      memset(tmp, 0, sizeof(tmp));
      goto out;
    }

    /* Get packet */
    packet = silc_packet_alloc(stream->sc->engine);
    if (silc_unlikely(!packet)) {
      silc_mutex_unlock(stream->lock);
      SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_NO_MEMORY);
      silc_mutex_lock(stream->lock);
      memset(tmp, 0, sizeof(tmp));
      goto out;
    }
    packet->stream = stream;

    /* Allocate more space to packet buffer, if needed */
    if (silc_unlikely(silc_buffer_truelen(&packet->buffer) < paddedlen)) {
      if (!silc_buffer_realloc(&packet->buffer,
			       silc_buffer_truelen(&packet->buffer) +
			       (paddedlen -
				silc_buffer_truelen(&packet->buffer)))) {
	silc_mutex_unlock(stream->lock);
	SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_NO_MEMORY);
	silc_mutex_lock(stream->lock);
	silc_packet_free(packet);
	memset(tmp, 0, sizeof(tmp));
	goto out;
      }
    }

    /* Parse packet header */
    packet->flags = (SilcPacketFlags)header[2];
    packet->type = (SilcPacketType)header[3];

    if (stream->sc->engine->local_is_router) {
      if (packet->type == SILC_PACKET_PRIVATE_MESSAGE &&
	  (packet->flags & SILC_PACKET_FLAG_PRIVMSG_KEY))
	normal = FALSE;
      else if (packet->type != SILC_PACKET_CHANNEL_MESSAGE ||
	       (packet->type == SILC_PACKET_CHANNEL_MESSAGE &&
		stream->is_router == TRUE))
	normal = TRUE;
    } else {
      if (packet->type == SILC_PACKET_PRIVATE_MESSAGE &&
	  (packet->flags & SILC_PACKET_FLAG_PRIVMSG_KEY))
	normal = FALSE;
      else if (packet->type != SILC_PACKET_CHANNEL_MESSAGE)
	normal = TRUE;
    }

    SILC_LOG_HEXDUMP(("Incoming packet (%d) len %d",
		      stream->receive_psn, paddedlen + ivlen + mac_len),
		     inbuf->data, paddedlen + ivlen + mac_len);

    /* Put the decrypted part, and rest of the encrypted data, and decrypt */
    silc_buffer_pull_tail(&packet->buffer, paddedlen);
    silc_buffer_put(&packet->buffer, header, block_len - psnlen);
    silc_buffer_pull(&packet->buffer, block_len - psnlen);
    silc_buffer_put(&packet->buffer, (inbuf->data + ivlen +
				      psnlen + (block_len - psnlen)),
		    paddedlen - ivlen - psnlen - (block_len - psnlen));
    if (silc_likely(cipher)) {
      silc_cipher_set_iv(cipher, iv);
      ret = silc_packet_decrypt(cipher, hmac, stream->receive_psn,
				&packet->buffer, normal);
      if (silc_unlikely(ret < 0)) {
	silc_mutex_unlock(stream->lock);
	SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_DECRYPTION_FAILED);
	silc_mutex_lock(stream->lock);
	silc_packet_free(packet);
	memset(tmp, 0, sizeof(tmp));
	goto out;
      }

      stream->receive_psn++;
    }
    silc_buffer_push(&packet->buffer, block_len);

    /* Pull the packet from inbuf thus we'll get the next one in the inbuf. */
    silc_buffer_pull(inbuf, paddedlen + mac_len);

    /* Parse the packet */
    if (silc_unlikely(!silc_packet_parse(packet))) {
      silc_mutex_unlock(stream->lock);
      SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_MALFORMED);
      silc_mutex_lock(stream->lock);
      silc_packet_free(packet);
      memset(tmp, 0, sizeof(tmp));
      goto out;
    }

    /* Dispatch the packet to application */
    if (!silc_packet_dispatch(packet))
      break;
  }

 out:
  /* Add inbuf back to free list, if we owned it. */
  if (stream->inbuf) {
    silc_dlist_add(stream->sc->inbufs, inbuf);
    stream->inbuf = NULL;
  }

  silc_buffer_reset(inbuf);
}

/****************************** Packet Waiting ******************************/

/* Packet wait receive callback */
static SilcBool
silc_packet_wait_packet_receive(SilcPacketEngine engine,
				SilcPacketStream stream,
				SilcPacket packet,
				void *callback_context,
				void *stream_context);

/* Packet waiting callbacks */
static SilcPacketCallbacks silc_packet_wait_cbs =
{
  silc_packet_wait_packet_receive, NULL, NULL
};

/* Packet waiting context */
typedef struct {
  SilcMutex wait_lock;
  SilcCond wait_cond;
  SilcList packet_queue;
  unsigned char id[28];
  unsigned int id_type     : 2;
  unsigned int id_len      : 5;
  unsigned int stopped     : 1;
} *SilcPacketWait;

/* Packet wait receive callback */

static SilcBool
silc_packet_wait_packet_receive(SilcPacketEngine engine,
				SilcPacketStream stream,
				SilcPacket packet,
				void *callback_context,
				void *stream_context)
{
  SilcPacketWait pw = callback_context;

  /* If source ID is specified check for it */
  if (pw->id_len) {
    if (pw->id_type != packet->src_id_type ||
	memcmp(pw->id, packet->src_id, pw->id_len))
      return FALSE;
  }

  /* Signal the waiting thread for a new packet */
  silc_mutex_lock(pw->wait_lock);

  if (silc_unlikely(pw->stopped)) {
    silc_mutex_unlock(pw->wait_lock);
    return FALSE;
  }

  silc_list_add(pw->packet_queue, packet);
  silc_cond_broadcast(pw->wait_cond);

  silc_mutex_unlock(pw->wait_lock);

  return TRUE;
}

/* Initialize packet waiting */

void *silc_packet_wait_init(SilcPacketStream stream,
			    const SilcID *source_id, ...)
{
  SilcPacketWait pw;
  SilcBool ret;
  va_list ap;

  pw = silc_calloc(1, sizeof(*pw));
  if (!pw)
    return NULL;

  /* Allocate mutex and conditional variable */
  if (!silc_mutex_alloc(&pw->wait_lock)) {
    silc_free(pw);
    return NULL;
  }
  if (!silc_cond_alloc(&pw->wait_cond)) {
    silc_mutex_free(pw->wait_lock);
    silc_free(pw);
    return NULL;
  }

  /* Link to the packet stream for the requested packet types */
  va_start(ap, source_id);
  ret = silc_packet_stream_link_va(stream, &silc_packet_wait_cbs, pw,
				   10000000, ap);
  va_end(ap);
  if (!ret) {
    silc_cond_free(pw->wait_cond);
    silc_mutex_free(pw->wait_lock);
    silc_free(pw);
    return NULL;
  }

  /* Initialize packet queue */
  silc_list_init(pw->packet_queue, struct SilcPacketStruct, next);

  if (source_id) {
    SilcUInt32 id_len;
    silc_id_id2str(SILC_ID_GET_ID(*source_id), source_id->type, pw->id,
		   sizeof(pw->id), &id_len);
    pw->id_type = source_id->type;
    pw->id_len = id_len;
  }

  return (void *)pw;
}

/* Uninitialize packet waiting */

void silc_packet_wait_uninit(void *waiter, SilcPacketStream stream)
{
  SilcPacketWait pw = waiter;
  SilcPacket packet;

  /* Signal any threads to stop waiting */
  silc_mutex_lock(pw->wait_lock);
  pw->stopped = TRUE;
  silc_cond_broadcast(pw->wait_cond);
  silc_mutex_unlock(pw->wait_lock);
  silc_thread_yield();

  /* Re-acquire lock and free resources */
  silc_mutex_lock(pw->wait_lock);
  silc_packet_stream_unlink(stream, &silc_packet_wait_cbs, pw);

  /* Free any remaining packets */
  silc_list_start(pw->packet_queue);
  while ((packet = silc_list_get(pw->packet_queue)) != SILC_LIST_END)
    silc_packet_free(packet);

  silc_mutex_unlock(pw->wait_lock);
  silc_cond_free(pw->wait_cond);
  silc_mutex_free(pw->wait_lock);
  silc_free(pw);
}

/* Blocks thread until a packet has been received. */

int silc_packet_wait(void *waiter, int timeout, SilcPacket *return_packet)
{
  SilcPacketWait pw = waiter;
  SilcBool ret = FALSE;

  silc_mutex_lock(pw->wait_lock);

  /* Wait here until packet has arrived */
  while (silc_list_count(pw->packet_queue) == 0) {
    if (silc_unlikely(pw->stopped)) {
      silc_mutex_unlock(pw->wait_lock);
      return -1;
    }
    ret = silc_cond_timedwait(pw->wait_cond, pw->wait_lock, timeout);
  }

  /* Return packet */
  silc_list_start(pw->packet_queue);
  *return_packet = silc_list_get(pw->packet_queue);
  silc_list_del(pw->packet_queue, *return_packet);

  silc_mutex_unlock(pw->wait_lock);

  return ret == TRUE ? 1 : 0;
}

/************************** Packet Stream Wrapper ***************************/

/* Packet stream wrapper receive callback */
static SilcBool
silc_packet_wrap_packet_receive(SilcPacketEngine engine,
				SilcPacketStream stream,
				SilcPacket packet,
				void *callback_context,
				void *stream_context);

const SilcStreamOps silc_packet_stream_ops;

/* Packet stream wrapper context */
typedef struct {
  const SilcStreamOps *ops;
  SilcPacketStream stream;
  SilcMutex lock;
  void *waiter;			  /* Waiter context in blocking mode */
  SilcPacketWrapCoder coder;
  void *coder_context;
  SilcBuffer encbuf;
  SilcStreamNotifier callback;
  void *context;
  SilcList in_queue;
  SilcPacketType type;
  SilcPacketFlags flags;
  unsigned int closed        : 1;
  unsigned int blocking      : 1;
  unsigned int read_more     : 1;
} *SilcPacketWrapperStream;

/* Packet wrapper callbacks */
static SilcPacketCallbacks silc_packet_wrap_cbs =
{
  silc_packet_wrap_packet_receive, NULL, NULL
};

/* Packet stream wrapper receive callback, non-blocking mode */

static SilcBool
silc_packet_wrap_packet_receive(SilcPacketEngine engine,
				SilcPacketStream stream,
				SilcPacket packet,
				void *callback_context,
				void *stream_context)
{
  SilcPacketWrapperStream pws = callback_context;

  if (pws->closed || !pws->callback)
    return FALSE;

  silc_mutex_lock(pws->lock);
  silc_list_add(pws->in_queue, packet);
  silc_mutex_unlock(pws->lock);

  /* Call notifier callback */
  pws->callback((SilcStream)pws, SILC_STREAM_CAN_READ, pws->context);

  return TRUE;
}

/* Task callback to notify more data is available for reading */

SILC_TASK_CALLBACK(silc_packet_wrap_read_more)
{
  SilcPacketWrapperStream pws = context;

  if (pws->closed || !pws->callback)
    return;

  /* Call notifier callback */
  pws->callback((SilcStream)pws, SILC_STREAM_CAN_READ, pws->context);
}

/* Read SILC packet */

int silc_packet_wrap_read(SilcStream stream, unsigned char *buf,
			  SilcUInt32 buf_len)
{
  SilcPacketWrapperStream pws = stream;
  SilcPacket packet;
  SilcBool read_more = FALSE;
  int len;

  if (pws->closed)
    return -2;

  if (pws->blocking) {
    /* Block until packet is received */
    if ((silc_packet_wait(pws->waiter, 0, &packet)) < 0)
      return -2;
    if (pws->closed)
      return -2;
  } else {
    /* Non-blocking mode */
    silc_mutex_lock(pws->lock);
    if (!silc_list_count(pws->in_queue)) {
      silc_mutex_unlock(pws->lock);
      return -1;
    }

    silc_list_start(pws->in_queue);
    packet = silc_list_get(pws->in_queue);
    silc_list_del(pws->in_queue, packet);
    silc_mutex_unlock(pws->lock);
  }

  /* Call decoder if set */
  if (pws->coder && !pws->read_more)
    pws->coder(stream, SILC_STREAM_CAN_READ, &packet->buffer,
	       pws->coder_context);

  len = silc_buffer_len(&packet->buffer);
  if (len > buf_len) {
    len = buf_len;
    read_more = TRUE;
  }

  /* Read data */
  memcpy(buf, packet->buffer.data, len);

  if (read_more && !pws->blocking) {
    /* More data will be available (in blocking mode not supported). */
    silc_buffer_pull(&packet->buffer, len);
    silc_list_insert(pws->in_queue, NULL, packet);
    silc_schedule_task_add_timeout(pws->stream->sc->schedule,
				   silc_packet_wrap_read_more, pws, 0, 0);
    pws->read_more = TRUE;
    return len;
  }

  pws->read_more = FALSE;
  silc_packet_free(packet);
  return len;
}

/* Write SILC packet */

int silc_packet_wrap_write(SilcStream stream, const unsigned char *data,
			   SilcUInt32 data_len)
{
  SilcPacketWrapperStream pws = stream;
  SilcBool ret = FALSE;

  /* Call encoder if set */
  if (pws->coder) {
    silc_buffer_reset(pws->encbuf);
    ret = pws->coder(stream, SILC_STREAM_CAN_WRITE, pws->encbuf,
		     pws->coder_context);
  }

  /* Send the SILC packet */
  if (ret) {
    if (!silc_packet_send_va(pws->stream, pws->type, pws->flags,
			     SILC_STR_DATA(silc_buffer_data(pws->encbuf),
					   silc_buffer_len(pws->encbuf)),
			     SILC_STR_DATA(data, data_len),
			     SILC_STR_END))
      return -2;
  } else {
    if (!silc_packet_send(pws->stream, pws->type, pws->flags, data, data_len))
      return -2;
  }

  return data_len;
}

/* Close stream */

SilcBool silc_packet_wrap_close(SilcStream stream)
{
  SilcPacketWrapperStream pws = stream;

  if (pws->closed)
    return TRUE;

  if (pws->blocking) {
    /* Close packet waiter */
    silc_packet_wait_uninit(pws->waiter, pws->stream);
  } else {
    /* Unlink */
    if (pws->callback)
      silc_packet_stream_unlink(pws->stream, &silc_packet_wrap_cbs, pws);
  }
  pws->closed = TRUE;

  return TRUE;
}

/* Destroy wrapper stream */

void silc_packet_wrap_destroy(SilcStream stream)

{
  SilcPacketWrapperStream pws = stream;
  SilcPacket packet;

  SILC_LOG_DEBUG(("Destroying wrapped packet stream %p", pws));

  silc_stream_close(stream);
  silc_list_start(pws->in_queue);
  while ((packet = silc_list_get(pws->in_queue)))
    silc_packet_free(packet);
  if (pws->lock)
    silc_mutex_free(pws->lock);
  if (pws->encbuf)
    silc_buffer_free(pws->encbuf);
  silc_packet_stream_unref(pws->stream);

  silc_free(pws);
}

/* Link stream to receive packets */

SilcBool silc_packet_wrap_notifier(SilcStream stream,
				   SilcSchedule schedule,
			           SilcStreamNotifier callback,
			           void *context)
{
  SilcPacketWrapperStream pws = stream;

  if (pws->closed || pws->blocking)
    return FALSE;

  /* Link to receive packets */
  if (callback)
    silc_packet_stream_link(pws->stream, &silc_packet_wrap_cbs, pws,
			    100000, pws->type, -1);
  else
    silc_packet_stream_unlink(pws->stream, &silc_packet_wrap_cbs, pws);

  pws->callback = callback;
  pws->context = context;

  return TRUE;
}

/* Return schedule */

SilcSchedule silc_packet_wrap_get_schedule(SilcStream stream)
{
  return NULL;
}

/* Wraps packet stream into SilcStream. */

SilcStream silc_packet_stream_wrap(SilcPacketStream stream,
                                   SilcPacketType type,
                                   SilcPacketFlags flags,
				   SilcBool blocking_mode,
				   SilcPacketWrapCoder coder,
				   void *context)
{
  SilcPacketWrapperStream pws;

  pws = silc_calloc(1, sizeof(*pws));
  if (!pws)
    return NULL;

  SILC_LOG_DEBUG(("Wrapping packet stream %p to stream %p", stream, pws));

  pws->ops = &silc_packet_stream_ops;
  pws->stream = stream;
  pws->type = type;
  pws->flags = flags;
  pws->blocking = blocking_mode;
  pws->coder = coder;
  pws->coder_context = context;

  /* Allocate small amount for encoder buffer. */
  if (pws->coder)
    pws->encbuf = silc_buffer_alloc(8);

  if (pws->blocking) {
    /* Blocking mode.  Use packet waiter to do the thing. */
    pws->waiter = silc_packet_wait_init(pws->stream, NULL, pws->type, -1);
    if (!pws->waiter) {
      silc_free(pws);
      return NULL;
    }
  } else {
    /* Non-blocking mode */
    silc_mutex_alloc(&pws->lock);
    silc_list_init(pws->in_queue, struct SilcPacketStruct, next);
  }

  silc_packet_stream_ref(stream);

  return (SilcStream)pws;
}

const SilcStreamOps silc_packet_stream_ops =
{
  silc_packet_wrap_read,
  silc_packet_wrap_write,
  silc_packet_wrap_close,
  silc_packet_wrap_destroy,
  silc_packet_wrap_notifier,
  silc_packet_wrap_get_schedule,
};
