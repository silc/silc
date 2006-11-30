/*

  silcpacket.c

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
/*
 * Created: Fri Jul 25 18:52:14 1997
 */
/* $Id$ */

#include "silc.h"

/************************** Types and definitions ***************************/

/* Packet engine */
struct SilcPacketEngineStruct {
  SilcRng rng;		                 /* RNG for engine */
  SilcPacketCallbacks *callbacks;	 /* Packet callbacks */
  void *callback_context;		 /* Context for callbacks */
  SilcList streams;			 /* All streams in engine */
  SilcList packet_pool;       		 /* Free list for received packets */
  SilcMutex lock;			 /* Engine lock */
  SilcBool local_is_router;
};

/* Packet procesor context */
typedef struct SilcPacketProcessStruct {
  SilcInt32 priority;		         /* Priority */
  SilcPacketType *types;		 /* Packets to process */
  SilcPacketCallbacks *callbacks;	 /* Callbacks or NULL */
  void *callback_context;
} *SilcPacketProcess;

/* Packet stream */
struct SilcPacketStreamStruct {
  struct SilcPacketStreamStruct *next;
  SilcPacketEngine engine;		 /* Packet engine */
  SilcStream stream;			 /* Underlaying stream */
  SilcMutex lock;			 /* Stream lock */
  SilcDList process;			 /* Packet processors, it set */
  void *stream_context;			 /* Stream context */
  SilcBufferStruct inbuf;	         /* In buffer */
  SilcBufferStruct outbuf;		 /* Out buffer */
  SilcCipher send_key[2];		 /* Sending key */
  SilcHmac send_hmac[2];		 /* Sending HMAC */
  SilcCipher receive_key[2];		 /* Receiving key */
  SilcHmac receive_hmac[2];		 /* Receiving HMAC */
  unsigned char *src_id;		 /* Source ID */
  unsigned char *dst_id;		 /* Destination ID */
  SilcUInt32 send_psn;			 /* Sending sequence */
  SilcUInt32 receive_psn;		 /* Receiving sequence */
  SilcAtomic8 refcnt;		         /* Reference counter */
  unsigned int src_id_len  : 6;
  unsigned int src_id_type : 2;
  unsigned int dst_id_len  : 6;
  unsigned int dst_id_type : 2;
  unsigned int is_router   : 1;		 /* Set if router stream */
  unsigned int destroyed   : 1;		 /* Set if destroyed */
  unsigned int iv_included : 1;          /* Set if IV included */
  SilcUInt8 sid;			 /* Security ID, set if IV included */
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
  (s)->engine->callbacks->eos((s)->engine, s,				\
			      (s)->engine->callback_context,		\
			      (s)->stream_context);			\
} while(0)

/* Error callback */
#define SILC_PACKET_CALLBACK_ERROR(s, err)				\
do {									\
  (s)->engine->callbacks->error((s)->engine, s, err,			\
				(s)->engine->callback_context,  	\
				(s)->stream_context);			\
} while(0)


/************************ Static utility functions **************************/

static void silc_packet_read_process(SilcPacketStream stream);

/* Our stream IO notifier callback. */

static void silc_packet_stream_io(SilcStream stream, SilcStreamStatus status,
				  void *context)
{
  SilcPacketStream ps = context;
  int ret;

  silc_mutex_lock(ps->lock);

  if (ps->destroyed) {
    silc_mutex_unlock(ps->lock);
    return;
  }

  switch (status) {

  case SILC_STREAM_CAN_WRITE:
    if (!silc_buffer_headlen(&ps->outbuf)) {
      silc_mutex_unlock(ps->lock);
      return;
    }

    SILC_LOG_DEBUG(("Writing pending data to stream"));

    /* Write pending data to stream */
    while (silc_buffer_len(&ps->outbuf) > 0) {
      ret = silc_stream_write(ps->stream, ps->outbuf.data,
			      silc_buffer_len(&ps->outbuf));
      if (ret == 0) {
	/* EOS */
	silc_buffer_reset(&ps->outbuf);
	silc_mutex_unlock(ps->lock);
	SILC_PACKET_CALLBACK_EOS(ps);
	return;
      }

      if (ret == -2) {
	/* Error */
	silc_buffer_reset(&ps->outbuf);
	silc_mutex_unlock(ps->lock);
	SILC_PACKET_CALLBACK_ERROR(ps, SILC_PACKET_ERR_WRITE);
	return;
      }

      if (ret == -1) {
	/* Cannot write now, write later. */
	silc_mutex_unlock(ps->lock);
	return;
      }

      /* Wrote data */
      silc_buffer_pull(&ps->outbuf, ret);
    }

    silc_buffer_reset(&ps->outbuf);

    silc_mutex_unlock(ps->lock);
    break;

  case SILC_STREAM_CAN_READ:
    SILC_LOG_DEBUG(("Reading data from stream"));

    /* Make sure we have fair amount of free space in inbuf */
    if (silc_buffer_taillen(&ps->inbuf) < SILC_PACKET_DEFAULT_SIZE)
      if (!silc_buffer_realloc(&ps->inbuf, silc_buffer_truelen(&ps->inbuf) +
			       SILC_PACKET_DEFAULT_SIZE * 2)) {
	silc_mutex_unlock(ps->lock);
	return;
      }

    /* Read data from stream */
    ret = silc_stream_read(ps->stream, ps->inbuf.tail,
			   silc_buffer_taillen(&ps->inbuf));

    if (ret == 0) {
      /* EOS */
      silc_buffer_reset(&ps->inbuf);
      silc_mutex_unlock(ps->lock);
      SILC_PACKET_CALLBACK_EOS(ps);
      return;
    }

    if (ret == -2) {
      /* Error */
      silc_buffer_reset(&ps->inbuf);
      silc_mutex_unlock(ps->lock);
      SILC_PACKET_CALLBACK_ERROR(ps, SILC_PACKET_ERR_READ);
      return;
    }

    if (ret == -1) {
      /* Cannot read now, do it later. */
      silc_buffer_pull(&ps->inbuf, silc_buffer_len(&ps->inbuf));
      silc_mutex_unlock(ps->lock);
      return;
    }

    /* Now process the data */
    silc_buffer_pull_tail(&ps->inbuf, ret);
    silc_packet_read_process(ps);

    silc_mutex_unlock(ps->lock);
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
    if (!packet)
      return NULL;

    SILC_LOG_DEBUG(("Allocating new packet %p", packet));

    tmp = silc_malloc(SILC_PACKET_DEFAULT_SIZE);
    if (!tmp) {
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
    if (!packet)
      return NULL;

    tmp = silc_malloc(SILC_PACKET_DEFAULT_SIZE);
    if (!tmp)
      return NULL;
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

  SILC_LOG_DEBUG(("Stopping packet engine"));

  if (!engine)
    return;

  /* XXX */

  silc_free(engine);
}

/* Create new packet stream */

SilcPacketStream silc_packet_stream_create(SilcPacketEngine engine,
					   SilcSchedule schedule,
					   SilcStream stream)
{
  SilcPacketStream ps;
  void *tmp;

  SILC_LOG_DEBUG(("Creating new packet stream"));

  if (!engine || !stream)
    return NULL;

  ps = silc_calloc(1, sizeof(*ps));
  if (!ps)
    return NULL;

  ps->engine = engine;
  ps->stream = stream;
  silc_atomic_init8(&ps->refcnt, 1);

  /* Allocate buffers */
  tmp = silc_malloc(SILC_PACKET_DEFAULT_SIZE);
  if (!tmp)
    return NULL;
  silc_buffer_set(&ps->inbuf, tmp, SILC_PACKET_DEFAULT_SIZE);
  silc_buffer_reset(&ps->inbuf);
  tmp = silc_malloc(SILC_PACKET_DEFAULT_SIZE);
  if (!tmp)
    return NULL;
  silc_buffer_set(&ps->outbuf, tmp, SILC_PACKET_DEFAULT_SIZE);
  silc_buffer_reset(&ps->outbuf);

  /* Initialize packet procesors list */
  ps->process = silc_dlist_init();

  /* Set IO notifier callback */
  silc_stream_set_notifier(ps->stream, schedule, silc_packet_stream_io, ps);

  silc_mutex_alloc(&ps->lock);

  /* Add to engine */
  silc_mutex_lock(engine->lock);
  silc_list_add(engine->streams, ps);
  silc_mutex_unlock(engine->lock);

  return ps;
}

/* Destroy packet stream */

void silc_packet_stream_destroy(SilcPacketStream stream)
{
  if (!stream)
    return;

  if (silc_atomic_get_int8(&stream->refcnt) > 1) {
    stream->destroyed = TRUE;
    return;
  }

  SILC_LOG_DEBUG(("Destroying packet stream %p", stream));

  /* Delete from engine */
  silc_mutex_lock(stream->engine->lock);
  silc_list_del(stream->engine->streams, stream);
  silc_mutex_unlock(stream->engine->lock);

  /* Clear and free buffers */
  silc_buffer_clear(&stream->inbuf);
  silc_buffer_clear(&stream->outbuf);
  silc_buffer_purge(&stream->inbuf);
  silc_buffer_purge(&stream->outbuf);

  /* XXX */

  /* Destroy the underlaying stream */
  silc_stream_destroy(stream->stream);

  silc_atomic_uninit8(&stream->refcnt);
  silc_dlist_uninit(stream->process);
  silc_mutex_free(stream->lock);
  silc_free(stream);
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

/* Reference packet stream */

void silc_packet_stream_ref(SilcPacketStream stream)
{
  silc_atomic_add_int8(&stream->refcnt, 1);
}

/* Unreference packet stream */

void silc_packet_stream_unref(SilcPacketStream stream)
{
  if (silc_atomic_sub_int8(&stream->refcnt, 1) == 0)
    silc_packet_stream_destroy(stream);
}

/* Return engine */

SilcPacketEngine silc_packet_get_engine(SilcPacketStream stream)
{
  return stream->engine;
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
				   SilcStream stream,
				   SilcSchedule schedule)
{
  if (ps->stream)
    silc_stream_set_notifier(ps->stream, schedule, NULL, NULL);
  ps->stream = stream;
  silc_stream_set_notifier(ps->stream, schedule, silc_packet_stream_io, ps);
}

/* Return underlaying stream */

SilcStream silc_packet_stream_get_stream(SilcPacketStream stream)
{
  return stream->stream;
}

/* Set ciphers for packet stream */

void silc_packet_set_ciphers(SilcPacketStream stream, SilcCipher send,
			     SilcCipher receive)
{
  SILC_LOG_DEBUG(("Setting new ciphers to packet stream"));

  silc_mutex_lock(stream->lock);

  /* In case IV Included is set, save the old key */
  if (stream->iv_included) {
    if (stream->send_key[1]) {
      silc_cipher_free(stream->send_key[1]);
      stream->send_key[1] = stream->send_key[0];
    }
    if (stream->receive_key[1]) {
      silc_cipher_free(stream->receive_key[1]);
      stream->receive_key[1] = stream->receive_key[0];
    }
  } else {
    if (stream->send_key[0])
      silc_cipher_free(stream->send_key[0]);
    if (stream->send_key[1])
      silc_cipher_free(stream->receive_key[0]);
  }

  stream->send_key[0] = send;
  stream->receive_key[0] = receive;

  silc_mutex_unlock(stream->lock);
}

/* Return current ciphers from packet stream */

SilcBool silc_packet_get_ciphers(SilcPacketStream stream, SilcCipher *send,
				 SilcCipher *receive)
{
  if (!stream->send_key[0] && !stream->receive_key[0])
    return FALSE;

  silc_mutex_lock(stream->lock);

  if (send)
    *send = stream->send_key[0];
  if (receive)
    *receive = stream->receive_key[0];

  silc_mutex_unlock(stream->lock);

  return TRUE;
}

/* Set HMACs for packet stream */

void silc_packet_set_hmacs(SilcPacketStream stream, SilcHmac send,
			   SilcHmac receive)
{
  SILC_LOG_DEBUG(("Setting new HMACs to packet stream"));

  silc_mutex_lock(stream->lock);

  /* In case IV Included is set, save the old HMAC */
  if (stream->iv_included) {
    if (stream->send_hmac[1]) {
      silc_hmac_free(stream->send_hmac[1]);
      stream->send_hmac[1] = stream->send_hmac[0];
    }
    if (stream->receive_hmac[1]) {
      silc_hmac_free(stream->receive_hmac[1]);
      stream->receive_hmac[1] = stream->receive_hmac[0];
    }
  } else {
    if (stream->send_hmac[0])
      silc_hmac_free(stream->send_hmac[0]);
    if (stream->receive_hmac[0])
      silc_hmac_free(stream->receive_hmac[0]);
  }

  stream->send_hmac[0] = send;
  stream->receive_hmac[0] = receive;

  silc_mutex_unlock(stream->lock);
}

/* Return current HMACs from packet stream */

SilcBool silc_packet_get_hmacs(SilcPacketStream stream, SilcHmac *send,
			       SilcHmac *receive)
{
  if (!stream->send_hmac[0] && !stream->receive_hmac[0])
    return FALSE;

  silc_mutex_lock(stream->lock);

  if (send)
    *send = stream->send_hmac[0];
  if (receive)
    *receive = stream->receive_hmac[0];

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

  silc_mutex_lock(stream->engine->lock);

  /* Put the packet back to freelist */
  silc_list_add(stream->engine->packet_pool, packet);
  if (silc_list_count(stream->engine->packet_pool) == 1)
    silc_list_start(stream->engine->packet_pool);

  silc_mutex_unlock(stream->engine->lock);
}

/****************************** Packet Sending ******************************/

/* Prepare outgoing data buffer for packet sending.  Returns the
   pointer to that buffer into the `packet'. */

static SilcBool silc_packet_send_prepare(SilcPacketStream stream,
					 SilcUInt32 totlen,
					 SilcHmac hmac,
					 SilcBuffer packet)
{
  unsigned char *oldptr;
  unsigned int mac_len = hmac ? silc_hmac_len(hmac) : 0;

  totlen += mac_len;

  /* Allocate more space if needed */
  if (silc_buffer_taillen(&stream->outbuf) < totlen) {
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

/* Internal routine to send packet */

static SilcBool silc_packet_send_raw(SilcPacketStream stream,
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
  int i, enclen, truelen, padlen, ivlen = 0, psnlen = 0;
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

  /* If IV is included, the SID, IV and sequence number is added to packet */
  if (stream->iv_included && cipher) {
    psnlen = sizeof(psn);
    ivlen = block_len + 1;
    iv[0] = stream->sid;
    memcpy(iv + 1, silc_cipher_get_iv(cipher), block_len);
  }

  /* We automatically figure out the packet structure from the packet
     type and flags, and calculate correct length.  Private messages with
     private keys and channel messages are special packets as their
     payload is encrypted already. */
  if ((type == SILC_PACKET_PRIVATE_MESSAGE &&
       flags & SILC_PACKET_FLAG_PRIVMSG_KEY) ||
      type == SILC_PACKET_CHANNEL_MESSAGE) {

    /* Padding is calculated from header + IDs */
    SILC_PACKET_PADLEN((SILC_PACKET_HEADER_LEN + src_id_len + dst_id_len +
			psnlen), block_len, padlen);

    /* Length to encrypt, header + IDs + padding. */
    enclen = (SILC_PACKET_HEADER_LEN + src_id_len + dst_id_len +
	      padlen + psnlen);
  } else {

    /* Padding is calculated from true length of the packet */
    if (flags & SILC_PACKET_FLAG_LONG_PAD)
      SILC_PACKET_PADLEN_MAX(truelen + psnlen, block_len, padlen);
    else
      SILC_PACKET_PADLEN(truelen + psnlen, block_len, padlen);

    enclen += padlen + psnlen;
  }

  /* Remove implementation specific flags */
  flags &= ~(SILC_PACKET_FLAG_LONG_PAD);

  /* Get random padding */
  for (i = 0; i < padlen; i++) tmppad[i] =
				 silc_rng_get_byte_fast(stream->engine->rng);

  silc_mutex_lock(stream->lock);

  /* Get packet pointer from the outgoing buffer */
  if (!silc_packet_send_prepare(stream, truelen + padlen + ivlen + psnlen,
				hmac, &packet)) {
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
  if (i < 0) {
    silc_mutex_unlock(stream->lock);
    return FALSE;
  }

  SILC_LOG_HEXDUMP(("Assembled packet, len %d", silc_buffer_len(&packet)),
		   silc_buffer_data(&packet), silc_buffer_len(&packet));

  /* Encrypt the packet */
  if (cipher) {
    SILC_LOG_DEBUG(("Encrypting packet"));
    if (!silc_cipher_encrypt(cipher, packet.data + ivlen,
			     packet.data + ivlen, enclen, NULL)) {
      SILC_LOG_ERROR(("Packet encryption failed"));
      silc_mutex_unlock(stream->lock);
      return FALSE;
    }
  }

  /* Compute HMAC */
  if (hmac) {
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

  /* Write the packet to the stream */
  while (silc_buffer_len(&stream->outbuf) > 0) {
    i = silc_stream_write(stream->stream, stream->outbuf.data,
			  silc_buffer_len(&stream->outbuf));
    if (i == 0) {
      /* EOS */
      silc_buffer_reset(&stream->outbuf);
      silc_mutex_unlock(stream->lock);
      SILC_PACKET_CALLBACK_EOS(stream);
      return FALSE;
    }

    if (i == -2) {
      /* Error */
      silc_buffer_reset(&stream->outbuf);
      silc_mutex_unlock(stream->lock);
      SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_WRITE);
      return FALSE;
    }

    if (i == -1) {
      /* Cannot write now, write later. */
      silc_mutex_unlock(stream->lock);
      return TRUE;
    }

    /* Wrote data */
    silc_buffer_pull(&stream->outbuf, i);
  }
  silc_buffer_reset(&stream->outbuf);

  silc_mutex_unlock(stream->lock);
  return TRUE;
}

/* Sends a packet */

SilcBool silc_packet_send(SilcPacketStream stream,
			  SilcPacketType type, SilcPacketFlags flags,
			  const unsigned char *data, SilcUInt32 data_len)
{
  return silc_packet_send_raw(stream, type, flags,
			      stream->src_id_type,
			      stream->src_id,
			      stream->src_id_len,
			      stream->dst_id_type,
			      stream->dst_id,
			      stream->dst_id_len,
			      data, data_len,
			      stream->send_key[0],
			      stream->send_hmac[0]);
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

  if (src_id)
    if (!silc_id_id2str(src_id, src_id_type, src_id_data,
			sizeof(src_id_data), &src_id_len))
      return FALSE;
  if (dst_id)
    if (!silc_id_id2str(dst_id, dst_id_type, dst_id_data,
			sizeof(dst_id_data), &dst_id_len))
      return FALSE;

  return silc_packet_send_raw(stream, type, flags,
			      src_id ? src_id_type : stream->src_id_type,
			      src_id ? src_id_data : stream->src_id,
			      src_id ? src_id_len : stream->src_id_len,
			      dst_id ? dst_id_type : stream->dst_id_type,
			      dst_id ? dst_id_data : stream->dst_id,
			      dst_id ? dst_id_len : stream->dst_id_len,
			      data, data_len,
			      cipher ? cipher : stream->send_key[0],
			      hmac ? hmac : stream->send_hmac[0]);
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

static SilcBool silc_packet_check_mac(SilcHmac hmac,
				      const unsigned char *data,
				      SilcUInt32 data_len,
				      const unsigned char *packet_mac,
				      const unsigned char *packet_seq,
				      SilcUInt32 sequence)
{
  /* Check MAC */
  if (hmac) {
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
    if (memcmp(packet_mac, mac, mac_len)) {
      SILC_LOG_DEBUG(("MAC failed"));
      return FALSE;
    }

    SILC_LOG_DEBUG(("MAC is Ok"));
  }

  return TRUE;
}

/* Decrypts SILC packet.  Handles both normal and special packet decryption.
   Return 0 when packet is normal and 1 when it it special, -1 on error. */

static int silc_packet_decrypt(SilcCipher cipher, SilcHmac hmac,
			       SilcUInt32 sequence, SilcBuffer buffer,
			       SilcBool normal)
{
  if (normal == TRUE) {
    if (cipher) {
      /* Decrypt rest of the packet */
      SILC_LOG_DEBUG(("Decrypting the packet"));
      if (!silc_cipher_decrypt(cipher, buffer->data, buffer->data,
			       silc_buffer_len(buffer), NULL))
	return -1;
    }
    return 0;

  } else {
    /* Decrypt rest of the header plus padding */
    if (cipher) {
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

      if (len > silc_buffer_len(buffer)) {
	SILC_LOG_ERROR(("Garbage in header of packet, bad packet length, "
			"packet dropped"));
	return -1;
      }
      if (!silc_cipher_decrypt(cipher, buffer->data, buffer->data,
			       len, NULL))
	return -1;
    }

    return 1;
  }
}

/* Parses the packet. This is called when a whole packet is ready to be
   parsed. The buffer sent must be already decrypted before calling this
   function. */

static SilcBool silc_packet_parse(SilcPacket packet)
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
  if (ret == -1) {
    SILC_LOG_ERROR(("Malformed packet header, packet dropped"));
    return FALSE;
  }

  if (src_id_len > SILC_PACKET_MAX_ID_LEN ||
      dst_id_len > SILC_PACKET_MAX_ID_LEN) {
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
  if (ret == -1) {
    SILC_LOG_ERROR(("Malformed packet header, packet dropped"));
    return FALSE;
  }

  if (src_id_type > SILC_ID_CHANNEL ||
      dst_id_type > SILC_ID_CHANNEL) {
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

/* Dispatch packet to application.  Called with stream->lock locked. */

static void silc_packet_dispatch(SilcPacket packet)
{
  SilcPacketStream stream = packet->stream;
  SilcPacketProcess p;
  SilcBool default_sent = FALSE;
  SilcPacketType *pt;

  /* Parse the packet */
  if (!silc_packet_parse(packet)) {
    silc_mutex_unlock(stream->lock);
    SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_MALFORMED);
    silc_mutex_lock(stream->lock);
    silc_packet_free(packet);
    return;
  }

  /* Dispatch packet to all packet processors that want it */

  if (!stream->process) {
    /* Send to default processor as no others exist */
    SILC_LOG_DEBUG(("Dispatching packet to default callbacks"));
    silc_mutex_unlock(stream->lock);
    if (!stream->engine->callbacks->
	packet_receive(stream->engine, stream, packet,
		       stream->engine->callback_context,
		       stream->stream_context))
      silc_packet_free(packet);
    silc_mutex_lock(stream->lock);
    return;
  }

  silc_dlist_start(stream->process);
  while ((p = silc_dlist_get(stream->process)) != SILC_LIST_END) {

    /* If priority is 0 or less, we send to default processor first
       because default processor has 0 priority */
    if (!default_sent && p->priority <= 0) {
      SILC_LOG_DEBUG(("Dispatching packet to default callbacks"));
      default_sent = TRUE;
      silc_mutex_unlock(stream->lock);
      if (stream->engine->callbacks->
	  packet_receive(stream->engine, stream, packet,
			 stream->engine->callback_context,
			 stream->stream_context)) {
	silc_mutex_lock(stream->lock);
	return;
      }
      silc_mutex_lock(stream->lock);
    }

    /* Send to processor */
    if (!p->types) {
      /* Send all packet types */
      SILC_LOG_DEBUG(("Dispatching packet to %p callbacks", p->callbacks));
      silc_mutex_unlock(stream->lock);
      if (p->callbacks->packet_receive(stream->engine, stream, packet,
				       p->callback_context,
				       stream->stream_context)) {
	silc_mutex_lock(stream->lock);
	return;
      }
      silc_mutex_lock(stream->lock);
    } else {
      /* Send specific types */
      for (pt = p->types; *pt; pt++) {
	if (*pt != packet->type)
	  continue;
	SILC_LOG_DEBUG(("Dispatching packet to %p callbacks", p->callbacks));
	silc_mutex_unlock(stream->lock);
	if (p->callbacks->packet_receive(stream->engine, stream, packet,
					 p->callback_context,
					 stream->stream_context)) {
	  silc_mutex_lock(stream->lock);
	  return;
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
    if (stream->engine->callbacks->
	packet_receive(stream->engine, stream, packet,
		       stream->engine->callback_context,
		       stream->stream_context)) {
      silc_mutex_lock(stream->lock);
      return;
    }
    silc_mutex_lock(stream->lock);
  }

  /* If we got here, no one wanted the packet, so drop it */
  silc_packet_free(packet);
}

/* Process incoming data and parse packets.  Called with stream->lock
   locked. */

static void silc_packet_read_process(SilcPacketStream stream)
{
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

  /* Parse the packets from the data */
  while (silc_buffer_len(&stream->inbuf) > 0) {
    ivlen = psnlen = 0;
    cipher = stream->receive_key[0];
    hmac = stream->receive_hmac[0];
    normal = FALSE;

    if (silc_buffer_len(&stream->inbuf) <
	(stream->iv_included ? SILC_PACKET_MIN_HEADER_LEN_IV :
	 SILC_PACKET_MIN_HEADER_LEN)) {
      SILC_LOG_DEBUG(("Partial packet in queue, waiting for the rest"));
      return;
    }

    if (hmac)
      mac_len = silc_hmac_len(hmac);
    else
      mac_len = 0;

    /* Decrypt first block of the packet to get the length field out */
    if (cipher) {
      block_len = silc_cipher_get_block_len(cipher);

      if (stream->iv_included) {
	/* SID, IV and sequence number is included in the ciphertext */
	sid = (SilcUInt8)stream->inbuf.data[0];
	memcpy(iv, stream->inbuf.data + 1, block_len);
	ivlen = block_len + 1;
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
	    silc_buffer_reset(&stream->inbuf);
	    return;
	  }
	}
      } else {
	memcpy(iv, silc_cipher_get_iv(cipher), block_len);
      }

      silc_cipher_decrypt(cipher, stream->inbuf.data + ivlen, tmp,
			  block_len, iv);

      header = tmp;
      if (stream->iv_included) {
	/* Take sequence number from packet */
	packet_seq = header;
	header += 4;
      }
    } else {
      block_len = SILC_PACKET_MIN_HEADER_LEN;
      header = stream->inbuf.data;
    }

    /* Get packet length and full packet length with padding */
    SILC_PACKET_LENGTH(header, packetlen, paddedlen);

    /* Sanity checks */
    if (packetlen < SILC_PACKET_MIN_LEN) {
      SILC_LOG_ERROR(("Received too short packet"));
      silc_mutex_unlock(stream->lock);
      SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_MALFORMED);
      silc_mutex_lock(stream->lock);
      memset(tmp, 0, sizeof(tmp));
      silc_buffer_reset(&stream->inbuf);
      return;
    }

    if (silc_buffer_len(&stream->inbuf) < paddedlen + ivlen + mac_len) {
      SILC_LOG_DEBUG(("Received partial packet, waiting for the rest "
		      "(%d bytes)",
		      paddedlen + mac_len - silc_buffer_len(&stream->inbuf)));
      memset(tmp, 0, sizeof(tmp));
      return;
    }

    /* Check MAC of the packet */
    if (!silc_packet_check_mac(hmac, stream->inbuf.data,
			       paddedlen + ivlen,
			       stream->inbuf.data + ivlen + paddedlen,
			       packet_seq, stream->receive_psn)) {
      silc_mutex_unlock(stream->lock);
      SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_MAC_FAILED);
      silc_mutex_lock(stream->lock);
      memset(tmp, 0, sizeof(tmp));
      silc_buffer_reset(&stream->inbuf);
      return;
    }

    /* Get packet */
    packet = silc_packet_alloc(stream->engine);
    if (!packet) {
      silc_mutex_unlock(stream->lock);
      SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_NO_MEMORY);
      silc_mutex_lock(stream->lock);
      memset(tmp, 0, sizeof(tmp));
      silc_buffer_reset(&stream->inbuf);
      return;
    }
    packet->stream = stream;

    /* Allocate more space to packet buffer, if needed */
    if (silc_buffer_truelen(&packet->buffer) < paddedlen) {
      if (!silc_buffer_realloc(&packet->buffer,
			       silc_buffer_truelen(&packet->buffer) +
			       (paddedlen -
				silc_buffer_truelen(&packet->buffer)))) {
	silc_mutex_unlock(stream->lock);
	SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_NO_MEMORY);
	silc_mutex_lock(stream->lock);
	silc_packet_free(packet);
	memset(tmp, 0, sizeof(tmp));
	silc_buffer_reset(&stream->inbuf);
	return;
      }
    }

    /* Parse packet header */
    packet->flags = (SilcPacketFlags)header[2];
    packet->type = (SilcPacketType)header[3];

    if (stream->engine->local_is_router) {
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
		     stream->inbuf.data, paddedlen + ivlen + mac_len);

    /* Put the decrypted part, and rest of the encrypted data, and decrypt */
    silc_buffer_pull_tail(&packet->buffer, paddedlen);
    silc_buffer_put(&packet->buffer, header, block_len - psnlen);
    silc_buffer_pull(&packet->buffer, block_len - psnlen);
    silc_buffer_put(&packet->buffer, (stream->inbuf.data + ivlen +
				      psnlen + (block_len - psnlen)),
		    paddedlen - ivlen - psnlen - (block_len - psnlen));
    if (cipher) {
      silc_cipher_set_iv(cipher, iv);
      ret = silc_packet_decrypt(cipher, hmac, stream->receive_psn,
				&packet->buffer, normal);
      if (ret < 0) {
	silc_mutex_unlock(stream->lock);
	SILC_PACKET_CALLBACK_ERROR(stream, SILC_PACKET_ERR_DECRYPTION_FAILED);
	silc_mutex_lock(stream->lock);
	silc_packet_free(packet);
	memset(tmp, 0, sizeof(tmp));
	return;
      }

      stream->receive_psn++;
    }
    silc_buffer_push(&packet->buffer, block_len);

    /* Pull the packet from inbuf thus we'll get the next one in the inbuf. */
    silc_buffer_pull(&stream->inbuf, paddedlen + mac_len);

    /* Dispatch the packet to application */
    silc_packet_dispatch(packet);
  }

  silc_buffer_reset(&stream->inbuf);
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

  /* Signal the waiting thread for a new packet */
  silc_mutex_lock(pw->wait_lock);

  if (pw->stopped) {
    silc_mutex_unlock(pw->wait_lock);
    return FALSE;
  }

  silc_list_add(pw->packet_queue, packet);
  silc_cond_broadcast(pw->wait_cond);

  silc_mutex_unlock(pw->wait_lock);

  return TRUE;
}

/* Initialize packet waiting */

void *silc_packet_wait_init(SilcPacketStream stream, ...)
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
  va_start(ap, stream);
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
    if (pw->stopped) {
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
