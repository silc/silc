/*
 
  silcnotify.h
 
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

/****h* silccore/SILC Notify Interface
 *
 * DESCRIPTION
 *
 * Implementation of the Notify Payload. Notify Payload is used usually
 * by servers to send different kind of important notify messages to other
 * servers and to clients.
 *
 ***/

#ifndef SILCNOTIFY_H
#define SILCNOTIFY_H

/****s* silccore/SilcNotifyAPI/SilcNotifyPayload
 *
 * NAME
 * 
 *    typedef struct SilcNotifyPayloadStruct *SilcNotifyPayload;
 *
 * DESCRIPTION
 *
 *    This context is the actual Notify Payload and is allocated
 *    by silc_notify_payload_parse and given as argument usually to
 *    all silc_notify_payload_* functions.  It is freed by the
 *    silc_notify_payload_free function.
 *
 ***/
typedef struct SilcNotifyPayloadStruct *SilcNotifyPayload;

/****d* silccore/SilcNotifyAPI/SilcNotifyType
 *
 * NAME
 * 
 *    typedef SilcUInt16 SilcNotifyType;
 *
 * DESCRIPTION
 *
 *    The notify type definition and all of the notify types.
 *
 * SOURCE
 */
typedef SilcUInt16 SilcNotifyType;

/* SILC notify types. Server may send these notify types to client to
   notify of some action. */
#define SILC_NOTIFY_TYPE_NONE            0  /* no specific type */
#define SILC_NOTIFY_TYPE_INVITE          1  /* invites/invite list change */
#define SILC_NOTIFY_TYPE_JOIN            2  /* "has joined channel" */
#define SILC_NOTIFY_TYPE_LEAVE           3  /* "has left channel" */
#define SILC_NOTIFY_TYPE_SIGNOFF         4  /* "signoff" */
#define SILC_NOTIFY_TYPE_TOPIC_SET       5  /* "topic has been changed" */
#define SILC_NOTIFY_TYPE_NICK_CHANGE     6  /* "has changed nickname" */
#define SILC_NOTIFY_TYPE_CMODE_CHANGE    7  /* "has changed channel mode" */
#define SILC_NOTIFY_TYPE_CUMODE_CHANGE   8  /* "has change mode" */
#define SILC_NOTIFY_TYPE_MOTD            9  /* message of the day */
#define SILC_NOTIFY_TYPE_CHANNEL_CHANGE  10 /* Channel's ID has changed */
#define SILC_NOTIFY_TYPE_SERVER_SIGNOFF  11 /* Server quitting SILC */
#define SILC_NOTIFY_TYPE_KICKED          12 /* Kicked from channel */
#define SILC_NOTIFY_TYPE_KILLED          13 /* Killed from the network */
#define SILC_NOTIFY_TYPE_UMODE_CHANGE    14 /* user mode was changed */
#define SILC_NOTIFY_TYPE_BAN             15 /* ban list change */
#define SILC_NOTIFY_TYPE_ERROR           16 /* error notify */
#define SILC_NOTIFY_TYPE_WATCH           17 /* watch notify */
/***/

/* Prototypes */

/****f* silccore/SilcNotifyAPI/silc_notify_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcNotifyPayload
 *    silc_notify_payload_parse(const unsigned char *payload,
 *                              SilcUInt32 payload_len);
 *
 * DESCRIPTION
 *
 *    Parse notify payload buffer and return data into payload structure.
 *    The `buffer' is the raw payload data.
 *
 ***/
SilcNotifyPayload silc_notify_payload_parse(const unsigned char *payload,
					    SilcUInt32 payload_len);

/****f* silccore/SilcNotifyAPI/silc_notify_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_notify_payload_encode(SilcNotifyType type,
 *                                          SilcUInt32 argc,
 *                                          va_list ap);
 *
 * DESCRIPTION
 *
 *    Encode notify payload with variable argument list. If `argc' is > 0
 *    argument payloads will be associated to the notify payload. Variable
 *    arguments must be {unsigned char *, SilcUInt32 (len)}.
 *
 ***/
SilcBuffer silc_notify_payload_encode(SilcNotifyType type, SilcUInt32 argc, 
				      va_list ap);

/****f* silccore/SilcNotifyAPI/silc_notify_payload_encode_args
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_notify_payload_encode_args(SilcNotifyType type,
 *                                               SilcUInt32 argc,
 *                                               SilcBuffer args);
 *
 * DESCRIPTION
 *
 *    Same as silc_notify_payload_encode but takes arguments from the `args'
 *    encoded Argument Payload buffer.
 *
 ***/
SilcBuffer silc_notify_payload_encode_args(SilcNotifyType type, 
					   SilcUInt32 argc,
					   SilcBuffer args);

/****f* silccore/SilcNotifyAPI/silc_notify_payload_free
 *
 * SYNOPSIS
 *
 *    void silc_notify_payload_free(SilcNotifyPayload payload);
 *
 * DESCRIPTION
 *
 *    Frees the Notify Payload and all data in it.
 *
 ***/
void silc_notify_payload_free(SilcNotifyPayload payload);

/****f* silccore/SilcNotifyAPI/silc_notify_get_type
 *
 * SYNOPSIS
 *
 *    SilcNotifyType silc_notify_get_type(SilcNotifyPayload payload);
 *
 * DESCRIPTION
 *
 *    Return the notify type from the payload.
 *
 ***/
SilcNotifyType silc_notify_get_type(SilcNotifyPayload payload);

/****f* silccore/SilcNotifyAPI/silc_notify_get_arg_num
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_notify_get_arg_num(SilcNotifyPayload payload);
 *
 * DESCRIPTION
 *
 *    Return the number of the arguments associated with the Notify Payload.
 *
 ***/
SilcUInt32 silc_notify_get_arg_num(SilcNotifyPayload payload);

/****f* silccore/SilcNotifyAPI/silc_notify_get_args
 *
 * SYNOPSIS
 *
 *    SilcArgumentPayload silc_notify_get_args(SilcNotifyPayload payload);
 *
 * DESCRIPTION
 *
 *    Return the Argument Payload containing the arguments from the
 *    Notify Payload. The caller must not free it.
 *
 ***/
SilcArgumentPayload silc_notify_get_args(SilcNotifyPayload payload);

#endif
