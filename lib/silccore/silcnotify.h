/*

  silcnotify.h

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

#ifndef SILCNOTIFY_H
#define SILCNOTIFY_H

/* Forward declarations */
typedef struct SilcNotifyPayloadStruct *SilcNotifyPayload;

/* Type definition of notify type */
typedef unsigned short SilcNotifyType;

/* SILC notify types. Server may send these notify types to client to
   notify of some action. Server also sends human readable notify message
   to the client which client may ignore. */
#define SILC_NOTIFY_TYPE_NONE            0 /* no specific type */
#define SILC_NOTIFY_TYPE_INVITE          1 /* "invites you to channel" */
#define SILC_NOTIFY_TYPE_JOIN            2 /* "has joined channel" */
#define SILC_NOTIFY_TYPE_LEAVE           3 /* "has left channel" */
#define SILC_NOTIFY_TYPE_SIGNOFF         4 /* "signoff" */
#define SILC_NOTIFY_TYPE_TOPIC_SET       5 /* "topic has been changed" */
#define SILC_NOTIFY_TYPE_NICK_CHANGE     6 /* "has changed nickname" */
#define SILC_NOTIFY_TYPE_CMODE_CHANGE    7 /* "has changed channel mode" */
#define SILC_NOTIFY_TYPE_CUMODE_CHANGE   8 /* "has change mode" */
#define SILC_NOTIFY_TYPE_MOTD            9 /* message of the day */
#define SILC_NOTIFY_TYPE_CHANNEL_CHANGE  10 /* Channel's ID has changed */

/* Prototypes */
SilcNotifyPayload silc_notify_payload_parse(SilcBuffer buffer);
SilcBuffer silc_notify_payload_encode(SilcNotifyType type, unsigned int argc, 
				      va_list ap);
void silc_notify_payload_free(SilcNotifyPayload payload);
SilcNotifyType silc_notify_get_type(SilcNotifyPayload payload);
unsigned int silc_notify_get_arg_num(SilcNotifyPayload payload);
SilcArgumentPayload silc_notify_get_args(SilcNotifyPayload payload);

#endif
