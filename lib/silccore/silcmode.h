/*

  silcmode.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCMODE_H
#define SILCMODE_H

/* Forward declarations */
typedef struct SilcSetModePayloadStruct *SilcSetModePayload;

/* Mode types defined for Set Mode payload */
#define SILC_MODE_TYPE_CHANNEL        0
#define SILC_MODE_TYPE_UCHANNEL       1
#define SILC_MODE_RESERVED            2      /* RESERVED */
#define SILC_MODE_PRIVATE             32768  /* RESERVED */

/* Channel modes */
#define SILC_CHANNEL_MODE_NONE        0x0000
#define SILC_CHANNEL_MODE_PRIVATE     0x0001 /* private channel */
#define SILC_CHANNEL_MODE_SECRET      0x0002 /* secret channel */
#define SILC_CHANNEL_MODE_PRIVKEY     0x0004 /* channel has private key */
#define SILC_CHANNEL_MODE_INVITE      0x0008 /* invite only channel */
#define SILC_CHANNEL_MODE_TOPIC       0x0010 /* topic setting by operator */
#define SILC_CHANNEL_MODE_ULIMIT      0x0020 /* user limit set */
#define SILC_CHANNEL_MODE_PASSPHRASE  0x0040 /* passphrase set */
#define SILC_CHANNEL_MODE_BAN         0x0080 /* ban list set */
#define SILC_CHANNEL_MODE_INVITE_LIST 0x0100 /* invite list set */
#define SILC_CHANNEL_MODE_CIPHER      0x0200 /* sets cipher of channel */

/* User modes on channel */
#define SILC_CHANNEL_UMODE_NONE       0x0000 /* Normal user */
#define SILC_CHANNEL_UMODE_CHANFO     0x0001 /* channel founder */
#define SILC_CHANNEL_UMODE_CHANOP     0x0002 /* channel operator */

/* Prototypes */
SilcSetModePayload silc_set_mode_payload_parse(SilcBuffer buffer);
SilcBuffer silc_set_mode_payload_encode(unsigned short mode_type, 
					unsigned int mode_mask,
					unsigned int argc, 
					va_list ap);
void silc_set_mode_payload_free(SilcSetModePayload payload);
unsigned short silc_set_mode_get_type(SilcSetModePayload payload);
unsigned int silc_set_mode_get_mode(SilcSetModePayload payload);
unsigned int silc_set_mode_get_arg_num(SilcSetModePayload payload);
SilcArgumentPayload silc_set_mode_get_args(SilcSetModePayload payload);

#endif
