/*
 
  silcmode.h
 
  Author: Pekka Riikonen <priikone@silcnet.org>
  
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

/****h* silccore/SILC Modes
 *
 * DESCRIPTION
 *
 * This header includes all mode definitions for the SILC. It includes
 * channel modes, channel user mode and user modes.
 *
 ***/

#ifndef SILCMODE_H
#define SILCMODE_H


/****d* silccore/Modes/ChannelModes
 *
 * DESCRIPTION
 *
 *    All channel modes.
 *
 * SOURCE
 */
#define SILC_CHANNEL_MODE_NONE         0x0000
#define SILC_CHANNEL_MODE_PRIVATE      0x0001 /* private channel */
#define SILC_CHANNEL_MODE_SECRET       0x0002 /* secret channel */
#define SILC_CHANNEL_MODE_PRIVKEY      0x0004 /* channel has private key */
#define SILC_CHANNEL_MODE_INVITE       0x0008 /* invite only channel */
#define SILC_CHANNEL_MODE_TOPIC        0x0010 /* topic setting by operator */
#define SILC_CHANNEL_MODE_ULIMIT       0x0020 /* user limit set */
#define SILC_CHANNEL_MODE_PASSPHRASE   0x0040 /* passphrase set */
#define SILC_CHANNEL_MODE_CIPHER       0x0080 /* sets cipher of the channel */
#define SILC_CHANNEL_MODE_HMAC         0x0100 /* sets hmac of the channel */
#define SILC_CHANNEL_MODE_FOUNDER_AUTH 0x0200 /* sets founder auth data */
#define SILC_CHANNEL_MODE_SILENCE_USERS 0x0400 /* sets founder auth data */
#define SILC_CHANNEL_MODE_SILENCE_OPERS 0x0800 /* sets founder auth data */
#define SILC_CHANNEL_MODE_CHANNEL_AUTH 0x1000 /* channel auth (signature) */
/***/

/****d* silccore/Modes/ChannelUserModes
 *
 * DESCRIPTION
 *
 *    All user modes on channel.  These indicate the user's status on the
 *    channel.  Some of the modes can be set by channel founder and channel
 *    operator.  Some modes may be set by users themself.
 *
 * SOURCE
 */
#define SILC_CHANNEL_UMODE_NONE            0x00000000 /* Normal user */
#define SILC_CHANNEL_UMODE_CHANFO          0x00000001 /* channel founder */
#define SILC_CHANNEL_UMODE_CHANOP          0x00000002 /* channel operator */
#define SILC_CHANNEL_UMODE_BLOCK_MESSAGES  0x00000004 /* messages blocked */
#define SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS  0x00000008 /* Block messages
							       from normal
							       users */
#define SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS 0x00000010 /* Block messages
							       from robots */
#define SILC_CHANNEL_UMODE_QUIET           0x00000020 /* user is quiet */
/***/

/****d* silccore/Modes/SilcUserMode
 *
 * DESCRIPTION
 *
 *    SILC User modes. These indicate the status and presence of the client
 *    in the SILC network.
 *
 * SOURCE
 */
#define SILC_UMODE_NONE              0x00000000 /* Normal SILC user */
#define SILC_UMODE_SERVER_OPERATOR   0x00000001 /* Server operator */
#define SILC_UMODE_ROUTER_OPERATOR   0x00000002 /* Router (SILC) operator */
#define SILC_UMODE_GONE              0x00000004 /* Client is gone */
#define SILC_UMODE_INDISPOSED        0x00000008 /* Client is indisposed */
#define SILC_UMODE_BUSY              0x00000010 /* Client is busy */
#define SILC_UMODE_PAGE              0x00000020 /* Client requests paging */
#define SILC_UMODE_HYPER             0x00000040 /* Client is hyper active */
#define SILC_UMODE_ROBOT             0x00000080 /* Client is a robot */
#define SILC_UMODE_ANONYMOUS         0x00000100 /* Client is anonymous */
#define SILC_UMODE_BLOCK_PRIVMSG     0x00000200 /* Client blocks privmsgs */
#define SILC_UMODE_DETACHED          0x00000400 /* Client is detached */
#define SILC_UMODE_REJECT_WATCHING   0x00000800 /* Client rejects watching */
#define SILC_UMODE_BLOCK_INVITE      0x00001000 /* Client blocks invites */
/***/

#endif
