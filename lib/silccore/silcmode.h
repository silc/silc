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
/***/

/****d* silccore/Modes/ChannelUserModes
 *
 * DESCRIPTION
 *
 *    All user modes on channel
 *
 * SOURCE
 */
#define SILC_CHANNEL_UMODE_NONE        0x0000 /* Normal user */
#define SILC_CHANNEL_UMODE_CHANFO      0x0001 /* channel founder */
#define SILC_CHANNEL_UMODE_CHANOP      0x0002 /* channel operator */
/***/

/****d* silccore/Modes/SilcUserMode
 *
 * DESCRIPTION
 *
 *    SILC User modes. These indicate the status of the client in the
 *    SILC network.
 *
 * SOURCE
 */
#define SILC_UMODE_NONE                0x0000 /* Normal SILC user */
#define SILC_UMODE_SERVER_OPERATOR     0x0001 /* Server operator */
#define SILC_UMODE_ROUTER_OPERATOR     0x0002 /* Router (SILC) operator */
#define SILC_UMODE_GONE                0x0004 /* Client is gone */
/***/

#endif
