/*

  silcstatus.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silccore/SILC Status Types
 *
 * DESCRIPTION
 *
 * This header includes the SILC Status Types that are used with
 * command replies and with notify packets.  With command reply packets
 * they indicate whether error occurred during procesing of the command
 * and indicate the error type.  With notify type they always indicate
 * which error occurred.  Both command reply and notify type share the
 * same status types.
 *
 ***/

#ifndef SILCSTATUS_H
#define SILCSTATUS_H

/****d* silccore/StatusTypes/SilcStatus
 *
 * NAME
 * 
 *    typedef SilcUInt8 SilcStatus
 *
 * DESCRIPTION
 *
 *    The SilcStatus type definition and the status defines.  The
 *    server returns a status in each Command Payload indicating
 *    the status of the command.  The server can also return this
 *    inside SILC_NOTIFY_TYPE_ERROR notify type.
 *
 * SOURCE
 */
typedef SilcUInt8 SilcStatus;

/* Command Status messages */
#define SILC_STATUS_OK                      0
#define SILC_STATUS_LIST_START              1
#define SILC_STATUS_LIST_ITEM               2
#define SILC_STATUS_LIST_END                3
#define SILC_STATUS_ERR_NO_SUCH_NICK        10
#define SILC_STATUS_ERR_NO_SUCH_CHANNEL     11
#define SILC_STATUS_ERR_NO_SUCH_SERVER      12
#define SILC_STATUS_ERR_TOO_MANY_TARGETS    13
#define SILC_STATUS_ERR_NO_RECIPIENT        14
#define SILC_STATUS_ERR_UNKNOWN_COMMAND     15
#define SILC_STATUS_ERR_WILDCARDS           16
#define SILC_STATUS_ERR_NO_CLIENT_ID        17
#define SILC_STATUS_ERR_NO_CHANNEL_ID       18
#define SILC_STATUS_ERR_NO_SERVER_ID        19
#define SILC_STATUS_ERR_BAD_CLIENT_ID       20
#define SILC_STATUS_ERR_BAD_CHANNEL_ID      21
#define SILC_STATUS_ERR_NO_SUCH_CLIENT_ID   22
#define SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID  23
#define SILC_STATUS_ERR_NICKNAME_IN_USE     24
#define SILC_STATUS_ERR_NOT_ON_CHANNEL      25
#define SILC_STATUS_ERR_USER_NOT_ON_CHANNEL 26
#define SILC_STATUS_ERR_USER_ON_CHANNEL     27
#define SILC_STATUS_ERR_NOT_REGISTERED      28
#define SILC_STATUS_ERR_NOT_ENOUGH_PARAMS   29
#define SILC_STATUS_ERR_TOO_MANY_PARAMS     30
#define SILC_STATUS_ERR_PERM_DENIED         31
#define SILC_STATUS_ERR_BANNED_FROM_SERVER  32
#define SILC_STATUS_ERR_BAD_PASSWORD        33
#define SILC_STATUS_ERR_CHANNEL_IS_FULL     34
#define SILC_STATUS_ERR_NOT_INVITED         35
#define SILC_STATUS_ERR_BANNED_FROM_CHANNEL 36
#define SILC_STATUS_ERR_UNKNOWN_MODE        37
#define SILC_STATUS_ERR_NOT_YOU             38
#define SILC_STATUS_ERR_NO_CHANNEL_PRIV     39
#define SILC_STATUS_ERR_NO_CHANNEL_FOPRIV   40
#define SILC_STATUS_ERR_NO_SERVER_PRIV      41
#define SILC_STATUS_ERR_NO_ROUTER_PRIV      42
#define SILC_STATUS_ERR_BAD_NICKNAME        43
#define SILC_STATUS_ERR_BAD_CHANNEL         44
#define SILC_STATUS_ERR_AUTH_FAILED         45
#define SILC_STATUS_ERR_UNKNOWN_ALGORITHM   46
#define SILC_STATUS_ERR_NO_SUCH_SERVER_ID   47
/***/

#endif /* SILCSTATUS_H */
