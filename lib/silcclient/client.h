/*

  client.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef CLIENT_H
#define CLIENT_H

/* Forward declarations */
typedef struct SilcClientStruct *SilcClient;
typedef struct SilcClientConnectionStruct *SilcClientConnection;
typedef struct SilcClientPingStruct SilcClientPing;
typedef struct SilcClientAwayStruct SilcClientAway;
typedef struct SilcClientKeyAgreementStruct *SilcClientKeyAgreement;
typedef struct SilcClientFtpSessionStruct *SilcClientFtpSession;
typedef struct SilcClientEntryStruct *SilcClientEntry;
typedef struct SilcChannelEntryStruct *SilcChannelEntry;
typedef struct SilcServerEntryStruct *SilcServerEntry;
typedef struct SilcClientCommandStruct *SilcClientCommand;
typedef struct SilcClientCommandContextStruct *SilcClientCommandContext;
typedef struct SilcClientCommandReplyContextStruct
                                           *SilcClientCommandReplyContext;
typedef struct SilcChannelUserStruct *SilcChannelUser;
typedef struct SilcClientInternalStruct *SilcClientInternal;
typedef struct SilcClientConnectionInternalStruct 
					   *SilcClientConnectionInternal;
typedef struct SilcChannelPrivateKeyStruct *SilcChannelPrivateKey;
  
/* Client entry status */
typedef enum {
  SILC_CLIENT_STATUS_NONE       = 0x0000,
  SILC_CLIENT_STATUS_RESOLVING  = 0x0001,
} SilcEntryStatus;

/* Client and its mode on a channel */
struct SilcChannelUserStruct {
  SilcClientEntry client;
  SilcUInt32 mode;
  SilcChannelEntry channel;
};

#endif
