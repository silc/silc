/*

  modules-formats.h

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

#include "fe-common/core/formats.h"

enum {
  SILCTXT_MODULE_NAME,
  
  SILCTXT_FILL_1,
  
  SILCTXT_CHANNEL_FOUNDER_YOU,
  SILCTXT_CHANNEL_FOUNDER,
  SILCTXT_CHANNEL_TOPIC,
  SILCTXT_CHANNEL_CMODE,
  SILCTXT_CHANNEL_CUMODE,
  SILCTXT_CHANNEL_ACTION,
  SILCTXT_CHANNEL_NOTICE,
  SILCTXT_CHANNEL_OWNACTION,
  SILCTXT_CHANNEL_OWNNOTICE,

  SILCTXT_FILL_2,

  SILCTXT_WHOIS_USERINFO,
  SILCTXT_WHOIS_CHANNELS,
  SILCTXT_WHOIS_MODES,
  SILCTXT_WHOIS_IDLE,
  SILCTXT_WHOWAS_USERINFO,

  SILCTXT_FILL_3,

  SILCTXT_CH_PRIVATE_KEY_ADD,
  SILCTXT_CH_PRIVATE_KEY_NOMODE,
  SILCTXT_CH_PRIVATE_KEY_ERROR,
  SILCTXT_CH_PRIVATE_KEY_LIST,
  SILCTXT_PRIVATE_KEY_LIST,
  SILCTXT_PRIVATE_KEY_LIST_NICK,
  SILCTXT_KEY_AGREEMENT,
  SILCTXT_KEY_AGREEMENT_REQUEST,
  SILCTXT_KEY_AGREEMENT_REQUEST_HOST,
  SILCTXT_KEY_AGREEMENT_NEGOTIATE,
  SILCTXT_KEY_AGREEMENT_PRIVMSG,
  SILCTXT_KEY_AGREEMENT_OK,
  SILCTXT_KEY_AGREEMENT_ERROR,
  SILCTXT_KEY_AGREEMENT_FAILURE,
  SILCTXT_KEY_AGREEMENT_TIMEOUT,

};

extern FORMAT_REC fecommon_silc_formats[];
