/*

  modules-formats.c

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

#include "module.h"
#include "fe-common/core/formats.h"
#include "printtext.h"

FORMAT_REC fecommon_silc_formats[] = {
	{ MODULE_NAME, "SILC", 0 },

	/* ---- */
	{ NULL, "Channel", 0 },

	{ "channel_founder_you", "You are channel founder on {channel $0}", 1, { 0 } },
	{ "channel_founder", "Channel founder on {channel $0} is: {channick_hilight $1}", 2, { 0, 0 } },
	{ "channel_topic", "Topic for {channel $0} is: $1", 2, { 0, 0 } },

	{ NULL, NULL, 0 }
};
