/*

  payload.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef PAYLOAD_H
#define PAYLOAD_H

#include "silcske_status.h"
#include "payload_internal.h"

/* Prototypes */
SilcSKEStatus silc_ske_payload_start_encode(SilcSKE ske,
					    SilcSKEStartPayload *payload,
					    SilcBuffer *return_buffer);
SilcSKEStatus 
silc_ske_payload_start_decode(SilcSKE ske,
			      SilcBuffer buffer,
			      SilcSKEStartPayload **return_payload);
void silc_ske_payload_start_free(SilcSKEStartPayload *payload);
SilcSKEStatus silc_ske_payload_ke_encode(SilcSKE ske,
					 SilcSKEKEPayload *payload,
					 SilcBuffer *return_buffer);
SilcSKEStatus silc_ske_payload_ke_decode(SilcSKE ske,
					 SilcBuffer buffer,
					 SilcSKEKEPayload **return_payload);
void silc_ske_payload_ke_free(SilcSKEKEPayload *payload);

#endif
