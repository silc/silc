/*

  silcpayload.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCPAYLOAD_H
#define SILCPAYLOAD_H

/* Forward declarations */
typedef struct SilcIDPayloadStruct *SilcIDPayload;
typedef struct SilcArgumentPayloadStruct *SilcArgumentPayload;

/* Prototypes */
SilcIDPayload silc_id_payload_parse(SilcBuffer buffer);
SilcBuffer silc_id_payload_encode(void *id, unsigned short len,
				  SilcIdType type);
SilcArgumentPayload silc_argument_payload_parse(SilcBuffer buffer,
						unsigned int argc);
void silc_id_payload_free(SilcIDPayload payload);
SilcIdType silc_id_payload_get_type(SilcIDPayload payload);
void *silc_id_payload_get_id(SilcIDPayload payload);
SilcBuffer silc_argument_payload_encode(unsigned int argc,
					unsigned char **argv,
					unsigned int *argv_lens,
					unsigned int *argv_types);
void silc_argument_payload_free(SilcArgumentPayload payload);
unsigned int silc_argument_get_arg_num(SilcArgumentPayload payload);
unsigned char *silc_argument_get_first_arg(SilcArgumentPayload payload,
					   unsigned int *ret_len);
unsigned char *silc_argument_get_next_arg(SilcArgumentPayload payload,
					  unsigned int *ret_len);
unsigned char *silc_argument_get_arg_type(SilcArgumentPayload payload,
					  unsigned int type,
					  unsigned int *ret_len);

#endif
