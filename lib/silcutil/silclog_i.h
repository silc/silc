/*

  silclog_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCLOG_I_H
#define SILCLOG_I_H

#ifndef SILCLOG_H
#error "Do not include this header directly"
#endif

#if defined(WIN32)
#ifndef __FUNCTION__
#define __FUNCTION__ ""
#endif
#endif

void silc_log_output(SilcLogType type, char *string);
void silc_log_output_debug(char *file, const char *function,
			   int line, char *string);
void silc_log_output_hexdump(char *file, const char *function,
			     int line, void *data_in,
			     SilcUInt32 len, char *string);

#endif /* SILCLOG_I_H */
