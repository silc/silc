/*

  silc.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILC_H
#define SILC_H

/* Default client configuration file. This can be overridden at the
   compilation time. Otherwise, use default. This can be overridden on
   command line as well. */
#ifndef SILC_CLIENT_CONFIG_FILE
#define SILC_CLIENT_CONFIG_FILE "/etc/silc/silc.conf"
#endif

/* Default user configuration file. This file is searched from users'
   home directory. This may override global configuration settings. */
#define SILC_CLIENT_HOME_CONFIG_FILE ".silcrc"

#endif
