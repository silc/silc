/*

  version.h

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

#ifndef VERSION_H
#define VERSION_H

#include "version_internal.h"

/* Version type definition */
typedef unsigned char SilcVersion;

/* SILC Protocol version number used in SILC packets */
#define SILC_VERSION_1 '\1'

/* SILC version string */
const char *silc_version = SILC_VERSION_STRING;
const char *silc_dist_version = SILC_DIST_VERSION_STRING;
const char *silc_version_string = SILC_PROTOCOL_VERSION_STRING;
const char *silc_name = SILC_NAME;
const char *silc_fullname = "Secure Internet Live Conferencing";

#endif
