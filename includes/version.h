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

/* Version type definition */
typedef unsigned char SilcVersion;

/* SILC Versions. XXX not used currently */
#define SILC_VERSION_MAJ 1
#define SILC_VERSION_MIN 0
#define SILC_VERSION_BUILD 0

/* SILC Protocol version number used in SILC packets */
#define SILC_VERSION_1 '\1'

/* SILC version string */
const char *silc_version = "18072000";
const char *silc_name = "SILC";
const char *silc_fullname = "Secure Internet Live Conferencing";

#endif
