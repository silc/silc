/*

  route.h

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

#ifndef ROUTE_H
#define ROUTE_H

/* Definitions */

/* Size of the route cache hash table */
#define SILC_SERVER_ROUTE_SIZE 256

/*
   SILC Server Route table

   Following short description of the fields.

   unsigned int dest

       Destination IPv4 address.  Can be used to quickly check whether
       the found route entry is what the caller wanted.

   SilcServerList *router

       Pointer to the router specific data.

*/
typedef struct {
  unsigned int dest;
  SilcServerList *router;
} SilcServerRouteTable;

/* Route cache hash table */
extern SilcServerRouteTable silc_route_cache[SILC_SERVER_ROUTE_SIZE];

/* Macros and super macros */

/* Returns route cache hash table entry index. This is IPv4 specific.
   `port' argument may be zero (0) if it doesn't exist.  This has been
   taken from Linux kernel's route cache code. */
extern inline
unsigned int silc_server_route_hash(unsigned int addr, 
				    unsigned short port)
{
  unsigned int hash;
  
  hash = ((addr & 0xf0f0f0f0) >> 4) | ((addr & 0x0f0f0f0f) << 4);
  hash ^= port;
  hash ^= (hash >> 16);
  hash ^= (hash >> 8);
  
  return hash & 0xff;
}

/* Prototypes */
void silc_server_route_add(unsigned int index, unsigned int dest,
			   SilcServerList *router);
SilcServerList *silc_server_route_check(unsigned int dest, 
					unsigned short port);

#endif
