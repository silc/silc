/*

  sftp_util.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SFTP_UTIL_H
#define SFTP_UTIL_H

typedef uint32 SilcSFTPPacket;

/* SFTP packet types */
#define SILC_SFTP_INIT               1
#define SILC_SFTP_VERSION            2
#define SILC_SFTP_OPEN               3
#define SILC_SFTP_CLOSE              4
#define SILC_SFTP_READ               5
#define SILC_SFTP_WRITE              6
#define SILC_SFTP_LSTAT              7
#define SILC_SFTP_FSTAT              8
#define SILC_SFTP_SETSTAT            9
#define SILC_SFTP_FSETSTAT           10
#define SILC_SFTP_OPENDIR            11
#define SILC_SFTP_READDIR            12
#define SILC_SFTP_REMOVE             13
#define SILC_SFTP_MKDIR              14
#define SILC_SFTP_RMDIR              15
#define SILC_SFTP_REALPATH           16
#define SILC_SFTP_STAT               17
#define SILC_SFTP_RENAME             18
#define SILC_SFTP_READLINK           19
#define SILC_SFTP_SYMLINK            20
#define SILC_SFTP_STATUS             101
#define SILC_SFTP_HANDLE             102
#define SILC_SFTP_DATA               103
#define SILC_SFTP_NAME               104
#define SILC_SFTP_ATTRS              105
#define SILC_SFTP_EXTENDED           200
#define SILC_SFTP_EXTENDED_REPLY     201

/* SFTP attributes flags */
#define SILC_SFTP_ATTR_SIZE          0x00000001
#define SILC_SFTP_ATTR_UIDGID        0x00000002
#define SILC_SFTP_ATTR_PERMISSIONS   0x00000004
#define SILC_SFTP_ATTR_ACMODTIME     0x00000008
#define SILC_SFTP_ATTR_EXTENDED      0x80000000

/* Encodes a SFTP packet of type `packet' of length `len'. The variable
   argument list is encoded as data payload to the buffer. Returns the
   encoded packet or NULL on error. The caller must free the returned
   buffer. */
SilcBuffer silc_sftp_packet_encode(SilcSFTPPacket packet, uint32 len, ...);

/* Same as silc_sftp_packet_encode but takes the variable argument list
   pointer as argument. */
SilcBuffer silc_sftp_packet_encode_vp(SilcSFTPPacket packet, uint32 len, 
				      va_list vp);

/* Decodes the SFTP packet data `data' and return the SFTP packet type.
   The payload of the packet is returned to the `payload' pointer. Returns
   NULL if error occurred during decoding. */
SilcSFTPPacket silc_sftp_packet_decode(SilcBuffer packet,
				       unsigned char **payload,
				       uint32 *payload_len);

/* Encodes the SFTP attributes to a buffer and returns the allocated buffer.
   The caller must free the buffer. */
SilcBuffer silc_sftp_attr_encode(SilcSFTPAttributes attr);

/* Decodes SilcSFTPAttributes from the buffer `buffer'. Returns the allocated
   attributes that the caller must free or NULL on error. */
SilcSFTPAttributes silc_sftp_attr_decode(SilcBuffer buffer);

/* Frees the attributes context and its internals. */
void silc_sftp_attr_free(SilcSFTPAttributes attr);

/* Adds an entry to the `name' context. */
void silc_sftp_name_add(SilcSFTPName name, const char *short_name,
			const char *long_name, SilcSFTPAttributes attrs);

/* Encodes the SilcSFTPName to a buffer and returns the allocated buffer. 
   The caller must free the buffer. */
SilcBuffer silc_sftp_name_encode(SilcSFTPName name);

/* Decodes a SilcSFTPName structure from the `buffer' that must include
   `count' many name, longname and attribute values. Returns the allocated
   structure or NULL on error. */
SilcSFTPName silc_sftp_name_decode(uint32 count, SilcBuffer buffer);

/* Frees the name context and its internals. */
void silc_sftp_name_free(SilcSFTPName name);

/* Maps errno to SFTP status message. */
SilcSFTPStatus silc_sftp_map_errno(int err);

#endif /* SFTP_UTIL_H */
