/*

  silchmac.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1999 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCHMAC_H
#define SILCHMAC_H

/****h* silccrypt/SilcHMACAPI
 *
 * DESCRIPTION
 *
 *    This is the interface for HMAC, or the keyed hash values, that are
 *    used for packet and message authentication.  These routines uses
 *    already implemented hash functions from the SilcHashAPI. These 
 *    routines were created according to RFC 2104.
 *
 ***/

/****s* silccrypt/SilcHMACAPI/SilcHmac
 *
 * NAME
 * 
 *    typedef struct SilcHmacStruct *SilcHmac;
 *
 * DESCRIPTION
 *
 *    This context is the actual HMAC context and is allocated
 *    by silc_hmac_alloc and given as argument usually to all
 *    silc_hmac_* functions.  It is freed by the silc_hmac_free
 *    function.
 *
 ***/
typedef struct SilcHmacStruct *SilcHmac;

/****s* silccrypt/SilcHMACAPI/SilcHmacObject
 *
 * NAME
 * 
 *    typedef struct { ... } SilcHmacObject;
 *
 * DESCRIPTION
 *
 *    This structure represents one HMAC.  The HMAC's name and the
 *    MAC length is defined in the structure.  This structure is
 *    then given as argument to the silc_hmac_register.  That function
 *    is used to register all HMACs into SILC.  They can be then
 *    allocated by the name found in this structure by calling the
 *    silc_hmac_alloc.
 *
 ***/
typedef struct {
  char *name;
  uint32 len;
} SilcHmacObject;

/* Marks for all hmacs. This can be used in silc_hmac_unregister
   to unregister all hmacs at once. */
#define SILC_ALL_HMACS ((SilcHmacObject *)1)

/* Default hmacs for silc_hmac_register_default(). */
extern SilcHmacObject silc_default_hmacs[];

/* Default HMAC in the SILC protocol */
#define SILC_DEFAULT_HMAC "hmac-sha1-96"

/* Prototypes */

/****f* silccrypt/SilcHMACAPI/silc_hmac_register
 *
 * SYNOPSIS
 *
 *    bool silc_hmac_register(SilcHmacObject *hmac);
 *
 * DESCRIPTION
 *
 *    Registers a new HMAC into the SILC. This function is used at the
 *    initialization of the SILC.  All registered HMACs should be
 *    unregistered with silc_hmac_unregister.  The `hmac' includes the
 *    name of the HMAC and the length of the MAC.  Usually this
 *    function is not called directly.  Instead, application can call
 *    the silc_hmac_register_default to register all default HMACs
 *    that are builtin the sources.  Returns FALSE on error.
 *
 ***/
bool silc_hmac_register(SilcHmacObject *hmac);

/****f* silccrypt/SilcHMACAPI/silc_hmac_unregister
 *
 * SYNOPSIS
 *
 *    bool silc_hmac_unregister(SilcHmacObject *hmac);
 *
 * DESCRIPTION
 *
 *    Unregister a HMAC from SILC by the HMAC structure `hmac'.  This
 *    should be called for all registered HMAC's.  Returns FALSE on
 *    error.
 *
 ***/
bool silc_hmac_unregister(SilcHmacObject *hmac);

/****f* silccrypt/SilcHMACAPI/silc_hmac_register_default
 *
 * SYNOPSIS
 *
 *    bool silc_hmac_register_default(void);
 *
 * DESCRIPTION
 *
 *    Registers all default HMACs into the SILC.  These are the HMACs
 *    that are builtin in the sources.  See the list of default HMACs
 *    in the silchmac.c source file.  The application may use this
 *    to register default HMACs if specific HMAC in any specific order
 *    is not wanted (application's configuration usually may decide
 *    the order of the registration, in which case this should not be
 *    used).
 *
 ***/
bool silc_hmac_register_default(void);

/****f* silccrypt/SilcHMACAPI/silc_hmac_alloc
 *
 * SYNOPSIS
 *
 *    bool silc_hmac_alloc(char *name, SilcHash hash, SilcHmac *new_hmac);
 *
 * DESCRIPTION
 *
 *    Allocates a new SilcHmac object of name of `name'.  The `hash' may
 *    be provided as argument.  If provided it is used as the hash function
 *    of the HMAC.  If it is NULL then the hash function is allocated and
 *    the name of the hash algorithm is derived from the `name'.  Returns
 *    FALSE if such HMAC does not exist.
 *
 ***/
bool silc_hmac_alloc(char *name, SilcHash hash, SilcHmac *new_hmac);

/****f* silccrypt/SilcHMACAPI/silc_hmac_free
 *
 * SYNOPSIS
 *
 *    void silc_hmac_free(SilcHmac hmac);
 *
 * DESCRIPTION
 *
 *    Frees the allocated HMAC context.  The key that may have been set
 *    with the silc_hmac_set_key is also destroyed.
 *
 ***/
void silc_hmac_free(SilcHmac hmac);

/****f* silccrypt/SilcHMACAPI/silc_hmac_is_supported
 *
 * SYNOPSIS
 *
 *    bool silc_hmac_is_supported(const char *name);
 *
 * DESCRIPTION
 *
 *    Returns TRUE if the HMAC indicated by the `name' exists.
 *
 ***/
bool silc_hmac_is_supported(const char *name);

/****f* silccrypt/SilcHMACAPI/silc_hmac_get_supported
 *
 * SYNOPSIS
 *
 *    char *silc_hmac_get_supported(void);
 *
 * DESCRIPTION
 *
 *    Returns comma (`,') separated list of registered HMACs.  This is
 *    used for example when sending supported HMAC list during the SILC
 *    Key Exchange protocol (SKE).  The caller must free the returned
 *    pointer.
 *
 ***/
char *silc_hmac_get_supported(void);

/****f* silccrypt/SilcHMACAPI/silc_hmac_len
 *
 * SYNOPSIS
 *
 *    uint32 silc_hmac_len(SilcHmac hmac);
 *
 * DESCRIPTION
 *
 *    Returns the length of the MAC that the HMAC will produce.
 *
 ***/
uint32 silc_hmac_len(SilcHmac hmac);

/****f* silccrypt/SilcHMACAPI/silc_hmac_get_hash
 *
 * SYNOPSIS
 *
 *    SilcHash silc_hmac_get_hash(SilcHmac hmac);
 *
 * DESCRIPTION
 *
 *    Returns the SilcHash context that has been associated with the
 *    HMAC context.  The caller must not free the returned context.
 *
 ***/
SilcHash silc_hmac_get_hash(SilcHmac hmac);

/****f* silccrypt/SilcHMACAPI/silc_hmac_get_name
 *
 * SYNOPSIS
 *
 *    const char *silc_hmac_get_name(SilcHmac hmac);
 *
 * DESCRIPTION
 *
 *    Returns the name of the HMAC context.
 *
 ***/
const char *silc_hmac_get_name(SilcHmac hmac);

/****f* silccrypt/SilcHMACAPI/silc_hmac_set_key
 *
 * SYNOPSIS
 *
 *    void silc_hmac_set_key(SilcHmac hmac, const unsigned char *key,
 *                           uint32 key_len);
 *
 * DESCRIPTION
 *
 *    Sets the key to be used in the HMAC operation.  This must be set
 *    before calling silc_hmac_make or silc_hmac_final functions.  If
 *    you do not want to set the key you can still produce a MAC by
 *    calling the silc_hmac_make_with_key where you give the key as
 *    argument.  Usually application still wants to set the key.
 *
 ***/
void silc_hmac_set_key(SilcHmac hmac, const unsigned char *key,
		       uint32 key_len);

/****f* silccrypt/SilcHMACAPI/silc_hmac_make
 *
 * SYNOPSIS
 *
 *    void silc_hmac_make(SilcHmac hmac, unsigned char *data,
 *                        uint32 data_len, unsigned char *return_hash,
 *                        uint32 *return_len);
 *
 * DESCRIPTION
 *
 *    Computes a MAC from a data buffer indicated by the `data' of the
 *    length of `data_len'.  The returned MAC is copied into the 
 *    `return_hash' pointer which must be at least the size of the
 *    value silc_hmac_len returns.  The returned length is still
 *    returned to `return_len'.
 *
 ***/
void silc_hmac_make(SilcHmac hmac, unsigned char *data,
		    uint32 data_len, unsigned char *return_hash,
		    uint32 *return_len);

/****f* silccrypt/SilcHMACAPI/silc_hmac_make_with_key
 *
 * SYNOPSIS
 *
 *    void silc_hmac_make_with_key(SilcHmac hmac, unsigned char *data,
 *                                 uint32 data_len, 
 *                                 unsigned char *key, uint32 key_len,
 *                                 unsigned char *return_hash,
 *                                 uint32 *return_len);
 *
 * DESCRIPTION
 *
 *    Same as the silc_hmac_make but takes the key for the HMAC as
 *    argument.  If this is used the key that may have been set by calling
 *    silc_hmac_set_key is ignored.
 *
 ***/
void silc_hmac_make_with_key(SilcHmac hmac, unsigned char *data,
			     uint32 data_len, 
			     unsigned char *key, uint32 key_len,
			     unsigned char *return_hash,
			     uint32 *return_len);

/****f* silccrypt/SilcHMACAPI/silc_hmac_make_truncated
 *
 * SYNOPSIS
 *
 *    void silc_hmac_make_truncated(SilcHmac hmac, 
 *                                  unsigned char *data, 
 *                                  uint32 data_len,
 *                                  uint32 truncated_len,
 *                                  unsigned char *return_hash);
 *
 * DESCRIPTION
 *
 *    Same as the silc_hmac_make except that the returned MAC is
 *    truncated to the length indicated by the `truncated_len'.  Some
 *    special applications may need this function.  The `return_hash'
 *    must be at least the size of `truncated_len'.
 *
 * NOTES
 *
 *    For security reasons, one should not truncate to less than half
 *    of the length of the true MAC lenght.  However, since this routine
 *    may be used to non-critical applications this allows these dangerous
 *    truncations.
 *
 ***/
void silc_hmac_make_truncated(SilcHmac hmac, 
			      unsigned char *data, 
			      uint32 data_len,
			      uint32 truncated_len,
			      unsigned char *return_hash);

/****f* silccrypt/SilcHMACAPI/silc_hmac_init
 *
 * SYNOPSIS
 *
 *    void silc_hmac_init(SilcHmac hmac);
 *
 * DESCRIPTION
 *
 *    Sometimes calling the silc_hmac_make might not be the most
 *    optimal case of doing MACs.  If you have a lot of different data
 *    that you need to put together for computing a MAC you may either
 *    put them into a buffer and compute the MAC from the buffer by
 *    calling the silc_hmac_make, or you can use the silc_hmac_init,
 *    silc_hmac_update and silc_hmac_final to do the MAC.  This function
 *    prepares the allocated HMAC context for this kind of MAC 
 *    computation.  The caller must have been called the function
 *    silc_hmac_set_key before calling this function.  To add the
 *    data to be used in the MAC computation call the silc_hmac_update
 *    function.
 *
 ***/
void silc_hmac_init(SilcHmac hmac);

/****f* silccrypt/SilcHMACAPI/silc_hmac_init_with_key
 *
 * SYNOPSIS
 *
 *    void silc_hmac_init_with_key(SilcHmac hmac, const unsigned char *key,
 *                                 uint32 key_len);
 *
 * DESCRIPTION
 *
 *    Same as silc_hmac_init but initializes with specific key.  The
 *    key that may have been set with silc_hmac_set_key is ignored.
 *
 ***/
void silc_hmac_init_with_key(SilcHmac hmac, const unsigned char *key,
			     uint32 key_len);

/****f* silccrypt/SilcHMACAPI/silc_hmac_update
 *
 * SYNOPSIS
 *
 *    void silc_hmac_update(SilcHmac hmac, const unsigned char *data,
 *                          uint32 data_len);
 *
 * DESCRIPTION
 *
 *    This function may be called to add data to be used in the MAC
 *    computation.  This can be called multiple times to add data from
 *    many sources before actually performing the HMAC.  Once you've
 *    added all the data you need you can call the silc_hmac_final to
 *    actually produce the MAC.
 *
 * EXAMPLE
 *
 *    unsigned char mac[20];
 *    uint32 mac_len;
 *
 *    silc_hmac_init(hmac);
 *    silc_hmac_update(hmac, data, data_len);
 *    silc_hmac_update(hmac, more_data, more_data_len);
 *    silc_hmac_final(hmac, mac, &mac_len);
 *
 ***/
void silc_hmac_update(SilcHmac hmac, const unsigned char *data,
		      uint32 data_len);

/****f* silccrypt/SilcHMACAPI/silc_hmac_final
 *
 * SYNOPSIS
 *
 *    void silc_hmac_final(SilcHmac hmac, unsigned char *return_hash,
 *                         uint32 *return_len);
 *
 * DESCRIPTION
 *
 *    This function is used to produce the final MAC from the data
 *    that has been added to the HMAC context by calling the 
 *    silc_hmac_update function.  The MAC is copied in to the
 *    `return_hash' pointer which must be at least the size that
 *    the silc_hmac_len returns.  The length of the MAC is still
 *    returned into `return_len'.
 *
 ***/
void silc_hmac_final(SilcHmac hmac, unsigned char *return_hash,
		     uint32 *return_len);

#endif
