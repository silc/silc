/*

  groups.h

  Author: Pekka Riikonen <priikone@silcnet.org>

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

/****h* silcske/SilcSKEGroups
 *
 * DESCRIPTION
 *
 * This interface defines the Diffie Hellman group management and utility
 * functions for the SKE.  They can be used find DH groups by group number,
 * and group name.  These routines are used during the SKE session.
 *
 ***/

#ifndef GROUPS_H
#define GROUPS_H

#include "silcske_status.h"

/****s* silcske/SilcSKEGroups/SilcSKEDiffieHellmanGroup
 *
 * NAME
 * 
 *    typedef struct SilcSKEDiffieHellmanGroupStruct 
 *                     *SilcSKEDiffieHellmanGroup;
 *
 * DESCRIPTION
 *
 *    This context represents one Diffie Hellman group, and is returned
 *    by the utility functions for finding correct groups.  The context
 *    is freed by calling the silc_ske_group_free function.
 *
 ***/
typedef struct SilcSKEDiffieHellmanGroupStruct *SilcSKEDiffieHellmanGroup;

/* Prototypes */

/****f* silcske/SilcSKEGroups/silc_ske_group_get_by_number
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus 
 *    silc_ske_group_get_by_number(int number,
 *                                 SilcSKEDiffieHellmanGroup *ret);
 *
 * DESCRIPTION
 *
 *    Returns the Diffie Hellman group into the `ret' pointer by
 *    group number indicated by the `number'.  Returns error status
 *    if the group was not found.
 *
 ***/
SilcSKEStatus silc_ske_group_get_by_number(int number,
					   SilcSKEDiffieHellmanGroup *ret);

/****f* silcske/SilcSKEGroups/silc_ske_group_get_by_name
 *
 * SYNOPSIS
 *
 *    SilcSKEStatus 
 *    silc_ske_get_group_by_name(const char *name,
 *                               SilcSKEDiffieHellmanGroup *ret);
 *
 * DESCRIPTION
 *
 *    Returns the Diffie Hellman group into the `ret' pointer by
 *    group name indicated by the `name'.  Returns error status
 *    if the group was not found.
 *
 ***/
SilcSKEStatus silc_ske_group_get_by_name(const char *name,
					 SilcSKEDiffieHellmanGroup *ret);

/****f* silcske/SilcSKEGroups/silc_ske_group_free
 *
 * SYNOPSIS
 *
 *    void silc_ske_group_free(SilcSKEDiffieHellmanGroup group);
 *
 * DESCRIPTION
 *
 *    Free the Diffie Hellman group indicated by the `group'.
 *
 ***/
void silc_ske_group_free(SilcSKEDiffieHellmanGroup group);

/****f* silcske/SilcSKEGroups/silc_ske_get_supported_groups
 *
 * SYNOPSIS
 *
 *    char *silc_ske_get_supported_groups();
 *
 * DESCRIPTION
 *
 *    Returns a comma separated list of support Diffie Hellman groups.
 *    This can be used to get the list of supported groups for SKE
 *    packets.
 *
 ***/
char *silc_ske_get_supported_groups();

/****f* silcske/SilcSKEGroups/silc_ske_group_get_number
 *
 * SYNOPSIS
 *
 *    int silc_ske_group_get_number(SilcSKEDiffieHellmanGroup group);
 *
 * DESCRIPTION
 *
 *    Return the group number of the group indicated by the `group'.
 *
 ***/
int silc_ske_group_get_number(SilcSKEDiffieHellmanGroup group);

/****f* silcske/SilcSKEGroups/silc_ske_group_get_name
 *
 * SYNOPSIS
 *
 *    const char *silc_ske_group_get_name(SilcSKEDiffieHellmanGroup group);
 *
 * DESCRIPTION
 *
 *    Return the group name of the group indicated by the `group'.
 *
 ***/
const char *silc_ske_group_get_name(SilcSKEDiffieHellmanGroup group);

#endif
