/*

  groups.c

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
/* $Id$ */

#include "silcincludes.h"
#include "groups_internal.h"

/* Fixed and public Diffie Hellman Groups defined by the SKE
   protocol. These are equivalent to the OAKLEY Key Determination
   protocol groups (taken from RFC 2412). */
const struct SilcSKEDiffieHellmanGroupDefStruct silc_ske_groups[] = 
{
  /* 1024 bits modulus (Mandatory group) */
  { 1, "diffie-hellman-group1",

    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF",

    "7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68"
    "948127044533E63A0105DF531D89CD9128A5043CC71A026E"
    "F7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122"
    "F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6"
    "F71C35FDAD44CFD2D74F9208BE258FF324943328F67329C0"
    "FFFFFFFFFFFFFFFF",
    "2" },

  /* 1536 bits modulus (Optional group) */
  { 2, "diffie-hellman-group2",

    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",

    "7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68"
    "948127044533E63A0105DF531D89CD9128A5043CC71A026E"
    "F7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122"
    "F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6"
    "F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9E"
    "E1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AF"
    "C1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483B84B4B36"
    "B3861AA7255E4C0278BA36046511B993FFFFFFFFFFFFFFFF",
    "2" },

  { 0, NULL, NULL, NULL }
};

/* Returns Diffie Hellman group by group number */

SilcSKEStatus silc_ske_get_group_by_number(int number,
					   SilcSKEDiffieHellmanGroup *ret)
{
  int i;
  SilcSKEDiffieHellmanGroup group;

  for (i = 0; silc_ske_groups[i].name; i++) {
    if (silc_ske_groups[i].number == number)
      break;
  }

  if (silc_ske_groups[i].name == NULL)
    return SILC_SKE_STATUS_UNKNOWN_GROUP;

  /* Return the group */
  if (ret) {
    group = silc_calloc(1, sizeof(*group));
    group->number = number;
    group->name = silc_ske_groups[i].name;
    silc_mp_init(&group->group);
    silc_mp_init(&group->group_order);
    silc_mp_init(&group->generator);
    silc_mp_set_str(&group->group, silc_ske_groups[i].group, 16);
    silc_mp_set_str(&group->group_order, silc_ske_groups[i].group_order, 16);
    silc_mp_set_str(&group->generator, silc_ske_groups[i].generator, 16);
    
    *ret = group;
  }

  return SILC_SKE_STATUS_OK;
}

/* Returns Diffie Hellman group by name */

SilcSKEStatus silc_ske_get_group_by_name(const char *name,
					 SilcSKEDiffieHellmanGroup *ret)
{
  int i;
  SilcSKEDiffieHellmanGroup group;

  for (i = 0; silc_ske_groups[i].name; i++) {
    if (!strcmp(silc_ske_groups[i].name, name))
      break;
  }

  if (silc_ske_groups[i].name == NULL)
    return SILC_SKE_STATUS_UNKNOWN_GROUP;

  /* Return the group */
  if (ret) {
    group = silc_calloc(1, sizeof(*group));
    group->number = silc_ske_groups[i].number;
    group->name = silc_ske_groups[i].name;
    silc_mp_init(&group->group);
    silc_mp_init(&group->group_order);
    silc_mp_init(&group->generator);
    silc_mp_set_str(&group->group, silc_ske_groups[i].group, 16);
    silc_mp_set_str(&group->group_order, silc_ske_groups[i].group_order, 16);
    silc_mp_set_str(&group->generator, silc_ske_groups[i].generator, 16);
    
    *ret = group;
  }

  return SILC_SKE_STATUS_OK;
}

/* Returns comma separated list of supported groups */

char *silc_ske_get_supported_groups()
{
  char *list = NULL;
  int i, len;

  len = 0;
  for (i = 0; silc_ske_groups[i].name; i++) {
    len += strlen(silc_ske_groups[i].name);
    list = silc_realloc(list, len + 1);

    memcpy(list + (len - strlen(silc_ske_groups[i].name)), 
	   silc_ske_groups[i].name, strlen(silc_ske_groups[i].name));
    memcpy(list + len, ",", 1);
    len++;
  }

  list[len - 1] = 0;

  return list;
}

/* Returns the number of the `group'. */

int silc_ske_group_get_number(SilcSKEDiffieHellmanGroup group)
{
  return group->number;
}
