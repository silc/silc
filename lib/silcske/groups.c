/*

  groups.c

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
/*
 * $Id$
 * $Log$
 * Revision 1.2  2000/07/05 06:05:15  priikone
 * 	Global cosmetic change.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"
#include "groups_internal.h"

/* Fixed and public Diffie Hellman Groups defined by the SKE
   protocol. These are equivalent to the OAKLEY Key Determination
   protocol groups (taken from RFC 2412). */
const struct SilcSKEDiffieHellmanGroupDefStruct silc_ske_groups[] = 
{
  /* 1024 bits modulus (Mandatory group) */
  { 1, "diffie-hellman-group1",
    "0x"
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381"
    "FFFFFFFF FFFFFFFF",
    "0x"
    "7FFFFFFF FFFFFFFF E487ED51 10B4611A 62633145 C06E0E68"
    "94812704 4533E63A 0105DF53 1D89CD91 28A5043C C71A026E"
    "F7CA8CD9 E69D218D 98158536 F92F8A1B A7F09AB6 B6A8E122"
    "F242DABB 312F3F63 7A262174 D31BF6B5 85FFAE5B 7A035BF6"
    "F71C35FD AD44CFD2 D74F9208 BE258FF3 24943328 F67329C0"
    "FFFFFFFF FFFFFFFF",
    "0x2" },

  /* 1536 bits modulus (Optional group) */
  { 2, "diffie-hellman-group2",
    "0x"
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
    "670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF",
    "0x"
    "7FFFFFFF FFFFFFFF E487ED51 10B4611A 62633145 C06E0E68"
    "94812704 4533E63A 0105DF53 1D89CD91 28A5043C C71A026E"
    "F7CA8CD9 E69D218D 98158536 F92F8A1B A7F09AB6 B6A8E122"
    "F242DABB 312F3F63 7A262174 D31BF6B5 85FFAE5B 7A035BF6"
    "F71C35FD AD44CFD2 D74F9208 BE258FF3 24943328 F6722D9E"
    "E1003E5C 50B1DF82 CC6D241B 0E2AE9CD 348B1FD4 7E9267AF"
    "C1B2AE91 EE51D6CB 0E3179AB 1042A95D CF6A9483 B84B4B36"
    "B3861AA7 255E4C02 78BA3604 6511B993 FFFFFFFF FFFFFFFF",
    "0x2" },

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
    silc_mp_set_str(&group->group, silc_ske_groups[i].group, 0);
    silc_mp_set_str(&group->group_order, silc_ske_groups[i].group_order, 0);
    silc_mp_set_str(&group->generator, silc_ske_groups[i].generator, 0);
    
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
    silc_mp_set_str(&group->group, silc_ske_groups[i].group, 0);
    silc_mp_set_str(&group->group_order, silc_ske_groups[i].group_order, 0);
    silc_mp_set_str(&group->generator, silc_ske_groups[i].generator, 0);
    
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
