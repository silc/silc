/*

  silcacc.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "softacc.h"

/************************** Types and definitions ***************************/

#ifndef SILC_SYMBIAN
/* Dynamically registered list of accelerators. */
SilcDList silc_acc_list = NULL;
#endif /* SILC_SYMBIAN */

/* Static list of accelerators */
const SilcAcceleratorStruct *silc_default_accs[] =
{
#ifndef SILC_SYMBIAN
  /* Software accelerator */
  &softacc,
#endif /* SILC_SYMBIAN */
  NULL
};

/*************************** SILC Accelerator API ***************************/

/* Register accelerator */

SilcBool silc_acc_register(const SilcAccelerator acc)
{
  if (!acc)
    return FALSE;

  if (!silc_acc_list) {
    silc_acc_list = silc_dlist_init();
    if (!silc_acc_list)
      return FALSE;
  }

  SILC_LOG_DEBUG(("Register accelerator %p, name %s", acc, acc->name));
  silc_dlist_add(silc_acc_list, acc);

  return TRUE;
}

/* Unregister accelerator */

void silc_acc_unregister(SilcAccelerator acc)
{
  if (!acc)
    return;

  if (!silc_acc_list)
    return;

  SILC_LOG_DEBUG(("Unregister accelerator %p, name %s", acc, acc->name));
  silc_dlist_del(silc_acc_list, acc);

  if (!silc_dlist_count(silc_acc_list)) {
    silc_dlist_uninit(silc_acc_list);
    silc_acc_list = NULL;
  }
}

/* Initialize accelerator */

SilcBool silc_acc_init(SilcAccelerator acc, SilcSchedule schedule, ...)
{
  va_list va;
  SilcBool ret;

  if (!acc || !schedule)
    return FALSE;

  SILC_LOG_DEBUG(("Initialize accelerator %p, name %s", acc, acc->name));

  va_start(va, schedule);
  ret = acc->init(schedule, va);
  va_end(va);

  return ret;
}

/* Uninitialize accelerator */

SilcBool silc_acc_uninit(SilcAccelerator acc)
{
  if (!acc)
    return FALSE;

  SILC_LOG_DEBUG(("Uninitialize accelerator %p, name %s", acc, acc->name));
  return acc->uninit();
}

/* Get list of registered accelerator */

SilcDList silc_acc_get_supported(void)
{
  SilcDList list;
  SilcAccelerator acc;
  int i;

  list = silc_dlist_init();
  if (!list)
    return NULL;

  if (silc_acc_list) {
    silc_dlist_start(silc_acc_list);
    while ((acc = silc_dlist_get(silc_acc_list)))
      silc_dlist_add(list, acc);
  }

  for (i = 0; silc_default_accs[i]->name; i++)
    silc_dlist_add(list, (void *)silc_default_accs[i]);

  return list;
}

/* Get accelerator */

SilcAccelerator silc_acc_find(const char *name)
{
  SilcAccelerator acc;
  int i;

  if (!name)
    return NULL;

  SILC_LOG_DEBUG(("Find accelerator %s", name));

  if (silc_acc_list) {
    silc_dlist_start(silc_acc_list);
    while ((acc = silc_dlist_get(silc_acc_list))) {
      if (!strcmp(acc->name, name)) {
	SILC_LOG_DEBUG(("Found accelerator %p", acc));
	return acc;
      }
    }
  }

  for (i = 0; silc_default_accs[i]->name; i++) {
    if (!strcmp(silc_default_accs[i]->name, name)) {
      SILC_LOG_DEBUG(("Found accelerator %p", silc_default_accs[i]));
      return (SilcAccelerator)silc_default_accs[i];
    }
  }

  SILC_LOG_DEBUG(("Accelerator %s does not exist", name));
  return NULL;
}

/* Get accelerator name */

const char *silc_acc_get_name(SilcAccelerator acc)
{
  if (!acc)
    return NULL;
  return acc->name;
}
