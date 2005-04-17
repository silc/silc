/*

  fe-common-silc.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "module.h"
#include "module-formats.h"
#include "modules.h"
#include "signals.h"
#include "themes.h"

#include "fe-silcnet.h"
#include "fe-silc-messages.h"
#include "fe-silc-queries.h"
#include "fe-silc-channels.h"


void fe_silc_modules_init(void);
void fe_silc_modules_deinit(void);

void fe_silc_init(void)
{
  theme_register(fecommon_silc_formats);

  fe_silc_channels_init();
  fe_silc_modules_init();
  fe_silc_messages_init();
  fe_silc_queries_init();
  fe_silcnet_init();

  module_register("silc", "fe");
}

void fe_silc_deinit(void)
{
  fe_silc_queries_deinit();
  fe_silc_messages_deinit();
  fe_silc_modules_deinit();
  fe_silc_channels_deinit();
  fe_silcnet_deinit();

  theme_unregister();
}
