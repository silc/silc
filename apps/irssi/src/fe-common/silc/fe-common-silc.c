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
#include "signals.h"
#include "themes.h"

void fe_silc_channels_init(void);
void fe_silc_channels_deinit(void);

void fe_silc_modules_init(void);
void fe_silc_modules_deinit(void);

void fe_common_silc_init(void)
{
  theme_register(fecommon_silc_formats);

  fe_silc_channels_init();
  fe_silc_modules_init();
}

void fe_common_silc_deinit(void)
{
  fe_silc_modules_deinit();
  fe_silc_channels_deinit();

  theme_unregister();
}

void fe_common_silc_finish_init(void)
{
}
