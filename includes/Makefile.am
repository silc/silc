#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>
#
#  Copyright (C) 2000 Pekka Riikonen
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#

AUTOMAKE_OPTIONS = 1.0 no-dependencies foreign

all:
	-cd ..

if SILC_DIST_TOOLKIT
include_HEADERS = \
	silcincludes.h \
	silcwin32.h \
	silcepoc.h \
	silcbeos.h \
	silcos2.h \
	silcversion.h \
	version_internal.h \
	silcdefs.h
endif

EXTRA_DIST = \
	silcincludes.h \
	silcwin32.h \
	silcepoc.h \
	silcbeos.h \
	silcos2.h \
	silcversion.h \
	version_internal.h \
	silcdefs.h.in
