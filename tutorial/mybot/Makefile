#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@silcnet.org>
#
#  Copyright (C) 2002 Pekka Riikonen
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#

AUTOMAKE_OPTIONS = 1.0 no-dependencies foreign

CFLAGS = $(INCLUDES) $(SILC_COMMON_LIBS) $(LDFLAGS)
SOURCES = mybot.c

all: mybot

clean:
	-rm -rf *.o
	-rm -rf mybot

mybot:
	$(CC) -o mybot $(SOURCES) $(CFLAGS)

include ../Makefile.defines.in

