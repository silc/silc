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

if SILC_SIM
noinst_LIBRARIES = libsilcsim.a
else
noinst_LIBRARIES = 
endif

libsilcsim_a_SOURCES = \
	silcsim.c \
	silcsimutil.c

SIM_MODULES_DIR = modules

SUBDIRS = modules

#
# SILC Ciphers to be compiled as modules
#
SIM_CIPHER_OBJS = \
        none.o \
        blowfish.o \
        rc5.o \
        rc6.o \
        mars.o \
        aes.o \
        rsa.o \
        twofish.o \
	cast.o

#
# SILC Hash Functions to be compiled as modules
#
SIM_HASH_OBJS = \
	md5.o \
	sha1.o

if SILC_SIM
all: $(SIM_CIPHER_OBJS) $(SIM_HASH_OBJS)
endif

$(SIM_CIPHER_OBJS): ../silccrypt/libsilccrypt.a
	$(LTCOMPILE) -c $(srcdir)/../silccrypt/$*.c
	$(LIBTOOL) --mode=link $(LINK) -rpath $(silc_modulesdir) -o lib$*.la $*.lo
	cd $(srcdir)/$(SIM_MODULES_DIR) && $(LN_S) -f $(srcdir)/../.libs/lib$*.so $(srcdir)/$*.sim.so

$(SIM_HASH_OBJS): ../silccrypt/libsilccrypt.a
	$(LTCOMPILE) -c $(srcdir)/../silccrypt/$*.c
	$(LIBTOOL) --mode=link $(LINK) -rpath $(silc_modulesdir) -o lib$*.la $*.lo
	cd $(srcdir)/$(SIM_MODULES_DIR) && $(LN_S) -f $(srcdir)/../.libs/lib$*.so $(srcdir)/$*.sim.so

CLEANFILES = $(SIM_MODULES_DIR)/*.sim.so *.la

if SILC_DIST_TOOLKIT
include_HEADERS = silcsim.h silcsimutil.h
endif

EXTRA_DIST = *.h

include $(top_srcdir)/Makefile.defines.in
