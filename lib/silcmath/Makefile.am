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

if SILC_MP_NSS_MPI
SUBDIRS = mpi
else
SUBDIRS =
endif

noinst_LIBRARIES = libsilcmath.a

if SILC_MP_NSS_MPI
MP_SOURCE = mp_mpi.c
if SILC_DIST_TOOLKIT
MP_HEADER = mpi/mpi.h mpi/mplogic.h mpi/mpprime.h mpi/mpi-config.h
else
MP_HEADER =
endif
else
MP_SOURCE = mp_gmp.c
MP_HEADER =
endif

libsilcmath_a_SOURCES = \
	silcprimegen.c \
	modinv.c \
	mpbin.c \
	$(MP_SOURCE)

if SILC_DIST_TOOLKIT
include_HEADERS = 	\
	mp_gmp.h	\
	mp_mpi.h	\
	silcmath.h	\
	silcmp.h	\
	$(MP_HEADER)
endif

EXTRA_DIST = mp_gmp.c mp_mpi.c *.h

include $(top_srcdir)/Makefile.defines.in
