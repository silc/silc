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
	touch draft-riikonen-silc-spec-00.txt
	touch draft-riikonen-silc-pp-00.txt
	touch draft-riikonen-silc-ke-auth-00.txt
	-cd ..

dist-hook:
	-rm -f draft-riikonen*.txt
	./makerfc draft-riikonen-silc-spec-00.nroff \
		draft-riikonen-silc-spec-00.txt
	./makerfc draft-riikonen-silc-pp-00.nroff \
		draft-riikonen-silc-pp-00.txt
	./makerfc draft-riikonen-silc-ke-auth-00.nroff \
		draft-riikonen-silc-ke-auth-00.txt

EXTRA_DIST = \
	CodingStyle \
	FAQ \
	example_silcd.conf \
	example_silc.conf \
	draft-riikonen*.txt
