# $Id$

ROBODOC=robodoc
DOCS=muppets.cpp.html muppets.h.html
XREF=$(DOCS:.html=.xref)

all: masterindex.html

myclean:
	rm -f *~
	rm -f *.xref
	rm -f *.xrefs
	rm -f *.html
	rm -f xref_files
#
# This makefile shows how with a few rules you can generate
# the documentation from all your sources.
#

#
# create xrefs file (file with the names of all .xref files).
#
muppets.xrefs : $(XREF)
	/bin/ls *.xref > $@

#
# Rule to create an .xref file.
#
%.xref : % muppets.xrefs
	$(ROBODOC) $< $(@:.xref=.html) INTERNAL -g $@ -v

#
# Rule to create an .html file.
#
%.html : %
	$(ROBODOC) $< $@ HTML INTERNAL -x muppets.xrefs -v

#
#
#
masterindex.html : muppets.xrefs $(DOCS)
	$(ROBODOC) $< $@ INDEX HTML


