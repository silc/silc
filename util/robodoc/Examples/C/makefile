#
# $Id$
#
#

myclean:
	rm -f *~
	rm -f *.xref
	rm -f *.html
	rm -f xref_files

#
# Creates the example used in the documentation.
# Assumed robodoc has been installed.
#
# It also shows how to make some plain makefile rules to
# generate documentation.
#

xref_files : prog1.c.xref prog2.c.xref 
	echo "prog1.c.xref" >  xref_files
	echo "prog2.c.xref" >> xref_files

prog1.c.xref : prog1.c 
	robodoc prog1.c prog1.c.html GENXREF prog1.c.xref HTML INTERNAL

prog2.c.xref : prog2.c
	robodoc prog2.c prog2.c.html GENXREF prog2.c.xref HTML INTERNAL

prog1.c.html : prog1.c xref_files 
	robodoc prog1.c prog1.c.html XREF xref_files HTML INTERNAL

prog2.c.html : prog2.c xref_files 
	robodoc prog2.c prog2.c.html XREF xref_files HTML INTERNAL
