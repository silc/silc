m4_include(`general.m4')m4_dnl
www_docstart()
www_header(`ROBODoc Manual')
www_bodystart
www_title(`ROBODoc VERSION Manual')

<P><STRONG>Updated July 2000</STRONG></P>

<P>ROBODoc is a documentation tool for C, C++, Java, Assembler, Basic,
Fortran, LaTeX, Postscript, Tcl/Tk, LISP, Forth, Perl, Shell
Scripts, Occam, COBOL, HTML and many other languages. Additional
languages can be supported by a few modifications to the source
code.</P>

<P>Copyright (C) 1994-2000 Frans Slothouber and Jacco van Weert.</P>

<P>This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of
the License, or (at your option) any later version.</P>

<P>This program is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.</P>

<P>You should have received a copy of the GNU General Public
License along with this program; if not, write to the Free
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
02111-1307 USA</P>



www_section(`creds', `Credits')

<UL>

  <LI>Original program and idea: Jacco van Weert</LI> 

  <LI>Versions 2.0 and up: Frans Slothouber, Petteri Kettunen,
      Bernd Koesling, Anthon Pang, Thomas Aglassinger,
      and Stefan Kost, Guillaume Etorre, Simo Muinonen,
      Petter Reinholdtsen.
  </LI>

  <LI>Maintainer: Frans Slothouber (fslothouber@acm.org),
      The Netherlands.</LI>

</UL>


www_section(`toc', `Table of Contents')

m4_include(stoc.html)



www_section(`INTRO', `Introduction')

<P>ROBODoc is based on the AutoDocs program written some time ago
by Commodore.  The idea is to include for every function a
standard header containing all sorts of information about that
procedure/function.  An AutoDocs program extracts these headers
from the source file and puts them in an autodocs file.  This
allows you to include the program documentation in the source
code and makes it unnecessary to maintain two documents.</P>


<P>ROBODoc is such a program, however ROBODoc has several
additions.  For one it can generate the documentation in
different formats, ASCII, HTML, RTF, LaTeX, and AmigaGuide.
Another feature is that it automatically creates links within the
document, and to other documents.  It is also possible to include
parts of the source in you documentation, complete with links.
For instance it is possible to include the complete source code
of a function, and have the function names in the source point to
their documentation. Besides documenting functions, you can also
document classes, methods, structures, variables, and
constants.</P>


<P>If you never have used AutoDoc or ROBODoc before you might
take a look at the example in the <TT>Source/</TT>.  Run the
command:</P>

<PRE>
  make xhtml
  make example
</PRE>


<P>This creates the ROBODoc
www_link(`../Source/ROBODoc_mi.html', `documentation') for the
ROBODoc program itself and then starts netscape to view the
documentation. Also have a look at the source files, they
illustrates the use of headers.</P>

<P>ROBODoc can generate documentation in five different
formats:</P>

<UL>
  <LI>HTML format complete with hyperlinks and mark-ups.</LI>

  <LI>LaTeX, based on D. Knuth excellent typesetting system.</LI>

  <LI>Plain ASCII text file, this file is very close to what the
      original AutoDocs program would generate.</LI>

  <LI>RTF, Rich Text Format, mostly used on Windows machines
      before WWW revolution.</LI>

  <LI>AmigaGuide format, it is the Amiga computer's equivalent
      HTML. The AmigaGuide program is necessary to view the
      resulting autodocs-file. (This was the preferred format when the
      program was written in 1994.)</LI>

</UL>


www_section(`HSR', `Hardware and software requirements')

<P>ROBODoc was developed in 1994 on a standard Amiga 1200, a
system with a 20MHz 68020 processor and 2 Mbyte of RAM. It should
therefore be no problem to run it on any of the currently
available systems :) The complete source code consists of a
series of file that can be found in the <TT>Source</TT>
directory.  It is written according (hopefully) to the ANSI C
standard and uses no special functions, so it should run on every
system with an ANSI C-compiler.</P>


www_section(`LMT', `Goals and Limitations')

<P>ROBODoc is intended for small to medium sized projects 
that have a relatively flat structure and especially projects 
that use a mix of different programming languages.</P>

<P>
ROBODoc was designed to be easy to use and to work with a lot of
different programming languages.  It has no knowledge of the
syntax of a programming languages.  It just some knowledge about
how remarks start and end in some programming languages. This
means that you sometimes have to do a little more work compared
to other tools that have detailed knowledge of the syntax of a
particular language.  They can use that knowledge to figure out
some of the information automatically.  This usually also means
that they work only with one or two languages.
</P>

<P>ROBODoc operates on one file at a time.  It has no mechanism to
process whole sets of source files. Makefiles should be used for
this.  How to do this is explained in this document with various
example makefiles. Have a look at them.
</P>

<P>ROBODoc can work with projects where the source code is located
in different subdirectories. However the generated documentation is
expected to go into one single directory.</P>


www_section(`HFCWR', `How to Format Your Code for use with ROBODoc')

<P>ROBODoc allows you to mix the program documentation with the
source code.  It does require though that this documentation has
a particular layout so ROBODoc can recognize it. The following
header was taken from the original ROBODoc program (many versions
back).</P>

<TABLE>
<TR>
<TD>
<PRE>
           <FONT COLOR="red">------------------------------- Header Name</FONT>
          <FONT COLOR="red">/                          \</FONT>
  /****f* financial.library/StealMoney  <FONT COLOR="red">&lt;---- Begin Marker</FONT>
  *    <FONT COLOR="red">^------- Header Type</FONT>
  *
  *  <FONT COLOR="red">&lt;---- Remark Marker</FONT>
  *  NAME
  *    StealMoney -- Steal money from the Federal Reserve Bank. (V77)
  *  SYNOPSIS  <FONT COLOR="red">&lt;---- Item Name</FONT>
  *    error = StealMoney( userName,amount,destAccount,falseTrail )
  *    D0,Z                D0       D1.W    A0         [A1]
  *
  *    BYTE StealMoney
  *         ( STRPTR,UWORD,struct AccountSpec *,struct falseTrail *);
  *  FUNCTION
  *    Transfer money from the Federal Reserve Bank into the
  *    specified interest-earning checking account.  No records of
  *    the transaction will be retained.
  *  INPUTS
  *    userName    - name to make the transaction under.  Popular
  *                  favorites include "Ronald Reagan" and
  *                  "Mohamar Quadaffi".
  *    amount      - Number of dollars to transfer (in thousands).
  *    destAccount - A filled-in AccountSpec structure detailing the
  *                  destination account (see financial/accounts.h).
  *                  If NULL, a second Great Depression will be
  *                  triggered.
  *    falseTrail  - If the DA_FALSETRAIL bit is set in the
  *                  destAccount, a falseTrail structure must be
  *                  provided.
  *  RESULT
  *    error - zero for success, else an error code is returned
  *           (see financial/errors.h).  The Z condition code
  *           is guaranteed.
  *  EXAMPLE
  *    Federal regulations prohibit a demonstration of this function.
  *  NOTES
  *    Do not run on Tuesdays!
  *  BUGS
  *    Before V88, this function would occasionally print the
  *    address and home phone number of the caller on local police
  *    976 terminals.  We are confident that this problem has been
  *    resolved.
  *  SEE ALSO
  *    CreateAccountSpec(),security.device/SCMD_DESTROY_EVIDENCE,
  *    financial/misc.h
  *
  ******  <FONT COLOR="red">&lt;---- End Marker</FONT>
  *
  * You can use this space for remarks that should not be included
  * in the documentation.
  *
  */
</PRE>
</TD>
</TR>
</TABLE>

<P>You would place this headers in front of functions, classes,
methods, structure definitions, or any of the major components in
your program.  The header itself contains a number of items that
provide structured information about the component. </P>

<P>There are a number of special markers in a header (indicated
in red above).  There are two special markers that mark the begin
and end of a header.  Each line in a header should start with a
remark marker.  The starts of each item is marked by an Item Name
(in all capitals).</P>


www_subSection(`hname', `Header Names')

<P>ROBODoc makes some assumptions about the structure a project.
It assumes that a project consists of a number of modules, and
that each module consists of a number of components.  These
components can be anything that you care to document; functions,
variables, structures, classes, methods etc.</P>

<P> Projects, modules, and components all have names.  The names
allow ROBODoc to structure the documentation and create
cross-links. Names are defined in the header name.  It is either
of the form <TT> &lt;project name&gt;/&lt;module name&gt;</TT>
for a module header, or of the form <TT>&lt;module
name&gt;/&lt;component name&gt;</TT> for all other headers.</P>

www_subSection(`htypes', `Header Types')

<P>You can provide ROBODoc with some additional information
by specifying the header type.  The header type tells ROBODoc
what kind of component you are documenting. This information
allows ROBODoc to create more useful index tables.</P>

<P>The type is identified by a single character, as listed in the
following table</P>

<TABLE>
<TR><TD>h</TD><TD>Header for a module in a project.</TD></TR>
<TR><TD>f</TD><TD>Header for a function.</TD></TR>
<TR><TD>s</TD><TD>Header for a structure.</TD></TR>
<TR><TD>c</TD><TD>Header for a class.</TD></TR>
<TR><TD>m</TD><TD>Header for a method.</TD></TR>
<TR><TD>v</TD><TD>Header for a variable.</TD></TR>
<TR><TD>d</TD><TD>Header for a constant 
(from <STRONG>d</STRONG>efine).</TD></TR>
<TR><TD>*</TD><TD>Generic header for every thing else.</TD></TR>
<TR><TD>i</TD><TD>Internal header.</TD></TR>
</TABLE>

<P>Internal headers are special. They can be used to hide certain
headers. They are only extracted if requested. You could use to
document internal functions that you do now want clients to
see.</P>


www_subSection(`bmar', `Begin Marker')

<P>The beginning of a header is marked with a special marker.
The above header is intended for a program in C.  In other
programming languages the marker looks slightly different, since
each language has its own convention for starting remarks.
ROBODoc recognizes the following begin markers:</P>

<TABLE >
<TR><TD><TT>"/****"</TT>
    <TD>C, C++</TD>
</TR>
<TR><TD><TT>"//****"</TT></TD>
    <TD>C++</TD>
</TR>
<TR><TD><TT>";****"</TT></TD>
    <TD>Assembler</TD>
</TR>
<TR><TD><TT>"****"</TT></TD>
    <TD>Assembler</TD>
</TR>
<TR><TD><TT>"{****"</TT></TD>
    <TD>Pascal</TD>
</TR>
<TR><TD><TT>"REM ****"</TT></TD>
    <TD>Basic (Rem, rem, or even rEM also works)</TD>
</TR>
<TR><TD><TT>"C     ****"</TT></TD>
    <TD>Fortran (c     **** also works)</TD>
</TR>
<TR><TD><TT>"%****"</TT></TD>
    <TD>LaTeX, TeX, Postscript.</TD>
</TR>
<TR><TD><TT>"#****"</TT></TD>
    <TD>Tcl/Tk, Perl, makefiles, gnuplot etc.</TD>
</TR>
<TR><TD><TT>"(****"</TT></TD>
    <TD>Pascal, Modula-2, LISP</TD>
</TR>
<TR><TD><TT>"--****"</TT></TD>
    <TD>Occam</TD>
</TR>
<TR><TD><TT>"&lt;!--****"</TT></TD>
    <TD>HTML</TD>
</TR>
<TR><TD><TT>"&lt;!---****"</TT></TD>
    <TD>HTML</TD>
</TR>
<TR><TD><TT>"|****"</TT></TD>
    <TD>GNU Assembler</TD>
</TR>
<TR><TD><TT>"!!****"</TT></TD>
    <TD>Fortran 90</TD>
</TR>
</TABLE>

<P>After these initial four asterisks, there is the character to
identify the kind of header, then another asterisks, and then
header name. After this you can specify a version number
surrounded by "[]". The version number is stored but not used for
anything at the moment. All characters after that are
ignored.</P>

<P>This might sound terribly complicated, it is not. Here are
some examples:</P>

<P>A header for a module called analyser in a project called ChessMaster
for C, is has version number 1.0</P>
<PRE>
  /****h* ChessMaster/analyser [1.0] *
</PRE>

<P>In Assembler, a function header, for the function init() in the 
  module finance.library:</P>
<PRE>
  ****f* finance.library/init *
</PRE>

<P>In C++, a class header for class Puppet, for the module puppetmaster,
version v2.12</P> 
<PRE>
  /****c* puppetMaster/Puppet [v2.12] ******
</PRE>

<P>For the same class a method called Puppet::Talk</P>
<PRE>
  /****m* puppetMaster/Puppet::Talk [v2.12] ******
</PRE>

<P>A project header, in Fortran</P>
<PRE>
  C     ****h* ChessMaster/analyser              C
</PRE>

<P>In Basic</P>
<PRE>
  REM ****h* ChessMaster/analyser
</PRE>



www_subSection(`rmarker', `Remark Marker')

<P>Each line in the body of a header should start with a remark
marker.  This marker is stripped from the line and the remaining
part is used to generated the documentation.  The following
markers are recognized by ROBODoc.</P>

<TABLE >
<TR><TD><TT>"*"</TT></TD>
    <TD>C, C++, Pascal, Modula-2</TD>
</TR> 
<TR><TD><TT>"//"</TT></TD>
    <TD>C++</TD>
</TR> 
<TR><TD><TT>" *"</TT></TD>
    <TD>C, C++, M68K assembler, Pascal, Modula-2, HTML</TD>
</TR> 
<TR><TD><TT>";*"</TT></TD>
    <TD>M68K assembler</TD>
</TR> 
<TR><TD><TT>";"</TT></TD>
    <TD>M68K assembler</TD>
</TR> 
<TR><TD><TT>"C    "</TT></TD>
    <TD>Fortran</TD>
</TR> 
<TR><TD><TT>"REM "</TT></TD>
    <TD>BASIC</TD>
</TR> 
<TR><TD><TT>"%"</TT></TD>
    <TD>LaTeX, TeX, Postscript</TD>
</TR> 
<TR><TD><TT>"#"</TT></TD>
    <TD>Tcl/Tk, shell scripts, makefiles</TD>
</TR> 
<TR><TD><TT>"      *"</TT></TD>
    <TD>COBOL</TD>
</TR> 
<TR><TD><TT>"--"</TT></TD>
    <TD>Occam</TD>
</TR> 
<TR><TD><TT>"|"</TT></TD>
    <TD>GNU Assembler</TD>
</TR>
<TR><TD><TT>"!!"</TT></TD>
    <TD>Fortan 90</TD>
</TR>
</TABLE>




www_subSection(`emar', `End Marker')

<P>A header ends with an end marker.  An end marker is a remark
marker followed by three asterisks.  ROBODoc recognizes following
strings as end markers:</P>

<TABLE >
<TR><TD><TT>"/***"</TT></TD>
    <TD> C, C++ </TD></TR>
<TR><TD><TT>"//***"</TT></TD>
    <TD> C++ </TD></TR>
<TR><TD><TT>" ****"</TT></TD>
    <TD> C, C++, Pascal, Modula-2 </TD></TR>
<TR><TD><TT>"{***"</TT></TD>
    <TD> Pascal </TD></TR>
<TR><TD><TT>"(***"</TT></TD>
    <TD> Pascal, Modula-2, B52 LISP</TD></TR>
<TR><TD><TT>";***"</TT></TD>
    <TD> M68K assembler </TD></TR>
<TR><TD><TT>"****"</TT></TD>
    <TD> M68K assembler </TD></TR>
<TR><TD><TT>"C     ***"</TT></TD>
    <TD> Fortran </TD></TR>
<TR><TD><TT>"REM ***"</TT></TD>
    <TD> BASIC </TD></TR>
<TR><TD><TT>"%***"</TT></TD>
    <TD> LaTeX, TeX, Postscript </TD></TR>
<TR><TD><TT>"#***"</TT></TD>
    <TD> Tcl/Tk, Perl, Makefiles, Shell scripts </TD></TR>
<TR><TD><TT>"      ****"</TT></TD>
    <TD> COBOL </TD></TR>
<TR><TD><TT>"--***"</TT></TD>
    <TD> Occam </TD></TR>
<TR><TD><TT>"&lt;!--***"</TT></TD>
    <TD> HTML </TD></TR>
<TR><TD><TT>"&lt;!---***"</TT></TD>
    <TD> HTML </TD></TR>
<TR><TD><TT>"|***"</TT></TD>
    <TD>GNU Assembler</TD></TR>
<TR><TD><TT>"!!***"</TT></TD>
    <TD>Fortan 90</TD></TR>
</TABLE>




www_subSection(`hitem', `Header Items')

<P>When ROBODoc has found a header it will try to identify the
items in this header.  It does this by looking for the item name. The following
item names are currently supported:</P>

<TABLE >
<TR><TD> NAME </TD>
    <TD> Item name plus a short description. </TD> 
<TR><TD> COPYRIGHT </TD>
    <TD> Who own the copyright : "(c) &lt;year&gt;-&lt;year&gt; by 
         &lt;company/person&gt;" </TD>
<TR><TD> SYNOPSIS, USAGE </TD>
    <TD> How to use it. </TD>
<TR><TD> FUNCTION, DESCRIPTION,  PURPOSE </TD>
    <TD> What does it do. </TD>
<TR><TD> AUTHOR </TD>
    <TD>Who wrote it. </TD> 
<TR><TD> CREATION DATE </TD>
    <TD> When did the work start. </TD> 
<TR><TD> MODIFICATION HISTORY,  HISTORY </TD>
    <TD> Who has done which changes and when. </TD>
<TR><TD> INPUTS, ARGUMENTS, OPTIONS, PARAMETERS, SWITCHES </TD>
    <TD> What can we feed into it.  </TD>
<TR><TD> OUTPUT, SIDE EFFECTS </TD>
    <TD> What output is made. </TD>
<TR><TD> RESULT, RETURN VALUE </TD>
    <TD> What do we get returned. </TD>
<TR><TD> EXAMPLE  </TD>
    <TD> A clear example of the items use. </TD> 
<TR><TD> NOTES </TD>
    <TD> Any annotations </TD> 
<TR><TD> DIAGNOSTICS  </TD>
    <TD>Diagnostical output  </TD>
<TR><TD> WARNINGS, ERRORS  </TD>
    <TD> Warning & error-messages. </TD>
<TR><TD> BUGS </TD>
    <TD> Known bugs. </TD> 
<TR><TD> TODO, IDEAS  </TD>
    <TD> What to implement next & ideas. </TD> 
<TR><TD> PORTABILITY </TD>
    <TD> Where does it come from, where will it work. </TD>
<TR><TD> SEE ALSO </TD>
    <TD> References to other functions, man pages, other documentation. </TD>
<TR><TD> METHODS, NEW METHODS </TD>
    <TD> OOP methods. </TD>
<TR><TD> ATTRIBUTES, NEW ATTRIBUTES </TD>
    <TD> OOP attributes  </TD>
<TR><TD> TAGS </TD>
    <TD> Tag-item description. </TD>
<TR><TD> COMMANDS </TD>
    <TD> Command description. </TD> 
<TR><TD> DERIVED FROM </TD>		
    <TD> OOP super class. </TD>
<TR><TD> DERIVED BY </TD>
    <TD> OOP sub class. </TD>
<TR><TD> USES, CHILDREN	</TD>
    <TD> What modules are used by this one. </TD> 
<TR><TD> USED BY, PARENTS </TD>
    <TD> Which modules do use this one. </TD> 
<TR><TD> SOURCE </TD>
    <TD> Source code inclusion. </TD> 
</TABLE>

<P>ROBODoc does this so that it can format each item with a
different style (colour, font, etc.) if the user want it.  These
can be specified in the robodoc.defaults file, see the next
section more information.</P>


www_subSection(`inlimits', `Item Name Limitations')

<P>If you happen to have a function which name is in all uppercase,
this sometimes conflicts with where ROBODoc thinks an item name
starts and where the item body starts.
Bernhard Roessmann suggest the following workaround:
Example header producing this error:</P>
<PRE>
/***** basic.c/RETURN
* NAME
*  RETURN : Return from subroutine
* SYNOPSIS
*  RETURN
* FUNCTION
*  Return from subroutine
******/
</PRE>
<P>Here the item name  "FUNCTION" will be interpreted as ordinary text, 
not as an item name.  Workaround: Add an empty line:</P>
<PRE>
/***** basic.c/RETURN
* NAME
*  RETURN : Return from subroutine
* SYNOPSIS
*  RETURN
*
* FUNCTION
*  Return from subroutine
******/
</PRE>



www_subSection(`SI', `Source Item')

<P>The source item allows you to include part of the source in
the documentation as is demonstrated by the following
example.</P>

<TABLE><TR><TD><PRE>
m4_include(`example.c')
</PRE></TD></TABLE>

<P>This would create the following documentation</P>

<TABLE><TR><TD>
<FONT SIZE="+1">NAME</FONT>
<PRE><EM>   <B>RB_Panic</B> -- Shout panic, free resources, and shut down.
</EM></PRE><FONT SIZE="+1">SYNOPSIS</FONT>
<PRE>   <B>RB_Panic</B> (cause, add_info)
   <B>RB_Panic</B> (char *, char *)
</PRE><FONT SIZE="+1">FUNCTION</FONT>
<PRE>   Prints an error message.
   Frees all resources used by robodoc.
   Terminates program.
</PRE><FONT SIZE="+1">INPUTS</FONT>
<PRE>   cause    - pointer to a string which describes the
              cause of the error.
   add_info - pointer to a string with additional information.
</PRE><FONT SIZE="+1">SEE ALSO</FONT>
<PRE>   RB_Close_The_Shop ()
</PRE><FONT SIZE="+1">SOURCE</FONT>
<PRE>      void <B>RB_Panic</B> (char *cause, char *add_info)
      {
        printf ("Robodoc: Error, %s\n",cause) ;
        printf ("         %s\n", add_info) ;
        printf ("Robodoc: Panic Fatal error, closing down...\n") ;
        RB_Close_The_Shop () ; <FONT COLOR = "#FF0000">/* Free All Resources */</FONT>
        exit(100) ;
      }    
</PRE></TD></TR></TABLE>




www_section(`CLD', `Creating Cross Links')

<P>Creating hyper links within a document and across documents
is the most interesting feature of ROBODoc.  A document with such
links is much more easier to read.  If your source code consists
of just one file, creating links is easy.  Just tell ROBODoc that
you want to have the output in HTML or AmigaGuide format, and it
will automatically generate the links.  That is, at the beginning
of the document it will create a table of contents that consists
of links to all your function headers.</P>

<P>ROBODoc will also search the complete text of you
documentation for reference to function names, and it will create
a link to the documentation of that function.</P>

<P>In most cases, however, your source code does not consists of
a single file.  It is also possible, however, to create links to
other files.  This does require the use of some additional files,
called xref files. These files can be generated with ROBODoc.
These files contain information about in which file and where in
the file references can be found.</P>

<P>Lets assume your project is split up in five different source
files, and you want to generate links between these five files.
What you have to do to accomplish this is to create a xref file
for each of those five files.</P>

<P>With the GENXREF option ROBODoc will generate such a xref file
from the a source-file.  When you use this option, only the xref
file is created not the autodocs-file, however you still have to
specify the name of the autodocs file because this name is needed
for the creation of the xref file.</P>

<P>When all xref files are created you are ready to create the
documentation.  To do so you use ROBODOC with the XREF option. It
needs a parameter which is the name of the file in which the
names of all xref files are defined.  Notice: this is a file with
file names, it has to be created it by hand.</P>

<P>An example will make things more clear. In the ROBODoc
archive, under <TT>examples/C</TT> there are two source files
www_link(`../Examples/C/prog1.c', `prog1.c') and
www_link(`../Examples/C/prog2.c', `prog2.c').  We can create
documentation with hyper links from these two files as follows:
</P>

<P>First create the xref files:</P>

<TABLE>
<TR>
<TD>
<PRE>
  robodoc prog1.c prog1.c.html GENXREF prog1.c.xref HTML INTERNAL
  robodoc prog2.c prog2.c.html GENXREF prog2.c.xref HTML INTERNAL
</PRE>
</TD>
</TR>
</TABLE>

<P>Now there are two xref files: prog1.c.xref and prog2.c.xref.
Note that ROBODoc did not create any HTML files, just the xref
files. The name prog1.c.html is needed to create the correct xref
files.  For prog1.c internal headers were also included. </P>

<P>Now create a file with the xref file names.  This file will
hold only two lines. You can give it any name, say
<TT>xref_files</TT>.</P>
<TABLE>
<TR>
<TD>
<PRE>
  echo prog1.c.xref &gt;  xref_files 
  echo prog2.c.xref &gt;&gt; xref_files
</PRE>
</TD>
</TR>
</TABLE>
<P>Now generate the final documentation:</P>
<TABLE>
<TR>
<TD>
<PRE>
  robodoc prog1.c prog1.c.html XREF xref_files HTML INTERNAL
  robodoc prog2.c prog2.c.html XREF xref_files HTML INTERNAL
</PRE>
</TD>
</TR>
</TABLE>

<P>Have a look the the documentation generated:</P>
<OL>
  <LI>www_link(`../Examples/C/prog1.c.html',  `prog1.c.html')</LI>
  <LI>www_link(`../Examples/C/prog2.c.html',  `prog2.c.html')</LI>
</OL>



www_subSection(`limits', `Limitations')

<P> ROBODoc knows very little about the grammar of programming
languages.  Links are created by looking up words in a table.
This means that it sometimes creates links where there should be
none.  For instance if you have a function called usage(); every
time you use the word usage in any of your documentation a link
will show up. It also means that sometimes is does not create
links where you would like it to create a link. Say you include
the source code of a method using the source item. Your method
uses other methods of the class. You would like to have links
pointing to the documentation of these methods each time you use
one. They will not appear though. Since to ROBODoc stores the
whole name of a method, ie, <TT>someClass::MethodName</TT>. In
the method source you will use just <TT>MethodName()</TT>. </P>



www_section(`MAIND', `Master Index File')

<P>If your project consists of many source files you might want
to create a master index file.</P> 

<P>For HTML output this file contains links to the documentation
generated from each of your source files as well as a list of all
"objects" that you documented. All "objects" are listed according
to header type, using the following order: Projects, Classes,
Methods, Stuctures, Functions, Variables, Constants, Generic,
Internal.</P>

<P>For LaTeX output this file is one big document that contains
the documentation generated from all your source files. It also
includes a table of contents and an index section.  This index
lists the page number of the page a function's documentation.
</P>

<P>This index file is generated based on the information found in
your xrefs file. That is the file with the names of all your xref
files. So before you can create the master index file you have to
create all your xref files.</P>

<P>To generate a master index file use:</P>
<PRE>
   robodoc &lt;xrefs file&gt; &lt;master index file&gt; INDEX HTML TITLE "Master Index"
</PRE>
<P>or</P>
<PRE>
   robodoc &lt;xrefs file&gt; &lt;master index file&gt; INDEX LATEX TITLE "ROBODoc API Documentation"
</PRE>
<P>The master index file can currently only be generated in HTML or LaTeX.</P>

<P>If you use if for LaTeX documentation you need to use the option
<TT>SINGLEDOC</TT> when you generate the documentation from your various
source files.  This ensures that no document preambles are generated.
The master index file contains command that includes all your documentation
files and make it into one single document.</P>


www_subSection(`MIEXM', `examples')

<P>Here are some examples of master index files</P>
<UL>

  <LI>www_link(`../Examples/CPP/masterindex.html', 
      `Master index for a C++ project') to be found in 
      <TT>Examples/CPP/</TT></LI>

  <LI>www_link(`../Source/ROBODoc_mi.html', 
      `Master index for ROBODoc') to be found in 
      <TT>Source/</TT>. 
  </LI>

</UL>



www_section(`makefile', `Automation with <TT>make</TT>')

<P>The whole process of creating documentation with ROBODoc is of
course best automated with <TT>make</TT>.
Have a look at the following makefile.</P> 

<TABLE><TR><TD><PRE>
SHELL = /bin/sh
.SUFFIXES:

ROBODOC=robodoc
ROBOOPTS=C SORT 

# Your source files.
#
SOURCES=analyser.c generator.c items.c util.c \
  folds.c headers.c links.c robodoc.c \
  analyser.h generator.h items.h util.h \
  folds.h headers.h links.h robodoc.h

# The name of your Project
#
PROJECT=robodoc

# The various documentation files, derived from the source files.
# HTML
#
HTMLDOCS=$(SOURCES:=.html)
HTMLXREFS=$(HTMLDOCS:.html=.html.xref)
HTMLXREFSFILE=$(PROJECT)_html.xrefs
# LATEX
#
LATEXDOCS=$(SOURCES:=.tex)
LATEXXREFS=$(LATEXDOCS:.tex=.tex.xref)
LATEXXREFSFILE=$(PROJECT)_tex.xrefs
# ASCII
#
ASCIIDOCS=$(SOURCES:=.txt)
# RTF
#
RTFDOCS=$(SOURCES:=.rtf)
RTFXREFS=$(RTFDOCS:.rtf=.rtf.xref)
RTFXREFSFILE=$(PROJECT)_rtf.xrefs

# Some common targets
xrefall: xrefhtml xreftex xrefrtf
docall: html tex ascii rtf

# Create the xref files for the various formats.
xhtml: $(HTMLXREFSFILE) 
xtex: $(LATEXXREFSFILE) 
xrtf: $(RTFXREFSFILE)

# Create the documentation files for the various formats.
html: $(HTMLDOCS) $(PROJECT)_mi.html 
tex: $(LATEXDOCS) $(PROJECT)_mi.tex
rtf: $(RTFDOCS)
ascii: $(ASCIIDOCS)

# master index file, currently works only for html and latex documentation.
# Note that you can define the title of the document.
$(PROJECT)_mi.html: $(HTMLXREFSFILE) 
	$(ROBODOC) $&lt; $@ INDEX HTML TITLE "$(PROJECT) Master Index"

$(PROJECT)_mi.tex: $(LATEXXREFSFILE)
	$(ROBODOC) $&lt; $@ INDEX LATEX TITLE "$(PROJECT) API Reference"

# create xrefs file (file with the names of all .xref files).
$(HTMLXREFSFILE) : $(HTMLXREFS)
	/bin/ls $(HTMLXREFS) &gt; $@
$(LATEXXREFSFILE) : $(LATEXXREFS)
	/bin/ls  $(LATEXXREFS) &gt; $@
$(RTFXREFSFILE) : $(RTFXREFS)
	/bin/ls  $(RTFXREFS) &gt; $@

# Rule to create an .xref file from a source file for the various formats.
%.html.xref : %
	$(ROBODOC) $&lt; $(@:.xref=) $(ROBOOPTS) INTERNAL GENXREF $@
%.tex.xref : %
	$(ROBODOC) $&lt; $(@:.xref=) $(ROBOOPTS) INTERNAL GENXREF $@
%.rtf.xref : %
	$(ROBODOC) $&lt; $(@:.xref=) $(ROBOOPTS) INTERNAL GENXREF $@

# Rule to create html documentation from a source file.
%.html : %
	$(ROBODOC) $&lt; $@ HTML $(ROBOOPTS) XREF $(HTMLXREFSFILE)

# Rule to create latex documentation from a source file.
# We do not include source items, and generate laxtex documents
# than can be included in a master document.
%.tex : %
	$(ROBODOC) $&lt; $@ LATEX $(ROBOOPTS) NOSOURCE SINGLEDOC XREF $(LATEXXREFSFILE)

# Rule to create ascii documentation from a source file.
%.txt : %
	$(ROBODOC) $&lt; $@ ASCII 

# Rule to create rtf documentation from a source file.
%.rtf : %
	$(ROBODOC) $&lt; $@ RTF $(ROBOOPTS) XREF $(RTFXREFSFILE)

# Use netscape to view the master index file for our project.
htmlview: html
	netscape $(PROJECT)_mi.html

# Use the latex programs to generate a .dvi from the master index file
# for our prokect. View this .dvi file with xdvi
texview:  tex
	latex $(PROJECT)_mi
	makeindex $(PROJECT)_mi
	latex $(PROJECT)_mi
	latex $(PROJECT)_mi
	xdvi  $(PROJECT)_mi.dvi

# Clean-up the mess we made
#
clean:
	rm -f $(HTMLXREFS) 
	rm -f $(HTMLDOCS) 
	rm -f $(LATEXXREFS)
	rm -f $(LATEXDOCS) 
	rm -f $(PROJECT)_mi.* *.aux
	rm -f $(RTFXREFS)
	rm -f $(RTFDOCS)
	rm -f $(ASCIIDOCS)
	rm -f $(HTMLXREFSFILE) 
	rm -f $(LATEXXREFSFILE) 
	rm -f $(RTFXREFSFILE)
</PRE></TD></TR></TABLE>

<P>It includes all the necessary commands to generate and view the documentation for you project. You create documentation in any of the four formats.
For instance to create documentation in html format use:</P>
<TABLE><TR><TD><PRE>
  make xhtml
  make html
</PRE></TD></TR></TABLE>
<P>To make documentation in LaTeX format use:</P>
<TABLE><TR><TD><PRE>
  make xtex
  make tex
</PRE></TD></TR></TABLE>
<P>To view your documentation use:</P>
<TABLE><TR><TD><PRE>
  make xhtml
  make texview
</PRE></TD></TR></TABLE>
<P>or</P>
<TABLE><TR><TD><PRE>
  make xtex
  make texview
</PRE></TD></TR></TABLE>


<P>To clean up all the documentation files use:</P>
<PRE>
  make clean
</PRE>

<P>To use this make file in project set the variable
<TT>SOURCE</TT> to the names of your source files and set the
variable <TT>PROJECT</TT> to the name of your project.</P>

<P>You can find a copy of the above makefile
<TT>Docs/example_makefile</TT>.  This should get you started in
no time.</P>

www_section(`MDSO', `What to do if You have Sources in Multiple Directories')

<P>It is possible to have your sources in multiple
subdirectories. However the generated documentation is expected
to be in one single directory. If not the cross references will
be wrong, at least in the HTML documentation.</P>

<P>Say you have the following directory structure:</P>
<TABLE><TR><TD><PRE>
  Project/
     Dir1/
        program1.c 
     Dir2/
        program2.c 
</PRE></TD></TR></TABLE>

<P>You can create the documentation for that as follows (assuming
you are in Project):
</P>
<TABLE><TR><TD><PRE>
  robodoc Dir1/prog1.c prog1.c.html HTML GENXREF Dir1/prog1.xref 
  robodoc Dir2/prog2.c prog2.c.html HTML GENXREF Dir2/prog2.xref 
  echo "Dir1/prog1.xref" &gt; xreffiles 
  echo "Dir2/prog2.xref" &gt;&gt; xreffiles 
  robodoc Dir1/prog1.c prog1.c.html HTML XREF xreffiles 
  robodoc Dir2/prog2.c prog2.c.html HTML XREF xreffiles 
  robodoc xreffiles master_index.html INDEX HTML 
</PRE></TD></TR></TABLE>
<P>
This generates the following files:
</P>
<TABLE><TR><TD><PRE>
   prog1.c.html
   prog2.c.html
   master_index.html
</PRE></TD></TR></TABLE>


<P>With some version of make (for instance the gnu version) you
can strip the directory part of a filename with $(notdir NAME)
How this can be used is shown in the following example
makefile.  Here we have the sources for robodoc, the <TT>.c</TT> files are
in the directory <TT>Sources/</TT> and <TT>.h</TT> files are in the
directory <TT>Headers/</TT>.</P>

<TABLE><TR><TD><PRE>
SHELL = /bin/sh
.SUFFIXES:

ROBODOC=./robodoc
ROBOOPTS=C SORT 

# Your source files.
#
SOURCES=Sources/analyser.c Sources/generator.c Sources/items.c Sources/util.c \
  Sources/folds.c Sources/headers.c Sources/links.c Sources/robodoc.c \
  Headers/analyser.h Headers/generator.h Headers/items.h Headers/util.h \
  Headers/folds.h Headers/headers.h Headers/links.h Headers/robodoc.h

# The name of your Project
#
PROJECT=ROBODoc

# The various documentation files, derived from the source files.
#
HTMLDOCS=$(SOURCES:=.html)
HTMLXREFS=$(HTMLDOCS:.html=.html.xref)
HTMLXREFSFILE=$(PROJECT)_html.xrefs

# Create the xref files for the various formats.
xhtml: $(HTMLXREFSFILE) 

# Create the documentation 
html: $(HTMLDOCS) $(PROJECT)_mi.html 

# Create master index file.
$(PROJECT)_mi.html: $(HTMLXREFSFILE) 
	$(ROBODOC) $&lt; $@ INDEX HTML TITLE "$(PROJECT) Master Index"

# Create the file with the names of all xref files.
$(HTMLXREFSFILE) : $(HTMLXREFS)
	/bin/ls $(HTMLXREFS) &gt; $@

# Rule to create an .xref file from a source file 
%.html.xref : %
	$(ROBODOC) $&lt; $(notdir $(@:.xref=)) $(ROBOOPTS) INTERNAL GENXREF $@

# Rule to create html documentation from a source file.
%.html : %
	$(ROBODOC) $&lt; $(notdir ${@}) HTML $(ROBOOPTS) XREF $(HTMLXREFSFILE)
</PRE></TD></TR></TABLE>

 

www_section(`RDF', `The ROBODoc Defaults File')

<P>The robodoc.default file can be used to change the appearance
of the documentation. For each item type you can define how the
corresponding text should be rendered.  Each line in the default
file consists of two parts, the item type and the item
attributes. For instance</P>

<PRE>
AUTHOR                    LARGE ITALICS BOLD UNDERLINE
</PRE>

<P>Specifies that the AUTHOR item has the attributes LARGE,
ITALICS, BOLD, and UNDERLINE.  The effect of each attribute is
listed in the following table.</P>

<TABLE>
<TR><TD>Item Attributes</TD> 
    <TD>Effect in HTML</TD>
</TR>
<TR><TD>LARGE</TD>
    <TD>&lt;FONT SIZE=5&gt;,&lt;/FONT&gt;</TD>
</TR>
<TR><TD>SMALL</TD>
    <TD>&lt;FONT SIZE=-1&gt;,&lt;/FONT&gt;</TD>
</TR>
<TR><TD>ITALICS</TD>
    <TD>&lt;I&gt;,&lt;/I&gt;</TD>
</TR>
<TR><TD>BOLD</TD>
    <TD>&lt;B&gt;,&lt;/B&gt;</TD>
</TR>
<TR><TD>UNDERLINE</TD>
    <TD>&lt;U&gt;,&lt;/U&gt;</TD>
</TR>
<TR><TD>HIGHLIGHT</TD>
    <TD>&lt;EM&gt;,&lt;/EM&gt;</TD>
</TR>
</TABLE>


www_section(`UOB', `ROBODoc Command Line Options')

<P>When using ROBODoc you should provide at least two
parameters</P>

<PRE>
  robodoc &lt;source file&gt; &lt;documentation file&gt; [options]
</PRE>

<P>Here sourcefile is the file with the program source from which
the documentation is to be extracted. The documentation file is
the file that will contain the extracted documentation.  </P>

<P>In case you are creating a master index file you have to
specify three parameters</P> 
<PRE>
  robodoc &lt;xrefs file&gt; &lt;master index file&gt; INDEX [options]
</PRE>


<P>In addition to this you can specify one or more of the
following options:</P>

<TABLE >
  <TR><TD><TT>ASCII</TT></TD>
      <TD>Generate documentation in ASCII format (default)</TD>
  </TR>
  <TR><TD><TT>GUIDE</TT></TD>
      <TD>Generate documentation in AmigaGuide format.</TD>
  </TR>
  <TR><TD><TT>HTML</TT></TD>
      <TD>Generate documentation in HTML format.</TD>
  </TR>
  <TR><TD><TT>LATEX</TT></TD>
      <TD>Generate documentation in LaTeX format. (Experimental)</TD>
  </TR>
  <TR><TD><TT>RTF</TT></TD>
      <TD>Generate documentation in RTF format.</TD>
  </TR>
  <TR><TD><TT>C</TT></TD>
      <TD>Use ANSI C grammar in source items (test, HTML only)</TD>
  </TR>
  <TR><TD><TT>FOLD</TT></TD>
      <TD>Enable folding. (Experimental)</TD>
  </TR>
  <TR><TD><TT>GENXREF &lt;xref file&gt;</TT></TD>
      <TD>Generate a xref file, which can be used to create
         www_link(`#CLD', `cross links') between documents.</TD>
  </TR>
  <TR><TD><TT>XREF &lt;xrefs file&gt;</TT></TD>
      <TD>Use a set of xref files to create references (links) to other
      documents or within the document. <TT>&lt;xrefs file&gt;</TT>
      is a file with xref file names.</TD>
  </TR>
  <TR><TD><TT>INDEX</TT></TD>
     <TD>Create a www_link(`#MAIND', `master index file').</TD>
  </TR>
  <TR><TD><TT>INTERNAL</TT></TD>
     <TD>Also include headers that are marked internal.</TD>
  </TR>
  <TR><TD><TT>INTERNALONLY</TT></TD>
      <TD>Only extract the headers marked internal.</TD>
  </TR>
  <TR><TD><TT>NOSOURCE</TT></TD>
      <TD>Do not include the source items in the documentation.</TD>
  </TR>
  <TR><TD><TT>SORT</TT></TD>
      <TD>Sort the headers alphabetically.</TD>
  </TR>
  <TR><TD><TT>SINGLEDOC</TT></TD>
      <TD>Do not create a document header and footer when creating 
          documentation in LaTeX format.  This allows you to include
          the generated documents into big document or 
          www_link(`#MAIND', `master index file').</TD>
  </TR>
  <TR><TD><TT>TITLE &lt;title&gt;</TT></TD>
      <TD>Sets the title that is used for the 
         www_link(`#MAIND', `master index file').</TD>
  </TR>
  <TR><TD><TT>TOC</TT></TD>
      <TD>Generate a table of contents.  It is only useful when you select
      ASCII as output mode.  With all other output modes the
      table of contents is generated anyway.</TD>
  </TR>
  <TR><TD><TT>TABSIZE &lt;n&gt;</TT></TD>
      <TD>Convert each tab into <TT>n</TT> spaces.</TD>
  </TR>
  <TR><TD><TT>-v</TT></TD>
      <TD>Verbose option, ROBODoc will tell you what it is doing.</TD>
  </TR>
</TABLE>

<P>If you wonder why all the odd ALL CAPS flags are used instead
of for instance "-x"; this was how it was done on the Amiga.</P>

<P>The following abbreviations are also allowed:</P>
<TABLE >
<TR><TD><TT>-s </TT></TD><TD><TT>SORT</TT></TD></TR>
<TR><TD><TT>-t </TT></TD><TD><TT>TOC</TT></TD></TR>
<TR><TD><TT>-x </TT></TD><TD><TT>XREF</TT></TD></TR>
<TR><TD><TT>-g </TT></TD><TD><TT>GENXREF</TT></TD></TR>
<TR><TD><TT>-i </TT></TD><TD><TT>INTERNAL</TT></TD></TR>
<TR><TD><TT>-io</TT></TD><TD><TT>INTERNALONLY</TT></TD></TR>
<TR><TD><TT>-ts</TT></TD><TD><TT>TABSIZE</TT></TD></TR>
</TABLE>


www_section(`ADV', `Adding New Languages')

<P>To add a new programming language to ROBODoc you have to edit
<TT>headers.c</TT>.  Here you find three variables:
<TT>header_markers</TT>, <TT>remark_markers</TT>, and
<TT>end_markers</TT>.  There are all arrays, and you have to add
an new entry to each of these three arrays.</P>

<P>Say your programming language uses the following type of remarks:</P>
<PRE>
   $%% This is a remark with some text       
       and some more and some more  %%$
</PRE>

<P>That is is starts with three spaces and then <TT>$%%</TT>, and
has to end with <TT>%%$</TT>. Then you would add to <TT>header_markers</TT>
</P>
<PRE>
   "   $%%****",
</PRE>
<P>To <TT>remark_markers</TT> you would add</P>
<PRE>
   "   *",
</PRE>
<P>And to <TT>end_markers</TT> you would add</P>
<PRE>
   "   $%%***",
</PRE>
<P>You can then use the following kind of headers in your program:</P>
<PRE>
   $%%****f* Test/afunction ***** 
   * NAME  
   *   afunction
   * FUNCTION
   *   A test.
   * SOURCE
   *%%$
     afunction(test,test) [
       print hello world ;
     ]
   $%%***%%$
</PRE>





www_section(`SAB', `Suggestions and Bugs')

<P>If you find any bugs, catch them, put them in a jar, and send
them to:</P> 
<ADDRESS>fslothouber@acm.org</ADDRESS>  
<P>Suggestions are also welcome at this address.  Flames can be
directed to the sun.</P>

www_bodyend
www_docend

