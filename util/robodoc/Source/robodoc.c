/****h* Autodoc/ROBODoc [3.2]
 * NAME
 *   ROBODoc -- AutoDoc formatter
 * COPYRIGHT
 *  Copyright (C) 1994-2000  Frans Slothouber and Jacco van Weert.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * FUNCTION
 *   ROBODoc is intended to be a replacement for the original AutoDocs
 *   program.  ROBODoc will extract the procedure comment headers
 *   from a source file, and put them into a separate documentation file.
 *   There are five different file output formats:
 *       ASCII
 *       HTML (HyperText Markup Langauge) -- mainly used on the Internet;
 *           thus the files can be viewed with a normal HTML viewer/browser
 *       AmigaGuide -- this format can be viewed by AmigaGuide (Amiga only)
 *       LaTeX - as input to LaTeX to produce .dvi files
 *       RTF (Rich Text Format) -- as input to the Help compiler (Windows only)
 *   For further information read the documentation in the archive.
 * AUTHOR
 *   Frans Slothouber:  <fslothouber@acm.org>.
 *     Source code and additional extensions from version 2.0 and up.
 *
 *   Petteri Kettunen: <petterik@iki.fi>
 *     Bug fixes, FOLD, C features.
 *
 *   Jacco van Weert: <weertj@xs4all.nl>
 *     Original idea and program.
 *
 *   Bernd Koesling:  <KOESSI@CHESSY.aworld.de>
 *     Bug fixes, functional improvements, code cleanup.
 *
 *   Anthon Pang:  <apang@mindlink.net>
 *     RTF support, Bug fixes.
 *
 *   Thomas Aglassinger: <agi@sbox.tu-graz.ac.at>
 *     Fixes and cleanup of HTML-output
 *
 * CREATION DATE
 *   20-Dec-94
 * MODIFICATION HISTORY
 *   Modifications by Jacco van Weert.
 *     19-Jan-95     -  v0.8:   First test beta-version
 *     26-Jan-95     -  v0.92:  2nd test beta-version
 *     2-Feb-95      -  v0.93:  Mungwall hit, solved.
 *                              When item headers, are also available
 *                              in body then parts are duplicated solved.
 *     Mar-95        -  v1.0a:  Final version
 *     2-Apr-95      -  v1.0b:  Bug fixes
 *                              Procedure header search bug solved.
 *                              Print 'created procedure' text
 *     20-Apr-95     -  v1.1a:  INTERNALONLY option added.
 *                              Sort problem solved.
 *   Modifications by FNC Slothouber.
 *     10-May-1995 -  v2.0a  * Program completely rewritten
 *                           * added SOURCE item and LaTeX output.
 *                           * added TAB converter.
 *     11-May-1995 -  v2.0b  * Accepts headers that start with
 *                             any sequence of non-spaces.
 *                             RoboDoc should work with any
 *                             type of programming language now.
 *     12-May-1995 -  v2.0c  * Bug fixes.
 *     15-May-1995 -  v2.0d  * New Defaults file.
 *                           * Added Verbose option.
 *     24-May-1995 -  v2.0e  * Fixed a bug that cause the
 *                             CleanUp Routine to lock up.
 *                           * Improved the HTML output,
 *                             should work faster now.
 *   Modifications by Koessi
 *     01-Aug-1995  - v2.0?  * more robust parsing, less enforcer-hits
 *                           * removed self-referencing links !
 *                           * remarked most changes with *koessi*
 *                           * added GoldEd-foldmarks
 *                           * compiled successfully with SAS-C 6.3
 *     07-Aug-1995   -       * automated foldmarks "\***"
 *                           ! GoldEd's foldmarks == RoboDoc marker !
 *                           * quoted source parsing enhanced
 *     08-Aug-1995   -       * a lot of while instead of for
 *                           * a lot of switch() instead of ifelse
 *                           * version defined
 *                           * RB_Say, RB_Panic now useable like printf()
 *                             new formats for nearly all output-strings
 *                           * char *whoami is global copy of argv[0]
 *                           * BOLD <- MAKE_LARGE && AMIGAGUIDE
 *                           * succesfully compiled&tested on HPUX
 *                           (HP9000/800)
 *                           * optimized listfunctions
 *                           * encapsulated header- and link-
 *                             allocating and freeing
 *                           * RB_Find_Function_Name() replaced
 *                             with RB_FilePart()
 *  Modifications by FNC Slothouber.
 *    18-Aug-1995   -  v3.0  
 *      o New scanner that searches for a set default markers 
 *        that define what is a comment or what is not and that 
 *        define what or what is not a header/end marker.
 *      o Added Beast Support
 *    27-Aug-1995   - v3.0b  
 *      o Fixed a bug with the defaults file
 *      o Improved search algorithm RoboDoc is now 5.8 times faster.
 *    06-Sep-1995   - v3.0c  
 *      o Bug fixes
 *    08-Oct-1995   - v3.0d  
 *      o Bug fixes
 *    04-Feb-1996   - v3.0e  
 *      o fixed the problem with the TOC that included links to headers that
 *                             were not selected. (i.e internal)
 *  Modifications by apang
 *    08-Mar-1996   - v3.0f  
 *      o Cleaner build for Borland C++ 4.52
 *      o Added more markers (C++, Pascal, Modula-2, COBOL)
 *      o Added more item types/names
 *      o Added #defines for the preamble (COMMENT_ROBODOC and 
 *        COMMENT_COPYRIGHT)
 *      o BLANK_HEADER for detection of asterisk'd lines
 *      o RB_Say() the GENERIC header warning instead of using printf()
 *      o Indents SOURCE body in output
 *      o ASCII respects the TOC flag; removed extraneous newline after 
 *        formfeed (so it's more like AutoDoc)
 *      o HTML output fixed to handle '<', '>', and '&'
 *      o LaTeX attributes and '%' handling added; fancied up the output a bit
 *      o RTF support added
 *      o Changed some fprintf()'s to fputc()'s for potentially lower overhead
 *      o Fixed line eater bug
 *      o More general fix to the TOC problem of including internal links 
 *        when it wasn't selected
 *  Modifications by FNC Slothouber.
 *    01-April-1996  - v3.0h 
 *      o Added ';' to &gt and &lt so lynx also recognizes them.
 *      o Fancied up the HTML output.
 *    10-July-1996   - v3.0i 
 *      o Bug Fix, Both the options INTERNAL and INTERNALONLY did not 
 *        work correctly.
 *  Modifications by agi
 *    15-Dec-1997    - v3.0j 
 *      o cleaned the HTML-output, so it now conforms to the DTD for HTML-3.2
 *      o TOC now is an ordered list (<OL> and <LI>)
 *      o added "<!DOCTYPE..>"
 *      o added quotes to values of some HTML-attributes
 *      o more compatible implementation of the SGML-comment containing 
 *        copyright-info replaced all occurrences of <B><PRE>.. by <PRE><B>
 *      o replaced <H2/3> by <H1/2>
 *      o fixed two minor warnings reported by gcc -Wall
 *  Modifications by FNC Slothouber.
 *    14-Aug-1998    - v3.0k * Tcl/Tk '#' handling added;
 *       Feb-1999    - v3.0l * Added function to reverse the header list.
 *  Modifications by Petteri Kettunen
 *    Feb 1999      - v3.0m 
 *      o Changed background color to white
 *      o Changed size of Table of Contents title. (H3 instead of H1)
 *      o The reverse function also reversed the sorted header list, 
 *        fixed this.
 *  Modifications by Petteri Kettunen
 *   August 1999 - v3.0m+ 
 *      o Support for folding in SOURCE items, HTML only.
 *      o indent -kr 
 *      o Added options FOLD and C
 *  Modifications by FNC Slothouber. 
 *   August 1999 - v3.1   
 *      o More documentation and a more informative usage() function. 
 *      o GPL-ed.
 *      o robodoc -c prints licence
 *      o removed a number of Source items from the documentation to reduce 
 *        the size of the robodoc.c.html file...  no fun for people
 *        to download a >100k file.
 *      o removed the warning about not using a robodoc default file.
 *      o indent -orig -i2 -nbc -ncdb -bad -bap
 *      o Fixed the warnings. 
 *      o Fixed some occurrences of (evil cast)malloc  (thou shalt not 
 *        cast malloc :) 
 *      o ROBODoc now returns EXIT_FAILURE or  EXIT_SUCCESS, as defined 
 *        in <stdlib.h>
 *      o Fixed a memory leak in RB_Analyse_Document()
 *   Oct 1999 - v3.1b     
 *      o <A NAME="source code file name"> is generated at the beginning of 
 *        each document. A mention of the source code name in another 
 *        document creates a link to this name (provided you use xrefs).
 *      o Moved most #defines and enums to robodoc.h
 *      o Made ROBODoc more forgiving in reading the xrefs file. Empty 
 *        lines are allowed and also spaces at the end of a file name.
 *   Nov 1999 - v3.1c  -- From patches that I received from Stefan Kost
 *      o renamed BEAST METHODS -> METHODS
 *      o renamed BEAST ATTRIBUTES -> ATTRIBUTES
 *      o added new items useful for object oriented programming; some of 
 *        these items are already used in os3.1 autodocs
 *        TAGS, COMMANDS, DERIVED FROM, DERIVED BY, USES,
 *        CHILDREN, USED BY, PARENTS, USAGE, PURPOSE
 *      o commented the item names
 *      o changed item-type enums to end all with _ITEM
 *      o changed RB_Find_Link to accept names ending with '...'
 *      o changed copyright comment to be a style-guide conform version string.
 *      o changed RB_VER[] to be a style-guide conform version string
 *      o changed AMIGA into _AMIGA, because the first one does not exists, 
 *        when compiling with NOANSI on SAS C/C++
 *   Dec 1999 - v3.1d
 *      o added new header types for, classes, methods, variables, 
 *        functions, strutures and constants. (Idea of Stefan Kost) 
 *      o added a command to create a master index file that contains
 *        sorted pointers to all classes, methods, variables, 
 *        functions, strutures and constants.
 *   Dec 1999 - v3.1e
 *      o added markers for HTML.
 *      o modified the RB_Find_Link() function to also words that include
 *        "::". This is used for C++ methods.
 *      o added a RB_Function_Name() function that correctly extracts the
 *        function name (or the name of any other object that is documented)
 *        from the header name.  The old code used RB_FilePart which failed
 *        on C++ method names. 
 *      o Fixed a core-dumping bug in RB_Set_Doc_Base()
 *   Dec 1999 - v3.1f
 *      o added RB_TimeStamp() to include time stamps in the documentation.
 *      o Documentation is now generated in LaTeX2e format.
 *      o added '|****' as begin marker, '|' as remark marker and '|***' as
 *        end marker for GNU assembler support.
 *      o ran ident on all source. Using the GNU standard now. 
 *      o Added new fold markers provided by Petteri
 *   May 2000 - v3.2
 *      o Using automake and autoconf.
 *      o Added fixes to folding code Petteri.
 *      o Added markers for FORTAN 90
 *   June 2000 - V3.2.1
 *      o Added patch from Simo Muinonen: This solved the following
 *        problem:
 *          When e.g. a field of a structured C variable (with an
 *          underscore in its name) is referred to using the
 *          point notation (e.g. "g_Status.tpstat"), the variable
 *          name is not recognized as a separate keyword.  This
 *          can also happen when a keyword is in a comment at the
 *          end of a sentence with an immediately following ".".
 *      o Fixed the "stuctures" type in the master index file.
 *      o Added mailto: support provided by Guillaume Etorre.
 *    July 2000 - V3.2.2
 *      o Added option SINGLEDOC
 *        For LaTeX output this generates documentation without
 *        the start and end headers.  This way the generated file
 *        can be included in a master file.  
 *      o Added master index file for LaTeX output.  The documentation
 *        gathered from several source files can now be included into
 *        one big file.
 *      o Added the option NOSOURCE.  With this option the SOURCE item
 *        is not included in the documentation.
 *      o Added the TITLE option. This allows to set the title for
 *        the master index file.
 *      o Made the search for headermarkers case insensitve.
 *        REM == Rem == rem  
 *    July 2000 - V3.2.3
 *      o Fixed a bug that caused links of the type
 *        "someword/anotherword," to be ignored, while
 *        "someword/anotherword" was recognized.
 *    Sep 2000 
 *      o Labels with identical names are now numbered.
 *    Apr 2001
 *      o The source file is opened "rb" this I hope will
 *        make it possible to use Robodoc under windows.
 *        (Thanks to Carlo Caminati) 
 *
 * NOTES
 *   Has been succesfully compiled:
 *     On an Amiga with SAS/C, DICE C and gcc (Amiga 1200)
 *     On a Sun Sparc Station with gcc   (under SunOS 4.1)
 *     On a Dec Alpha Station
 *     Under HP/UX on a HP9000/800
 *     Under IRIX
 *     On a Linux box with gcc, Slackware, Redhat, and Debian 2.1.
 * BUGS
 *   - HTML output is not Lynx friendly -- attributes are applied
 *     to leading white space =P ... solution: fix Lynx  >=)
 *   - Can't get the escape character for @ to work in
 *     AmigaGuide format.
 *   - Horrible use of feof() and fgets() 
 *   Other bugs?
 *     Catch them in a jar and send them to fslothouber@acm.org
 *     Latest version can be found on 
 *       http://robodoc.sourceforge.net
 *       http://www.xs4all.nl/~rfsber/Robo/
 *       http://freshmeat.net/ 
 *     
 ****/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "robodoc.h"
#include "folds.h"
#include "headers.h"
#include "items.h"
#include "util.h"
#include "links.h"
#include "analyser.h"
#include "generator.h"

#ifdef _AMIGA
char RB_VER[] = "\0$VER: robodoc " VERSION " " __AMIGADATE__ " (c) by Maverick Software Development 1994-2001";
#else
char RB_VER[] = "$VER: robodoc " VERSION " (" __DATE__ ") (c) by Maverick Software Development 1994-2001";
#endif


/****v* ROBODoc/source
 * NAME
 *   source -- source code file.
 * PURPOSE
 *   Pointer to the file with source code.   
 * NOTES
 *   This is a global. It is however only used by main() and
 *   RB_Close_The_Shop(). All other functions are passed a copy.
 *
 *   It is a global so that the file can be closed by
 *   RB_Close_The_Shop() when the program exits (normally or
 *   abnormaly).
 *****
 */

FILE *source = NULL;

/****v* ROBODoc/documentation
 * NAME
 *   documentation -- documentation file.
 * PURPOSE
 *   Pointer to the file that will contain the documentation extracted
 *   from the source code.   
 * NOTES
 *   This is a global. It is however only used by main() and
 *   RB_Close_The_Shop(). All other functions are passed a copy.
 *
 *   It is a global so that the file can be closed by
 *   RB_Close_The_Shop() when the program exits (normally or
 *   abnormaly).
 *****
 */

FILE *documentation = NULL;


/****v* ROBODoc/document_title
 * NAME
 *   documentat_title -- title for the documentation.
 * PURPOSE
 *   Used as the title for master index files or for latex documentation.
 *****
 */

char *document_title = NULL;

/****v* ROBODoc/output_mode [2.0]
 * NAME
 *   output_mode -- the mode of output
 * FUNCTION
 *   Controls which type of output will be generated.
 * SOURCE
 */

int output_mode = ASCII;

/*******/


/****v* ROBODoc/course_of_action [2.0]
 * NAME
 *   course_of_action
 * FUNCTION
 *   Global Variable that defines the course of action.
 * SOURCE
 */

int course_of_action = DO_MAKE_DOCUMENT;

/*******/


/****v* ROBODoc/line_buffer [2.0]
 * NAME
 *   line_buffer -- global line buffer
 * FUNCTION
 *   Temporary storage area for lines
 *   that are read from an input file.
 * SOURCE
 */

char line_buffer[MAX_LINE_LEN];

/*******/


/****v* ROBODoc/line_number [2.0]
 * NAME
 *   line_number -- global line counter
 * PURPOSE
 *   Keeps track of the number of lines that are read from the source file.
 * AUTHOR
 *   Koessi
 * SOURCE
 */

int line_number = 0;

/*******/


/****v* ROBODoc/use [3.0h]
 * NAME
 *   use -- usage string
 * FUNCTION
 *   Inform the user how to use ROBODoc.
 * AUTHOR
 *   Koessi
 * SOURCE
 */

char use[] =
"ROBODoc Version " VERSION ", autodocs formatter ($Revision$)\n"
"(c) 1994-2001 Frans Slothouber and Jacco van Weert\n"
"robodoc comes with ABSOLUTELY NO WARRANTY.\n"
"This is free software, and you are welcome to redistribute it\n"
"under certain conditions; type `robodoc -c' for details.\n"
"\n"
"Usage:\n"
"  robodoc <source file> <documentation file> [options]\n"
"    or\n"
"  robodoc <xrefs file> <master index file> INDEX [options]\n"
"\n"
"You can use one or more of the following options:\n"
"  GENXREF <xref file>  - to generate an xref file.\n"
"  XREF    <xrefs file> - if you want to use xref files to create\n"
"                         cross links.\n"
"  INDEX           - create a master index file.\n"
"  TABSIZE <nr_sp> - convert each TAB to nr_sp of spaces.\n"
"  TOC             - a table of contents will be generated.\n"
"  SORT            - the headers will be sorted.\n"
"  -v              - tell robodoc to tell you all about it.\n"
"  INTERNAL        - headers marked internal will also be included.\n"
"  INTERNALONLY    - only headers marked internal will be included.\n"
"  FOLD            - enable folding if HTML output is selected.\n"
"  C               - Use ANSI C grammar in source items (test, HTML only).\n"
"The type of output is selected with one of the following switches:\n"
"  ASCII, GUIDE, HTML, LATEX, or RTF\n"
"If no type is specified ASCII is used.\n"
"The following abbreviations are also allowed:\n"
"  TOC = -t  XREF = -x   SORT = -s  INTERNAL = -i \n"
"  GENXREF = -g  INTERNALONLY = -io  TABSIZE = -ts\n"
"Example:\n"
"  robodoc simulator.c simulator.html HTML -v TOC SORT\n"
"Authors/Contributors: Frans Slothouber <fslothouber@acm.org>,"
" Jacco van Weert,\n"
"  Petteri Kettunen, Bernd Koesling, Thomas Aglassinger, Anthon Pang, and\n"
"  Stefan Kost\n"
"For more information, and the lastest version:\n"
"  http://www.xs4all.nl/~rfsber/Robo/index.html\n"
"  Send bug reports to <fslothouber@acm.org>.\n";

/********/


/****v* ROBODoc/copying [3.1]
 * NAME
 *   copying -- licence information
 * FUNCTION
 *   inform the user how to copy me
 * AUTHOR
 *   Frans
 *******
 */

char copying[] =
"\n"
" Distributed under the GNU GENERAL PUBLIC LICENSE\n"
"   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION\n"
" See the source archive for a copy of the complete licence\n"
" If you do not have it you can get it from\n"
" http://freshmeat.net/appindex/1999/08/30/936003795.html\n";


/* Global variables */

char *whoami = NULL;		/* me,myself&i */
int tab_size = 8;
char doc_base[1024];		/* PetteriK */


/****f* ROBODoc/RB_Set_Doc_Base
 * NAME
 *   RB_Set_Doc_Base -- get file name without extension.
 ******
 */

void
RB_Set_Doc_Base (char *path)
{
  int ptr = 0, n = -1;

  while (path[ptr] != '\0')
    {
      if (path[ptr] == '.')
	{
	  n = ptr;
	}
      ptr++;
    }
  if (n != -1)
    {
      strncpy (doc_base, path, n);
    }
  else
    {
      strcpy (doc_base, path);
    }
  RB_Say ("doc_base is \"%s\"\n", doc_base);
}




/****f* ROBODoc/main [2.0d]
 * NAME
 *   main -- Entry point of ROBODoc
 * SYNOPSIS
 *   main (int argc, char **argv)
 * FUNCTION
 *   Get and parse the arguments.
 *   Analyse document and generate the documentation.
 * SOURCE
 */

int
main (int argc, char **argv)
{
  char *file_with_xrefs, *output_file_for_xrefs;

  whoami = argv[0];		/* global me,myself&i */
  if (argc < 2)
    {
      printf ("%s", use);
    }
  else if (argc < 3)
    {
      if (strcmp (argv[1], "-c") == 0)
	{
	  printf ("%s", copying);
	}
      else
	{
	  printf ("%s", use);
	}
    }
  else
    {
      RB_Analyse_Arguments (argc, argv, &file_with_xrefs,
			    &output_file_for_xrefs);

      RB_Say ("Analysing Defaults File\n");
      RB_Analyse_Defaults_File ();

      RB_Say ("trying to open source file \"%s\"\n", argv[1]);
      if ((source = fopen (argv[1], "rb")) != NULL)
	{
	  if (!(course_of_action & DO_INDEX))
	    {
	      RB_Say ("analysing source file \"%s\"\n", argv[1]);
	      RB_Analyse_Document (source);
              RB_Number_Duplicate_Headers();

	      if (course_of_action & DO_SORT)
		{
		  RB_Say ("sorting headers\n");
		  RB_Slow_Sort ();
		}
	      else
		{
		  RB_Reverse_List ();
		}
	      if ((course_of_action & DO_USE_XREFS) && file_with_xrefs)
		{
		  if ((xreffiles_file = fopen (file_with_xrefs, "r")) != NULL)
		    {
		      RB_Analyse_Xrefs (xreffiles_file);
		    }
		  else
		    {
		      RB_Panic ("can't open file with xref files \"%s\"\n",
				file_with_xrefs);
		    }
		}
	    }
	  else
	    {			/* INDEX */
	      if ((xreffiles_file = fopen (argv[1], "r")) != NULL)
		{
		  RB_Analyse_Xrefs (xreffiles_file);
		}
	      else
		{
		  RB_Panic ("can't open file with xref files \"%s\"\n",
			    argv[1]);
		}
	    }
	  if (course_of_action & DO_MAKE_DOCUMENT)
	    {
	      RB_Say ("trying to open destination file \"%s\"\n", argv[2]);
	      if ((documentation = fopen (argv[2], "w")) != NULL)
		{
		  RB_Say ("generating documentation\n");
		  RB_Set_Doc_Base (argv[2]);
		  RB_Generate_Documentation (documentation,
					     RB_FilePart (argv[1]),
					     RB_FilePart (argv[2]));
		  fclose (documentation);
		  documentation = NULL;
		}
	      else
		RB_Panic ("can't open destination file \"%s\"\n", argv[2]);
	    }
	  else if ((course_of_action & DO_MAKE_XREFS)
		   && output_file_for_xrefs)
	    {
	      RB_Say ("trying to open xref destination file \"%s\"\n",
		      output_file_for_xrefs);
	      if ((documentation = fopen (output_file_for_xrefs, "w")) != NULL)
		{
		  RB_Say ("generating xref destination file \"%s\"\n",
			  output_file_for_xrefs);
		  RB_Generate_xrefs (documentation, argv[1], argv[2]);
		  fclose (documentation);
		  documentation = NULL;
		}
	      else
		RB_Panic ("can't open xref destination file \"%s\"\n",
			  output_file_for_xrefs);
	    }
	  else if (course_of_action & DO_INDEX)
	    {
	      if ((documentation = fopen (argv[2], "w")) != NULL)
		{
		  RB_Generate_Index (documentation, argv[1]);
		  fclose (documentation);
		  documentation = NULL;
		}
	      else
		{
		  RB_Panic ("can't open destination file \"%s\"\n", argv[2]);
		}
	    }
	}
      else
	RB_Panic ("can't open source file \"%s\"\n", argv[1]);
    }
  RB_Say ("Ready\n");
  RB_Close_The_Shop ();
  return EXIT_SUCCESS;
}

/*****/




/****f* ROBODoc/RB_Analyse_Arguments [3.0h]
 * NAME
 *   RB_Analyse_Arguments
 * SYNOPSIS
 *   RB_Analyse_Arguments (argc, argv, file_with_xrefs,
 *                         output_file_for_xrefs)
 *   RB_Analyse_Arguments (int, char **, char **, char **)
 * FUNCTION
 *   Get and parse the arguments. This is a quite complex function.
 *   It assumes that the first and second parameter are the
 *   name of the source file and name of the documentation file
 *   respectively. They are therefore skipped.
 *   May modifie: output_mode, course_of_action, file_with_xrefs, 
 *   output_file_for_xrefs, document_title.
 * SOURCE
 */

void
RB_Analyse_Arguments (int argc, char **argv,
		      char **file_with_xrefs,
		      char **output_file_for_xrefs)
{
  char **parameter;
  int parameter_nr;

  for (parameter_nr = argc - 3, parameter = argv + 3;
       parameter_nr > 0;
       parameter++, parameter_nr--)
    {

      if (!RB_Str_Case_Cmp (*parameter, "HTML"))
	output_mode = HTML;
      else if (!RB_Str_Case_Cmp (*parameter, "GUIDE"))
	output_mode = AMIGAGUIDE;
      else if (!RB_Str_Case_Cmp (*parameter, "LATEX"))
	output_mode = LATEX;
      else if (!RB_Str_Case_Cmp (*parameter, "ASCII"))
	output_mode = ASCII;
      else if (!RB_Str_Case_Cmp (*parameter, "RTF"))
	output_mode = RTF;
      else if (!RB_Str_Case_Cmp (*parameter, "FOLD"))
	extra_flags |= FOLD;	/* PetteriK */
      else if (!RB_Str_Case_Cmp (*parameter, "C"))
	extra_flags |= C_MODE;	/* PetteriK */
      else if (!RB_Str_Case_Cmp (*parameter, "SORT") ||
	       !RB_Str_Case_Cmp (*parameter, "-S"))
	course_of_action |= DO_SORT;
      else if (!RB_Str_Case_Cmp (*parameter, "INDEX"))
	{
	  course_of_action |= DO_INDEX;
	  course_of_action &= ~DO_MAKE_DOCUMENT;
	}
      else if (!RB_Str_Case_Cmp (*parameter, "INTERNAL") ||
	       !RB_Str_Case_Cmp (*parameter, "-I"))
	course_of_action |= DO_INCLUDE_INTERNAL;
      else if (!RB_Str_Case_Cmp (*parameter, "SINGLEDOC"))	       
	course_of_action |= DO_SINGLEDOC;
      else if (!RB_Str_Case_Cmp (*parameter, "NOSOURCE"))	       
	course_of_action |= DO_NOSOURCE;
      else if (!RB_Str_Case_Cmp (*parameter, "INTERNALONLY") ||
	       !RB_Str_Case_Cmp (*parameter, "-IO"))
	course_of_action |= DO_INTERNAL_ONLY;
      else if (!RB_Str_Case_Cmp (*parameter, "TOC") ||
	       !RB_Str_Case_Cmp (*parameter, "-T"))
	course_of_action |= DO_TOC;
      else if (!RB_Str_Case_Cmp (*parameter, "-V"))
	course_of_action |= DO_TELL;
      else if (!RB_Str_Case_Cmp (*parameter, "TITLE"))
	{
	  if (--parameter_nr)
	    {
	      parameter++;
	      document_title = *parameter;
	      RB_Say ("TITLE=\"%s\"\n", *document_title);
	    }
	  else
	    RB_Panic ("you must specify a title with the TITLE option\n");
	}
      else if (!RB_Str_Case_Cmp (*parameter, "XREF") ||
	       !RB_Str_Case_Cmp (*parameter, "-X"))
	{
	  if (--parameter_nr)
	    {
	      parameter++;
	      *file_with_xrefs = *parameter;
	      RB_Say ("XREF=\"%s\"\n", *file_with_xrefs);
	      course_of_action |= DO_USE_XREFS;
	    }
	  else
	    RB_Panic ("you must specify a xref file with the XREF option\n");
	}
      else if (!RB_Str_Case_Cmp (*parameter, "TABSIZE") ||
	       !RB_Str_Case_Cmp (*parameter, "-TS"))
	{
	  if (--parameter_nr)
	    {
	      parameter++;
	      tab_size = atoi (*parameter);
	    }
	  else
	    {
	      RB_Panic ("you must specify the number of spaces with the"
			" TABSIZE option\n");
	    }
	}
      else if (!RB_Str_Case_Cmp (*parameter, "GENXREF") ||
	       !RB_Str_Case_Cmp (*parameter, "-G"))
	{
	  if (--parameter_nr)
	    {
	      ++parameter;
	      *output_file_for_xrefs = *parameter;
	      RB_Say ("GENXREF=\"%s\"\n", *output_file_for_xrefs);
	      course_of_action |= DO_MAKE_XREFS;
	      course_of_action &= ~DO_MAKE_DOCUMENT;
	    }
	  else
	    RB_Panic ("you must specify a xref file with the GENXREF option\n");
	}
      else
	{
	  RB_Panic ("unknown option %s\n", *parameter);
	}
    }
  if ((course_of_action & DO_USE_XREFS) &&
      (output_mode == ASCII) &&
      !(course_of_action & DO_INDEX))
    {
      printf ("%s: WARNING, you can not use xrefs when you generate\n"
	      "\t\tdocumentation in ASCII [discarding switch]\n",
	      argv[0]);
      course_of_action &= ~DO_USE_XREFS;
    }
  if (course_of_action & DO_INDEX)
    {
      if ((output_mode != LATEX) && (output_mode != HTML)) { 
	    RB_Panic ("you can only use the INDEX option in combination with LATEX or HTML\n");
      }
    }
}

/******/



/****i* ROBODoc/RB_Close_The_Shop [3.0b]
 * NAME
 *   RB_Close_The_Shop -- free resources.
 * SYNOPSIS
 *   void RB_Close_The_Shop ()
 * FUNCTION
 *   Frees all resources used by robodoc.
 * SEE ALSO
 *   RB_Free_Header(), RB_Free_Link()
 * SOURCE
 */

void
RB_Close_The_Shop (void)
{
  struct RB_header *cur_header, *tmp_header;
  struct RB_link *cur_link, *tmp_link;

  if (source)
    fclose (source);
  if (documentation)
    fclose (documentation);
  if (xreffiles_file)
    fclose (xreffiles_file);
  if (xref_file)
    fclose (xref_file);

  for (cur_header = first_header; cur_header;)
    {
      tmp_header = cur_header->next_header;
      RB_Free_Header (cur_header);
      cur_header = tmp_header;
    }

  for (cur_link = first_link; cur_link;)
    {
      tmp_link = cur_link->next_link;
      RB_Free_Link (cur_link);
      cur_link = tmp_link;
    }

  if (header_index)
    free (header_index);
  if (link_index)
    free (link_index);
}

/******/
