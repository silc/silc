#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "robodoc.h"
#include "headers.h"
#include "items.h"
#include "folds.h"
#include "util.h"
#include "links.h"
#include "generator.h"
#include "analyser.h"
#include <errno.h>

/****f* ROBODoc/RB_Generate_Documentation [3.0h]
 * NAME
 *   RB_Generate_Documentation
 * SYNOPSIS
 *   RB_Generate_Documentation (dest_doc, name, name)
 *
 *   RB_Generate_Documentation (FILE *, char *, char *)
 * FUNCTION
 *   Generates the autodoc documentation from the list of
 *   function headers that has been created by
 *   RB_Analyse_Document.
 * INPUTS
 *   dest_doc   - Pointer to the file to which the output will be written.
 *   src_name   - The name of the source file.
 *   dest_name  - The name of this file.
 * BUGS
 *   There might be plenty.
 * SEE ALSO
 *   RB_Generate_Doc_Start,
 *   RB_Generate_Doc_End,
 *   RB_Generate_Header_Start,
 *   RB_Generate_Header_End,
 *   RB_Generate_Header_Name,
 *   RB_Generate_Item_Name,
 *   RB_Generate_Item_Doc,
 *   RB_Generate_Item_Body .
 * SOURCE
 */

void
RB_Generate_Documentation (
			    FILE * dest_doc, char *src_name, char *dest_name)
{
  struct RB_header *cur_header;
  char fname[256];
  FILE *orig_doc = dest_doc;

  RB_Make_Index_Tables ();

  RB_Generate_Doc_Start (dest_doc, src_name, dest_name, 1);

  for (cur_header = first_header;
       cur_header;
       cur_header = cur_header->next_header)
    {
      int item_type;
      char *next_line, *item_line = NULL;

      RB_Say ("generating documentation for \"%s\"\n", cur_header->name);

      if (output_mode == HTML)
        {
          sprintf(fname, "%s-%s.html", doc_base, cur_header->function_name);
          dest_doc = fopen(fname, "w");
          if (!dest_doc)
            {
	      fprintf(stderr, "%s\n", strerror(errno));
	      exit(1);
	    }
        }

      RB_Generate_Header_Start (dest_doc, cur_header, src_name);

      next_line = cur_header->contents;
      item_type = RB_Find_Item (&next_line, &item_line);

      if (item_type != NO_ITEM)
	{
	  int old_item_type;
	  char *old_next_line;

	  do
	    {
	      if (course_of_action & DO_TELL)
		printf ("[%s] ", item_names[item_type]);

	      if (!((item_type == SOURCE_ITEM) &&  
		  (course_of_action & DO_NOSOURCE)))
		RB_Generate_Item_Name (dest_doc, item_type);
	      
	      old_next_line = next_line;
	      old_item_type = item_type;
	      
	      item_type = RB_Find_Item (&next_line, &item_line);

	      if (!((old_item_type == SOURCE_ITEM) &&  
		  (course_of_action & DO_NOSOURCE)))
		RB_Generate_Item_Doc (dest_doc, dest_name,
				      old_next_line, item_line,
				      cur_header->function_name, 
				      old_item_type);
	    }
	  while (item_type != NO_ITEM);
	  if (course_of_action & DO_TELL)
	    putchar ('\n');
	}
      else
	printf ("%s: WARNING, header \"%s\" has no items\n",
		whoami, cur_header->name);

      RB_Generate_Header_End (dest_doc, cur_header);

      if (output_mode == HTML)
        fclose(dest_doc);
    }

  dest_doc = orig_doc;
  RB_Generate_Doc_End (dest_doc, dest_name);
}

/***** RB_Generate_Documentation ***/





/****f* ROBODoc/RB_Generate_Doc_Start [3.0j]
 * NAME
 *   RB_Generate_Doc_Start -- Generate document header.
 * SYNOPSIS
 *   RB_Generate_Doc_Start (dest_doc, src_name, name, toc)
 *
 *   RB_Generate_Doc_Start (FILE *, char *, char *, char)
 * FUNCTION
 *   Generates for depending on the output_mode the text that
 *   will be at the start of a document.
 *   Including the table of contents.
 * INPUTS
 *   dest_doc - pointer to the file to which the output will
 *              be written.
 *   src_name - the name of the source file.
 *   name     - the name of this file.
 *   output_mode - global variable that indicates the output
 *                 mode.
 *   toc      - generate table of contens
 * SEE ALSO
 *   RB_Generate_Doc_End
 * SOURCE
 */

void
RB_Generate_Doc_Start (
		      FILE * dest_doc, char *src_name, char *name, char toc)
{
  struct RB_header *cur_header;
  int cur_len, max_len, header_nr;

  switch (output_mode)
    {
    case AMIGAGUIDE:
      if (strstr (name + 1, ".guide") == NULL)
	fprintf (dest_doc, "@database %s.guide\n", name);
      else
	fprintf (dest_doc, "@database %s\n", name);
      fprintf (dest_doc, "@rem Source: %s\n", src_name);
      fprintf (dest_doc, "@rem " COMMENT_ROBODOC);
      fprintf (dest_doc, "@rem " COMMENT_COPYRIGHT);
      fprintf (dest_doc, "@node Main %s\n", name);
      fprintf (dest_doc, "@{jcenter}\n");
      fprintf (dest_doc,
	       "@{fg highlight}@{b}TABLE OF CONTENTS@{ub}@{fg text}\n\n");

      max_len = 0;
      for (cur_header = first_header;
	   cur_header;
	   cur_header = cur_header->next_header)
	{
	  if (cur_header->name)
	    {
	      cur_len = strlen (cur_header->name);
	      if (cur_len > max_len)
		max_len = cur_len;
	    }
	}

      for (cur_header = first_header;
	   cur_header;
	   cur_header = cur_header->next_header)
	{
	  if (cur_header->name && cur_header->function_name)
	    {
	      fprintf (dest_doc, "@{\"%s", cur_header->name);

	      for (cur_len = strlen (cur_header->name);
		   cur_len < max_len;
		   ++cur_len)
		fputc (' ', dest_doc);
	      fprintf (dest_doc, "\" Link \"%s\"}\n", cur_header->function_name);
	    }
	}

      fprintf (dest_doc, "@{jleft}\n");
      fprintf (dest_doc, "@endnode\n");
      break;

    case HTML:
      /* Append document type and title */
      fprintf (dest_doc,
	       "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n");
      fprintf (dest_doc, "<HTML><HEAD>\n<TITLE>%s</TITLE>\n", name);

      /* append SGML-comment with document- and copyright-info. This code
       * ensures that every line has an own comment to avoid problems with 
       * buggy browsers */
      fprintf (dest_doc, "<!-- Source: %s -->\n", src_name);
      {
	static const char copyright_text[]
	= COMMENT_ROBODOC COMMENT_COPYRIGHT;
	size_t i = 0;
	char previous_char = '\n';
	char current_char = copyright_text[i];

	while (current_char)
	  {
	    if (previous_char == '\n')
	      {
		fprintf (dest_doc, "<!-- ");
	      }
	    if (current_char == '\n')
	      {
		fprintf (dest_doc, " -->");
	      }
	    else if ((current_char == '-') && (previous_char == '-'))
	      {
		/* avoid "--" inside SGML-comment, and use "-_" instead; this
		 * looks a bit strange, but one should still be able to figure 
		 * out what is meant when reading the output */
		current_char = '_';
	      }
	    fputc (current_char, dest_doc);
	    i += 1;
	    previous_char = current_char;
	    current_char = copyright_text[i];
	  }
      }

      /* append heading and start list of links to functions */
      fprintf (dest_doc, "</HEAD><BODY BGCOLOR=\"#FFFFFF\">\n");
#if 0
      fprintf (dest_doc, "<A NAME=\"%s\">Generated from %s</A> with ROBODoc v"
	       VERSION
	       " on ",
	       src_name, src_name);
      RB_TimeStamp (dest_doc);
#endif
      fprintf (dest_doc, "<BR>\n");
      if (toc)
	{
	  char iname[256];
	  FILE *index;
	  int start = 0;

	  /* do toc if not in fold */
#if 0
	  fprintf (dest_doc,
		   "<H3 ALIGN=\"center\">TABLE OF CONTENTS</H3>\n");
	  fprintf (dest_doc, "<OL>\n");
#endif

	  /* Generate quick index file, for fast referencing */
	  sprintf(iname, "%s-index.tmpl", doc_base);
          index = fopen(iname, "w");
          if (!index)
	    {
	      fprintf(stderr, "%s\n", strerror(errno));
	      exit(1);
	    }

	  for (cur_header = first_header;
	       cur_header;
	       cur_header = cur_header->next_header)
	    {
	      char fname[256];

	      sprintf(fname, "%s-%s.html", RB_FilePart(doc_base), 
		      cur_header->function_name);

	      if (cur_header->name && cur_header->function_name)
		{
		  if (start == 0) 
		    {
		      int item_type;
		      char *next_line, *item_line = NULL;
		    
		      RB_Generate_Header_Start (dest_doc, cur_header, 
						src_name);

		      next_line = cur_header->contents;
		      item_type = RB_Find_Item (&next_line, &item_line);
		      
		      if (item_type != NO_ITEM)
			{
			  int old_item_type;
			  char *old_next_line;
			  
			  do
			    {
			      if (course_of_action & DO_TELL)
				printf ("[%s] ", item_names[item_type]);
			      
			      if (!((item_type == SOURCE_ITEM) &&
				    (course_of_action & DO_NOSOURCE)))
				RB_Generate_Item_Name (dest_doc, item_type);
			      
			      old_next_line = next_line;
			      old_item_type = item_type;
			      
			      item_type = RB_Find_Item (&next_line, 
							&item_line);
			      
			      if (!((old_item_type == SOURCE_ITEM) &&
				    (course_of_action & DO_NOSOURCE)))
				RB_Generate_Item_Doc(dest_doc, name,
						     old_next_line, item_line,
						     cur_header->function_name,
						     old_item_type);
			    }
			  while (item_type != NO_ITEM);
			  if (course_of_action & DO_TELL)
			    putchar ('\n');
			}

		      if (index)
			{
			  fprintf (index, "<A HREF=\"%s\"><IMG SRC=\"index_pic.gif\" BORDER=\"0\" ALT=\"\">%s</A><BR>\n",
				   name, cur_header->function_name);
			}

		      start = 1;
		    }
		  else
		    {
		      fprintf (dest_doc, "<LI><A HREF=\"%s\">%s</A>\n",
			       fname, cur_header->function_name);
		      if (index)
			fprintf (index, "<A HREF=\"%s\"><IMG SRC=\"index_pic.gif\" BORDER=\"0\" ALT=\"\">%s</A><BR>\n",
				 fname, cur_header->function_name);
		    }
		}
	    }

#if 0
	  fprintf (dest_doc, "</OL>\n");
#endif

	  if (index)
	    fclose(index);
	}
      break;

    case LATEX:
      fprintf (dest_doc, "%% Document: %s\n", name);
      fprintf (dest_doc, "%% Source: %s\n", src_name);
      fprintf (dest_doc, "%% " COMMENT_ROBODOC);
      fprintf (dest_doc, "%% " COMMENT_COPYRIGHT);
      if (course_of_action & DO_SINGLEDOC) {
	fprintf (dest_doc, "\\section{%s}\n", src_name);
      } else {
	fprintf (dest_doc, "\\documentclass{article}\n");
        fprintf (dest_doc, "\\usepackage{makeidx}\n");
	fprintf (dest_doc, "\\oddsidemargin  0.15 in\n");
	fprintf (dest_doc, "\\evensidemargin 0.35 in\n");
	fprintf (dest_doc, "\\marginparwidth 1 in   \n");
	fprintf (dest_doc, "\\oddsidemargin 0.25 in \n");
	fprintf (dest_doc, "\\evensidemargin 0.25 in\n");
	fprintf (dest_doc, "\\marginparwidth 0.75 in\n");
	fprintf (dest_doc, "\\textwidth 5.875 in\n");
	
	fprintf (dest_doc, "\\setlength{\\parindent}{0in}\n");
	fprintf (dest_doc, "\\setlength{\\parskip}{.08in}\n\n");
	
	/* changed default header to use boldface (vs slant) */
	fprintf (dest_doc, "\\pagestyle{headings}\n");

	if (document_title) {
	  fprintf (dest_doc, "\\title{%s}\n", 
		   document_title);
	} else {
	  fprintf (dest_doc, "\\title{API Reference}\n");
	}
	fprintf (dest_doc, "\\author{%s}\n", COMMENT_ROBODOC);
	fprintf (dest_doc, "\\makeindex\n");
	fprintf (dest_doc, "\\begin{document}\n");
	fprintf (dest_doc, "\\maketitle\n");
	/* autogenerate table of contents! */
 	fprintf (dest_doc, "\\printindex\n");
	fprintf (dest_doc, "\\tableofcontents\n");
	fprintf (dest_doc, "\\newpage\n");
	/* trick to disable the autogenerated \newpage */
	fprintf (dest_doc, "\n");
      }
      break;

    case RTF:
      {
	char *cook_link;

	/* RTF header */
	fprintf (dest_doc, "{\\rtf1\\ansi \\deff0"
		 "{\\fonttbl;"
		 "\\f0\\fswiss MS Sans Serif;"
		 "\\f1\\fmodern Courier New;"
		 "\\f2\\ftech Symbol;"
		 "}"
		 "{\\colortbl;"
		 "\\red255\\green255\\blue255;"
		 "\\red0\\green0\\blue0;"
		 "\\red0\\green0\\blue255;"
		 "}");

	/* RTF document info */
	fprintf (dest_doc, "{\\info"
		 "{\\title %s}"
		 "{\\comment\n"
		 " Source: %s\n"
		 " " COMMENT_ROBODOC
		 " " COMMENT_COPYRIGHT
		 "}"
		 "}", name, src_name);

	/* RTF document format */
	fprintf (dest_doc, "{\\margl1440\\margr1440}\n");

	/* RTF document section */
	fprintf (dest_doc, "\\f0\\cb1\\cf3\\fs28\\b1\\qc"
		 "{\\super #{\\footnote{\\super #}%s_TOC}}"
		 "{\\super ${\\footnote{\\super $}Contents}}"
		 "{TABLE OF CONTENTS}\\ql\\b0\\fs20\\cf2\\par\n", src_name);
	for (cur_header = first_header;
	     cur_header;
	     cur_header = cur_header->next_header)
	  {
	    if (cur_header->name && cur_header->function_name)
	      {
		cook_link = RB_CookStr (cur_header->function_name);
		fprintf (dest_doc, "{\\uldb %s}{\\v %s}\\line\n",
			 cur_header->name, cook_link);
		free (cook_link);
	      }
	  }
	fprintf (dest_doc, "\\par\n");
      }
      break;
    case ASCII:
      if (course_of_action & DO_TOC)
	{
	  fprintf (dest_doc, "TABLE OF CONTENTS\n");
	  for (cur_header = first_header, header_nr = 1;
	       cur_header;
	       cur_header = cur_header->next_header, header_nr++)
	    {
	      if (cur_header->name && cur_header->function_name)
		{
		  fprintf (dest_doc, "%4.4d %s\n",
			   header_nr, cur_header->name);
		}
	    }
	  fputc ('\f', dest_doc);
	}
    default:
      break;
    }
}

/***************/


/****f* ROBODoc/RB_Generate_Doc_End [3.0h]
 * NAME
 *   RB_Generate_Doc_End -- generate document trailer.
 * SYNOPSIS
 *   RB_Generate_Doc_End (dest_doc, name)
 *
 *   RB_Generate_Doc_End (FILE *, char *)
 * FUNCTION
 *   Generates for depending on the output_mode the text that
 *   will be at the end of a document.
 * INPUTS
 *   dest_doc - pointer to the file to which the output will
 *              be written.
 *   name     - the name of this file.
 *   output_mode - global variable that indicates the output
 *                 mode.
 * NOTES
 *   Doesn't do anything with its arguments, but that might
 *   change in the future.
 * BUGS
 * SOURCE
 */

void
RB_Generate_Doc_End (FILE * dest_doc, char *name)
{
  switch (output_mode)
    {
    case AMIGAGUIDE:
      fputc ('\n', dest_doc);
      break;
    case HTML:
      fprintf (dest_doc, "</BODY></HTML>\n");
      break;
    case LATEX:
      if (!(course_of_action & DO_SINGLEDOC)) { 
	fprintf (dest_doc, "\\end{document}\n");
      }
      break;
    case RTF:
      fputc ('}', dest_doc);
      break;
    case ASCII:
      break;
    }
}

/************/


/****f* ROBODoc/RB_Generate_Header_Start [3.0h]
 * NAME
 *   RB_Generate_Header_Start -- generate header start text.
 * SYNOPSIS
 *  void RB_Generate_Header_Start (dest_doc, cur_header)
 *
 *  void RB_Generate_Header_Start (FILE *, struct RB_header *)
 * FUNCTION
 *   Generates depending on the output_mode the text that
 *   will be at the end of each header.
 * INPUTS
 *   dest_doc - pointer to the file to which the output will
 *              be written.
 *   cur_header - pointer to a RB_header structure.
 * SEE ALSO
 *   RB_Generate_Header_End
 * SOURCE
 */

void
RB_Generate_Header_Start (FILE * dest_doc, struct RB_header *cur_header,
			  const char *src_name)
{
  char *cook_link;

  switch (output_mode)
    {				/* switch by *koessi */
    case AMIGAGUIDE:
      if (cur_header->name && cur_header->function_name)
	{
	  fprintf (dest_doc, "@Node \"%s\" \"%s\"\n",
		   cur_header->function_name,
		   cur_header->name);
	  fprintf (dest_doc, "%s", att_start_command[MAKE_SHINE][output_mode]);
	  fprintf (dest_doc, "%s", cur_header->name);
	  fprintf (dest_doc, "%s", att_stop_command[MAKE_SHINE][output_mode]);
	  fprintf (dest_doc, "\n\n");
	}
      break;
    case HTML:
      if (cur_header->name && cur_header->function_name)
	{
#if 0
	  fprintf (dest_doc, "<HR>\n");
#endif
	  if (cur_header->type == FUNCTION_HEADER)
	    fprintf (dest_doc, 
		     "\n<FONT SIZE=\"+2\" COLOR=\"#000055\"><B>"
		     "Function <A NAME=\"%s\">%s</A>"
		     "</FONT></B><BR><BR>\n\n",
		     cur_header->function_name,
		     cur_header->function_name);
	  else if (cur_header->type == STRUCT_HEADER)
	    fprintf (dest_doc, 
		     "\n<FONT SIZE=\"+2\" COLOR=\"#000055\"><B>"
		     "Structure <A NAME=\"%s\">%s</A>"
		     "</FONT></B><BR><BR>\n\n",
		     cur_header->function_name,
		     cur_header->function_name);
	  else if (cur_header->type == VARIABLE_HEADER)
	    fprintf (dest_doc, 
		     "\n<FONT SIZE=\"+2\" COLOR=\"#000055\"><B>"
		     "Variable <A NAME=\"%s\">%s</A>"
		     "</FONT></B><BR><BR>\n\n",
		     cur_header->function_name,
		     cur_header->function_name);
	  else if (cur_header->type == MAIN_HEADER)
	    fprintf (dest_doc, 
		     "\n<FONT SIZE=\"+2\" COLOR=\"#000055\"><B>"
		     "<A NAME=\"%s\">%s</A>"
		     "</FONT></B><BR><SMALL>Header: %s</SMALL><BR><BR>\n\n",
		     cur_header->function_name,
		     cur_header->function_name, src_name);
	  else
	    fprintf (dest_doc, 
		     "\n<FONT SIZE=\"+2\" COLOR=\"#000055\"><B>"
		     "<A NAME=\"%s\">%s</A>"
		     "</FONT></B><BR><BR>\n\n",
		     cur_header->function_name,
		     cur_header->function_name);
	}
      break;
    case LATEX:
      cook_link = RB_CookStr (cur_header->name);
      if (!(course_of_action & DO_SINGLEDOC)) {
	fprintf (dest_doc, "\\newpage\n");
      }
      fprintf (dest_doc, "\\subsection{%s}\n", cook_link);
      free (cook_link);
      if (cur_header->function_name) {
	cook_link = RB_CookStr (cur_header->function_name);
	fprintf (dest_doc, "\\index{unsorted!%s}\\index{%s!%s}\n", cook_link, 
		 RB_header_type_names[cur_header->type], cook_link);
	free (cook_link);
      }
      break;
    case RTF:
      if (cur_header->name && cur_header->function_name)
	{
	  cook_link = RB_CookStr (cur_header->function_name);
	  fprintf (dest_doc, "\\page"
		   "{\\super #{\\footnote{\\super #}%s}}"
		   "{\\super ${\\footnote{\\super $}%s}}"
		   "\\cf3 %s\\cf2\\line\n",
		   cur_header->function_name,
		   cur_header->name,
		   cur_header->name);
	  free (cook_link);
	}
      break;
    case ASCII:
      {
	fprintf (dest_doc, "%s", att_start_command[MAKE_SHINE][output_mode]);
	fprintf (dest_doc, "%s", cur_header->name);
	fprintf (dest_doc, "%s", att_stop_command[MAKE_SHINE][output_mode]);
	fprintf (dest_doc, "\n\n");
      }
      break;
    }
}

/******/


/****f* ROBODoc/RB_Generate_Header_End [3.0h]
 * NAME
 *   RB_Generate_Header_End
 * SYNOPSIS
 *   void RB_Generate_Header_End (dest_doc, cur_header)
 *
 *   void RB_Generate_Header_End (FILE *, struct RB_header *)
 * FUNCTION
 *   Generates for depending on the output_mode the text that
 *   will be at the end of a header.
 * INPUTS
 *   dest_doc - pointer to the file to which the output will
 *              be written.
 *   cur_header - pointer to a RB_header structure.
 * SEE ALSO
 *   RB_Generate_Header_Start
 * SOURCE
 */

void
RB_Generate_Header_End (FILE * dest_doc, struct RB_header *cur_header)
{
  switch (output_mode)
    {				/* switch by *koessi */
    case AMIGAGUIDE:
      if (cur_header->name && cur_header->function_name)
	fprintf (dest_doc, "@endnode\n");
      break;
    case HTML:
    case LATEX:
      fputc ('\n', dest_doc);
      break;
    case RTF:
      fprintf (dest_doc, "\\par\n");
      break;
    case ASCII:
      fputc ('\f', dest_doc);
    default:
      break;
    }
}

/*****/


/****f* ROBODoc/RB_Generate_Header_Name [3.0c]
 * NAME
 *   RB_Generate_Header_Name
 * SYNOPSIS
 *   RB_Generate_Header_Name (dest_doc, name)
 *
 *   RB_Generate_Header_Name (FILE *, char *)
 * INPUTS
 *  dest_doc - pointer to the file to which the output will
 *             be written.
 *  name - pointer to the header name.
 * SOURCE
 */

void
RB_Generate_Header_Name (FILE * dest_doc, char *name)
{
  char format_str[] = "%s";

  fprintf (dest_doc, format_str, att_start_command[MAKE_SHINE][output_mode]);
  fprintf (dest_doc, format_str, name);
  fprintf (dest_doc, format_str, att_stop_command[MAKE_SHINE][output_mode]);
  fprintf (dest_doc, "\n\n");
}

/*** RB_Generate_Header_Name ***/


/****** ROBODoc/RB_Generate_Item_Name [2.01]
 * NAME
 *   RB_Generate_Item_Name -- fast&easy
 * SYNOPSIS
 *   void RB_Generate_Item_Name( FILE * dest_doc, int item_type )
 * FUNCTION
 *   write the items name to the doc
 * INPUTS
 *   FILE * dest_doc         -- document in progress
 *   int item_type           -- this leads to the name and makes colors
 * AUTHOR
 *   Koessi
 * NOTES
 *   uses globals: output_mode, item_names[]
 * SOURCE
 */

void
RB_Generate_Item_Name (FILE * dest_doc, int item_type)
{
  char format_str[] = "%s";

  if (item_attributes[item_type] & ITEM_NAME_LARGE_FONT)
    {
      fprintf (dest_doc, format_str,
	       att_start_command[MAKE_LARGE][output_mode]);
      fprintf (dest_doc, format_str,
	       att_start_command[MAKE_BOLD][output_mode]);
      if (output_mode == HTML)
	fprintf (dest_doc, "\n<FONT COLOR=\"#000055\">");
      fprintf (dest_doc, format_str, item_names[item_type]);
      if (output_mode == HTML)
	fprintf (dest_doc, "\n</FONT>");
      fprintf (dest_doc, format_str,
	       att_stop_command[MAKE_BOLD][output_mode]);
      fprintf (dest_doc, format_str,
	       att_stop_command[MAKE_LARGE][output_mode]);
    }
  else
    fprintf (dest_doc, format_str, item_names[item_type]);

  fputc ('\n', dest_doc);
}

/*****/



/****f* ROBODoc/RB_Generate_Item_Doc [3.0j]
 * NAME
 *   RB_Generate_Item_Doc
 * SYNOPSIS
 *   void RB_Generate_Item_Doc(FILE * dest_doc, char *dest_name,
 *                             char *begin_of_item,
 *                             char *end_of_item,
 *                             char *function_name,
 *                             int item_type)
 * FUNCTION
 *   Generates the body text of an item, applying predefined attributes
 *   to the text.
 * NOTES
 *   Body text is always non-proportional for several reasons:
 *   1) text is rarely written with prop spacing and text wrapping
 *      in mind -- e.g., see SYNOPSIS above
 *   2) source code looks better
 *   3) it simplifies LaTeX handling
 * SOURCE
 */

void
RB_Generate_Item_Doc (FILE * dest_doc, char *dest_name,
		      char *begin_of_item,
		      char *end_of_item,
		      char *function_name,
		      int item_type)
{
  char format_str[] = "%s";

  if (begin_of_item == end_of_item)
    {
      switch (output_mode)
	{
	case HTML:
	  fprintf (dest_doc, "<BR>\n");
	  break;
	case LATEX:
	  fprintf (dest_doc, "\\\\\n");
	  break;
	case RTF:
	  fprintf (dest_doc, "\n");
	  break;
	default:
	  break;
	}
      return;
    }
  /* For text body in HTML, change to non-prop _before_ changing font
   * style. * To conform to DTD, this avoids <B><PRE> and instead uses
   * <PRE><B> */
  if (output_mode == HTML)
    {
      fprintf (dest_doc, "<PRE>");
    }
  /* change font style */
  if (item_attributes[item_type] & TEXT_BODY_LARGE_FONT)
    fprintf (dest_doc, format_str,
	     att_start_command[MAKE_LARGE][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_ITALICS)
    fprintf (dest_doc, format_str,
	     att_start_command[MAKE_ITALICS][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_NON_PROP)
    fprintf (dest_doc, format_str,
	     att_start_command[MAKE_NON_PROP][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_SMALL_FONT)
    fprintf (dest_doc, format_str,
	     att_start_command[MAKE_SMALL][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_BOLD)
    fprintf (dest_doc, format_str,
	     att_start_command[MAKE_BOLD][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_UNDERLINE)
    fprintf (dest_doc, format_str,
	     att_start_command[MAKE_UNDERLINE][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_SHINE)
    fprintf (dest_doc, format_str,
	     att_start_command[MAKE_SHINE][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_DEFAULT)
    fprintf (dest_doc, format_str,
	     att_start_command[MAKE_DEFAULT][output_mode]);

  /* 
   * For some modes, the text body is always non-prop
   */
  switch (output_mode)
    {
    case LATEX:
      fprintf (dest_doc, "\\begin{verbatim}\n");
      break;
    case RTF:
      fprintf (dest_doc, "{\\f1{}");
      break;
    default:
      break;
    }

  RB_Generate_Item_Body (dest_doc, dest_name, begin_of_item, end_of_item,
			 function_name, item_type, 0);

  switch (output_mode)
    {
    case LATEX:
      /* split the text so LaTeX doesn't get confused ;) */
      fprintf (dest_doc, "\\" "end{verbatim}\n");
      break;
    case RTF:
      fputc ('}', dest_doc);
    default:
      break;
    }

  /* restore font style */
  if (item_attributes[item_type] & TEXT_BODY_SHINE)
    fprintf (dest_doc, format_str,
	     att_stop_command[MAKE_SHINE][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_UNDERLINE)
    fprintf (dest_doc, format_str,
	     att_stop_command[MAKE_UNDERLINE][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_BOLD)
    fprintf (dest_doc, format_str,
	     att_stop_command[MAKE_BOLD][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_SMALL_FONT)
    fprintf (dest_doc, format_str,
	     att_stop_command[MAKE_SMALL][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_NON_PROP)
    fprintf (dest_doc, format_str,
	     att_stop_command[MAKE_NON_PROP][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_ITALICS)
    fprintf (dest_doc, format_str,
	     att_stop_command[MAKE_ITALICS][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_LARGE_FONT)
    fprintf (dest_doc, format_str,
	     att_stop_command[MAKE_LARGE][output_mode]);
  if (item_attributes[item_type] & TEXT_BODY_DEFAULT)
    fprintf (dest_doc, format_str,
	     att_stop_command[MAKE_DEFAULT][output_mode]);

  if (output_mode != HTML)
    {
      fputc ('\n', dest_doc);
    }
  /* for HTML, switch back to prop-font after restoring font style */
  if (output_mode == HTML)
    {
      fprintf (dest_doc, "</PRE>");
    }
}

/******/



/****f* ROBODoc/RB_Generate_Item_Body [3.0h]
 * NAME
 *  RB_Generate_Item_Body
 * SYNOPSIS
 *  char * RB_Generate_Item_Body(FILE * dest_doc, char *dest_name,
 *                             char *begin_of_item, char *end_of_item,
 *                             char *function_name,
 *                             int   item_type, int tabs_to_skip)
 *
 * FUNCTION
 *   Generates body of an item in output-specific form
 * INPUTS
 *   dest_doc      - pointer to the file to which
 *                   the output will be written.
 *   dest_name     - the name of this file.
 *   begin_of_item -
 *   end_of_item   -
 *   function_name -
 *   item_type     -
 *   tabs_to_skip  - how many tabs to skip in this fold.
 * BUGS
 *   o Unbalanced fold marks lead to crash.
 * NOTES
 *   o Almost completely rewritten by koessi
 *   o Almost completely Re-Rewritten by Slothouber :)
 *   o Folding mode by PetteriK.
 *   o Linking fixed inside folds / PetteriK 08.04.2000 
 * SOURCE
 */

char *
RB_Generate_Item_Body (FILE * dest_doc, char *dest_name,
		       char *begin_of_item, char *end_of_item,
		       char *function_name,
		       int item_type, int tabs_to_skip)
{
  char *cur_char, old_char, c;
  int html_incr;
  char fname[128], foldname[128];
  static int in_fold = 0;	/* PetteriK 08.04.2000 */

  cur_char = begin_of_item;

  if (item_type == SOURCE_ITEM)
    {
      /* skip end_comment_marker */
      for (; *cur_char && *cur_char != '\n'; cur_char++);

      /* skip blank lines leading up to source code */
      while (*cur_char == '\n')
	cur_char++;

      /* trim blanks following source code */
      do
	{
	  end_of_item--;
	}
      while (end_of_item > cur_char && isspace (*end_of_item));
      end_of_item++;		/* advance 1 for placement of the NUL */
    }
  old_char = *end_of_item;
  *end_of_item = '\0';

  for (; *cur_char; cur_char++)
    {
      int tb = tab_size;
      int do_search = TRUE;
      int was_link = FALSE;
      int tabs = 0;

      if (item_type != SOURCE_ITEM)
	{
          /* Skip empty lines */
          while (*cur_char == '\n') {
                cur_char++;
          }
	  cur_char = RB_Skip_Remark_Marker (cur_char);
	}
      else
	{
	  /* indent source */
	  switch (output_mode)
	    {
	    case RTF:
	      fprintf (dest_doc, "\\tab ");
	      break;

	    case AMIGAGUIDE:
	    case HTML:
	    case LATEX:
	    default:
	      fprintf (dest_doc, "    ");
	    }
	}

      while (((c = *cur_char) != '\0') && (c != '\n'))
	{
	  char *label_name, *file_name;
	  char found = 0;
	  int tmp;

	  if (!do_search)
	    {
	      if (!isalnum (c) && (c != '_'))
		{
		  do_search = TRUE;
		}
	    }
	  else
	    {
	      if (isalpha (c) || (c == '_'))
		{
		  if (((was_link = RB_Find_Link (cur_char, &label_name,
						 &file_name)) == FALSE))
		    {
		      do_search = FALSE;
		    }
		}
	      else
		was_link = FALSE;
	    }

	  if (!was_link)
	    {
	      switch (output_mode)
		{
		case AMIGAGUIDE:
		  switch (c)
		    {
		    case '\n':
		      --cur_char;
		      break;
		    case '\t':
		      for (tb %= tab_size; tb < tab_size; ++tb)
			fputc (' ', dest_doc);
		      break;
		    case '@':
		      fprintf (dest_doc, "\\@");
		      tb++;
		      break;
		    case '\\':
		      fprintf (dest_doc, "\\\\");
		      tb++;
		      break;
		    default:
		      fputc (c, dest_doc);
		      tb++;
		    }
		  break;

		case HTML:
		  /* PetteriK 26.07.1999 */
		  if (extra_flags & FOLD)
		    {
		      cur_char = RB_Check_Fold_Start (cur_char,
						      foldname, &found);
		    }
		  if ((extra_flags & FOLD) && found)
		    {
		      FILE *fp;

		      RB_Say ("fold name %s\n", foldname);
		      RB_Say ("fold begin %d\n", ++fold);
		      RB_Say ("tabs %d\n", tabs);
		      sprintf (fname, "%s_fold_%d.html", doc_base, fold);
		      RB_Say ("opening file %s\n", fname);
		      fp = fopen (fname, "w");
		      RB_Generate_Doc_Start (fp, foldname, foldname, 0);
		      fprintf (fp, "<PRE>\n");
		      fprintf (dest_doc, "<A HREF=\"%s\">... %s</A>",
			       fname, foldname);
		      in_fold++;	/* PetteriK 08.04.2000 */
		      cur_char = RB_Generate_Item_Body (fp, dest_name,
						      cur_char, end_of_item,
							function_name,
							item_type, tabs);
		      in_fold--;	/* PetteriK 08.04.2000 */
		      /* skip chars until newline */
		      while (*cur_char != '\n')
			{
			  cur_char++;
			}
		      cur_char--;
		      fprintf (fp, "\n</PRE>\n");
		      RB_Generate_Doc_End (fp, foldname);
		      fclose (fp);
		    }
		  else if ((extra_flags & FOLD) && RB_Check_Fold_End (cur_char))
		    {
		      RB_Say ("fold end found\n");
		      return cur_char;
		    }
		  else if ((html_incr = RB_HTML_Extra (dest_doc,
						       item_type, cur_char)))
		    {
		      cur_char += html_incr;
		    }
		  else
		    {
		      switch (c)
			{
			case '\n':
			  --cur_char;
			  break;
			case '\t':
			  if (extra_flags & FOLD)
			    {
			      if (tabs >= tabs_to_skip)
				{
				  for (tb %= tab_size; tb < tab_size; ++tb)
				    {
				      fputc (' ', dest_doc);
				    }
				}
			      tabs++;
			    }
			  else
			    {
			      for (tb %= tab_size; tb < tab_size; ++tb)
				{
				  fputc (' ', dest_doc);
				}
			    }
			  break;
			case '<':
			  fprintf (dest_doc, "&lt;");
			  tb++;
			  break;
			case '>':
			  fprintf (dest_doc, "&gt;");
			  tb++;
			  break;
			case '&':
			  fprintf (dest_doc, "&amp;");
			  tb++;
			  break;
			default:
			  fputc (c, dest_doc);
			  tb++;
			}
		    }
		  break;	/* end case HTML */

		case LATEX:
		  switch (c)
		    {
		    case '\n':
		      --cur_char;
		      break;
		    case '\t':
		      for (tb %= tab_size; tb < tab_size; ++tb)
			fputc (' ', dest_doc);
		      break;
#if 0
		      /* not used in LaTeX's verbatim environment */
		    case '$':
		    case '&':
		    case '%':
		    case '#':
		    case '_':
		    case '{':
		    case '}':
		      fputc ('\\', dest_doc);
		      fputc (c, dest_doc);
		      tb++;
		      break;
		    case '\\':
		      fprintf (dest_doc, "$\\backslash$");
		      tb++;
		      break;
		    case '~':
		      fprintf (dest_doc, "$\\tilde$");
		      tb++;
		      break;
		    case '^':
		      fprintf (dest_doc, "$\\,\\!^{\\sim}$");
		      tb++;
		      break;
#endif
		    default:
		      fputc (c, dest_doc);
		      tb++;
		    }
		  break;

		case RTF:
		  switch (c)
		    {
		    case '\n':
		      --cur_char;
		      break;
		    case '\t':
		      for (tb %= tab_size; tb < tab_size; ++tb)
			fputc (' ', dest_doc);
		      break;
		    case '\\':
		    case '{':
		    case '}':
		      fputc ('\\', dest_doc);
		      fputc (c, dest_doc);
		      tb++;
		      break;
		    default:
		      fputc (c, dest_doc);
		      tb++;
		    }
		  break;

		default:
		  fputc (c, dest_doc);
		  tb++;
		}
	      cur_char++;
	    }
	  else
	    {
	      switch (output_mode)
		{
		case AMIGAGUIDE:
		  if (file_name && strcmp (file_name, dest_name))
		    fprintf (dest_doc, "@{\"%s\" Link \"%s/%s\"}",
			     label_name, file_name, label_name);
		  else
		    {
		      if (strcmp (label_name, function_name))
			fprintf (dest_doc, "@{\"%s\" Link \"%s\"}",
				 label_name, label_name);
		      else
			{
			  fprintf (dest_doc, "%s",
				 att_start_command[MAKE_BOLD][output_mode]);
			  fprintf (dest_doc, "%s", label_name);
			  fprintf (dest_doc, "%s",
				   att_stop_command[MAKE_BOLD][output_mode]);
			}
		    }
		  break;

		case HTML:
		  /* Include the file name in the link if we are in fold
		   * PetteriK 08.04.2000 
		   */
		  if (in_fold)
		    {
		      /* We are in fold, always use the file name in the link, 
		       * in file_name == NULL (i.e. the label is in the current file 
		       * that we are processing), refer to value in dest_name. 
		       * This also makes sure that we link correctly if function_name
		       * is the same as label_name.
		       */
		      fprintf (dest_doc, "<A HREF=\"%s#%s\">%s</A>",
			       (file_name ? file_name : dest_name),
			       label_name, label_name);
		    }
		  else if (file_name && strcmp (file_name, dest_name))
		    {
#if 0
		      fprintf (dest_doc, "<A HREF=\"%s#%s\">%s</A>",
			       file_name, label_name, label_name);
#endif
		      fprintf (dest_doc, "<A HREF=\"%s-%s.html\">%s</A>",
			       RB_FilePartStart(file_name), label_name, 
			       label_name);
		    }
		  else
		    {
		      if (strcmp (label_name, function_name))
			{
#if 0
			  fprintf (dest_doc, "<A HREF=\"#%s\">%s</A>",
				   label_name, label_name);
#endif
			  fprintf (dest_doc, "<A HREF=\"%s-%s.html\">%s</A>",
				   RB_FilePart(doc_base), label_name, 
					       label_name);
			}
		      else
			{
			  fprintf (dest_doc, "%s",
				 att_start_command[MAKE_BOLD][output_mode]);
			  fprintf (dest_doc, "%s", label_name);
			  fprintf (dest_doc, "%s",
				   att_stop_command[MAKE_BOLD][output_mode]);
			}
		    }
		  break;

		case RTF:
		  if (strcmp (label_name, function_name))
		    {
		      char *cook_link;

		      cook_link = RB_CookStr (label_name);
		      fprintf (dest_doc, "{\\uldb %s}{\\v %s}",
			       label_name, cook_link);
		      free (cook_link);
		    }
		  else
		    {
		      fprintf (dest_doc, "%s",
			       att_start_command[MAKE_BOLD][output_mode]);
		      fprintf (dest_doc, "%s", label_name);
		      fprintf (dest_doc, "%s",
			       att_stop_command[MAKE_BOLD][output_mode]);
		    }
		  break;
		default:
		  fprintf (dest_doc, "%s", label_name);
		}
	      tmp = strlen (label_name);
	      cur_char += tmp;
	      tb += tmp;
	    }			/* end if */
	}

      if (*cur_char)
	{
	  if (output_mode == RTF)
	    fprintf (dest_doc, "\\line");
	  fputc ('\n', dest_doc);
	  tabs = 0;
	}
    }
  *end_of_item = old_char;
  return (char *) 0;
}


/***************/


/****f* ROBODoc/RB_HTML_Extra
* NAME
*   RB_HTML_Extra
* AUTHOR
*   PetteriK
* HISTORY
*   05/15/2000 Added mailto: support (Guillaume Etorre)
* FUNCTION
*   Check and process embedded hyperlinks.
* RETURN VAL* FUNCTION
*   Check and process embedded hyperlinks.
* RETURN VALUE
*   Number of chars processed from *cur_char
* TODO
*   Flag for C and other grammars.
* BUGS
*   As the documentation generated for this functions shows, if
*   the C source code contains a string with " / * " in it, this
*   function fails :)
* SOURCE
*/

int
RB_HTML_Extra (FILE * dest_doc, int item_type, char *cur_char)
{
  int res = 0;
  char link[1024];

  if (strncmp ("http://", cur_char, strlen ("http://")) == 0)
    {
      sscanf (cur_char, "%s", link);
      RB_Say ("found link %s\n", link);
      res = (strlen (link) - 1);
      fprintf (dest_doc, "<A HREF=\"%s\">%s</A>", link, link);
    }
  else if (strncmp ("href:", cur_char, strlen ("href:")) == 0)
    {
      /* handy in relative hyperlink paths, e.g. href:../../modulex/ */
      sscanf ((cur_char + strlen ("href:")), "%s", link);
      RB_Say ("found link %s\n", link);
      res = (strlen (link) + strlen ("href:") - 1);
      fprintf (dest_doc, "<A HREF=\"%s\">%s</A>", link, link);
    }
  else if (strncmp ("mailto:", cur_char, strlen ("mailto:")) == 0)
    {
      sscanf ((cur_char + strlen ("mailto:")), "%s", link);
      RB_Say ("found mail to %s\n", link);
      res = (strlen (link) + strlen ("mailto:") - 1);
      fprintf (dest_doc, "<A HREF=\"mailto:%s\">%s</A>", link, link);
    }
  else if ((extra_flags & C_MODE) && (item_type == SOURCE_ITEM) &&
	   (strncmp ("/*", cur_char, 2) == 0))
    {
      /* start of C comment */
      fprintf (dest_doc, "<FONT COLOR = \"#FF0000\">/*");
      res = 1;
    }
  else if ((extra_flags & C_MODE) && (item_type == SOURCE_ITEM) &&
	   (strncmp ("*/", cur_char, 2) == 0))
    {
      /* end of C comment */
      fprintf (dest_doc, "*/</FONT>");
      res = 1;
    }
  return res;
}

/**********/


/****f* ROBODoc/RB_Generate_Index
 * NAME
 *   RB_Generate_Index -- generate index file based on xref files.
 * SYNOPSIS
 *   void RB_Generate_Index(FILE *dest, char *name) 
 * FUNCTION
 *   Create a master index file. It contains pointers to the
 *   documentation generated for each source file, as well as all
 *   "objects" found in the source files.
 ********
 */

void
RB_Generate_Index (FILE * dest, char *source)
{
  RB_Slow_Sort_Links ();

  switch (output_mode)
    {
    case HTML:
      {
	if (document_title) {
	  RB_Generate_Doc_Start (dest, source, document_title, 0);
	  fprintf (dest, "<H1>%s</H1>\n", document_title);
	} else {
	  RB_Generate_Doc_Start (dest, source, "Master Index File", 0);
	  fprintf (dest, "<H1>Master Index File</H1>\n");
	}
	if (RB_Number_Of_Links (MAIN_HEADER, NULL))
	  RB_Generate_Index_Table (dest, MAIN_HEADER, "Project Modules");
	RB_Generate_Index_Table (dest, NO_HEADER, "Source Files");
	if (RB_Number_Of_Links (CLASS_HEADER, NULL))
	  RB_Generate_Index_Table (dest, CLASS_HEADER, "Classes");
	if (RB_Number_Of_Links (METHOD_HEADER, NULL))
	  RB_Generate_Index_Table (dest, METHOD_HEADER, "Methods");
	if (RB_Number_Of_Links (STRUCT_HEADER, NULL))
	  RB_Generate_Index_Table (dest, STRUCT_HEADER, "Structures");
	if (RB_Number_Of_Links (FUNCTION_HEADER, NULL))
	  RB_Generate_Index_Table (dest, FUNCTION_HEADER, "Functions");
	if (RB_Number_Of_Links (VARIABLE_HEADER, NULL))
	  RB_Generate_Index_Table (dest, VARIABLE_HEADER, "Variables");
	if (RB_Number_Of_Links (CONSTANT_HEADER, NULL))
	  RB_Generate_Index_Table (dest, CONSTANT_HEADER, "Constants");
	if (RB_Number_Of_Links (GENERIC_HEADER, NULL))
	  RB_Generate_Index_Table (dest, GENERIC_HEADER, "Generic");
	if (RB_Number_Of_Links (INTERNAL_HEADER, NULL))
	  RB_Generate_Index_Table (dest, INTERNAL_HEADER, "Internal");
	RB_Generate_Doc_End (dest, source);
      } break;
    case LATEX:
      {
	RB_Generate_Doc_Start (dest, source, "Master File", 0);
	RB_Generate_LaTeX_Includes (dest);
	RB_Generate_Doc_End (dest, source);
      }
    }
}


/****f* ROBODoc/Generate_LaTeX_Includes
 * NAME
 *   Generate_LaTeX_Includes -- generate include commands
 * SYNOPSIS
 *   void RB_Generate_LaTeX_Includes (FILE *dest)
 * FUNCTION
 *   Generates a series of \include commands to include the
 *   documentation generated for each source file into one
 *   big file.
 ****
 */

void
RB_Generate_LaTeX_Includes (FILE *dest)
{
  struct RB_link *cur_link;
  for (cur_link = first_link;
       cur_link;
       cur_link = cur_link->next_link) {
    {
      if (cur_link->type == NO_HEADER)
	fprintf (dest, "\\include{%s}\n", cur_link->label_name);
    }
  }
}

/****f* ROBODoc/RB_Generate_Index_Table
 * NAME
 *   RB_Generate_Index --
 * SYNOPSIS
 *   void RB_Generate_Index_Table(FILE *, int type, char *title)
 *        RB_Generate_Index_Table(dest, type, title)
 * FUNCTION
 *   Creates a table with index items of a particular type.
 *   If the type is NO_HEADER, then the table is a table of
 *   source files. In this case no link is added if the
 *   source file did not contain any documentation.  
 * INPUTS
 *   dest  -- output file
 *   type  -- kind of header index. 
 *   title -- title for the table
 * SOURCE
 */

void
RB_Generate_Index_Table (FILE * dest, int type, char *title)
{
  struct RB_link *cur_link;
  int number_of_columns;
  int cur_column;

  number_of_columns = 60 / RB_Max_Name_Length (type, NULL);

  fprintf (dest, "<H2>%s</H2>\n", title);
  fprintf (dest, "<TABLE>\n");
  cur_column = 0;
  for (cur_link = first_link;
       cur_link;
       cur_link = cur_link->next_link)
    {
      if (cur_link->type == type)
	{
	  if (cur_column == 0)
	    {
	      fprintf (dest, "<TR>\n");
	    }
	  if (type == NO_HEADER)
	    {
	      if (RB_Number_Of_Links (NO_HEADER, cur_link->file_name) > 1)
		{
		  fprintf (dest,
			   "<TD><A HREF=\"%s#%s\"><TT>%s</TT></A></TD>\n",
			   cur_link->file_name, cur_link->label_name,
			   cur_link->label_name);
		}
	      else
		{
		  fprintf (dest, "<TD>%s</TD>\n", cur_link->label_name);
		}
	    }
	  else
	    {
	      fprintf (dest, "<TD><A HREF=\"%s#%s\"><TT>%s</TT></A></TD>\n",
		       cur_link->file_name, cur_link->label_name,
		       cur_link->label_name);
	    };
	  cur_column++;
	  if (cur_column > number_of_columns)
	    {
	      fprintf (dest, "</TR>\n");
	      cur_column = 0;
	    }
	}
    }
  for (; cur_column <= number_of_columns;)
    {
      if (cur_column == 0)
	{
	  fprintf (dest, "<TR>\n");
	}
      fprintf (dest, "<TD></TD>\n");
      cur_column++;
    }
  fprintf (dest, "</TR>\n");
  fprintf (dest, "</TABLE>\n");
}

/******* END RB_Generate_Index_Table  *****/


/****f* ROBODoc/RB_Number_Of_Links
 * NAME
 *   RB_Number_Of_Links -- Count the number of links.
 * FUNCTION
 *   Counts the number of links that are of a particular type
 *   and that can be found in a particular file.
 * INPUTS
 *   type      -- the header type of the header the link is pointing to.
 *                If NO_HEADER, all header types are counted.
 *   file_name -- name of the file the link comes from, can be NULL, in
 *                which case only the type is checked.
 * RESULT
 *   number of links.
 ******
 */

int
RB_Number_Of_Links (int type, char *file_name)
{
  struct RB_link *cur_link;
  int n = 0;

  for (cur_link = first_link;
       cur_link;
       cur_link = cur_link->next_link)
    {
      if (cur_link->type == type || (type == NO_HEADER))
	{
	  if (file_name)
	    {
	      if (strcmp (file_name, cur_link->file_name) == 0)
		{
		  n++;
		}
	    }
	  else
	    {
	      n++;
	    }
	}
    }

  return n;
}


/****f* ROBODoc/RB_Max_Name_Length
 * NAME
 *   RB_Max_Name_Length -- find longest label name.
 * FUNCTION
 *   Find the length of the longest label name in a sub list
 *   of the list with links.  This is used to determine how
 *   many columns can be displayed in a table.
 *   The sublist is specified by the type of header the link
 *   should point to, as well as by the name of the documentation 
 *   file.
 * EXAMPLE
 *     RB_Max_Name_Length(CLASS_HEADER, "muppets.c.html")
 *   longest label name in the list of links to class headers 
 *   in muppets.c.html.
 *     RB_Max_Name_Length(CLASS_HEADER, NULL)
 *   longest label name in the list of links to class headers.
 * INPUTS
 *   type      -- type of header
 *   file_name -- file the header come from, can be NULL.
 *                In which links from all files are used.
 * SOURCE
 */

int
RB_Max_Name_Length (int type, char *file_name)
{
  struct RB_link *cur_link;
  int n = 1;

  for (cur_link = first_link;
       cur_link;
       cur_link = cur_link->next_link)
    {
      if (cur_link->type == type)
	{
	  if (file_name)
	    {
	      if (strcmp (file_name, cur_link->file_name) == 0)
		{
		  if (strlen (cur_link->label_name) > n)
		    {
		      n = strlen (cur_link->label_name);
		    }
		}
	    }
	  else
	    {
	      if (strlen (cur_link->label_name) > n)
		{
		  n = strlen (cur_link->label_name);
		}
	    }
	}
    }
  return n;
}

/*********/
