#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "robodoc.h"
#include "headers.h"
#include "util.h"
#include "links.h"
#include "folds.h"


FILE *xreffiles_file = NULL;
FILE *xref_file = NULL;
int link_index_size = 0;
struct RB_link **link_index = NULL;

/****f* ROBODoc/RB_Analyse_Xrefs [3.0b]
 * NAME
 *   RB_Analyse_Xrefs -- scan the xref files.
 * SYNOPSIS
 *   RB_Analyse_Xrefs (xreffiles_file)
 *   RB_Analyse_Xrefs (FILE *)
 * FUNCTION
 *   Scan the file xreffiles_file. This file contains the
 *   names of one or more xref files. All the references in the
 *   files are scaned and stored in a link list of the type
 *   RB_link. These xref files can be generated with robodoc.
 * INPUTS
 *   xreffiles_file - a file pointer to the file with xref file
 *   names.
 * RESULT
 *   none
 * BUGS
 *   Might fail if there are syntax errors in one of the xref
 *   files.
 *   Bad use of feof() and fgets().
 * SEE ALSO
 *   RB_Generate_xrefs, RB_Add_Link
 * SOURCE
 */

void
RB_Analyse_Xrefs (FILE * xreffiles_file)
{
  while (!feof (xreffiles_file))
    {
      fgets (line_buffer, MAX_LINE_LEN, xreffiles_file);
      if (!feof (xreffiles_file))
	{
	  char *cur_char;

	  cur_char = line_buffer;
	  find_eol;
	  if (*cur_char == '\n')
	    *cur_char = '\0';
	  if (strlen (line_buffer) > 1)
	    {
	      for (cur_char--;
		   (cur_char != line_buffer) && isspace (*cur_char);
		   cur_char--)
		*cur_char = '\0';
	      if ((xref_file = fopen (line_buffer, "r")) != NULL)
		{
		  int xrefs_found = FALSE;
		  int end_of_xrefs = FALSE;

		  while (!feof (xref_file) && !xrefs_found)
		    {
		      fgets (line_buffer, MAX_LINE_LEN, xref_file);
		      if (!feof (xref_file) && !strncmp ("XREF:",
							 line_buffer, 5))
			xrefs_found = TRUE;
		    }

		  while (!feof (xref_file) && !end_of_xrefs)
		    {
		      fgets (line_buffer, MAX_LINE_LEN, xref_file);
		      if (!feof (xref_file))
			{
			  cur_char = line_buffer;
			  find_quote;
			  if (*cur_char == '\"')
			    RB_Add_Link ();
			  else
			    end_of_xrefs = TRUE;
			}
		    }
		  fclose (xref_file);
		  xref_file = NULL;
		}
	      else
		RB_Panic ("could not open xref file \"%s\"\n", line_buffer);
	    }
	}
    }
}

/*************/


/****f* ROBODoc/RB_Slow_Sort_Links
 * NAME
 *   RB_Slow_Sort_Links -- sort all links according to label name.
 ******
 */

void
RB_Slow_Sort_Links (void)
{
  struct RB_link *cur_link, *unsorted_links, *bigger_link;

  if ((unsorted_links = first_link) != NULL)
    {				/* additional check koessi */
      for (first_link = NULL;
	   unsorted_links->next_link;)
	{
	  for (bigger_link = unsorted_links,
	       cur_link = bigger_link->next_link;
	       cur_link;
	       cur_link = cur_link->next_link)
	    {
	      if (strcmp (cur_link->label_name, bigger_link->label_name) > 0)
		bigger_link = cur_link;
	    }
	  RB_Remove_From_List ((struct RB_header **) &unsorted_links,
			       (struct RB_header *) bigger_link);
	  RB_Insert_In_List ((struct RB_header **) &first_link,
			     (struct RB_header *) bigger_link);
	}
      RB_Insert_In_List ((struct RB_header **) &first_link,
			 (struct RB_header *) unsorted_links);
    }
}


/****f* ROBODoc/RB_Add_Link [3.0b]
 * NAME
 *   RB_Add_Link -- add a reference link to the list
 * SYNOPSIS
 *   void RB_Add_Link ()
 * FUNCTION
 *   Adds a reference from a xref file to the linked list
 *   with references.
 * INPUTS
 *   Uses the global variable line_buffer and first_link.
 * NOTES
 *   Makes sneaky use of the function RB_Insert_In_List.
 * SEE ALSO
 *   RB_Analyse_Xrefs, RB_link.
 * SOURCE
 */

void
RB_Add_Link ()
{
  char *label_name, *file_name;
  struct RB_link *new_link;
  char *cur_char = line_buffer;

  find_quote;
  label_name = ++cur_char;
  find_quote;
  *cur_char++ = '\0';
  find_quote;
  file_name = ++cur_char;
  find_quote;
  *cur_char = '\0';
  ++cur_char;

  RB_Say ("adding xref link \"%s\"->\"%s\"\n", label_name, file_name);

  new_link = RB_Alloc_Link (label_name, file_name);
  new_link->type = atoi (cur_char);
  RB_Insert_In_List ((struct RB_header **) &first_link,
		     (struct RB_header *) new_link);
}

/*** RB_Add_Link ***/



/****f* ROBODoc/RB_Generate_xrefs [2.0]
 * NAME
 *   RB_Generate_xrefs
 * SYNOPSIS
 *   RB_Generate_xrefs (dest_doc, source_name, dest_name)
 *
 *   RB_Generate_xrefs (FILE *, char *, char *)
 * FUNCTION
 *   Generates a xref file for the document that has been
 *   analysed by ROBODoc.
 * INPUTS
 *   dest_doc    - pointer to the file to which the xrefs will be
 *                 written.
 *   source_name - pointer to the name of the document that has
 *                 been analysed by robodoc
 *   dest_name   - pointer to the name of the document robodoc will
 *                 write the documentation to.
 *   first_header - global variable, the list with function
 *                 headers.
 * SOURCE
 */

void
RB_Generate_xrefs (FILE * dest_doc, char *source_name, char *dest_name)
{
  struct RB_header *cur_header;

  fprintf (dest_doc, "/* XREF-File generated by ROBODoc v" VERSION
	   " */\n");
  fprintf (dest_doc, "\nXREF:\n");
  fprintf (dest_doc, " \"%s\" \"%s\" 0\n", source_name, dest_name);
  for (cur_header = first_header;
       cur_header;
       cur_header = cur_header->next_header
    )
    {
      if (cur_header->function_name)
	fprintf (dest_doc, " \"%s\" \"%s\" %d\n",
		 cur_header->function_name, dest_name, cur_header->type);
    }
  fprintf (dest_doc, "\n/* End of XREF-File */\n");
}

/*** RB_Generate_xrefs ***/



/****f* ROBODoc/RB_Find_Link [3.0h]
 * NAME
 *   RB_Find_Link -- try to match word with a link
 * SYNOPSIS
 *   result = RB_Find_Link (word_begin, label_name, file_name)
 *   int      RB_Find_Link (char *,     char **,    char **)
 * FUNCTION
 *   Searches for the given word in the list of links and
 *   headers.  There are three passes (or four, when the C option
 *   is selected). Each pass uses a different definition of "word".
 *   In the first pass it is any thing that ends with a 'space', a '.' 
 *   or a ','.
 *   In the second pass it is any string that consists of alpha
 *   numerics, '_', ':', '.', or '-'.  
 *   In the third pass (for C) it is any string that consists 
 *   of alpha numerics or '_'.
 *   In the last pass it is any string that consists of alpha
 *   numerics.
 * INPUTS
 *   word_begin  - pointer to a word (a string).
 *   label_name  - pointer to a pointer to a string
 *   file_name   - pointer to a pointer to a string
 * SIDE EFFECTS
 *   label_name & file_name are modified
 * RESULT
 *   label_name    -- points to the label if a match was found,
 *                    NULL otherwise.
 *   file_name     -- points to the file name if a match was found,
 *                    NULL otherwise.
 *   TRUE          -- a match was found.
 *   FALSE         -- no match was found.
 * NOTES
 *   This is a rather sensitive algorithm.
 * BUGS
 ******
 */

int
RB_Find_Link (char *word_begin, char **label_name, char **file_name)
{
  char *cur_char, old_char;
  int low_index, high_index, cur_index, state, pass;


  for (pass = 0; pass < 4; pass++)
    {

      switch (pass)
	{
	case 0:
	  {
	    for (cur_char = word_begin;
		 isalnum (*cur_char) || ispunct (*cur_char);
		 cur_char++);
	    if (((*(cur_char-1)) == ',') || ((*(cur_char-1)) == '.')) 
	      cur_char--;
	    break;
	  }
	case 1:
	  {
	    for (cur_char = word_begin;
		 isalnum (*cur_char) || (*cur_char == '_') ||
		 (*cur_char == '-') || (*cur_char == '.') ||
		 (*cur_char == ':');
		 cur_char++);
	    break;
	  }
	case 2:
	  {
	    if (extra_flags & C_MODE) {
          for (cur_char = word_begin;
		   isalnum(*cur_char) || (*cur_char  == '_');
		   cur_char++);
	      break;
		}
	    else continue;
	  }
	case 3:
	  {
	    for (cur_char = word_begin;
		 isalnum (*cur_char);
		 cur_char++);
	    break;
	  }
	}

      old_char = *cur_char;
      *cur_char = '\0';		/* End the word with a '\0' */
/*      RB_Say ("Testing \"%s\"\n", word_begin); */

      /* Search in header table */
      for (cur_index = 0, low_index = 0, high_index = header_index_size - 1;
	   high_index >= low_index;)
	{
	  cur_index = (high_index - low_index) / 2 + low_index;
	  state = strcmp (word_begin, header_index[cur_index]->function_name);
	  if (state < 0)
	    high_index = cur_index - 1;
	  else if (state > 0)
	    low_index = cur_index + 1;
	  else
	    {
	      *label_name = header_index[cur_index]->function_name;
	      *file_name = NULL;
              RB_Say ("linking \"%s\"->\"%s\"\n", word_begin, *label_name);
	      *cur_char = old_char;
	      return (TRUE);
	    }
	}

      /* Search in the link table */
      for (cur_index = 0, low_index = 0, high_index = link_index_size - 1;
	   high_index >= low_index;)
	{
	  cur_index = (high_index - low_index) / 2 + low_index;
	  state = strcmp (word_begin, link_index[cur_index]->label_name);
	  if (state < 0)
	    {
	      high_index = cur_index - 1;
	    }
	  else if (state == 0)
	    {
	      *label_name = link_index[cur_index]->label_name;
	      *file_name = link_index[cur_index]->file_name;
              RB_Say ("linking \"%s\"->\"%s\" form \"%s\"\n",
                              word_begin, *label_name, *file_name);
	      *cur_char = old_char;
	      return (TRUE);
	    }
	  else if (state > 0)
	    {
	      low_index = cur_index + 1;
	    }
	}
      *cur_char = old_char;
      *file_name = NULL;
      *label_name = NULL;
    }

  return (FALSE);
}





/****f* ROBODoc/RB_Alloc_Link [2.01]
 * NAME
 *   RB_Alloc_Link              -- oop
 * SYNOPSIS
 *   struct RB_link *RB_Alloc_Link( char *label_name, char *file_name )
 * FUNCTION
 *   allocate struct + strings
 * INPUTS
 *   char *label_name -- strings to copy into the link
 *   char *file_name
 * RESULT
 *   struct RB_link *  -- ready-to-use
 * AUTHOR
 *   Koessi
 * SEE ALSO
 *   RB_StrDup(), RB_Free_Link()
 *******
 */

struct RB_link *
RB_Alloc_Link (char *label_name, char *file_name)
{
  struct RB_link *new_link;
  if ((new_link = malloc (sizeof (struct RB_link))) != NULL)
    {
      memset (new_link, 0, sizeof (struct RB_link));

      if (file_name)
	new_link->file_name = RB_StrDup (file_name);
      if (label_name)
	new_link->label_name = RB_StrDup (label_name);
    }
  else
    RB_Panic ("out of memory! [Alloc Link]\n");

  return (new_link);
}


/****f* ROBODoc/RB_Free_Link [2.01]
 * NAME
 *   RB_Free_Link               -- oop
 * SYNOPSIS
 *   void RB_Free_Link( struct RB_link *link )
 * FUNCTION
 *   free struct + strings
 * INPUTS
 *   struct RB_link *link
 * AUTHOR
 *   Koessi
 * SEE ALSO
 *   RB_Alloc_Link(), RB_Close_The_Shop()
 * SOURCE
 ******
 */

void
RB_Free_Link (struct RB_link *link)
{
  if (link)
    {
      if (link->label_name)
	free (link->label_name);
      if (link->file_name)
	free (link->file_name);
      free (link);
    }
}
