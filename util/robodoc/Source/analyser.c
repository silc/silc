#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "robodoc.h"
#include "headers.h"
#include "items.h"
#include "util.h"
#include "folds.h"
#include "links.h"
#include "analyser.h"


/****** ROBODoc/RB_Analyse_Document [3.0i]
 * NAME
 *   RB_Analyse_Document -- scan document for headers and store them
 * SYNOPSIS
 *   RB_Analyse_Document (document)
 *   RB_Analyse_Document (FILE *)
 * FUNCTION
 *   Searches the document for headers. Stores information about
 *   any headers that are found in a linked list. Information
 *   that is stored includes, the name of the header, its version
 *   number, and its contents.
 * INPUTS
 *   document - a pointer to a file with the document to be
 *              analysed
 *   the gobal buffer line_buffer.
 * RESULT
 *   1)   A linked list pointed to by the global variable
 *        first_header that contains information about each
 *        header.
 * NOTES
 *   Using fseek and ftell because gcc doesn't know fgetpos and fsetpos,
 *   on the sun unix system that I use.
 * SEE ALSO
 *   RB_Find_Marker
 * SOURCE
 */

void
RB_Analyse_Document (FILE * document)
{
  int header_type;
  int real_size;
  char *name;

  for (;
       (header_type = RB_Find_Marker (document)) != NO_HEADER;
       )
    {
      struct RB_header *new_header;
      
      if (!
	  (
	   ((header_type == INTERNAL_HEADER) &&
	    !(course_of_action & (DO_INCLUDE_INTERNAL | DO_INTERNAL_ONLY)))
	   ||
	   ((header_type != INTERNAL_HEADER) &&
	    (course_of_action & DO_INTERNAL_ONLY))
	   ||
	   (header_type == BLANK_HEADER)
	   )
	  )
	{
	  long cur_file_pos;
	  
	  new_header = RB_Alloc_Header ();
	  RB_Insert_In_List (&first_header, new_header);
	  new_header->type = header_type;
	  if ((new_header->name = RB_Find_Header_Name ()) != NULL)
	    {
	      RB_Say ("found header [line %5d]: \"%s\"\n",
		      line_number, new_header->name);
	      if ((new_header->function_name
		   = RB_Function_Name (new_header->name)) == NULL)
		{
		  RB_Panic ("Can't determine the \"function\" name.\n");
		}
	      cur_file_pos = (long) ftell (document);
	      if ((real_size = RB_Find_End_Marker (document,
						   &new_header->size))
		  != 0)
		{
		  char *contents;
		  
		  fseek (document, cur_file_pos, 0);
		  if ((contents = malloc ((new_header->size +
					   2) * sizeof (char)))
		      != NULL)
		    {
		      fread (contents, new_header->size, sizeof (char), document);
		      
		      contents[real_size] = '\0';
		      new_header->contents = contents;
		      new_header->size = real_size;
		    }
		  else
		    RB_Panic ("out of memory! [Alloc Header Contents]\n");
		}
	      else
		{
		  RB_Panic ("found header with no end marker \"%s\"\n",
			    new_header->name);
		}
	    }
	  else
	    {
	      RB_Panic ("found header marker but no name [line %d]\n",
			line_number);
	    }
	}
      else
	{
	  if (header_type != BLANK_HEADER)
	    {
	      if ((name = RB_Find_Header_Name ()) != NULL)
		{
		  new_header = RB_Alloc_Header ();
		  if ((real_size =
		       RB_Find_End_Marker (document, &new_header->size))
		      == 0)
		    {
		      RB_Free_Header (new_header);
		      RB_Panic ("found header with no end marker \"%s\"\n", name);
		    }
		  else
		    {
		      RB_Free_Header (new_header);
		    }
		}
	      else
		{
		  RB_Panic ("found header marker but no name [line %d]\n",
			    line_number);
		}
	    }
	}
    }
}

/****** END RB_Analyse_Document *******/




/****f* ROBODoc/RB_Function_Name [2.0x]
 * NAME
 *   RB_Function_Name -- get pointer to the function name.
 * SYNOPSIS
 *   char *RB_NamePart(char *header_name)
 * FUNCTION
 *   A header name is consists of two parts. The module name and
 *   the function name. This returns a pointer to the function name.
 *   The name "function name" is a bit obsolete. It is really the name
 *   of any of objects that can be documented; classes, methods,
 *   variables, functions, projects, etc.
 * SOURCE
 */

char *
RB_Function_Name (char *header_name)
{
  char *cur_char;
  char c;
  char *name;

  name = NULL;
  if ((cur_char = header_name) != NULL)
    {
      for (; (c = *cur_char) != '\0'; ++cur_char)
	{
	  if ('/' == *cur_char)
	    {
	      ++cur_char;
	      if (*cur_char)
		name = cur_char;
	    }
	}
    }
  if (name) {
     char *temp;
     temp = malloc((strlen(name) + 1) * sizeof(char));
     strcpy(temp, name);
     return temp; 
  } else {
     return (name);
  }
}

/*** RB_Name_Part ***/



/****** ROBODoc/RB_Find_Marker [3.0h]
 * NAME
 *   RB_Find_Marker -- Search for header marker in document.
 * SYNOPSIS
 *   header_type = RB_Find_Marker (document)
 *             int RB_Find_Marker (FILE *)
 * FUNCTION
 *   Read document file line by line, and search each line for the
 *   any of the headers defined in the array  header_markers
 * INPUTS
 *   document - pointer to the file to be searched.
 *   the gobal buffer line_buffer.
 * RESULT
 *   header type
 *   can be:
 *    (1) NO_HEADER - no header found, end of file reached
 *    (2) MAIN_HEADER
 *    (3) GENERIC_HEADER
 *    (4) INTERNAL_HEADER
 * BUGS
 *   Bad use of feof(), fgets().
 * SEE ALSO
 *   RB_Find_End_Marker
 * SOURCE
 */

int
RB_Find_Marker (FILE * document)
{
  int found;
  int marker, marker_type;
  char *cur_char, *cur_mchar;

  marker_type = NO_HEADER;
  cur_char = NULL;
  found = FALSE;
  while (!feof (document) && !found)
    {
      *line_buffer = '\0';
      fgets (line_buffer, MAX_LINE_LEN, document);
      if (!feof (document))
	{
	  line_number++;
	  for (marker = 0;
	       ((cur_mchar = header_markers[marker]) != NULL) && !found;
	       marker++)
	    {
	      for (found = TRUE, cur_char = line_buffer;
		   *cur_mchar && *cur_char && found;
		   cur_mchar++, cur_char++)
		{
		  if (tolower(*cur_mchar) != tolower(*cur_char))
		    found = FALSE;
		}
	    }
	  if (found)
	    {
	      switch (*cur_char)
		{
		case 'h':
		  marker_type = MAIN_HEADER;
		  break;
		case '*':
		  marker_type = GENERIC_HEADER;
		  break;
		case 'i':
		  marker_type = INTERNAL_HEADER;
		  break;
		case 'f':
		  marker_type = FUNCTION_HEADER;
		  break;
		case 's':
		  marker_type = STRUCT_HEADER;
		  break;
		case 'c':
		  marker_type = CLASS_HEADER;
		  break;
		case 'm':
		  marker_type = METHOD_HEADER;
		  break;
		case 'd':
		  marker_type = CONSTANT_HEADER;
		  break;
		case 'v':
		  marker_type = VARIABLE_HEADER;
		  break;
		default:
		  RB_Say ("%s: WARNING, [line %d] undefined headertype,"
			  " using GENERIC\n", whoami, line_number);
		  marker_type = GENERIC_HEADER;
		}
	    }
	}
    }
  if (!found || feof (document))
    {
      marker_type = NO_HEADER;
    }
  else if (marker_type == GENERIC_HEADER)
    {
      skip_while (*cur_char == '*');
      if (*cur_char == '/')
	{
	  marker_type = BLANK_HEADER;
	}
    }
  return marker_type;
}

/******** END RB_Find_Marker ******/


/****** ROBODoc/RB_Find_End_Marker [3.0h]
 * NAME
 *   RB_Find_End_Marker -- Search for end marker in document.
 * SYNOPSIS
 *   result = RB_Find_End_Marker (document)
 *        int RB_Find_End_Marker (FILE *)
 * FUNCTION
 *   Searches line by line till any of the markers in the
 *   array: end_markers is found.
 * INPUTS
 *   document   - pointer to the file to be searched.
 *   int *total_size - external size
 *   the gobal buffer line_buffer.
 * RESULT
 *                real_size if end marker was found
 *   0          - no end marker was found
 * SEE ALSO
 *   RB_Find_Marker
 * SOURCE
 */

int
RB_Find_End_Marker (FILE * document, int *total_size)
{
  int real_size = 0;
  int found = FALSE;
  int marker;
  int line_len = 0;
  char *cur_char, *cur_mchar;

  while (!feof (document) && !found)
    {
      cur_char = line_buffer;
      *cur_char = '\0';
      fgets (cur_char, MAX_LINE_LEN, document);
      ++line_number;		/* global linecounter *koessi */

      line_len = strlen (cur_char);
      real_size += line_len;

      if (!feof (document))
	{
	  for (marker = 0;
	       ((cur_mchar = end_markers[marker]) != NULL) && !found;
	       marker++)
	    {
	      for (found = TRUE, cur_char = line_buffer;
		   *cur_mchar && *cur_char && found;
		   cur_mchar++, cur_char++)
		{
		  if (tolower(*cur_mchar) != tolower(*cur_char))
		    found = FALSE;
		}
	    }
	}
    }
  if (total_size)
    *total_size = real_size;
  if (found)
    return real_size - line_len;
  else
    return 0;
}

/*****  RB_Find_End_Marker   *****/


/****** ROBODoc/RB_Find_Header_Name   [3.0b]
 * NAME
 *   RB_Find_Header_Name -- search for header name
 * SYNOPSIS
 *   result = RB_Find_Header_Name ()
 *      char *RB_Find_Header_Name ()
 * FUNCTION
 *   Searches the line buffer for the header name.
 *   It assumes that the header name follows after the
 *   header marker, seperated by one or more spaces, and terminated
 *   by one or more spaces or a '\n'.
 *   It allocates an array of chars and copies the name to this array.
 * INPUTS
 *   the gobal buffer line_buffer.
 * RESULT
 *   pointer to the allocated array of chars that contains the name,
 *   terminated with a '\0'.
 *   NULL if no header name was found.
 * MODIFICATION HISTORY
 *   8. August 1995      --  optimized by koessi
 * SEE ALSO
 *   RB_Find_Function_Name(), RB_WordLen(), RB_StrDup()
 * SOURCE
 */

char *
RB_Find_Header_Name (void)
{
  char *cur_char;

  cur_char = line_buffer;
  skip_while (*cur_char != '*');
  skip_while (!isspace (*cur_char));
  skip_while (isspace (*cur_char));
  if (*cur_char)
    {
      char *end_char, old_char;

      end_char = cur_char + RB_WordLen (cur_char);
      old_char = *end_char;
      *end_char = '\0';
      cur_char = RB_StrDup (cur_char);
      *end_char = old_char;
      return (cur_char);
    }
  return (NULL);
}

/*****  RB_Find_Header_Name  *****/


/****** ROBODoc/RB_Find_Item [3.0b]
 * NAME
 *   RB_Find_Item -- find item in header contents.
 * SYNOPSIS
 *   item_type = RB_Find_Item (next_line,item_line)
 *
 *           int RB_Find_Item (char **,  char **)
 * FUNCTION
 *   Searches the header contents line by line, looking
 *   for an item Indicator.
 * INPUTS
 *   next_line  - pointer to a pointer that points to line
 *                at which the search will start.
 * SIDE-EFFECTS
 *   next_line  - pointer to a pointer that points to begin of the line
 *                after the line the item was found on.
 *   item_line  - pointer to a pointer that points to the line the item
 *                was found on.
 * RESULT
 *   item_type  - one of possible items indicators.
 * SOURCE
 */

int
RB_Find_Item (char **next_line, char **item_line)
{
  char *cur_char = *next_line;
  int item_type;

  for (item_type = NO_ITEM;
       *cur_char && (item_type == NO_ITEM);
    )
    {
      *item_line = cur_char;
      cur_char = RB_Skip_Remark_Marker (cur_char);

      skip_while (isspace (*cur_char) && *cur_char != '\n');
      if (isupper (*cur_char))
	{
	  char *item_begin = cur_char;
	  char *item_end;

	  skip_while (isupper (*cur_char));
	  item_end = cur_char;
	  if (isspace (*cur_char) && *cur_char)
	    {
	      skip_while (isspace (*cur_char) && *cur_char != '\n');

	      /* Item consists of two words ? */
	      if (isupper (*cur_char) && *cur_char)
		{
		  skip_while (isupper (*cur_char));
		  item_end = cur_char;
		  skip_while (isspace (*cur_char) && *cur_char != '\n');
		}
	      if (*cur_char == '\n')
		{
		  char old_char = *item_end;

		  *item_end = '\0';
		  item_type = RB_Get_Item_Type (item_begin);
		  *item_end = old_char;
		  cur_char++;
		}
	    }
	}
      if (item_type == NO_ITEM)
	{
	  find_eol;
	  if (*cur_char)
	    cur_char++;
	}
    }

  /* advance item_line to end of comment block when we have no more items */
  if (item_type == NO_ITEM)
    {
      *item_line = cur_char;
    }
  *next_line = cur_char;
  return item_type;
}

/*****  RB_Find_Item    *****/


/****** ROBODoc/RRB_Number_Duplicate_Headers 
 * NAME
 *    RB_Number_Duplicate_Headers -- number duplicate headers
 * SYNOPSIS
 *    RB_Number_Duplicate_Headers (void)
 * FUNCTION
 *    Extends the function name with an additional number if there 
 *    are several components with the same name.
 *    Otherwise there will be labels with the same name in HTML
 *    which confuses the browser.
 * SOURCE
 */

void 
RB_Number_Duplicate_Headers (void)
{
  struct RB_header *cur_header;
  struct RB_header *dup_header;
  for (cur_header = first_header; 
       cur_header;
       cur_header = cur_header->next_header)
  {  
    char number[20];
    int  nr = 0;
    for (dup_header = cur_header->next_header; 
         dup_header;
         dup_header = dup_header->next_header)
    {
       if (strcmp(cur_header->function_name,
                  dup_header->function_name) == 0) {
          char *new_name;
          nr++;
          sprintf(number, "(%d)", nr);
          new_name = malloc ((strlen(number) + 1 + 
              strlen(dup_header->function_name) + 1 ) * sizeof(char));
          if (new_name == NULL) 
             RB_Panic ("out of memory! [Number Duplicates]\n");
          sprintf(new_name, "%s%s", dup_header->function_name,
                  number);
          free(dup_header->function_name);
          dup_header->function_name = new_name;
       }
    }
  }
}

/******/


/****** ROBODoc/RB_Make_Index_Tables [3.0b]
 * NAME
 *    RB_Make_Index_Tables
 * SYNOPSIS
 *    void RB_Make_Index_Tables (void)
 * FUNCTION
 *    Creates sorted index tables of headers and links to speed up
 *    matching links later on.
 * INPUTS
 *    none
 * SIDE EFFECTS
 *    Modifies header_index & link_index
 * RESULT
 *    none
 * SOURCE
 */

void
RB_Make_Index_Tables ()
{
  int nr_of_headers, header;
  int nr_of_links, link;
  struct RB_link *cur_link;
  struct RB_header *cur_header;

  for (cur_header = first_header, nr_of_headers = 0;
       cur_header;
       cur_header = cur_header->next_header)
    nr_of_headers++;

  for (cur_link = first_link, nr_of_links = 0;
       cur_link;
       cur_link = cur_link->next_link)
    nr_of_links++;

  if (nr_of_headers)
    {
      int sort1, sort2;

      RB_Say ("Allocating Header Index Table\n");
      header_index = malloc (nr_of_headers * sizeof (struct RB_header **));

      header_index_size = nr_of_headers;
      if (!header_index)
	RB_Panic ("out of memory! [Make Index Tables]\n");

      /* Fill Index Table */
      for (cur_header = first_header, header = 0;
	   cur_header;
	   cur_header = cur_header->next_header, header++)
	header_index[header] = cur_header;

      /* Sort Index Table */
      RB_Say ("Sorting Header Index Table\n");
      for (sort1 = 0; sort1 < nr_of_headers; sort1++)
	{
	  struct RB_header *temp;

	  for (sort2 = sort1; sort2 < nr_of_headers; sort2++)
	    {
	      if (strcmp (header_index[sort1]->function_name,
			  header_index[sort2]->function_name) > 0)
		{
		  temp = header_index[sort1];
		  header_index[sort1] = header_index[sort2];
		  header_index[sort2] = temp;
		}
	    }
	}
    }
  if (nr_of_links)
    {
      int sort1, sort2;

      RB_Say ("Allocating Link Index Table\n");
      link_index = malloc (nr_of_links * sizeof (struct RB_link **));

      link_index_size = nr_of_links;
      if (!link_index)
	RB_Panic ("out of memory! [Make Index Tables]\n");

      /* Fill Index Table */
      for (cur_link = first_link, link = 0;
	   cur_link;
	   cur_link = cur_link->next_link, link++)
	{
	  link_index[link] = cur_link;
	}

      /* Sort Index Table */
      RB_Say ("Sorting Link Index Table\n");
      for (sort1 = 0; sort1 < nr_of_links; sort1++)
	{
	  struct RB_link *temp;

	  for (sort2 = sort1; sort2 < nr_of_links; sort2++)
	    {
	      if (strcmp (link_index[sort1]->label_name,
			  link_index[sort2]->label_name) > 0)
		{
		  temp = link_index[sort1];
		  link_index[sort1] = link_index[sort2];
		  link_index[sort2] = temp;
		}
	    }
	}
    }
}

/****** RB_Make_Index_Tables  *****/
