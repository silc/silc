#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>		/* for RB_Say() */

#include "robodoc.h"
#include "links.h"
#include "headers.h"
#include "folds.h"
#include "items.h"
#include "util.h"
#include "time.h"




/****f* ROBODoc/RB_FilePart [2.0x]
 * NAME
 *   RB_FilePart
 * SYNOPSIS
 *   char *RB_FilePart(char *file_name)
 * FUNCTION
 *   return the basename (like Amiga/Dos/FilePart())
 * NOTES
 *   koessi
 * SEE ALSO
 * SOURCE
 */

char *
RB_FilePart (char *file_name)
{
  char *cur_char;
  char c;

  if ((cur_char = file_name) != NULL)
    {
      for (; (c = *cur_char) != '\0'; ++cur_char)
	{
	  if ((c == '/') || (c == ':'))
	    {
	      ++cur_char;
	      while ('/' == *cur_char)
		++cur_char;

	      if (*cur_char)
		file_name = cur_char;
	    }
	}
    }
  return (file_name);
}

/* Same except remove trailing dot (.). -Pekka */
char *
RB_FilePartStart (char *file_name)
{
  char *cur_char;
  char c;

  if ((cur_char = file_name) != NULL)
    {
      for (; (c = *cur_char) != '\0'; ++cur_char)
	{
	  if ((c == '/') || (c == ':'))
	    {
	      ++cur_char;
	      while ('/' == *cur_char)
		++cur_char;

	      if (*cur_char)
		file_name = cur_char;
	    }
	}
    }

  if (strchr(file_name, '.'))
    *strchr(file_name, '.') = '\0';

  return (file_name);
}

/*** RB_File_Part ***/



/****f* ROBODoc/RB_Analyse_Defaults_File [3.0b]
 * NAME
 *   RB_Analyse_Defaults_file -- read default from defaults file
 * SYNOPSIS
 *   RB_Analyse_Defaults_file
 * FUNCTION
 *   Read the default vaules from the default file.
 * NOTES
 *   FS: The use of while (!feof(defaults_file)) {
 *       is wrong here. Should check return value of
 *       fgets().
 * SOURCE
 */

void
RB_Analyse_Defaults_File ()
{
  FILE *defaults_file;

  /* defaults file in working directory? */
  defaults_file = fopen ("robodoc.defaults", "r");
  if (defaults_file == NULL)
    {
      /* try again from the directory from 
         which this application was started  */
#ifdef _MSC_VER
      /* windows */
      char path[_MAX_PATH], *c;

      strcpy (path, whoami);
      if ((c = strrchr (path, '\\')) != NULL)
	{
	  *c = '\0';
	  strcat (path, "\\");
	}
      strcat (path, "robodoc.defaults");
      defaults_file = fopen (path, "r");
#else
      /* non-windows ... to be done */
#endif /* _MSC_VER */
    }
  if (defaults_file != NULL)
    {
      while (!feof (defaults_file))
	{
	  char *cur_char;

	  *line_buffer = '\0';

	  fgets (line_buffer, MAX_LINE_LEN, defaults_file);

	  if (*line_buffer != '\n')
	    {
	      int item_type;

	      item_type = RB_Get_Item_Type (line_buffer);
	      if (item_type != NO_ITEM)
		{
		  char *values;

		  item_attributes[item_type] = ITEM_NAME_LARGE_FONT;

		  cur_char = line_buffer + strlen (item_names[item_type]);
		  for (; *cur_char && isspace (*cur_char); cur_char++);

		  while (*cur_char)
		    {
		      for (values = cur_char;
			   *cur_char && !isspace (*cur_char);
			   cur_char++);
		      if (*cur_char)
			{
			  int item_attr;

			  *cur_char = '\0';
			  item_attr = RB_Get_Item_Attr (values);
			  if (item_attr != MAKE_NORMAL)
			    {
			      RB_Say ("Default: %s = %s\n", 
				      item_names[item_type],
				      item_attr_names[item_attr]);
			      item_attributes[item_type] |=
				(1 << (item_attr + 1));
			    }
			}
		      for (cur_char++; *cur_char && isspace (*cur_char);
			   cur_char++);
		    }
		}
	    }
	}
      fclose (defaults_file);
    }
/* else { printf("%s: WARNING, robodoc.defaults file was not found.\n",
 * whoami); printf("\t\tyou should really use one.\n"); } */
}

/**********/



/****f* ROBODoc/RB_Skip_Remark_Marker [2.0e]
 * NAME
 *    RB_Skip_Remark_Marker
 * SYNOPSIS
 *     text  = RB_Skip_Remark_Marker (line_buffer)
 *    char *                            char *
 * FUNCTION
 *    Scan and search for a recognized remark marker; skip past the
 *    marker to the body of the text
 * NOTE
 *    This should be in generator.c
 * SOURCE
 */

char *
RB_Skip_Remark_Marker (char *line_buffer)
{
  int marker, found;
  char *cur_char, *cur_mchar;

  found = FALSE;
  cur_char = NULL;
  for (marker = 0;
       ((cur_mchar = remark_markers[marker]) != NULL) && !found;
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
  return (cur_char);
}

/**************/




/****f* ROBODoc/RB_Slow_Sort [2.0]
 * NAME
 *   RB_Slow_Sort -- sort list of headers alphabetically
 * SYNOPSIS
 *   RB_Slow_Sort ()
 * FUNCTION
 *   Sorts the list of headers according to the header name
 *   in alphabetically fashion.
 * NOTES
 *   This isn't a particularly speedy way of sorting.
 * SOURCE
 */

void
RB_Slow_Sort (void)
{
  struct RB_header *cur_header, *unsorted_headers, *bigger_header;

  if ((unsorted_headers = first_header) != NULL)
    {				/* additional
				 * check *koessi */
      for (first_header = NULL;
	   unsorted_headers->next_header;)
	{
	  for (bigger_header = unsorted_headers,
	       cur_header = bigger_header->next_header;
	       cur_header;
	       cur_header = cur_header->next_header)
	    {
	      if (strcmp (cur_header->name, bigger_header->name) > 0)
		bigger_header = cur_header;
	    }
	  RB_Remove_From_List (&unsorted_headers, bigger_header);
	  RB_Insert_In_List (&first_header, bigger_header);
	}
      RB_Insert_In_List (&first_header, unsorted_headers);
    }
}

/*********/


/****f* ROBODoc/RB_Insert_In_List [2.0]
 * NAME
 *   RB_Insert_In_List -- Insert a header in a list.
 * SYNOPSIS
 *   RB_Insert_In_List (anchor,new_header)
 *
 *   RB_Insert_In_List (struct RB_header **, struct RB_header *)
 * FUNCTION
 *   Insert a node in a doubly linked list.
 * INPUTS
 *   anchor     - pointer to the first node in the list.
 *   new_header - node to be inserted.
 * MODIFICATION HISTORY
 *   8. August 1995      --  optimized by koessi
 * NOTES
 *   
 * SOURCE
 */

void
RB_Insert_In_List (struct RB_header **anchor,
		   struct RB_header *new_header)
{
  struct RB_header *old_header;

  if ((old_header = *anchor) != NULL)
    old_header->prev_header = new_header;
  new_header->next_header = old_header;
  new_header->prev_header = NULL;
  *anchor = new_header;
}

/*** RB_Insert_In_List ***/

/****f* ROBODoc/RB_Reverse_List [2.0]
 * NAME
 *   RB_Reverse_List -- Insert a header in a list.
 * SYNOPSIS
 *   RB_Reverse_List (void)
 * FUNCTION
 *
 * INPUTS
 *
 * MODIFICATION HISTORY
 *
 * NOTES
 *
 * SOURCE
 */

void
RB_Reverse_List (void)
{
  struct RB_header *cur_header;
  struct RB_header *temp_header;

  for (cur_header = first_header;
       cur_header;
    )
    {
      first_header = cur_header;
      temp_header = cur_header->next_header;
      cur_header->next_header = cur_header->prev_header;
      cur_header->prev_header = temp_header;
      cur_header = temp_header;
    }
}

/*** ***/


/****f* ROBODoc/RB_Remove_From_List [2.0]
 * NAME
 *   RB_Remove_From_List -- remove a header from a list.
 * SYNOPSIS
 *   RB_Remove_From_List (anchor, old_header)
 *   RB_Remove_From_List (struct RB_header **, struct RB_header *)
 * MODIFICATION HISTORY
 *   8. August 1995      --  optimized by koessi
 * SOURCE
 */

void
RB_Remove_From_List (struct RB_header **anchor,
		     struct RB_header *old_header)
{
  struct RB_header *next_header = old_header->next_header;
  struct RB_header *prev_header = old_header->prev_header;

  if (next_header)
    next_header->prev_header = prev_header;
  if (prev_header)
    prev_header->next_header = next_header;
  else
    *anchor = next_header;
}

/********/


/****f* ROBODoc/RB_Alloc_Header [2.01]
 * NAME
 *   RB_Alloc_Header            -- oop
 * SYNOPSIS
 *   struct RB_header *RB_Alloc_Header( void )
 * FUNCTION
 *   allocate the struct RB_header
 * RESULT
 *   struct RB_header *      -- all attributes/pointers set to zero
 * AUTHOR
 *   Koessi
 * SEE ALSO
 *   RB_Free_Header()
 * SOURCE
 */

struct RB_header *
RB_Alloc_Header (void)
{
  struct RB_header *new_header;

  if ((new_header = malloc (sizeof (struct RB_header))) != NULL)
      memset (new_header, 0, sizeof (struct RB_header));
  else
    RB_Panic ("out of memory! [Alloc Header]\n");
  return (new_header);
}

/********/


/****f* ROBODoc/RB_Free_Header [2.01]
 * NAME
 *   RB_Free_Header             -- oop
 * SYNOPSIS
 *   void RB_Free_Header( struct RB_header *header )
 * FUNCTION
 *   free struct RB_header and associated strings
 * INPUTS
 *   struct RB_header *header -- this one
 * AUTHOR
 *   Koessi
 * SEE ALSO
 *   RB_Alloc_Header(), RB_Close_The_Shop()
 * SOURCE
 */

void
RB_Free_Header (struct RB_header *header)
{
  if (header)
    {
      if (header->version)
	free (header->version);
      if (header->name)
	free (header->name);
      if (header->contents)
	free (header->contents);
      free (header);
    }
}

/************/


/****i* ROBODoc/RB_WordLen [2.01]
 * NAME
 *   RB_WordLen -- like strlen
 * SYNOPSIS
 *   int RB_WordLen( char *str )
 * FUNCTION
 *   get the amount of bytes until next space
 * INPUTS
 *   char *str -- the word
 * RESULT
 *   int -- length of the next word or 0
 * AUTHOR
 *   Koessi
 * SEE ALSO
 *   RB_Find_Header_Name()
 * SOURCE
 */

int
RB_WordLen (char *str)
{
  int len;
  char c;

  for (len = 0; ((c = *str) != '\0') && !isspace (c) && (c != '\n');
       ++str, ++len);
  return (len);
}

/*** RB_WordLen ***/


/****i* ROBODoc/RB_StrDup [2.01]
 * NAME
 *   RB_StrDup
 * SYNOPSIS
 *   char *RB_StrDup( char *str )
 * FUNCTION
 *   duplicate the given string
 * INPUTS
 *   char *str               -- source
 * RESULT
 *   char *                  -- destination
 * AUTHOR
 *   Koessi
 * SOURCE
 */

char *
RB_StrDup (char *str)
{
  char *dupstr;
  if ((dupstr = malloc ((strlen (str) + 1) * sizeof (char))) != NULL)
      strcpy (dupstr, str);
  else
    RB_Panic ("out of memory! [StrDup]\n");
  return (dupstr);
}

/*** RB_StrDup ***/


/****f* ROBODoc/RB_CookStr [3.0h]
 * NAME
 *   RB_CookStr
 * SYNOPSIS
 *   char *RB_CookStr( char *str )
 * FUNCTION
 *   duplicate the given string, massaging it for the current output_mode
 * INPUTS
 *   char *str               -- source
 * RESULT
 *   char *                  -- destination
 * AUTHOR
 *   apang
 * NOTES
 *   Doesn't try/need to be as aggressive as RB_Generate_Item_Body()
 * SOURCE
 */

char *
RB_CookStr (char *str)
{
  static char work_buf[MAX_LINE_LEN];
  char *cptr, c;
  int i;

  cptr = work_buf;
  switch (output_mode)
    {
    case LATEX:
      for (i = 0; ((c = *str++) != '\0') && (i < (MAX_LINE_LEN - 1));)
	{
	  i++;
	  if (c == '_')
	    {
	      if (i < (MAX_LINE_LEN - 1))
		{
		  *cptr++ = '\\';
		  *cptr++ = '_';
		  i++;
		}
	      else
		{
		  break;
		}
	    }
	  else
	    {
	      *cptr++ = c;
	    }
	}
      break;

    case RTF:
      for (; (c = *str++) != '\0';)
	{
	  if (isalnum (c) || c == '.' || c == '_')
	    {
	      *cptr++ = c;
	    }
	}
      break;

    default:
      return RB_StrDup (str);
    }

  *cptr = '\0';
  return RB_StrDup (work_buf);
}

/*** RB_CookStr ***/


/****f* ROBODoc/RB_Say [2.01]
 * NAME
 *   RB_Say                     -- varargs
 * SYNOPSIS
 *   void RB_Say( char *what, char *why, ... )
 * FUNCTION
 *   say what's going on
 * INPUTS
 *   char *format            -- formatstring
 *    ...                    -- parameters
 * AUTHOR
 *   Koessi
 * SOURCE
 */

void
RB_Say (char *format,...)
{
  va_list ap;

  if (course_of_action & DO_TELL)
    {
      va_start (ap, format);
      printf ("%s: ", whoami);
      vprintf (format, ap);
      va_end (ap);
    }
}

/*** RB_Say ***/


/****f* ROBODoc/RB_Panic [2.01]
 * NAME
 *   RB_Panic -- free resources and shut down
 * SYNOPSIS
 *   void RB_Panic( char *format, char *why, ... )
 * FUNCTION
 *   Print error message.
 *   Frees all resources used by robodoc.
 *   Terminates program
 * INPUTS
 *   char *format            -- formatstring
 *   ...                     -- parameters
 * AUTHOR
 *   Koessi
 * SOURCE
 */

void
RB_Panic (char *format,...)
{
  va_list ap;

  va_start (ap, format);
  printf ("%s: FATAL ERROR - [line %d]\n", whoami, line_number);
  printf ("%s: %s\n%s: ", whoami, line_buffer, whoami);
  vprintf (format, ap);
  printf ("%s: closing down...\n", whoami);
  va_end (ap);
  RB_Close_The_Shop ();
  exit (EXIT_FAILURE);
}

/*** RB_Panic ***/




/****f* ROBODoc/RB_Str_Case_Cmp
 * NAME
 *   RB_Str_Case_Cmp
 * SYNOPSIS
 *   int      RB_Str_Case_Cmp(char *, char *)
 *   result = RB_Str_Case_Cmp(s, t)
 * FUNCTION
 *   Compare two strings, regardless of the case of the characters.
 * RESULT
 *    0  s == t
 *   -1  s < t
 *    1  s > t
 * SOURCE
 */

int
RB_Str_Case_Cmp (char *s, char *t)
{
  for (; tolower (*s) == tolower (*t); s++, t++)
    if (*s == '\0')
      return 0;
  return (int) (tolower (*s) - tolower (*t));
}

/*********/


/****f* ROBODoc/RB_TimeStamp
 * NAME
 *   RB_TimeStamp -- print a time stamp
 *****
 */

void 
RB_TimeStamp (FILE * f)
{
  time_t ttp;
  char timeBuffer[255];

  time (&ttp);
  strftime (timeBuffer, 255, "%a %b %d %H:%M:%S %Y\n", localtime (&ttp));
  fprintf (f, "%s", timeBuffer);
}
