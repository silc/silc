#include <stddef.h>
#include <string.h>
#include "robodoc.h"
#include "folds.h"


/****v* ROBODoc/fold_start_markers 
 * NAME
 *   fold_start_markers
 * FUNCTION
 *   Strings for fold start.
 * SOURCE
 */
fold_mark_t     fold_start_markers[] =
{
  {"/*{{{", "*/"},     /* C, C++ */
  {"--{{{", "\n"},     /* Occam, line ends with newline */
  {"#{{{", "\n"},      /* Various scripts, line ends with newline */
  {NULL, NULL}
};

/****/


/****v* ROBODoc/fold_end_markers 
 * NAME
 *   fold_start_end
 * FUNCTION
 *   Strings for fold end.
 * SOURCE
 */
fold_mark_t fold_end_markers[] =
{
  {"/*}}}", "*/"},
  {"--}}}", "\n"},
  {"#}}}", "\n"},
  {NULL, NULL}
};

/****/

int extra_flags = 0;

/****v* ROBODoc/fold 
* NAME
*   fold
* FUNCTION
*   Fold counter - true global. 
* SOURCE
*/

int fold = 0;

/****/



/****f* ROBODoc/RB_Check_Fold_End [3.0h]
* NAME
*  RB_Check_Fold_End
* AUTHOR
*  PetteriK
* FUNCTION
*  See if a fold end is found.
* RETURN VALUE
*   1 if end mark is found
* SOURCE
*/

char
RB_Check_Fold_End (char *cur_char)
{
  fold_mark_t *t = fold_end_markers;
  char found = 0;

  while (found == 0 && t->start != NULL)
    {
      if (strncmp (t->start, cur_char, strlen (t->start)) == 0)
	{
	  found = 1;
	  break;
	}
      t++;			/* try the next fold mark string */
    }
  return found;
}

/*******/

/****f* ROBODoc/RB_Check_Fold_Start 
 * NAME
 *   RB_Check_Fold_Start
 * AUTHOR
 *   PetteriK
 * FUNCTION
 *   Check if a fold start is found.
 * RETURN VALUE
 *   Pointer to the item body, fold mark and name skipped.
 * SIDE EFFECTS
 *   *found = 1 if fold mark is found. Fold name is copied to *foldname.
 *******
 */

char *
RB_Check_Fold_Start (char *cur_char, char *foldname, char *found)
{
  int n = 0;
  fold_mark_t *t = fold_start_markers;

  *found = 0;
  while (*found == 0 && t->start != NULL)
    {
      if (strncmp (t->start, cur_char, strlen (t->start)) == 0)
	{
	  *found = 1;
	  break;
	}
      t++;			/* try the next fold mark string */
    }
  if (*found == 0)
    {
      return cur_char;		/* not found, get out of here */
    }
  cur_char += strlen (t->start);	/* skip fold mark */
  /* get the fold name */
  while (strncmp (t->end, cur_char, strlen (t->end)) != 0)
    {
      foldname[n++] = *cur_char++;
    }
  /* if fold mark does not end with newline, skip chars... */
  if (t->end[0] != '\n')
    {
      cur_char += strlen (t->end);
    }
  foldname[n] = '\0';
  while (*cur_char != '\n')
    {
      cur_char++;		/* not so sure about this */
    }
  return cur_char;
}
