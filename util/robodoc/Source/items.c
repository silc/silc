#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "robodoc.h"
#include "items.h"

/****v* ROBODoc/item_names [3.0g]
 * NAME
 *   item_names
 * SYNOPSIS
 *   char *item_names[]
 * FUNCTION
 *   Defines the names of items that ROBODoc recognized as
 *   items. For each name their is a corresponding 
 *   item type (see ItemType). So if you add a name here
 *   you have to add an item type to. In addition you
 *   have to add an item attribute (see item_attributes) 
 *   entry too.
 * AUTHOR
 *   Koessi
 * SEE ALSO
 *   RB_Get_Item_Type(), item_attributes, item_attr_names,
 * SOURCE
 */

char *item_names[] =
{
  NULL,
  "NAME",
  /* Item name + short description */
  "COPYRIGHT",
  /* who own the copyright : "(c) <year>-<year> by <company/person>" */
  "SYNOPSIS", "USAGE",
  /* how to use it */
  "FUNCTION", "DESCRIPTION", "PURPOSE",
  /* what does it */
  "AUTHOR",
  /* who wrote it */
  "CREATION DATE",
  /* when did the work start */
  "MODIFICATION HISTORY", "HISTORY",
  /* who done what changes when */
  "INPUTS", "ARGUMENTS", "OPTIONS", "PARAMETERS", "SWITCHES",
  /* what can we feed into it */
  "OUTPUT", "SIDE EFFECTS",
  /* what output will be made */
  "RESULT", "RETURN VALUE",
  /* what do we get returned */
  "EXAMPLE",
  /* a clear example of the items use */
  "NOTES",
  /* any annotations */
  "DIAGNOSTICS",
  /* diagnostical output */
  "WARNINGS", "ERRORS",
  /* warning & error-messages */
  "BUGS",
  /* known bugs */
  "TODO", "IDEAS",
  /* what to implement next & ideas */
  "PORTABILITY",
  /* where does it come from, where will it work */
  "SEE ALSO",
  /* references */
  "SOURCE",
  /* source code inclusion */
  "METHODS", "NEW METHODS",
  /* oop methods */
  "ATTRIBUTES", "NEW ATTRIBUTES",
  /* oop attributes */
  "TAGS",
  /* tagitem description */
  "COMMANDS",
  /* command description */
  "DERIVED FROM",
  /* oop super class */
  "DERIVED BY",
  /* oop sub class */
  "USES", "CHILDREN",
  /* what modules are used by this one */
  "USED BY", "PARENTS",
  /* which modules do use this */
  NULL,
};

/***********/


/****v* ROBODoc/item_attributes [3.0h]
 * NAME
 *   item_attributes -- attributes of the various items
 * FUNCTION
 *   links each item type with a text attribute.
 * SEE ALSO
 *   RB_Get_Item_Type(), item_names, item_attr_names
 * SOURCE
 */

long item_attributes[NUMBER_OF_ITEMS] =
{
  0,				/* NO_ITEM */
  ITEM_NAME_LARGE_FONT | TEXT_BODY_SHINE,	/* NAME_ITEM */
  ITEM_NAME_LARGE_FONT,		/* COPYRIGHT_ITEM */
  ITEM_NAME_LARGE_FONT | TEXT_BODY_SHINE,	/* SYNOPSIS_ITEM */
  ITEM_NAME_LARGE_FONT,		/* USAGE_ITEM */
  ITEM_NAME_LARGE_FONT,		/* FUNCTION_ITEM */
  ITEM_NAME_LARGE_FONT,		/* DESCRIPTION_ITEM */
  ITEM_NAME_LARGE_FONT,		/* PURPOSE_ITEM */
  ITEM_NAME_LARGE_FONT | TEXT_BODY_BOLD,	/* AUTHOR_ITEM */
  ITEM_NAME_LARGE_FONT | TEXT_BODY_BOLD,	/* CREATION_DATE_ITEM */
  ITEM_NAME_LARGE_FONT,		/* MODIFICATION_HISTORY_ITEM */
  ITEM_NAME_LARGE_FONT,		/* HISTORY_ITEM */
  ITEM_NAME_LARGE_FONT,		/* INPUT_ITEM */
  ITEM_NAME_LARGE_FONT,		/* ARGUMENT_ITEM */
  ITEM_NAME_LARGE_FONT,		/* OPTION_ITEM */
  ITEM_NAME_LARGE_FONT,		/* PARAMETER_ITEM */
  ITEM_NAME_LARGE_FONT,		/* SWITCH_ITEM */
  ITEM_NAME_LARGE_FONT,		/* OUTPUT_ITEM */
  ITEM_NAME_LARGE_FONT,		/* SIDE_EFFECTS_ITEM */
  ITEM_NAME_LARGE_FONT,		/* RESULT_ITEM */
  ITEM_NAME_LARGE_FONT,		/* RETURN_VALUE_ITEM */
  ITEM_NAME_LARGE_FONT,		/* EXAMPLE_ITEM */
  ITEM_NAME_LARGE_FONT | TEXT_BODY_SHINE,	/* NOTE_ITEM */
  ITEM_NAME_LARGE_FONT,		/* DIAGNOSTICS_ITEM */
  ITEM_NAME_LARGE_FONT,		/* WARNING_ITEM */
  ITEM_NAME_LARGE_FONT,		/* ERROR_ITEM */
  ITEM_NAME_LARGE_FONT | TEXT_BODY_SHINE,	/* BUGS_ITEM */
  ITEM_NAME_LARGE_FONT,		/* TODO_ITEM */
  ITEM_NAME_LARGE_FONT,		/* IDEAS_ITEM */
  ITEM_NAME_LARGE_FONT,		/* PORTABILITY_ITEM */
  ITEM_NAME_LARGE_FONT,		/* SEE_ALSO_ITEM */
  ITEM_NAME_LARGE_FONT,		/* SOURCE_ITEM */
  ITEM_NAME_LARGE_FONT,		/* METHODS_ITEM */
  ITEM_NAME_LARGE_FONT,		/* NEW_METHODS_ITEM */
  ITEM_NAME_LARGE_FONT,		/* ATTRIBUTES_ITEM */
  ITEM_NAME_LARGE_FONT,		/* NEW_ATTRIBUTES_ITEM */
  ITEM_NAME_LARGE_FONT,		/* TAGS_ITEM */
  ITEM_NAME_LARGE_FONT,		/* COMMANDS_ITEM */
  ITEM_NAME_LARGE_FONT,		/* DERIVED_FROM_ITEM */
  ITEM_NAME_LARGE_FONT,		/* DERIVED_BY_ITEM */
  ITEM_NAME_LARGE_FONT,		/* USES_ITEM */
  ITEM_NAME_LARGE_FONT,		/* CHILDREN */
  ITEM_NAME_LARGE_FONT,		/* USED_BY_ITEM */
  ITEM_NAME_LARGE_FONT,		/* PARENTS */
  0				/* OTHER_ITEM */
};

/**********/


/****v* ROBODoc/item_attr_names [3.0j]
 * NAME
 *   item_attr_names
 * SYNOPSIS
 *   char *item_attr_names[]
 * FUNCTION
 *   used for strcmp() in RB_Get_Item_Attr()
 * AUTHOR
 *   Koessi
 * SEE ALSO
 *   RB_Get_Item_Attr(), item_attributes, item_names
 * SOURCE
 */

char *item_attr_names[] =
{
/* "NORMAL", */
  "LARGE", "ITALICS", "NONPROP", "SMALL", "BOLD",
  "UNDERLINE", "SHINE", "HIGHLIGHT"
};

/*************/


/* ASCII AMIGAGUIDE HTML LATEX RTF */

char *att_start_command[SIZE_ATTRIBUTES][SIZE_MODES] =
{
  {"", "@{b}", "<FONT SIZE=\"+1\">", "{\\large ", "\\par\\fs28 "},
  /* Large Font */
  {"", "@{i}", "<I>", "{\\it ", "\\i1 "},	/* Italics. */
  {"", "", "", "", ""},		/* NON-Proportional font. */
  {"", "", "<SMALL>", "{\\small ", "\\fs16 "},	/* Small Font. */
  {"", "@{b}", "<B>", "{\\bf ", "\\b1 "},	/* Bold. */
  {"", "@{u}", "<U>", "\\underline{", "\\ul1 "},	/* Underline */
  {"", "@{fg shine}", "<FONT FACE=\"courier\" size=\"3\">", "{\\em ", ""},/* Shine */
  {"", "@{fg highlight}", "<EM>", "{\\em ", ""}       	/* Highlight */
};

char *att_stop_command[SIZE_ATTRIBUTES][SIZE_MODES] =
{
  {"", "@{ub}", "</FONT>", "}", "\\fs20\\line "},	/* Large Font */
  {"", "@{ui}", "</I>", "}", "\\i0 "},	/* Italics. */
  {"", "", "", "", ""},		/* NON-Proportional font. */
  {"", "", "</SMALL>", "}", "\\fs20 "},		/* Small Font. */
  {"", "@{ub}", "</B>", "}", "\\b0 "},	/* Bold. */
  {"", "@{uu}", "</U>", "}", "\\ul0 "},		/* Underline */
  {"", "@{fg text}", "</FONT>", "}", ""},		/* Shine */
  {"", "@{fg text}", "</EM>", "}", ""}	/* Highlight */
};



/****f* ROBODoc/RB_Get_Item_Type [3.0b]
 * NAME
 *   RB_Get_Item_Type -- shortcut
 * SYNOPSIS
 *   int RB_Get_Item_Type( char *cmp_name )
 * FUNCTION
 *   return the item_type represented by the given string
 * INPUTS
 *   char *cmp_name          -- item_name to evaluate
 * RESULT
 *   int                     -- the right item_type or NO_ITEM
 * NOTES
 *   uses global char *item_names[]
 * AUTHOR
 *   Koessi
 * SEE ALSO
 *   RB_Analyse_Defaults_File(), RB_Get_Item_Attr()
 * SOURCE
 */

int
RB_Get_Item_Type (char *cmp_name)
{
  int item_type;

  for (item_type = NAME_ITEM; item_type < OTHER_ITEM; ++item_type)
    {
      if (!strncmp (item_names[item_type], cmp_name,
		    strlen (item_names[item_type])))
	return (item_type);
    }
  return (NO_ITEM);
}

/*** RB_Get_Item_Type ***/



/****f* ROBODoc/RB_Get_Item_Attr [3.0b]
 *
 * NAME
 *   RB_Get_Item_Attr -- shortcut
 * SYNOPSIS
 *   int RB_Get_Item_Attr( char *cmp_name )
 * FUNCTION
 *   return the item_attr represented by the given string
 * INPUTS
 *   char *cmp_name  -- item_attr_name to evaluate
 * RESULT
 *   int             -- the right item_attr or NULL
 * NOTES
 *   uses global char *item_attr_names[]
 * AUTHOR
 *   Koessi
 * SEE ALSO
 *   RB_Analyse_Defaults_File(), RB_Get_Item_Type()
 * SOURCE
 */

int
RB_Get_Item_Attr (char *cmp_name)
{
  int item_attr;

  for (item_attr = MAKE_LARGE; item_attr < SIZE_ATTRIBUTES; ++item_attr)
    if (!strcmp (item_attr_names[item_attr], cmp_name))
      return (item_attr);
  if (strcmp ("NORMAL", cmp_name))
    {
      fprintf (stderr, "%s: Warning unknown attribute [%s] in defaults file.\n",
	       whoami, cmp_name);
    }
  return (MAKE_NORMAL);
}

/************/
