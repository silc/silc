


#ifndef ROBODOC_ITEMS_H
#define ROBODOC_ITEMS_H

enum
  {
    MAKE_NORMAL = -1, MAKE_LARGE, MAKE_ITALICS, MAKE_NON_PROP, MAKE_SMALL,
    MAKE_BOLD, MAKE_UNDERLINE, MAKE_SHINE, MAKE_HIGH, MAKE_DEFAULT,
    SIZE_ATTRIBUTES
  };

#define ITEM_NAME_LARGE_FONT (1<<0)
#define TEXT_BODY_LARGE_FONT (1<<(MAKE_LARGE     + 1))
#define TEXT_BODY_ITALICS    (1<<(MAKE_ITALICS   + 1))
#define TEXT_BODY_NON_PROP   (1<<(MAKE_NON_PROP  + 1))
#define TEXT_BODY_SMALL_FONT (1<<(MAKE_SMALL     + 1))
#define TEXT_BODY_BOLD       (1<<(MAKE_BOLD      + 1))
#define TEXT_BODY_UNDERLINE  (1<<(MAKE_UNDERLINE + 1))
#define TEXT_BODY_SHINE      (1<<(MAKE_SHINE     + 1))
#define TEXT_BODY_HIGHLIGHT  (1<<(MAKE_HIGH      + 1))
#define TEXT_BODY_DEFAULT    (1<<(MAKE_DEFAULT   + 1))


/****** ROBODoc/ItemTypes *
 * NAME 
 *   ItemTypes -- enumeration of item types
 * FUNCTION
 *   Give an unique number to each item type. This defines all item types that
 *   are recognized by ROBODoc. The corresponding names (string) of each item
 *   are defined in item_names.  If you add an item here you also should
 *   add an corresponding item name.  
 * SOURCE
 */

enum
  {
    NO_ITEM = 0,
    NAME_ITEM,
    COPYRIGHT_ITEM,
    SYNOPSIS_ITEM, USAGE_ITEM,
    FUNCTION_ITEM, DESCRIPTION_ITEM, PURPOSE_ITEM,
    AUTHOR_ITEM,
    CREATION_DATE_ITEM,
    MODIFICATION_HISTORY_ITEM, HISTORY_ITEM,
    INPUT_ITEM, ARGUMENT_ITEM, OPTION_ITEM, PARAMETER_ITEM, SWITCH_ITEM,
    OUTPUT_ITEM, SIDE_EFFECTS_ITEM,
    RESULT_ITEM, RETURN_VALUE_ITEM,
    EXAMPLE_ITEM,
    NOTE_ITEM,
    DIAGNOSTICS_ITEM,
    WARNING_ITEM, ERROR_ITEM,
    BUGS_ITEM,
    TODO_ITEM, IDEAS_ITEM,
    PORTABILITY_ITEM,
    SEE_ALSO_ITEM,
    SOURCE_ITEM,
    METHODS_ITEM, NEW_METHODS_ITEM,
    ATTRIBUTES_ITEM, NEW_ATTRIBUTES_ITEM,
    TAGS_ITEM,
    COMMANDS_ITEM,
    DERIVED_FROM_ITEM,
    DERIVED_BY_ITEM,
    USES_ITEM, CHILDREN_ITEM,
    USED_BY_ITEM, PARENTS_ITEM,
    OTHER_ITEM,
    NUMBER_OF_ITEMS
  };

/****/

extern char *item_names[];
extern long item_attributes[NUMBER_OF_ITEMS];
extern char *item_attr_names[];
extern char *att_start_command[SIZE_ATTRIBUTES][SIZE_MODES];
extern char *att_stop_command[SIZE_ATTRIBUTES][SIZE_MODES];

int RB_Get_Item_Type (char *);
int RB_Get_Item_Attr (char *cmp_name);


#endif /* ROBODOC_ITEMS_H */
