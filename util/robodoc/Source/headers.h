#ifndef ROBODOC_HEADERS_H
#define ROBODOC_HEADERS_H

/****d* ROBODoc/RB_header_types
 * NAME 
 *   RB_header_types -- symbolic constants for the header types.
 * SOURCE
 */

enum
  {
    NO_HEADER = 0,
    MAIN_HEADER,
    GENERIC_HEADER,
    INTERNAL_HEADER,
    FUNCTION_HEADER,
    STRUCT_HEADER,
    CLASS_HEADER,
    METHOD_HEADER,
    CONSTANT_HEADER,
    VARIABLE_HEADER,
    BLANK_HEADER
  };

/********/


/****s* ROBODoc/RB_header [2.0]
 *  NAME
 *    RB_header -- header data structure
 *  MODIFICATION HISTORY
 *    8. August 1995: Koessi
 *                    changed int version to char *version
 *  ATTRIBUTES
 *    next_header 
 *    prev_header 
 *    name          -- 
 *    version       -- unused
 *    type          -- header type see RB_header_types
 *    size          --
 *    function_name --
 *    contents      --
 *  SOURCE
 */

struct RB_header
  {
    struct RB_header *next_header;
    struct RB_header *prev_header;
    char *name;
    char *version;
    int type;
    int size;
    char *function_name;
    char *contents;
  };

/*********/

extern char *header_markers[];
extern char *remark_markers[];
extern char *end_markers[];
extern char *RB_header_type_names[];
extern struct RB_header *first_header;
extern struct RB_header *last_header;
extern struct RB_link *first_link;
extern int header_index_size;
extern struct RB_header **header_index;

#endif /* ROBODOC_HEADERS_H */


