

#ifndef ROBODOC_LINKS_H
#define ROBODOC_LINKS_H

/****s* ROBODoc/RB_link [2.0e]
 *  NAME
 *    RB_link -- link data structure
 *  PURPOSE
 *    Structure to store links to the documentation of an component. 
 *  PROPERTIES
 *    next_link
 *    prev_link
 *    label_name  -- the label under which the component can be found.
 *    file_name   -- the file the component can be found in.
 *    type        -- the type of component (the header type).
 *  SOURCE
 */

struct RB_link
  {
    struct RB_link *next_link;
    struct RB_link *prev_link;
    char *label_name;
    char *file_name;
    int type;
  };

/*********/

extern FILE *xreffiles_file;
extern FILE *xref_file;
extern int link_index_size;
extern struct RB_link **link_index;

void RB_Analyse_Xrefs (FILE * xreffiles_file);
void RB_Add_Link ();
void RB_Generate_xrefs (FILE * dest_doc, char *source_name, char *dest_name);
int RB_Find_Link (char *word_begin, char **label_name, char **file_name);
struct RB_link *RB_Alloc_Link (char *label_name, char *file_name);
void RB_Free_Link (struct RB_link *link);
void RB_Slow_Sort_Links (void);

#endif /* ROBODOC_LINKS_H */
