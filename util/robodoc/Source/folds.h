#ifndef ROBODOC_FOLDS_H
#define ROBODOC_FOLDS_H



/****s* ROBODoc/fold_mark_t
 * NAME
 *   fold_mark_t
 * FUNCTION
 *   Handy structure for fold start/end markers.
 * SOURCE
 */

typedef struct _fold_mark_t
  {
    char *start;
    char *end;
  }
fold_mark_t;

/*******/

/****d* ROBODoc/extra_flags 
* NAME
*   extra_flags
* AUTHOR
*   PetteriK
* FUNCTION
*   Bitflags for extra controls. 
* SOURCE
*/

#define FOLD     (1<<0)
#define C_MODE   (1<<1)


/****/

extern fold_mark_t fold_start_markers[];
extern fold_mark_t fold_end_markers[];
extern int extra_flags;
extern int fold;

char RB_Check_Fold_End (char *cur_char);
char *RB_Check_Fold_Start (char *cur_char, char *foldname, char *found);

#endif /* ROBODOC_FOLDS_H */
