






#ifndef ROBODOC_UTIL_H
#define ROBODOC_UTIL_H

char *RB_FilePart (char *);
void RB_Analyse_Defaults_File (void);
char *RB_Skip_Remark_Marker (char *line_buffer);
void RB_Slow_Sort (void);
void RB_Reverse_List (void);
void RB_Insert_In_List (struct RB_header **, struct RB_header *);
void RB_Remove_From_List (struct RB_header **, struct RB_header *);
struct RB_header *RB_Alloc_Header (void);
void RB_Free_Header (struct RB_header *);
int RB_WordLen (char *);
char *RB_StrDup (char *);
char *RB_CookStr (char *);
void RB_Say (char *,...);
void RB_Panic (char *,...);
void RB_Close_The_Shop (void);
int RB_Str_Case_Cmp (char *s, char *t);
void RB_TimeStamp (FILE * f);


#endif /* ROBODOC_UTIL_H */
