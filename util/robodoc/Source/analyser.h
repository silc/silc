#ifndef ROBODOC_ANALYSER_H
#define ROBODOC_ANALYSER_H

void RB_Analyse_Document (FILE *);
int RB_Find_Marker (FILE *);
char *RB_Find_Header_Name (void);
int RB_Find_End_Marker (FILE *, int *);
int RB_Find_Item (char **, char **);
void RB_Number_Duplicate_Headers(void);
void RB_Make_Index_Tables (void);
char *RB_Function_Name (char *header_name);

#endif /* ROBODOC_ANALYSER_H */
