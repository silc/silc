#ifndef ROBODOC_GENERATOR_H
#define ROBODOC_GENERATOR_H

void RB_Generate_Documentation (FILE *, char *, char *);
void RB_Generate_Item_Doc (FILE *, char *, char *, char *, char *, int);
char *RB_Generate_Item_Body (FILE *, char *, char *, char *, char *, int, int);
void RB_Generate_Header_Name (FILE *, char *);
void RB_Generate_Item_Name (FILE *, int);
void RB_Generate_Doc_Start (FILE *, char *, char *, char);
void RB_Generate_Doc_End (FILE *, char *);
void RB_Generate_Header_Start (FILE *, struct RB_header *);
void RB_Generate_Header_End (FILE *, struct RB_header *);
int RB_HTML_Extra (FILE * dest_doc, int item_type, char *cur_char);
void RB_Generate_Index (FILE * dest, char *name);
void RB_Generate_LaTeX_Includes (FILE *dest);
void RB_Generate_Index_Table (FILE * dest, int type, char *source);
int RB_Max_Name_Length (int type, char *file_name);
int RB_Number_Of_Links (int type, char *file_name);

#endif /* ROBODOC_GENERATOR_H */
