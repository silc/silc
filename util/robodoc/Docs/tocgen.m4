m4_changecom(`/-*', `*-/')m4_dnl
m4_define(`www_sectionCounter',0)m4_dnl
m4_define(`www_subSectionCounter',0)m4_dnl
m4_define(`www_incrCounter',`m4_define(`$1',m4_incr($1))')m4_dnl
m4_define(`www_section', `www_incrCounter(`www_sectionCounter')<STRONG><FONT COLOR="red">m4_format(`%02d', www_sectionCounter)</FONT>......... <A HREF="#$1">$2</A></STRONG><BR> m4_define(`www_subSectionCounter', 0)')m4_dnl
m4_define(`www_subSection', `www_incrCounter(`www_subSectionCounter')<STRONG><font color="red">m4_format(`%02d.%02d', www_sectionCounter, www_subSectionCounter)</font>.......... <A HREF="#$1">$2</A></STRONG><BR>')m4_dnl
