m4_changecom(`/--*--', `--*--/')m4_dnl
m4_define(`www_docstart', `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2//EN"><HTML>')m4_dnl
m4_define(`www_header', `<HEAD><LINK rel=stylesheet href="main.css"><TITLE>$1</TITLE></HEAD>')m4_dnl
m4_define(`www_link', `<A HREF="$1">$2</A>')m4_dnl
m4_define(`www_bodystart', `<BODY>')m4_dnl
m4_define(`www_bodyend', `</BODY>')m4_dnl
m4_define(`www_docend', `</HTML>')m4_dnl
m4_define(`www_title', `<H1>$1</H1>')m4_dnl
m4_define(`www_sectionCounter',0)m4_dnl
m4_define(`www_subSectionCounter',0)m4_dnl
m4_define(`www_incrCounter',`m4_define(`$1',m4_incr($1))')m4_dnl
m4_define(`www_section', `www_incrCounter(`www_sectionCounter') <H2><font color="red">www_sectionCounter  </font><A NAME="$1">$2</A></H2> m4_define(`www_subSectionCounter', 0)')m4_dnl
m4_define(`www_subSection', `www_incrCounter(`www_subSectionCounter')<H3><font color="red">www_sectionCounter.www_subSectionCounter  </font><A NAME="$1">$2</A></H3>')m4_dnl

