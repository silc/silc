#ifndef __XTEXT_H__
#define __XTEXT_H__

#include <gdk/gdk.h>
#include <gtk/gtkadjustment.h>
#include <gtk/gtkwidget.h>
#include <time.h>

/*#define GTK_XTEXT(obj)          GTK_CHECK_CAST (obj, gtk_xtext_get_type (), GtkXText)*/
#define GTK_XTEXT(obj) ((GtkXText*)obj)
#define GTK_XTEXT_CLASS(klass)  GTK_CHECK_CLASS_CAST (klass, gtk_xtext_get_type (), GtkXTextClass)
#define GTK_IS_XTEXT(obj)       GTK_CHECK_TYPE (obj, gtk_xtext_get_type ())

#define FONT_1BYTE 0
#define FONT_2BYTE 1
#define FONT_SET 2

#define ATTR_BOLD '\002'
#define ATTR_COLOR '\003'
#define ATTR_BEEP '\007'
#define ATTR_RESET '\017'
#define ATTR_REVERSE '\026'
#define ATTR_ESCAPE '\033'
#define ATTR_UNDERLINE '\037'

typedef struct _GtkXText GtkXText;
typedef struct _GtkXTextClass GtkXTextClass;

typedef struct textentry
{
	struct textentry *next;
	char *str;
	int str_width;
	time_t stamp;
	short str_len;
	short mark_start;
	short mark_end;
	short indent;
	short lines_taken;
	short left_len;
}
textentry;

struct _GtkXText
{
	GtkWidget widget;

	GtkAdjustment *adj;
	gfloat old_value;					/* last known adj->value */
	GdkPixmap *pixmap;				/* 0 = use palette[19] */
	GdkDrawable *draw_buf;			/* points to ->window or ->tmp_pix */
	GdkPixmap *tmp_pix;				/* double buffer */
	GdkCursor *hand_cursor;

	int ts_orig_x;
	int ts_orig_y;

	int last_win_x;
	int last_win_y;
	int last_win_h;
	int last_win_w;

	int tint_red;
	int tint_green;
	int tint_blue;

	GdkGC *bgc;						  /* backing pixmap */
	GdkGC *fgc;						  /* text foreground color */
	GdkGC *light_gc;				  /* sep bar */
	GdkGC *dark_gc;
	gulong palette[20];

	textentry *text_first;
	textentry *text_last;

	gint io_tag;					  /* for delayed refresh events */
	gint add_io_tag;				  /* "" when adding new text */
	gint scroll_tag;				  /* marking-scroll timeout */

	GdkFont *font;
	int fontsize;
	int fonttype;
	guint16 fontwidth[256];		  /* each char's width, only for FONT_1BYTE type */
	int space_width;				  /* width (pixels) of the space " " character */
	int stamp_width;				  /* width of "[88:88:88]" */

	int indent;						  /* position of separator (pixels) from left */
	int max_auto_indent;

	int select_start_adj;		  /* the adj->value when the selection started */
	int select_start_x;
	int select_start_y;
	int select_end_x;
	int select_end_y;

	textentry *last_ent_start;	  /* this basically describes the last rendered */
	textentry *last_ent_end;	  /* selection. */
	int last_offset_start;
	int last_offset_end;

	textentry *old_ent_start;
	textentry *old_ent_end;

	int num_lines;
	int max_lines;

	int pagetop_subline;
	textentry *pagetop_ent;			/* what's at xtext->adj->value */

	int col_fore;
	int col_back;

	int depth;						  /* gdk window depth */

/*   int frozen;*/

	char num[8];					  /* for parsing mirc color */
	int nc;							  /* offset into xtext->num */

	textentry *hilight_ent;
	int hilight_start;
	int hilight_end;

	short grid_offset[256];

	GtkWidget *(*error_function) (char *text);
	int (*urlcheck_function) (GtkXText * xtext, char *word);

	unsigned char scratch_buffer[4096];

	unsigned int fixed_width_font:1;
	unsigned int double_buffer:1;
	unsigned int auto_indent:1;
	unsigned int moving_separator:1;
	unsigned int time_stamp:1;
	unsigned int scrollbar_down:1;
	unsigned int word_or_line_select:1;
	unsigned int color_paste:1;
	unsigned int thinline:1;
	unsigned int parsing_backcolor:1;
	unsigned int parsing_color:1;
	unsigned int backcolor:1;
	unsigned int button_down:1;
	unsigned int bold:1;
	unsigned int underline:1;
	unsigned int reverse:1;
	unsigned int transparent:1;
	unsigned int separator:1;
	unsigned int shaded:1;
	unsigned int wordwrap:1;
	unsigned int dont_render:1;
	unsigned int cursor_hand:1;
	unsigned int skip_fills:1;
	unsigned int skip_border_fills:1;
	unsigned int do_underline_fills_only:1;
};

struct _GtkXTextClass
{
	GtkWidgetClass parent_class;
	void (*word_click) (GtkXText * xtext, char *word, GdkEventButton * event);
};

GtkWidget *gtk_xtext_new (int indent, int separator);
guint gtk_xtext_get_type (void);
void gtk_xtext_append (GtkXText * xtext, char *text, int len);
void gtk_xtext_append_indent (GtkXText * xtext,
										char *left_text, int left_len,
										char *right_text, int right_len);
void gtk_xtext_set_font (GtkXText * xtext, GdkFont * font, char *name);
void gtk_xtext_set_background (GtkXText * xtext, GdkPixmap * pixmap,
										 int trans, int shaded);
void gtk_xtext_set_palette (GtkXText * xtext, GdkColor palette[]);
void gtk_xtext_remove_lines (GtkXText * xtext, int lines, int refresh);
gchar *gtk_xtext_get_chars (GtkXText * xtext);
void gtk_xtext_refresh (GtkXText * xtext, int do_trans);
void gtk_xtext_thaw (GtkXText * xtext);
void gtk_xtext_freeze (GtkXText * xtext);
void *gtk_xtext_search (GtkXText * xtext, char *text, void *start);
char *gtk_xtext_strip_color (unsigned char *text, int len, char *outbuf, int *newlen);

#endif
