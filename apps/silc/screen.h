/*

  screen.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SCREEN_H
#define SCREEN_H

typedef struct {
  char *mode;
  char *nickname;
  char *connection;
  char *channel;
  int away;
} *SilcScreenBottomLine;

typedef struct {
  /* Status line window top of the screen */
  WINDOW *upper_stat_line;

  /* Output windows */
  WINDOW **output_win;
  WINDOW **output_stat_line;
  unsigned int output_win_count;

  /* Input window at the bottom of the screen */
  WINDOW *input_win;
  unsigned char *input_buffer;
  unsigned int input_pos;
  unsigned int input_end;
  unsigned int cursor_pos;
  int virtual_window;

  /* Bottom line on screen */
  SilcScreenBottomLine bottom_line;

  /* On/off flag for insert */
  int insert;

  /* XXX */
  struct upper_status_line {
    char *program_name;
    char *program_version;
  } u_stat_line;

} SilcScreenObject;

typedef SilcScreenObject *SilcScreen;

/* Size of the input window. User can type this many characters into
   the window. After that no more characters may be added into the 
   window. */
#define SILC_SCREEN_INPUT_WIN_SIZE 1024

/* Maximum length of nickaname that will be shown on the screen */
#define SILC_SCREEN_MAX_NICK_LEN 16

/* Maximum length of channel name that will be shown on the screen */
#define SILC_SCREEN_MAX_CHANNEL_LEN 20

/* Maximum length of connection name that will be shown on the screen */
#define SILC_SCREEN_MAX_CONN_LEN 20

/* Macros */

/* Macro used to insert typed character into the buffer. The character
   is not added at the end of the buffer but somewhere in between. */
#define SILC_SCREEN_INPUT_INSERT(__x, __y, __ch, __end)	\
do {							\
  unsigned char __tmp[SILC_SCREEN_INPUT_WIN_SIZE + 1];	\
  memcpy(__tmp, &(__x)[(__y)], (__end) - (__y));	\
  (__x)[(__y)] = __ch;					\
  memcpy(&(__x)[(__y) + 1], __tmp, (__end) - (__y));	\
} while(0)

/* Macro used to delete character from the buffer. The character
   is not removed from the end of the buffer but somewhere in between. */
#define SILC_SCREEN_INPUT_DELETE(__x, __y, __end)	\
do {							\
  unsigned char __tmp[SILC_SCREEN_INPUT_WIN_SIZE + 1];	\
  memcpy(__tmp, &(__x)[(__y) + 1], (__end));		\
  memset(&(__x)[(__y)], 0, (__end) - (__y) + 1);	\
  memcpy(&(__x)[(__y)], __tmp, strlen(__tmp));		\
} while(0)

/* Prototypes */
SilcScreen silc_screen_init();
WINDOW *silc_screen_create_output_window(SilcScreen screen);
WINDOW *silc_screen_add_output_window(SilcScreen screen);
void silc_screen_create_input_window(SilcScreen screen);
void silc_screen_init_upper_status_line(SilcScreen screen);
void silc_screen_print_upper_stat_line(SilcScreen screen);
void silc_screen_init_output_status_line(SilcScreen screen);
void silc_screen_print_clock(SilcScreen screen);
void silc_screen_print_coordinates(SilcScreen screen, int win_index);
void silc_screen_print_bottom_line(SilcScreen screen, int win_index);
void silc_screen_refresh_all(SilcScreen screen);
void silc_screen_refresh_win(WINDOW *win);
void silc_screen_input_reset(SilcScreen screen);
void silc_screen_input_backspace(SilcScreen screen);
void silc_screen_input_insert(SilcScreen screen);
void silc_screen_input_cursor_right(SilcScreen screen);
void silc_screen_input_cursor_left(SilcScreen screen);
void silc_screen_input_cursor_home(SilcScreen screen);
void silc_screen_input_cursor_end(SilcScreen screen);
void silc_screen_input_print(SilcScreen screen, unsigned char c);
void silc_screen_input_print_prompt(SilcScreen screen, char *prompt);

#endif
