/*

  screen.c

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
/*
 * SILC client screen routines. These implement the user interface
 * on ncurses routines. Most of these routines were taken from the
 * old version of the SILC client dating back to 1997.
 */
/* XXX: Input line handling is really buggy! */
/*
 * $Id$
 * $Log$
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Importet from internal CVS/Added Log headers.
 *
 *
 */

#include "clientincludes.h"

SilcScreen silc_screen_init()
{
  SilcScreen new;

  new = silc_malloc(sizeof(*new));
  if (new == NULL) {
    SILC_LOG_ERROR(("Could not create new screen object"));
    return NULL;
  }

  new->output_win_count = 0;
  new->input_pos = 0;
  new->cursor_pos = 0;
  new->virtual_window = 0;
  new->insert = TRUE;

  initscr();
  cbreak();
  nonl();
  noecho();

  silc_screen_create_output_window(new);
  silc_screen_create_input_window(new);

  return new;
}

/* Creates one (main) output window. Returns new created physical 
   window. */

WINDOW *silc_screen_create_output_window(SilcScreen screen)
{
  assert(screen != NULL);

  screen->output_win = silc_malloc(sizeof(*screen->output_win) * 1);
  screen->output_win_count = 1;
  screen->output_win[0] = newwin(LINES - 3, COLS, 1, 0);
  scrollok(screen->output_win[0], TRUE);
  idlok(screen->output_win[0], TRUE);
  wrefresh(screen->output_win[0]);

  return screen->output_win[0];
}

/* Adds new output window. Return new created physical window. */

WINDOW *silc_screen_add_output_window(SilcScreen screen)
{
  int i;

  assert(screen != NULL);

  screen->output_win = silc_realloc(screen->output_win, 
				    (screen->output_win_count + 1) *
				    sizeof(*screen->output_win));
  i = screen->output_win_count;
  screen->output_win[i] = newwin(LINES - 3, COLS, 1, 0);
  scrollok(screen->output_win[i], TRUE);
  idlok(screen->output_win[i], TRUE);
  wrefresh(screen->output_win[i]);
  screen->output_win_count++;

  return screen->output_win[i];
}

void silc_screen_create_input_window(SilcScreen screen)
{
  assert(screen != NULL);

  screen->input_win = newwin(0, COLS, LINES - 1, 0);
  scrollok(screen->input_win, TRUE);
  keypad(screen->input_win, TRUE);
  wrefresh(screen->input_win);
}

void silc_screen_init_upper_status_line(SilcScreen screen)
{
  int i;
  int justify;
  
  assert(screen != NULL);

  /* Create upper status line */
  screen->upper_stat_line = newwin(0, COLS, 0, 0);
  scrollok(screen->upper_stat_line, FALSE);
  wattrset(screen->upper_stat_line, A_REVERSE);
  
  /* Print empty line */
  for (i = 0; i < COLS - 1; i++)
    mvwprintw(screen->upper_stat_line, 0, i, " ");
  
  /* Print stuff with justify */
  justify = COLS / 5;
  mvwprintw(screen->upper_stat_line, 0, 1, "%s %s", 
	    screen->u_stat_line.program_name, 
	    screen->u_stat_line.program_version);
  /*
  mvwprintw(screen->upper_stat_line, 0, justify, "[Your Connection: %s]", 
	    stat.uconnect_status[stat.uconnect]);
  mvwprintw(screen->upper_stat_line, 0, 
	    (justify + justify + justify), "[SILC: %s]", 
	    stat.silc_status[stat.silc]);
  */

  /* Prints clock on upper stat line */	
  silc_screen_print_clock(screen);
  wrefresh(screen->upper_stat_line);
}

void silc_screen_init_output_status_line(SilcScreen screen)
{
  int i;

  assert(screen != NULL);

  screen->output_stat_line = silc_calloc(1, sizeof(*screen->output_stat_line));
  
  screen->output_stat_line[0] = newwin(1, COLS, LINES - 2, 0);
  scrollok(screen->output_stat_line[0], FALSE);
  wattrset(screen->output_stat_line[0], A_REVERSE);
  
  /* print first just blank line */
  for (i = 0; i < COLS - 1; i++)
    mvwprintw(screen->output_stat_line[0], 0, i, " ");

  /* Allocate bottom line */
  screen->bottom_line = silc_calloc(1, sizeof(*screen->bottom_line));

  wattrset(screen->output_stat_line[0], A_NORMAL);
  wrefresh(screen->output_stat_line[0]);
}

void silc_screen_print_clock(SilcScreen screen)
{
  time_t curtime;
  struct tm *tp;

  curtime = time(0);
  tp = localtime(&curtime);

  mvwprintw(screen->upper_stat_line, 0, COLS - 8, "[%02d:%02d] ", 
	    tp->tm_hour, tp->tm_min);
  wrefresh(screen->upper_stat_line);
}

/* Prints current cursor coordinates on some output stat line */

void silc_screen_print_coordinates(SilcScreen screen, int win_index)
{
  wattrset(screen->output_stat_line[win_index], A_REVERSE);
  mvwprintw(screen->output_stat_line[win_index], 0, COLS - 10,
	    "[%4d,%3d]", screen->input_pos, LINES);
  wrefresh(screen->output_stat_line[win_index]);
  wattrset(screen->output_stat_line[win_index], A_NORMAL);
}

/* Prints bottom line (the status line) of the screen. */

void silc_screen_print_bottom_line(SilcScreen screen, int win_index)
{
  char buf[512];
  SilcScreenBottomLine line = screen->bottom_line;
  int i, len;

  memset(buf, 0, sizeof(buf));

  if (line->mode) {
    len = strlen(line->mode);
    strncat(buf, line->mode, len);
  }

  if (line->nickname) {
    len = strlen(line->nickname);
    strncat(buf, line->nickname, len > SILC_SCREEN_MAX_NICK_LEN ? 
	    SILC_SCREEN_MAX_NICK_LEN : len);
  }

  if (line->connection) {
    len = strlen(line->connection);
    strncat(buf, " via ", 5);
    strncat(buf, line->connection, len > SILC_SCREEN_MAX_CONN_LEN ? 
	    SILC_SCREEN_MAX_CONN_LEN : len);
  }

  if (line->channel) {
    len = strlen(line->channel);
    strncat(buf, " ", 1);
    strncat(buf, line->channel, len > SILC_SCREEN_MAX_CHANNEL_LEN ?
	    SILC_SCREEN_MAX_CHANNEL_LEN : len);
  }

  wattrset(screen->output_stat_line[win_index], A_REVERSE);

  for (i = 0; i < COLS - 10; i++)
    mvwprintw(screen->output_stat_line[win_index], 0, i, " ");

  mvwprintw(screen->output_stat_line[win_index], 0, 0, " %s", buf);
  silc_screen_print_coordinates(screen, win_index);
  wrefresh(screen->output_stat_line[win_index]);
  wattrset(screen->output_stat_line[win_index], A_NORMAL);
}

/* Refresh all windows */

void silc_screen_refresh_all(SilcScreen screen)
{
  int i;

  assert(screen != NULL);

  redrawwin(screen->upper_stat_line);

  for (i = 0; i < screen->output_win_count; i++) {
    wrefresh(screen->output_win[i]);
    redrawwin(screen->output_win[i]);
  }

  wrefresh(screen->input_win);
  redrawwin(screen->input_win);
}

/* Refreshes a window */

void silc_screen_refresh_win(WINDOW *win)
{
  assert(win != NULL);

  redrawwin(win);
  wrefresh(win);
}

/* Resets input window */

void silc_screen_input_reset(SilcScreen screen)
{
  int i;

  assert(screen != NULL);
  for (i = 0; i < COLS - 1; i++)
    mvwprintw(screen->input_win, 0, i, " ");
  mvwprintw(screen->input_win, 0, 0, "");
  wrefresh(screen->input_win);
  screen->input_pos = 0;
  screen->input_end = 0;
  screen->cursor_pos = 0;
  screen->virtual_window = 0;
}

/* Backspace. Removes one character from input windows. */

void silc_screen_input_backspace(SilcScreen screen)
{
  WINDOW *win;
  char *buffer;

  assert(screen != NULL);
  buffer = screen->input_buffer;
  win = screen->input_win;

  /* Return directly if at the start of input line */
  if (screen->input_pos == 0)
    return;

  if (screen->virtual_window) {
    if (screen->cursor_pos <= 10) {
      int i;

      /* Clear line */
      for (i = 0; i < COLS; i++)
        mvwprintw(win, 0, i, " ");
      mvwprintw(win, 0, 0, "");

      screen->virtual_window--;
      
      waddnstr(win, &buffer[screen->virtual_window * (COLS - 5)], COLS);
      screen->input_pos = ((screen->virtual_window + 1) * (COLS - 5)) + 1;
      screen->input_end = ((screen->virtual_window + 1) * (COLS - 5)) + 1;
      screen->cursor_pos = (COLS - 5) + 1;
      wrefresh(win);
    }
  }

  screen->cursor_pos--;
  screen->input_pos--;
  screen->input_end--;
  mvwdelch(win, 0, screen->cursor_pos);

  if (screen->input_pos < screen->input_end)
    /* Delete from inside the input line */
    SILC_SCREEN_INPUT_DELETE(buffer, screen->input_pos, screen->input_end);
  else
    /* Delete from the end of the input line */
    buffer[screen->input_pos] = 0;

  wrefresh(win);
}

/* Switches insert on input window on/off */

void silc_screen_input_insert(SilcScreen screen)
{
  assert(screen != NULL);

  screen->insert = screen->insert == TRUE ? FALSE : TRUE;
}

/* Moves cursor one character length to rightward */

void silc_screen_input_cursor_right(SilcScreen screen)
{
  WINDOW *win;
  char *buffer;

  assert(screen != NULL);
  buffer = screen->input_buffer;
  win = screen->input_win;

  /* Return directly if we are at the end of input line */
  if (screen->cursor_pos >= SILC_SCREEN_INPUT_WIN_SIZE)
    return;

  /* Make sure cursor doesn't advance over the end of the line */
  if (screen->input_pos >= screen->input_end)
    return;

  /* When cursor advances enough we switch to new window and show
     rest of the typed characters on the screen. */
  if (screen->cursor_pos >= (COLS - 5)) {
    int i;

    /* Clear line */
    for (i = 0; i < COLS; i++)
      mvwprintw(win, 0, i, " ");
    mvwprintw(win, 0, 0, "");

    waddnstr(win, &buffer[screen->input_pos - 10], 
	     ((screen->input_pos - 10) - screen->input_end >= COLS) ?
	     COLS : (screen->input_pos - 10) - screen->input_end);
    screen->cursor_pos = 10;
    wrefresh(win);

    screen->virtual_window++;
  }

  screen->cursor_pos++;
  screen->input_pos++;
  wmove(win, 0, screen->cursor_pos);
  wrefresh(win);
}

/* Moves cursor one character length to leftward */

void silc_screen_input_cursor_left(SilcScreen screen)
{
  WINDOW *win;
  char *buffer;

  assert(screen != NULL);
  buffer = screen->input_buffer;
  win = screen->input_win;

  /* Return directly if at the start of input line */
  if (screen->input_pos == 0)
    return;

  /* When cursor advances enough we switch to new window and show
     rest of the typed characters on the screen. */
  if (screen->virtual_window) {
    if (screen->cursor_pos <= 10) {
      int i;

      /* Clear line */
      for (i = 0; i < COLS; i++)
        mvwprintw(win, 0, i, " ");
      mvwprintw(win, 0, 0, "");

      screen->virtual_window--;
      
      waddnstr(win, &buffer[screen->virtual_window * (COLS - 5)], COLS);
      screen->input_pos = ((screen->virtual_window + 1) * (COLS - 5)) + 1;
      screen->cursor_pos = (COLS - 5) + 1;
      wrefresh(win);
    }
  }

  screen->cursor_pos--;
  screen->input_pos--;
  wmove(win, 0, screen->cursor_pos);
  wrefresh(win);
}

/* Moves cursor at the very start of the input line */

void silc_screen_input_cursor_home(SilcScreen screen)
{
  WINDOW *win;
  char *buffer;

  assert(screen != NULL);
  buffer = screen->input_buffer;
  win = screen->input_win;

  wclear(win);
  waddnstr(win, &buffer[0], COLS);
  wrefresh(win);

  screen->input_pos = 0;
  screen->cursor_pos = 0;
  screen->virtual_window = 0;
}

/* Moves cursor at the very end of the input line */

void silc_screen_input_cursor_end(SilcScreen screen)
{
  WINDOW *win;
  char *buffer;

  assert(screen != NULL);
  buffer = screen->input_buffer;
  win = screen->input_win;

  wclear(win);
  waddnstr(win, &buffer[screen->input_end - 10], 10);
  wrefresh(win);

  screen->input_pos = screen->input_end;
  screen->cursor_pos = 10;
  /* XXX */
  screen->virtual_window = 0;
}

/* Prints typed character into the input window for user to see. Character 
   attributes must be set separately outside this function. */

void silc_screen_input_print(SilcScreen screen, unsigned char c)
{
  WINDOW *win;
  char *buffer;

  assert(screen != NULL);
  buffer = screen->input_buffer;
  win = screen->input_win;

  /* Return directly if input window is full */
  if (screen->input_pos >= SILC_SCREEN_INPUT_WIN_SIZE)
    return;

  /* The input window is COLS wide but one can type into it at most
     SILC_SCREEN_INPUT_SIZE characters. When COLS - 5 characters is
     typed the window is cleared and the cursor is moved at the tenth
     character in the input window. Ten last typed character is then
     showed at the start of the window. */
  if (screen->cursor_pos >= (COLS - 5)) {
    int i;

    /* Clear line */
    for (i = 0; i < COLS; i++)
      mvwprintw(win, 0, i, " ");
    mvwprintw(win, 0, 0, "");

    /* Show ten last typed characters from the buffer on the screen */
    waddnstr(win, &buffer[screen->input_pos - 10], 10);
    screen->cursor_pos = 10;
    wrefresh(win);

    screen->virtual_window++;
  }

  if (screen->input_pos < screen->input_end) {
    /* User moved cursor into the typed line. We are not adding 
       character at the end of the line anymore */

    if (screen->insert == FALSE) {
      /* Add new character somewhere inside typed line. The input
	 line position is not advanced since a character was replaced
	 by the new character. */
      waddch(win, c);
      buffer[screen->input_pos] = c;
      screen->cursor_pos++;
      screen->input_pos++;
      screen->input_end = screen->input_pos;
    } else {
      /* Insert new character somewhere inside typed line. Other
	 characters are moved forward. We must advance the input line
	 posititon. */
      winsch(win, c);
      wmove(win, 0, screen->cursor_pos + 1);
      SILC_SCREEN_INPUT_INSERT(buffer, screen->input_pos, 
			       c, screen->input_end);
      screen->cursor_pos++;
      screen->input_pos++;
      screen->input_end++;
    }
  } else {
    /* Add new character at the end of input line */
    waddch(win, c);
    buffer[screen->input_pos] = c;
    screen->input_pos++;
    screen->cursor_pos++;
    screen->input_end = screen->input_pos;
  }

  /* Advance the cursor position. Cursor moves one to rightward always */
  wrefresh(win);
}

/* Prints prompt to the input window. Cursors position aftern printing
   is length of the prompt. */

void silc_screen_input_print_prompt(SilcScreen screen, char *prompt)
{
  WINDOW *win;

  assert(screen != NULL);
  win = screen->input_win;

  wclear(win);
  waddnstr(win, prompt, strlen(prompt));
  wrefresh(win);

  screen->input_pos = strlen(prompt);
  screen->cursor_pos = strlen(prompt);
  screen->virtual_window = 0;
}
