/*

  client.c

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
 * $Id$
 * $Log$
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Importet from internal CVS/Added Log headers.
 *
 *
 */

#include "clientincludes.h"

/* Internal routine used to print lines to window. This can split the
   line neatly if a word would overlap the line. */

static void silc_print_to_window(WINDOW *win, char *message)
{
  int str_len, len;

  str_len = strlen(message);
 
  if (str_len > COLS - 1) {
    /* Split overlapping words to next line */
    /* XXX In principal this is wrong as this modifies the original
       string as it replaces the last ' ' with '\n'. This could be done
       with little more work so that it would not replace anything. */
    len = COLS - 1;
    while (1) {

      while (len && message[len] != ' ')
	len--;

      if (!len)
	break;

      message[len] = '\n';
      len += COLS - 1;
      if (len > str_len)
	break;
    }
  }

  wprintw(win, "%s", message);
  wrefresh(win);
}

/* Prints a message with three star (*) sign before the actual message
   on the current output window. This is used to print command outputs
   and error messages. */
/* XXX Change to accept SilcClientWindow and use output window 
   from there (the pointer to the output window must be added to the
   SilcClientWindow object. */

void silc_say(SilcClient client, char *msg, ...)
{
  va_list vp;
  char message[1024];
  
  memset(message, 0, sizeof(message));
  strncat(message, "\n***  ", 5);

  va_start(vp, msg);
  vsprintf(message + 5, msg, vp);
  va_end(vp);
  
  /* Print the message */
  silc_print_to_window(client->screen->output_win[0], message);
}

/* Prints message to the screen. This is used to print the messages
   user is typed and message that came on channels. */

void silc_print(SilcClient client, char *msg, ...)
{
  va_list vp;
  char message[1024];
  
  memset(message, 0, sizeof(message));
  strncat(message, "\n ", 2);

  va_start(vp, msg);
  vsprintf(message + 1, msg, vp);
  va_end(vp);
  
  /* Print the message */
  silc_print_to_window(client->screen->output_win[0], message);
}

/* Returns user's mail path */

char *silc_get_mail_path()
{
  char pathbuf[MAXPATHLEN];
  char *path;
  
  if ((path = (char *)getenv("MAIL")) != 0) {
    strncpy(pathbuf, path, strlen(path));
  } else {
    strcpy(pathbuf, _PATH_MAILDIR);
    strcat(pathbuf, "/");
    strcat(pathbuf, silc_get_username());
  }

  return strdup(pathbuf);
}

/* gets the number of the user's mails, if possible */

int silc_get_number_of_emails()
{
  FILE *tl;
  int num = 0;
  char *filename;
  char data[1024];
  
  filename = silc_get_mail_path();
  
  tl = fopen(filename, "r");
  if (!tl) {
    fprintf(stderr, "Couldn't open mail file (%s).\n", filename);
  } else {
    while((fscanf(tl, "%s", data)) != EOF) { 
      if(!strcmp(data, "Subject:"))
	num++;
    }
    
    fclose(tl);
  }
  
  return num;
}

/* Returns the username of the user. If the global variable LOGNAME
   does not exists we will get the name from the password file. */

char *silc_get_username()
{
  char *logname = NULL;
  
  logname = strdup(getenv("LOGNAME"));
  if (!logname) {
    logname = getlogin();
    if (!logname) {
      struct passwd *pw;

      pw = getpwuid(getuid());
      if (!pw) {
	fprintf(stderr, "silc_get_username: %s\n", strerror(errno));
	return NULL;
      }
      
      logname = strdup(pw->pw_name);
    }
  }
  
  return logname;
}                          

/* Returns the real name of ther user. */

char *silc_get_real_name()
{
  char *realname = NULL;
  struct passwd *pw;
    
  pw = getpwuid(getuid());
  if (!pw) {
    fprintf(stderr, "silc_get_username: %s\n", strerror(errno));
    return NULL;
  }

  if (strchr(pw->pw_gecos, ','))
    *strchr(pw->pw_gecos, ',') = 0;

  realname = strdup(pw->pw_gecos);

  return realname;
}

/* Returns time til next minute changes. Used to update the clock when
   needed. */

int silc_client_time_til_next_min()
{
  time_t curtime;
  struct tm *min;
  
  curtime = time(0);
  min = localtime(&curtime);
  
  return 60 - min->tm_sec;
}

/* Asks passphrase from user on the input line. */

char *silc_client_ask_passphrase(SilcClient client)
{
  char pass1[256], pass2[256];
  char *ret;
  int try = 3;

  while(try) {

    /* Print prompt */
    wattroff(client->screen->input_win, A_INVIS);
    silc_screen_input_print_prompt(client->screen, "Passphrase: ");
    wattron(client->screen->input_win, A_INVIS);
    
    /* Get string */
    memset(pass1, 0, sizeof(pass1));
    wgetnstr(client->screen->input_win, pass1, sizeof(pass1));
    
    /* Print retype prompt */
    wattroff(client->screen->input_win, A_INVIS);
    silc_screen_input_print_prompt(client->screen, "Retype passphrase: ");
    wattron(client->screen->input_win, A_INVIS);
    
    /* Get string */
    memset(pass2, 0, sizeof(pass2));
    wgetnstr(client->screen->input_win, pass2, sizeof(pass2));

    if (!strncmp(pass1, pass2, strlen(pass2)))
      break;

    try--;
  }

  ret = silc_calloc(strlen(pass1), sizeof(char));
  memcpy(ret, pass1, strlen(pass1));

  memset(pass1, 0, sizeof(pass1));
  memset(pass2, 0, sizeof(pass2));

  wattroff(client->screen->input_win, A_INVIS);
  silc_screen_input_reset(client->screen);

  return ret;
}

/* Lists supported (builtin) ciphers */

void silc_client_list_ciphers()
{

}

/* Lists supported (builtin) hash functions */

void silc_client_list_hash_funcs()
{

}

/* Lists supported PKCS algorithms */

void silc_client_list_pkcs()
{

}

/* Displays input prompt on command line and takes input data from user */

char *silc_client_get_input(const char *prompt)
{
  char input[2048];
  int fd;

  fd = open("/dev/tty", O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "silc: %s\n", strerror(errno));
    exit(1);
  }

  memset(input, 0, sizeof(input));

  printf("%s", prompt);
  fflush(stdout);

  if ((read(fd, input, sizeof(input))) < 0) {
    fprintf(stderr, "silc: %s\n", strerror(errno));
    exit(1);
  }

  if (strlen(input) <= 1)
    return NULL;

  if (strchr(input, '\n'))
    *strchr(input, '\n') = '\0';

  return strdup(input);
}

/* Displays prompt on command line and takes passphrase with echo 
   off from user. */

char *silc_client_get_passphrase(const char *prompt)
{
#if 0
  char input[2048];
  char *ret;
  int fd;
  struct termios to;
  struct termios to_old;

  fd = open("/dev/tty", O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "silc: %s\n", strerror(errno));
    exit(1);
  }

  signal(SIGINT, SIG_IGN);

  /* Get terminal info */
  tcgetattr(fd, &to);
  to_old = to;

  /* Echo OFF */
  to.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
  tcsetattr(fd, TCSANOW, &to);

  memset(input, 0, sizeof(input));

  printf("%s", prompt);
  fflush(stdout);

  if ((read(fd, input, sizeof(input))) < 0) {
    fprintf(stderr, "silc: %s\n", strerror(errno));
    exit(1);
  }

  if (strlen(input) <= 1) {
    tcsetattr(fd, TCSANOW, &to_old);
    return NULL;
  }

  if (strchr(input, '\n'))
    *strchr(input, '\n') = '\0';

  /* Restore old terminfo */
  tcsetattr(fd, TCSANOW, &to_old);
  signal(SIGINT, SIG_DFL);

  ret = silc_calloc(strlen(input), sizeof(char));
  memcpy(ret, input, strlen(input));
  memset(input, 0, sizeof(input));
  return ret;
#else
  return NULL;
#endif
}

/* Creates new public key and private key pair. This is used only
   when user wants to create new key pair from command line. */

void silc_client_create_key_pair(char *pkcs_name, int bits)
{
  SilcPKCS pkcs;
  SilcRng rng;
  unsigned char *key;
  unsigned int key_len;
  char *pkfile = NULL, *prvfile = NULL;

  printf("\
New pair of keys will be created.  Please, answer to following questions.\n\
");

  if (!pkcs_name) {
  again_name:
    pkcs_name = 
      silc_client_get_input("PKCS name (l to list names) [rsa]: ");
    if (!pkcs_name)
      pkcs_name = strdup("rsa");

    if (*pkcs_name == 'l' || *pkcs_name == 'L') {
      silc_client_list_pkcs();
      silc_free(pkcs_name);
      goto again_name;
    }
  }

  if (!bits) {
    char *length = NULL;
    length = 
      silc_client_get_input("Key length in bits [1024]: ");
    if (!length)
      bits = 1024;
    else
      bits = atoi(length);
  }

  rng = silc_rng_alloc();
  silc_rng_init(rng);
  silc_math_primegen_init();

 again_pk:
  pkfile = silc_client_get_input("Public key filename: ");
  if (!pkfile) {
    printf("Public key filename must be defined\n");
    goto again_pk;
  }

 again_prv:
  prvfile = silc_client_get_input("Private key filename: ");
  if (!prvfile) {
    printf("Private key filename must be defined\n");
    goto again_prv;
  }

  /* Generate keys */
  silc_pkcs_alloc(pkcs_name, &pkcs);
  pkcs->pkcs->init(pkcs->context, bits, rng);

  /* Save keys into file */
  key = silc_pkcs_get_public_key(pkcs, &key_len);
  silc_pkcs_save_public_key(pkcs, pkfile, key, key_len);
  memset(key, 0, sizeof(key_len));
  silc_free(key);
  key = silc_pkcs_get_private_key(pkcs, &key_len);
  silc_pkcs_save_private_key(pkcs, prvfile, key, key_len, "");
  memset(key, 0, sizeof(key_len));
  silc_free(key);

  silc_math_primegen_uninit();
  silc_rng_free(rng);
  silc_pkcs_free(pkcs);
}
