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
/* $Id$ */

#include "clientincludes.h"

/* Routine used to print lines to window. This can split the
   line neatly if a word would overlap the line. */

void silc_print_to_window(WINDOW *win, char *message)
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

/* Prints message to the screen. This is used to print the messages
   user is typed and message that came on channels. */

void silc_print(SilcClient client, char *msg, ...)
{
  va_list vp;
  char message[2048];
  SilcClientInternal app = client->application;
  
  memset(message, 0, sizeof(message));
  strncat(message, "\n ", 2);

  va_start(vp, msg);
  vsprintf(message + 1, msg, vp);
  va_end(vp);
  
  /* Print the message */
  silc_print_to_window(app->screen->output_win[0], message);
}

/* Returns user's mail path */

char *silc_get_mail_path()
{
  char pathbuf[MAXPATHLEN];
  char *path;

#ifndef _PATH_MAILDIR
#define _PATH_MAILDIR "/var/mail"
#endif
  
  path = getenv("MAIL");
  if (path) {
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
      if(!strcmp(data, "From:"))
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

/* Asks yes/no from user on the input line. Returns TRUE on "yes" and
   FALSE on "no". */

int silc_client_ask_yes_no(SilcClient client, char *prompt)
{
  SilcClientInternal app = (SilcClientInternal)client->application;
  char answer[4];
  int ret;

 again:
  silc_screen_input_reset(app->screen);

  /* Print prompt */
  wattroff(app->screen->input_win, A_INVIS);
  silc_screen_input_print_prompt(app->screen, prompt);

  /* Get string */
  memset(answer, 0, sizeof(answer));
  echo();
  wgetnstr(app->screen->input_win, answer, sizeof(answer));
  if (!strncasecmp(answer, "yes", strlen(answer)) ||
      !strncasecmp(answer, "y", strlen(answer))) {
    ret = TRUE;
  } else if (!strncasecmp(answer, "no", strlen(answer)) ||
	     !strncasecmp(answer, "n", strlen(answer))) {
    ret = FALSE;
  } else {
    silc_say(client, app->conn, "Type yes or no");
    goto again;
  }
  noecho();

  silc_screen_input_reset(app->screen);

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
    return NULL;
  }

  memset(input, 0, sizeof(input));

  printf("%s", prompt);
  fflush(stdout);

  if ((read(fd, input, sizeof(input))) < 0) {
    fprintf(stderr, "silc: %s\n", strerror(errno));
    return NULL;
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
    return NULL;
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
    return NULL;
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

/* Returns identifier string for public key generation. */

char *silc_client_create_identifier()
{
  char *username = NULL, *realname = NULL;
  char hostname[256], email[256];
  
  /* Get realname */
  realname = silc_get_real_name();

  /* Get hostname */
  memset(hostname, 0, sizeof(hostname));
  gethostname(hostname, sizeof(hostname));

  /* Get username (mandatory) */
  username = silc_get_username();
  if (!username)
    return NULL;

  /* Create default email address, whether it is right or not */
  snprintf(email, sizeof(email), "%s@%s", username, hostname);

  return silc_pkcs_encode_identifier(username, hostname, realname, email,
				     NULL, NULL);
}

/* Creates new public key and private key pair. This is used only
   when user wants to create new key pair from command line. */

int silc_client_create_key_pair(char *pkcs_name, int bits,
				char *public_key, char *private_key,
				char *identifier, 
				SilcPublicKey *ret_pub_key,
				SilcPrivateKey *ret_prv_key)
{
  SilcPKCS pkcs;
  SilcPublicKey pub_key;
  SilcPrivateKey prv_key;
  SilcRng rng;
  unsigned char *key;
  unsigned int key_len;
  char line[256];
  char *pkfile = NULL, *prvfile = NULL;

  if (!pkcs_name || !public_key || !private_key)
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

  if (!silc_pkcs_is_supported(pkcs_name)) {
    fprintf(stderr, "Unsupported PKCS `%s'", pkcs_name);
    return FALSE;
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

  if (!identifier) {
    char *def = silc_client_create_identifier();

    memset(line, 0, sizeof(line));
    if (def)
      snprintf(line, sizeof(line), "Identifier [%s]: ", def);
    else
      snprintf(line, sizeof(line),
	       "Identifier (eg. UN=jon, HN=jon.dummy.com, "
	       "RN=Jon Johnson, E=jon@dummy.com): ");

    while (!identifier) {
      identifier = silc_client_get_input(line);
      if (!identifier && def)
	identifier = strdup(def);
    }

    if (def)
      silc_free(def);
  }

  rng = silc_rng_alloc();
  silc_rng_init(rng);
  silc_math_primegen_init();

  if (!public_key) {
    memset(line, 0, sizeof(line));
    snprintf(line, sizeof(line), "Public key filename [%s] ", 
	     SILC_CLIENT_PUBLIC_KEY_NAME);
    pkfile = silc_client_get_input(line);
    if (!pkfile)
      pkfile = SILC_CLIENT_PUBLIC_KEY_NAME;
  } else {
    pkfile = public_key;
  }

  if (!private_key) {
    memset(line, 0, sizeof(line));
    snprintf(line, sizeof(line), "Public key filename [%s] ", 
	     SILC_CLIENT_PRIVATE_KEY_NAME);
    prvfile = silc_client_get_input(line);
    if (!prvfile)
      prvfile = SILC_CLIENT_PRIVATE_KEY_NAME;
  } else {
    prvfile = private_key;
  }

  /* Generate keys */
  silc_pkcs_alloc(pkcs_name, &pkcs);
  pkcs->pkcs->init(pkcs->context, bits, rng);

  /* Save public key into file */
  key = silc_pkcs_get_public_key(pkcs, &key_len);
  pub_key = silc_pkcs_public_key_alloc(pkcs->pkcs->name, identifier,
				       key, key_len);
  silc_pkcs_save_public_key(pkfile, pub_key, SILC_PKCS_FILE_PEM);
  if (ret_pub_key)
    *ret_pub_key = pub_key;

  memset(key, 0, sizeof(key_len));
  silc_free(key);

  /* Save private key into file */
  key = silc_pkcs_get_private_key(pkcs, &key_len);
  prv_key = silc_pkcs_private_key_alloc(pkcs->pkcs->name, key, key_len);

  silc_pkcs_save_private_key(prvfile, prv_key, NULL, SILC_PKCS_FILE_BIN);
  if (ret_prv_key)
    *ret_prv_key = prv_key;

  printf("Public key has been save into `%s'.\n", pkfile);
  printf("Private key has been saved into `%s'.\n", prvfile);
  printf("Press <Enter> to continue...\n");
  getchar();

  memset(key, 0, sizeof(key_len));
  silc_free(key);

  silc_math_primegen_uninit();
  silc_rng_free(rng);
  silc_pkcs_free(pkcs);

  return TRUE;
}

/* This checks stats for various SILC files and directories. First it 
   checks if ~/.silc directory exist and is owned by the correct user. If 
   it doesn't exist, it will create the directory. After that it checks if
   user's Public and Private key files exists and that they aren't expired.
   If they doesn't exist or they are expired, they will be (re)created
   after return. */

int silc_client_check_silc_dir()
{
  char filename[256], file_public_key[256], file_private_key[256];
  char servfilename[256];
  char *identifier;
  struct stat st;
  struct passwd *pw;
  int firstime = FALSE;
  time_t curtime, modtime;

  SILC_LOG_DEBUG(("Checking ~./silc directory"));

  memset(filename, 0, sizeof(filename));
  memset(file_public_key, 0, sizeof(file_public_key));
  memset(file_private_key, 0, sizeof(file_private_key));

  pw = getpwuid(getuid());
  if (!pw) {
    fprintf(stderr, "silc: %s\n", strerror(errno));
    return FALSE;
  }

  identifier = silc_client_create_identifier();

  /* We'll take home path from /etc/passwd file to be sure. */
  snprintf(filename, sizeof(filename) - 1, "%s/.silc/", pw->pw_dir);
  snprintf(servfilename, sizeof(servfilename) - 1, "%s/.silc/serverkeys", 
	   pw->pw_dir);

  /*
   * Check ~/.silc directory
   */
  if ((stat(filename, &st)) == -1) {
    /* If dir doesn't exist */
    if (errno == ENOENT) {
      if (pw->pw_uid == geteuid()) {
	if ((mkdir(filename, 0755)) == -1) {
	  fprintf(stderr, "Couldn't create `%s' directory\n", filename);
	  return FALSE;
	}

	/* Directory was created. First time running SILC */
	firstime = TRUE;
      } else {
	fprintf(stderr, "Couldn't create `%s' directory due to a wrong uid!\n",
		filename);
	return FALSE;
      }
    } else {
      fprintf(stderr, "%s\n", strerror(errno));
      return FALSE;
    }
  } else {
    
    /* Check the owner of the dir */
    if (st.st_uid != 0 && st.st_uid != pw->pw_uid) { 
      fprintf(stderr, "You don't seem to own `%s' directory\n",
	      filename);
      return FALSE;
    }
    
    /* Check the permissions of the dir */
    if ((st.st_mode & 0777) != 0755) {
      if ((chmod(filename, 0755)) == -1) {
	fprintf(stderr, "Permissions for `%s' directory must be 0755\n", 
		filename);
	return FALSE;
      }
    }
  }

  /*
   * Check ~./silc/serverkeys directory
   */
  if ((stat(servfilename, &st)) == -1) {
    /* If dir doesn't exist */
    if (errno == ENOENT) {
      if (pw->pw_uid == geteuid()) {
	if ((mkdir(servfilename, 0755)) == -1) {
	  fprintf(stderr, "Couldn't create `%s' directory\n", servfilename);
	  return FALSE;
	}
      } else {
	fprintf(stderr, "Couldn't create `%s' directory due to a wrong uid!\n",
		servfilename);
	return FALSE;
      }
    } else {
      fprintf(stderr, "%s\n", strerror(errno));
      return FALSE;
    }
  }
  
  /*
   * Check Public and Private keys
   */
  snprintf(file_public_key, sizeof(file_public_key) - 1, "%s%s", 
	   filename, SILC_CLIENT_PUBLIC_KEY_NAME);
  snprintf(file_private_key, sizeof(file_private_key) - 1, "%s%s", 
	   filename, SILC_CLIENT_PRIVATE_KEY_NAME);
  
  /* If running SILC first time */
  if (firstime) {
    fprintf(stdout, "Running SILC for the first time\n");
    silc_client_create_key_pair(SILC_CLIENT_DEF_PKCS, 
				SILC_CLIENT_DEF_PKCS_LEN,
				file_public_key, file_private_key, 
				identifier, NULL, NULL);
    return TRUE;
  }
  
  if ((stat(file_public_key, &st)) == -1) {
    /* If file doesn't exist */
    if (errno == ENOENT) {
      fprintf(stdout, "Your public key doesn't exist\n");
      silc_client_create_key_pair(SILC_CLIENT_DEF_PKCS, 
				  SILC_CLIENT_DEF_PKCS_LEN,
				  file_public_key, 
				  file_private_key, identifier, NULL, NULL);
    } else {
      fprintf(stderr, "%s\n", strerror(errno));
      return FALSE;
    }
  }

  if ((stat(file_private_key, &st)) == -1) {
    /* If file doesn't exist */
    if (errno == ENOENT) {
      fprintf(stdout, "Your private key doesn't exist\n");
      silc_client_create_key_pair(SILC_CLIENT_DEF_PKCS, 
				  SILC_CLIENT_DEF_PKCS_LEN,
				  file_public_key, 
				  file_private_key, identifier, NULL, NULL);
    } else {
      fprintf(stderr, "%s\n", strerror(errno));
      return FALSE;
    }
  }
    
  /* Check the owner of the public key */
  if (st.st_uid != 0 && st.st_uid != pw->pw_uid) { 
    fprintf(stderr, "You don't seem to own your public key!?\n");
    return FALSE;
  }
  
  /* Check the owner of the private key */
  if (st.st_uid != 0 && st.st_uid != pw->pw_uid) { 
    fprintf(stderr, "You don't seem to own your private key!?\n");
    return FALSE;
  }
    
  /* Check the permissions for the private key */
  if ((st.st_mode & 0777) != 0600) {
    fprintf(stderr, "Wrong permissions in your private key file `%s'!\n"
	    "Trying to change them ... ", file_private_key);
    if ((chmod(file_private_key, 0600)) == -1) {
      fprintf(stderr,
	      "Failed to change permissions for private key file!\n" 
	      "Permissions for your private key file must be 0600.\n");
      return FALSE;
    }
    fprintf(stderr, "Done.\n\n");
  }

  /* See if the key has expired. */
  modtime = st.st_mtime;	/* last modified */
  curtime = time(0) - modtime;
    
  /* 86400 is seconds in a day. */
  if (curtime >= (86400 * SILC_CLIENT_KEY_EXPIRES)) {
    fprintf(stdout, 
	    "--------------------------------------------------\n"
	    "Your private key has expired and needs to be\n" 
	    "recreated.  This will be done automatically now.\n"
	    "Your new key will expire in %d days from today.\n"
	    "--------------------------------------------------\n",
	    SILC_CLIENT_KEY_EXPIRES);

    silc_client_create_key_pair(SILC_CLIENT_DEF_PKCS, 
				SILC_CLIENT_DEF_PKCS_LEN,
				file_public_key, 
				file_private_key, identifier, NULL, NULL);
  }
  
  if (identifier)
    silc_free(identifier);

  return TRUE;
}

/* Loads public and private key from files. */

int silc_client_load_keys(SilcClient client)
{
  char filename[256];
  struct passwd *pw;

  SILC_LOG_DEBUG(("Loading public and private keys"));

  pw = getpwuid(getuid());
  if (!pw)
    return FALSE;

  memset(filename, 0, sizeof(filename));
  snprintf(filename, sizeof(filename) - 1, "%s/.silc/%s", 
	   pw->pw_dir, SILC_CLIENT_PRIVATE_KEY_NAME);

  if (silc_pkcs_load_private_key(filename, &client->private_key,
				 SILC_PKCS_FILE_BIN) == FALSE)
    if (silc_pkcs_load_private_key(filename, &client->private_key,
				   SILC_PKCS_FILE_PEM) == FALSE)
      return FALSE;

  memset(filename, 0, sizeof(filename));
  snprintf(filename, sizeof(filename) - 1, "%s/.silc/%s", 
	   pw->pw_dir, SILC_CLIENT_PUBLIC_KEY_NAME);

  if (silc_pkcs_load_public_key(filename, &client->public_key,
				SILC_PKCS_FILE_PEM) == FALSE)
    if (silc_pkcs_load_public_key(filename, &client->public_key,
				  SILC_PKCS_FILE_BIN) == FALSE)
      return FALSE;

  return TRUE;
}

/* Parses mode mask and returns the mode as string. */

char *silc_client_chmode(unsigned int mode)
{
  char string[20];

  if (!mode)
    return NULL;

  memset(string, 0, sizeof(string));

  if (mode & SILC_CHANNEL_MODE_PRIVATE)
    strncat(string, "p", 1);

  if (mode & SILC_CHANNEL_MODE_SECRET)
    strncat(string, "s", 1);

  if (mode & SILC_CHANNEL_MODE_PRIVKEY)
    strncat(string, "k", 1);

  if (mode & SILC_CHANNEL_MODE_INVITE)
    strncat(string, "i", 1);

  if (mode & SILC_CHANNEL_MODE_TOPIC)
    strncat(string, "t", 1);

  if (mode & SILC_CHANNEL_MODE_ULIMIT)
    strncat(string, "l", 1);

  if (mode & SILC_CHANNEL_MODE_PASSPHRASE)
    strncat(string, "a", 1);

  /* Rest of mode is ignored */

  return strdup(string);
}

/* Parses channel user mode mask and returns te mode as string */

char *silc_client_chumode(unsigned int mode)
{
  char string[4];

  if (!mode)
    return NULL;

  memset(string, 0, sizeof(string));

  if (mode & SILC_CHANNEL_UMODE_CHANFO)
    strncat(string, "f", 1);

  if (mode & SILC_CHANNEL_UMODE_CHANOP)
    strncat(string, "o", 1);

  return strdup(string);
}

/* Parses channel user mode and returns it as special mode character. */

char *silc_client_chumode_char(unsigned int mode)
{
  char string[4];

  if (!mode)
    return NULL;

  memset(string, 0, sizeof(string));

  if (mode & SILC_CHANNEL_UMODE_CHANFO)
    strncat(string, "*", 1);

  if (mode & SILC_CHANNEL_UMODE_CHANOP)
    strncat(string, "@", 1);

  return strdup(string);
}
