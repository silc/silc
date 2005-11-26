/*

  silcconfig.c

  Author: Giovanni Giacobbi <giovanni@giacobbi.net>

  Copyright (C) 2002 - 2003 Giovanni Giacobbi

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"

/* limit debug logging verbosity */
#if 0
#define SILC_CONFIG_DEBUG(fmt) SILC_LOG_DEBUG(fmt)
#else
#define SILC_CONFIG_DEBUG(fmt)
#endif

/* this is the option struct and currently it is only used internally to
 * the module and other structs. */
typedef struct SilcConfigOptionStruct {
  char *name;			/* *lowercase* name of the option */
  SilcConfigType type;		/* important: the type of the returned value */
  SilcConfigCallback cb;	/* the value handler */
  const SilcConfigTable *subtable; /* used if type is SILC_CONFIG_ARG_BLOCK */
  void *context;		/* context passed to the callback function */
  struct SilcConfigOptionStruct *next;
} SilcConfigOption;

/* unique for each config file (and included ones) */
struct SilcConfigFileObject {
  char *filename;	/* the original filename opened */
  int level;		/* parsing level, how many nested
			   silc_config_main we have */
  char *base;		/* this is a fixed pointer to the base location */
  char *p;		/* the Parser poitner */
  SilcUInt32 len;	/* fixed length of the whole file */
  SilcUInt32 line;	/* current parsing line, strictly linked to p */
  SilcBool included;	/* wether this file is main or included */
};

/* We need the entity to base our block-style parsing on */
struct SilcConfigEntityObject {
  SilcConfigOption *opts;	/* known options list */
  SilcConfigFile *file;		/* parsing file object */
};

/* access error descriptions only with silc_config_strerror() */
static char *errorstrs[] = {
  "-OK",				      /* SILC_CONFIG_OK */
  "-SILENT",				      /* SILC_CONFIG_ESILENT */
  "-PRINTLINE",				      /* SILC_CONFIG_EPRINTLINE */
  "Invalid syntax",			      /* SILC_CONFIG_EGENERIC */
  "Internal error! Please report this bug",   /* SILC_CONFIG_EINTERNAL */
  "Can't open specified file",		      /* SILC_CONFIG_ECANTOPEN */
  "Expected open-brace '{'",		      /* SILC_CONFIG_EOPENBRACE */
  "Missing close-brace '}'",		      /* SILC_CONFIG_ECLOSEBRACE */
  "Invalid data type",			      /* SILC_CONFIG_ETYPE */
  "Unknown option",			      /* SILC_CONFIG_EBADOPTION */
  "Invalid text",			      /* SILC_CONFIG_EINVALIDTEXT */
  "Double option specification",	      /* SILC_CONFIG_EDOUBLE */
  "Expected data but not found",	      /* SILC_CONFIG_EEXPECTED */
  "Expected '='",			      /* SILC_CONFIG_EEXPECTEDEQUAL */
  "Unexpected data",			      /* SILC_CONFIG_EUNEXPECTED */
  "Missing mandatory fields",		      /* SILC_CONFIG_EMISSFIELDS */
  "Missing ';'",			      /* SILC_CONFIG_EMISSCOLON */
};

/* return string describing SilcConfig's error code */
char *silc_config_strerror(int errnum)
{
  if ((errnum < 0) || (errnum >= sizeof(errorstrs)/sizeof(*errorstrs)) ||
    (errorstrs[errnum] == NULL)) {
    char *defret = "-INVALIDERROR";
    return defret;
  }
  return errorstrs[errnum];
}

/* Begin of internal SilcConfig's text util functions */

/* Points the first non-space character */
static void my_trim_spaces(SilcConfigFile *file)
{
  register char *r = file->p;
  while ((*r != '\0' && *r != EOF) && isspace(*r))
    if (*r++ == '\n') file->line++;
  file->p = r;
}
/* Skips the current line until newline (lf or cr) */
static void my_skip_line(SilcConfigFile *file)
{
  register char *r = file->p;
  while ((*r != '\0' && *r != EOF) && (*r != '\n') && (*r != '\r')) r++;
  file->p = ((*r != '\0' && *r != EOF) ? r + 1 : r);
  file->line++;
}
/* Obtains a text token from the current position until first separator.
 * a separator is any non alphanumeric character nor "_" or "-" */
static char *my_next_token(SilcConfigFile *file, char *to)
{
  register char *o;
  my_trim_spaces(file);
  o = file->p;
  while (isalnum(*o) || (*o == '_') || (*o == '-'))
    *to++ = *o++;
  *to = '\0';
  file->p = o;
  return to;
}
/* Obtains a string from the current position. The only difference from
 * next_token() is that quoted-strings are also accepted */
static char *my_get_string(SilcConfigFile *file, char *to)
{
  char *o;
  my_trim_spaces(file);
  o = file->p;
  if (*o == '"') {
    char *quot = strchr(++o, '"');
    int len = quot - o;
    if (!quot) { /* XXX FIXME: gotta do something here */
      printf("Bullshit, missing matching \"");
      exit(1);
    }
    if (len <= 0)
      *to = '\0';
    else {
      strncpy(to, o, len);
      to[len] = '\0';
    }
    /* update stream pointer */
    file->p = quot + 1;
    return to;
  }
  /* we don't need quote parsing, fall-back to token extractor */
  my_next_token(file, to);
  return to;
};
/* Skips all comment lines and spaces lines until first useful character */
static void my_skip_comments(SilcConfigFile *file)
{
  while (1) {
    my_trim_spaces(file);
    if (*file->p != '#') return;
    my_skip_line(file);
  }
}

/* End of internal text functions
 * Next section contains SilcConfig internal config utils */

/* find an option in the list by name and returns its pointer */
static SilcConfigOption *silc_config_find_option(SilcConfigEntity ent,
	const char *name)
{
  SilcConfigOption *tmp;
  for (tmp = ent->opts; tmp; tmp = tmp->next) {
    if (!strcasecmp(tmp->name, name))
      return tmp;
  }
  return NULL;
}
/* Converts a string in the type specified. returns a dynamically
 * allocated pointer. */
static void *silc_config_marshall(SilcConfigType type, const char *val)
{
  void *pt;
  int val_int;
  SilcBool val_boolean;
  char *val_tmp;
  SilcUInt32 val_size;

  switch (type) {
    case SILC_CONFIG_ARG_TOGGLE:
      if (!strcasecmp(val, "yes") || !strcasecmp(val, "true") ||
		!strcasecmp(val, "on") || !strcasecmp(val, "1")) {
	val_boolean = TRUE;
      }
      else if (!strcasecmp(val, "no") || !strcasecmp(val, "false") ||
		!strcasecmp(val, "off") || !strcasecmp(val, "0")) {
	val_boolean = FALSE;
      }
      else
	return NULL;
      pt = silc_calloc(1, sizeof(val_boolean));
      *(SilcBool *)pt = (SilcBool) val_boolean;
      return pt;
    case SILC_CONFIG_ARG_INT:
      val_int = (int) strtol(val, &val_tmp, 0);
      if (*val_tmp) /* error converting string */
	return NULL;
      pt = silc_calloc(1, sizeof(val_int));
      *(int *)pt = val_int;
      return pt;
    case SILC_CONFIG_ARG_SIZE:
      val_size = (SilcUInt32) strtol(val, &val_tmp, 0);
      if (val == val_tmp)
	return NULL; /* really wrong, there must be at least one digit */
      /* Search for a designator */
      switch (tolower(val_tmp[0])) {
	case '\0': /* None */
	  break;
	case 'k': /* Kilobytes */
	  val_size *= (SilcUInt32) 1024;
	  break;
	case 'm': /* Megabytes */
	  val_size *= (SilcUInt32) (1024 * 1024);
	  break;
	case 'g':
	  val_size *= (SilcUInt32) (1024 * 1024 * 1024);
	  break;
	default:
	  return NULL;
      }
      /* the string must die here */
      if (val_tmp[1])
	return NULL;
      pt = silc_calloc(1, sizeof(val_size));
      *(SilcUInt32 *)pt = val_size;
      return pt;
    case SILC_CONFIG_ARG_STR: /* the only difference between STR and STRE is */
      if (!val[0])	      /* that STR cannot be empty, while STRE can.  */
	return NULL;
    case SILC_CONFIG_ARG_STRE:
      pt = (void *) strdup(val);
      return pt;
    /* following types are not supposed to have a return value */
    case SILC_CONFIG_ARG_BLOCK:
    case SILC_CONFIG_ARG_NONE:
      return NULL;
    default:
      return NULL;
  }

  return NULL;
}

/* End of internal functions */


/* Tries to open the config file and returns a valid SilcConfigFile object
 * or NULL if failed */

SilcConfigFile *silc_config_open(const char *configfile)
{
  char *buffer;
  SilcUInt32 filelen;
  SilcConfigFile *ret;

  if (!(buffer = silc_file_readfile(configfile, &filelen)))
    return NULL;

  ret = silc_calloc(1, sizeof(*ret));
  ret->filename = strdup(configfile);
  ret->base = ret->p = buffer;
  ret->len = filelen;
  ret->line = 1; /* line count, start from first line */
  return ret;
}

/* Frees a file object */

void silc_config_close(SilcConfigFile *file)
{
  if (file) {
    silc_free(file->filename);
    memset(file->base, 'F', file->len);
    silc_free(file->base);
    memset(file, 'F', sizeof(*file));
    silc_free(file);
  }
}

/* initializes a SilcConfigEntity pointer allocation */

SilcConfigEntity silc_config_init(SilcConfigFile *file)
{
  SilcConfigEntity ret;

  if (!file)
    return NULL;

  SILC_CONFIG_DEBUG(("Allocating new config entity"));
  ret = silc_calloc(1, sizeof(*ret));
  ret->file = file;
  return ret;
};

/* Returns the original filename of the object file */

char *silc_config_get_filename(SilcConfigFile *file)
{
  if (file)
    return file->filename;
  return NULL;
}

/* Returns the current line that file parsing arrived at */

SilcUInt32 silc_config_get_line(SilcConfigFile *file)
{
  if (file)
    return file->line;
  return 0;
}

/* Returns a pointer to the beginning of the requested line.  If the line
 * was not found, NULL is returned */

char *silc_config_read_line(SilcConfigFile *file, SilcUInt32 line)
{
  register char *p;
  int len;
  char *ret = NULL, *endbuf;

  if (!file || (line <= 0))
    return NULL;
  for (p = file->base; *p && (*p != EOF); p++) {
    if (line <= 1)
      goto found;
    if (*p == '\n')
      line--;
  }
  return NULL;

 found:
  if ((endbuf = strchr(p, '\n'))) {
    len = endbuf - p;
    if (len > 0)
      ret = silc_memdup(p, len);
  } else {
    ret = silc_memdup(p, strlen(p));
  }
  return ret;
}

/* Convenience function to read the current parsed line */

char *silc_config_read_current_line(SilcConfigFile *file)
{
  return silc_config_read_line(file, file->line);
}

/* (Private) destroy a SilcConfigEntity */

static void silc_config_destroy(SilcConfigEntity ent, SilcBool destroy_opts)
{
  SilcConfigOption *oldopt, *nextopt;
  SILC_CONFIG_DEBUG(("Freeing config entity [ent=0x%x] [opts=0x%x]",
			(SilcUInt32) ent, (SilcUInt32) ent->opts));

  /* if she wants to preserve options just free the object struct */
  if (!destroy_opts)
    goto skip_sect;

  for (oldopt = ent->opts; oldopt; oldopt = nextopt) {
    nextopt = oldopt->next;
    memset(oldopt->name, 'F', strlen(oldopt->name) + 1);
    silc_free(oldopt->name);
    memset(oldopt, 'F', sizeof(*oldopt));
    silc_free(oldopt);
  }

 skip_sect:
  memset(ent, 'F', sizeof(*ent));
  silc_free(ent);
}

/* Registers a new option in the specified entity.
 * Returns TRUE on success, FALSE if already registered. */

SilcBool silc_config_register(SilcConfigEntity ent, const char *name,
			  SilcConfigType type, SilcConfigCallback cb,
			  const SilcConfigTable *subtable, void *context)
{
  SilcConfigOption *newopt;
  SILC_CONFIG_DEBUG(("Register new option=\"%s\" "
		     "type=%u cb=0x%08x context=0x%08x",
		     name, type, (SilcUInt32) cb, (SilcUInt32) context));

  /* if we are registering a block, make sure there is a specified sub-table */
  if (!ent || !name || ((type == SILC_CONFIG_ARG_BLOCK) && !subtable))
    return FALSE;

  /* don't register a reserved tag */
  if (!strcasecmp(name, "include"))
    return FALSE;

  /* check if an option was previously registered */
  if (silc_config_find_option(ent, name)) {
    SILC_LOG_DEBUG(("Error: Can't register \"%s\" twice.", name));
    return FALSE;
  }

  /* allocate and append the new option */
  newopt = silc_calloc(1, sizeof(*newopt));
  newopt->name = strdup(name);
  newopt->type = type;
  newopt->cb = cb;
  newopt->subtable = subtable;
  newopt->context = context;

  /* append this option to the list */
  if (!ent->opts)
    ent->opts = newopt;
  else {
    SilcConfigOption *tmp;
    for (tmp = ent->opts; tmp->next; tmp = tmp->next);
    tmp->next = newopt;
  }
  return TRUE;
}

/* Register a new option table in the specified config entity */

SilcBool silc_config_register_table(SilcConfigEntity ent,
				const SilcConfigTable table[], void *context)
{
  int i;
  if (!ent || !table)
    return FALSE;
  SILC_CONFIG_DEBUG(("Registering table"));
  /* XXX FIXME: some potability checks needed - really? */
  for (i = 0; table[i].name; i++) {
    if (!silc_config_register(ent, table[i].name, table[i].type,
			      table[i].callback, table[i].subtable, context))
      return FALSE;
  }
  return TRUE;
}

/* ... */

static int silc_config_main_internal(SilcConfigEntity ent)
{
  SilcConfigFile *file = ent->file;
  char **p = &file->p;

  /* loop throught statements */
  while (1) {
    char buf[255];
    SilcConfigOption *thisopt;

    /* makes it pointing to the next interesting char */
    my_skip_comments(file);
    /* got eof? */
    if (**p == '\0' || **p == EOF) {
      if (file->level > 1) /* cannot get eof in a sub-level! */
	return SILC_CONFIG_EEXPECTED;
      goto finish;
    }
    /* check if we completed this (sub) section (it doesn't matter if this
     * is the main section) */
    if (**p == '}') {
      if (file->level < 2) /* can't be! must be at least one sub-block */
	return SILC_CONFIG_EUNEXPECTED;
      (*p)++;
      goto finish;
    }
    //SILC_LOG_HEXDUMP(("Preparing lookup at line=%lu", file->line), *p, 16);

    /* obtain the keyword */
    my_next_token(file, buf);
    SILC_CONFIG_DEBUG(("Looking up keyword=\"%s\" [line=%lu]",
		       buf, file->line));

    /* handle special directive */
    if (!strcasecmp(buf, "include")) {
      int ret;
      SilcConfigFile *inc_file;
      SilcConfigEntity inc_ent;

      my_trim_spaces(file); /* prepare next char */

      /* Now trying to include the specified file.  The included file will
       * be allowed to include sub-files but it will preserve the block-level
       * of the including block. Note that the included file won't be allowed
       * to raise the block level of the including block. */

      my_get_string(file, buf); /* get the filename */
      SILC_LOG_DEBUG(("Including file \"%s\"", buf));
      /* before getting on, check if this row is REALLY complete */
      if (*(*p)++ != ';')
	return SILC_CONFIG_EMISSCOLON;

      /* open the file and start the parsing */
      inc_file = silc_config_open(buf);
      if (!inc_file) /* does it point a valid filename? */
        return SILC_CONFIG_ECANTOPEN;
      inc_file->included = TRUE;

      /* create a new entity and hack it to use the same options */
      inc_ent = silc_config_init(inc_file);
      inc_ent->opts = ent->opts;
      ret = silc_config_main(inc_ent);

      /* Cleanup.
       * If the included file returned an error, the application will probably
       * want to output some kind of error message. Because of this, we can't
       * destroy THIS file object. The hack works this way: The application
       * expects to destroy the originally created object file, so we'll swap
       * the original file with the included file. */
      if (ret) {
        SilcConfigFile tmp_file;
        SILC_CONFIG_DEBUG(("SWAPPING FILE OBJECTS"));
        memcpy(&tmp_file, inc_file, sizeof(tmp_file));
        memcpy(inc_file, file, sizeof(tmp_file));
        silc_config_close(inc_file);
        memcpy(file, &tmp_file, sizeof(tmp_file));
        return ret;
      }
      /* otherwise if no errors encoured, continue normally */
      silc_config_close(inc_file);
      continue; /* this one is handled */
    }

    /* we have a registered option (it can also be a sub-block) */
    thisopt = silc_config_find_option(ent, buf);
    if (!thisopt)
      return SILC_CONFIG_EBADOPTION;

    my_trim_spaces(file); /* prepare next char */

    /* option type is a block? */
    if (thisopt->type == SILC_CONFIG_ARG_BLOCK) {
      int ret;
      SilcConfigEntity sub_ent;

      SILC_CONFIG_DEBUG(("Entering sub-block"));
      if (*(*p)++ != '{')
	return SILC_CONFIG_EOPENBRACE;
      /* build the new entity for this sub-block */
      sub_ent = silc_config_init(ent->file);
      /* use the previous specified table to describe this block's options */
      silc_config_register_table(sub_ent, thisopt->subtable, thisopt->context);
      /* run this block! */
      ret = silc_config_main(sub_ent);
      SILC_CONFIG_DEBUG(("Returned from sub-block [ret=%d]", ret));

      if (ret) /* now check the result */
	return ret;

      /* now call block clean-up callback (if any) */
      if (thisopt->cb) {
	int ret;
	SILC_CONFIG_DEBUG(("Now calling clean-up callback"));
	ret = thisopt->cb(thisopt->type, thisopt->name, file->line, NULL,
			  thisopt->context);
	if (ret) {
	  SILC_CONFIG_DEBUG(("Callback refused the value [ret=%d]", ret));
	  return ret;
	}
      }
      /* Do we want ';' to be mandatory after close brace? */
      if (*(*p)++ != ';')
	return SILC_CONFIG_EMISSCOLON;
    }
    else if (thisopt->type == SILC_CONFIG_ARG_NONE) {
      /* before getting on, check if this row is REALLY complete */
      if (*(*p)++ != ';')
	return SILC_CONFIG_EMISSCOLON;
      SILC_CONFIG_DEBUG(("Triggering callback for none"));
      if (thisopt->cb) {
	thisopt->cb(thisopt->type, thisopt->name, file->line,
		    NULL, thisopt->context);
      }
    }
    else {
      void *pt;
      int ret = 0;	/* very important in case of no cb */

      if (*(*p)++ != '=')
	return SILC_CONFIG_EEXPECTEDEQUAL;

      my_get_string(file, buf); /* get the option argument */
      SILC_CONFIG_DEBUG(("With argument=\"%s\"", buf));

      /* before getting on, check if this row is REALLY complete */
      if (*(*p)++ != ';')
	return SILC_CONFIG_EMISSCOLON;

      /* convert the option argument to the right format */
      pt = silc_config_marshall(thisopt->type, buf);
      if (!pt)
	return SILC_CONFIG_EINVALIDTEXT;
      if (thisopt->cb)
	ret = thisopt->cb(thisopt->type, thisopt->name, file->line,
			  pt, thisopt->context);

      /* since we have to free "pt" both on failure and on success, we
         assume that ret == 0 if we didn't actually call any cb. */
      silc_free(pt);
      if (ret) {
	SILC_CONFIG_DEBUG(("Callback refused the value [ret=%d]", ret));
	return ret;
      }
    }
    continue;

 finish:
    break;
  }

  return SILC_CONFIG_OK;
}

/* ... */

int silc_config_main(SilcConfigEntity ent)
{
  SilcConfigFile *file = ent->file;
  int ret;

  /* don't silently accept a NULL entity */
  if (!ent) {
    ret = SILC_CONFIG_EGENERIC;
    goto main_cleanup;
  }

  /* call the real main and store the result */
  file->level++;
  SILC_CONFIG_DEBUG(("[Lev=%d] Entering config parsing core", file->level));
  ret = silc_config_main_internal(ent);
  SILC_CONFIG_DEBUG(("[Lev=%d] Quitting main [ret=%d]", file->level, ret));
  if (!file->level) /* when swap happens, we could close a file twice */
    goto main_end;
  file->level--;

  /* If this file was included don't destroy the options set because it is
   * the same of the including block. Although if this entity is in a
   * sub-block created inside the included file, this options set must be
   * destroyed. */
 main_cleanup:
  if ((file->level != 0) || (file->included != TRUE))
    silc_config_destroy(ent, TRUE);
  else
    silc_config_destroy(ent, FALSE);

 main_end:
  return ret;
}
