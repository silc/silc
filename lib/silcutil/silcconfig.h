/*

  silcconfig.h

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

/****h* silcutil/SILC Config Interface
 *
 * DESCRIPTION
 *
 * The SILC Config util library is based on two main objects, SilcConfigFile
 * (or File object) and SilcConfigEntity (or Entity).  The File objects are
 * structs directly corresponding to the real files in the filesystem, while
 * Entities are a little more abstract.
 *
 * An Entity is composed by delimited area on a File object (it can take the
 * whole File object or just part of it), plus a group of known options.
 * In order to parse this file, first you need to create a File object with
 * the silc_config_open() function, and then you need to create the Entity
 * with the silc_config_init() function.
 *
 * Now you can use the newly created Entity to register a group of expected
 * known options and sub-blocks, and then you can call the main parsing loop
 * with the silc_config_main() function. When silc_config_main() will 
 * return, if some error encoured the object file will point to the file 
 * that caused this error (this can be different from the originally 
 * opened file if it contained `Include' directives).  If no errors 
 * encoured then the File objects will still point to the original file.
 *
 * While silc_config_main() will take care of destroying Entities before
 * returning, you need to take care that the File object you created is freed
 * with the silc_config_close() function.
 *
 * The SILC Config library won't take care about storing the values contained
 * in the config file.  You must take care about it with the callback
 * functions.
 *
 * The config file syntax is pretty straightforward.  All lines starting
 * with `#' will be skipped, while sub-blocks are delimited by braces (see
 * the example below).
 *
 * Options with argument must have the `=' character between the option
 * name and the value.  Simple words and numbers does not require quoting.
 * There is a special built-in directive "Include" which allows you to include
 * another config file in the point the directive is.  You can also Include
 * inside a sub-block body, in this case when parsing the included config file
 * it will be assumed that we are within this block, and the included file
 * won't be allowed to close his root block.
 *
 * Example:
 *
 *    cipher {
 *       name = aes-256-cbc;
 *       module = "aes.sim.so";
 *       key_length = 32;       # usually the default is just fine
 *       block_length = 16;
 *    };
 *    Include "/etc/silc/hash_funcs.conf";
 *
 ***/

#ifndef SILCCONFIG_H
#define SILCCONFIG_H

/****d* silcutil/SilcConfigAPI/SilcConfigErrno
 *
 * NAME
 *
 *    enum { ... } - describe a SILC Config error
 *
 * DESCRIPTION
 *
 *    The virtual integer `errno' is returned by the silc_config_main()
 *    function and indicates what went wrong.
 *    You can convert it to the corresponding error string with the function
 *    silc_config_strerror().
 *
 * SOURCE
 */
enum {
  SILC_CONFIG_OK,		/* OK */
  SILC_CONFIG_ESILENT,		/* Error defined by callback function */
  SILC_CONFIG_EPRINTLINE,	/* Error defined by callback function */
  SILC_CONFIG_EGENERIC,		/* Invalid syntax */
  SILC_CONFIG_EINTERNAL,	/* Internal Error (caused by developer) */
  SILC_CONFIG_ECANTOPEN,	/* Can't open specified file */
  SILC_CONFIG_EOPENBRACE,	/* Expected open-brace '{' */
  SILC_CONFIG_ECLOSEBRACE,	/* Missing close-brace '}' */
  SILC_CONFIG_ETYPE,		/* Invalid data type */
  SILC_CONFIG_EBADOPTION,	/* Unknown option */
  SILC_CONFIG_EINVALIDTEXT,	/* Invalid text */
  SILC_CONFIG_EDOUBLE,		/* Double option specification */
  SILC_CONFIG_EEXPECTED,	/* Expected data but not found */
  SILC_CONFIG_EEXPECTEDEQUAL,	/* Expected '=' */
  SILC_CONFIG_EUNEXPECTED,	/* Unexpected data */
  SILC_CONFIG_EMISSFIELDS,	/* Missing mandatory fields */
  SILC_CONFIG_EMISSCOLON,	/* Missing ';' */
};
/***/

/****d* silcutil/SilcConfigAPI/SilcConfigType
 *
 * NAME
 *
 *    typedef enum { ... } SilcConfigType;
 *
 * DESCRIPTION
 *
 *    This identifies the parameter type that an option has. This parameter
 *    is very important because the callback's *val pointer points to a
 *    memory location containing the previously specified data type.
 *    For example, if you specified an option with an integer parameter
 *    callback's *val will be a pointer to an integer.
 *
 * SOURCE
 */
typedef enum {
  SILC_CONFIG_ARG_TOGGLE,	/* TOGGLE on,off; yes,no; true, false; */
  SILC_CONFIG_ARG_INT,		/* callback wants an integer */
  SILC_CONFIG_ARG_STR,		/* callback expects \0-terminated str */
  SILC_CONFIG_ARG_STRE,		/* same as above, but can also be empty */
  SILC_CONFIG_ARG_BLOCK,	/* this is a sub-block */
  SILC_CONFIG_ARG_SIZE,		/* like int, but accepts suffixes kMG */
  SILC_CONFIG_ARG_NONE,		/* does not expect any args */
} SilcConfigType;
/***/

/****f* silcutil/SilcConfigAPI/SilcConfigCallback
 *
 * SYNOPSIS
 *
 *    typedef int (*SilcConfigCallback)(SilcConfigType type, const char *name,
 *                                      SilcUInt32 line, void *val,
 *                                      void *context);
 * DESCRIPTION
 *
 *    This is the callback prototype for the options handler.  The pointer
 *    `val' points to a location of type described by `type'.  `name' points
 *    to a null-terminated string with the name of the option which triggered
 *    this callback, that is stated at line `line'.  `context' is the
 *    user-specified context provided when this option was registered.
 *
 ***/
typedef int (*SilcConfigCallback)(SilcConfigType type, const char *name,
				  SilcUInt32 line, void *val, void *context);

/****s* silcutil/SilcConfigAPI/SilcConfigTable
 *
 * SYNOPSIS
 *
 *    typedef struct { ... } SilcConfigTable;
 *
 * DESCRIPTION
 *
 *    SILC Config table defines an easy and quick way of registering options
 *    in an entity. The function silc_config_register_table() will take as
 *    argument a SilcConfigTable array terminated by a NULL struct, it is
 *    important thus, that the `name' field of the terminating struct is set
 *    to NULL.
 *
 *    char *name
 *
 *       The option name lowercase. The matching is always case-insensitive,
 *       but for convention the option specification must always be lowercase.
 *
 *    SilcConfigType type
 *
 *       This specifies what kind of parameter this option expects.  The
 *       special cases SILC_CONFIG_ARG_BLOCK tells SILC Config that this is
 *       not a normal option but the name of a sub-block of the current
 *       block (there is no limit to the number of nested blocks allowed).
 *
 *    SilcConfigCallback callback
 *
 *       Normally this is the value handler of the current option. If this
 *       field is set to NULL then the value is silently discarded. Useful
 *       for example to support deprecated options.
 *
 *    SilcConfigTable *subtable
 *
 *       If the `type' field is set to SILC_CONFIG_ARG_BLOCK, then this field
 *       must point to a valid sub-table NULL-terminated array. If `type' is
 *       something else, this valued is unused.
 *
 ***/
typedef struct SilcConfigTableStruct {
  char *name;
  SilcConfigType type;
  SilcConfigCallback callback;
  const struct SilcConfigTableStruct *subtable;
} SilcConfigTable;

/****s* silcutil/SilcConfigAPI/SilcConfigFile
 *
 * SYNOPSIS
 *
 *    typedef struct SilcConfigFileObject SilcConfigFile;
 *
 * DESCRIPTION
 *
 *    A File object holds the data contained in a previously loaded file by
 *    the silc_config_open() function.
 *    This is an internally allocated struct and must be used only with the
 *    helper functions.
 *
 ***/
typedef struct SilcConfigFileObject SilcConfigFile;

/****s* silcutil/SilcConfigAPI/SilcConfigEntity
 *
 * SYNOPSIS
 *
 *    typedef struct SilcConfigEntityObject *SilcConfigEntity;
 *
 * DESCRIPTION
 *
 *    The SILC Config is based on config entities.  An entity contains the
 *    SilcConfigFile object we are parsing and the registered options.
 *
 ***/
typedef struct SilcConfigEntityObject *SilcConfigEntity;

/* Macros */

/****d* silcutil/SilcConfigAPI/SILC_CONFIG_CALLBACK
 *
 * NAME
 *
 *    #define SILC_CONFIG_CALLBACK ...
 *
 * DESCRIPTION
 *
 *    Generic macro to define SilcConfigCallback functions. This defines a
 *    static function with name `func' as a config callback function.
 *
 * SOURCE
 */
#define SILC_CONFIG_CALLBACK(func)				\
static int func(SilcConfigType type, const char *name,		\
		SilcUInt32 line, void *val, void *context)
/***/

/* Prototypes */

/****f* silcutil/SilcConfigAPI/silc_config_open
 *
 * SYNOPSIS
 *
 *    SilcConfigFile *silc_config_open(char *configfile);
 *
 * DESCRIPTION
 *
 *    Tries to open the config file `configfile' and returns a valid File
 *    object on success, or NULL on failure.
 *    An File object created this way must be destroyed with the function
 *    silc_config_close().
 *
 ***/
SilcConfigFile *silc_config_open(const char *configfile);

/****f* silcutil/SilcConfigAPI/silc_config_close
 *
 * SYNOPSIS
 *
 *    void silc_config_close(SilcConfigFile *file);
 *
 * DESCRIPTION
 *
 *    Closes and frees the File object `file', which must have been returned
 *    by a previous call to silc_config_open().  Otherwise, or if
 *    this function has already been called before for the same File object,
 *    undefined behaviour occurs.
 *    If `file' is NULL, no operation is performed.
 *
 ***/
void silc_config_close(SilcConfigFile *file);

/****f* silcutil/SilcConfigAPI/silc_config_init
 *
 * SYNOPSIS
 *
 *    SilcConfigEntity silc_config_init(SilcConfigFile *file);
 *
 * DESCRIPTION
 *
 *    Creates an Entity pointing to the valid File object `file', which must
 *    be returned by a previous call to silc_config_open(), otherwise NULL
 *    is returned.
 *    Entities will be automatically destroyed after the call to the
 *    silc_config_main() function, because of this no uninit functions are
 *    provided.
 *
 ***/
SilcConfigEntity silc_config_init(SilcConfigFile *file);

/****f* silcutil/SilcConfigAPI/silc_config_strerror
 *
 * SYNOPSIS
 *
 *    char *silc_config_strerror(int errnum);
 *
 * DESCRIPTION
 *
 *    The silc_config_strerror() function returns a string describing the
 *    error code passed in the argument `errnum'.
 *
 ***/
char *silc_config_strerror(int errnum);

/****f* silcutil/SilcConfigAPI/silc_config_get_filename
 *
 * SYNOPSIS
 *
 *    char *silc_config_get_filename(SilcConfigFile *file);
 *
 * DESCRIPTION
 *
 *    Returns the original filename of the object file.
 *    The returned pointer points to internally allocated storage and must
 *    not be freed, modified or stored.
 *
 ***/
char *silc_config_get_filename(SilcConfigFile *file);

/****f* silcutil/SilcConfigAPI/silc_config_get_line
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_config_get_line(SilcConfigFile *file);
 *
 * DESCRIPTION
 *
 *    Returns the current line that file parsing arrived at.
 *
 ***/
SilcUInt32 silc_config_get_line(SilcConfigFile *file);

/****f* silcutil/SilcConfigAPI/silc_config_read_line
 *
 * SYNOPSIS
 *
 *    char *silc_config_read_line(SilcConfigFile *file, SilcUInt32 line);
 *
 * DESCRIPTION
 *
 *    Returns a dynamically allocated null-terminated buffer containing the
 *    line `line' of `file'.
 *    The returned pointer must be freed when it's not needed any longer.
 *
 * SEE ALSO
 *    silc_config_read_current_line
 *
 ***/
char *silc_config_read_line(SilcConfigFile *file, SilcUInt32 line);

/****f* silcutil/SilcConfigAPI/silc_config_read_current_line
 *
 * SYNOPSIS
 *
 *    char *silc_config_read_current_line(SilcConfigFile *file);
 *
 * DESCRIPTION
 *
 *    Returns a dynamically allocated buffer containing the line that the
 *    parser stopped at.  This is a convenience function for
 *    silc_config_read_line.
 *    The returned pointer must be freed when it's not needed any longer.
 *
 ***/
char *silc_config_read_current_line(SilcConfigFile *file);

/****f* silcutil/SilcConfigAPI/silc_config_register
 *
 * SYNOPSIS
 *
 *    bool silc_config_register(SilcConfigEntity ent, const char *name,
 *                              SilcConfigType type, SilcConfigCallback cb,
 *                              const SilcConfigTable *subtable,
 *                              void *context);
 *
 * DESCRIPTION
 *
 *    Register option `name' in the entity `ent'. If `cb' is not NULL, it
 *    will be called with the *val pointer pointing to an internally
 *    allocated storage of type described by `type'.
 *
 *    If `type' is SILC_CONFIG_ARG_BLOCK, then `subtable' must be a valid
 *    pointer to a SilcConfigTable array specifying the options in the
 *    sub-block.
 *
 *    If the option `name' was already registered in this sub-block or it
 *    matches the reserved word "Include", then this function returns FALSE,
 *    otherwise it returns TRUE.
 *
 * SEE ALSO
 *    silc_config_register_table
 *
 ***/
bool silc_config_register(SilcConfigEntity ent, const char *name,
			  SilcConfigType type, SilcConfigCallback cb,
			  const SilcConfigTable *subtable, void *context);

/****f* silcutil/SilcConfigAPI/silc_config_register_table
 *
 * SYNOPSIS
 *
 *    bool silc_config_register_table(SilcConfigEntity ent,
 *                                    const SilcConfigTable table[],
 *                                    void *context);
 *
 * DESCRIPTION
 *
 *    Register the tableset of options `table' automatically in the entity
 *    `ent'.  If defined in the table, the callback functions will be called
 *    all with the same context `context'.
 *
 *    The `table' array must be terminated with an entry with the name field
 *    set to NULL.
 *
 *    If the table contains invalid data this function returns FALSE, otherwise
 *    it returns TRUE.  If a calling to this function failed, you must destroy
 *    and recreate the entity before retrying, as it's impossible to detect
 *    the point at the function stopped the registering process.
 *
 * SEE ALSO
 *    SilcConfigTable
 *
 ***/
bool silc_config_register_table(SilcConfigEntity ent,
				const SilcConfigTable table[], void *context);

/****f* silcutil/SilcConfigAPI/silc_config_main
 *
 * SYNOPSIS
 *
 *    int silc_config_main(SilcConfigEntity ent);
 *
 * DESCRIPTION
 *
 *    Enter the main parsing loop. When this function returns the parsing
 *    is finished in the current block (and sub-blocks).
 *
 *    When this function exits, the entity is already destroyed, because
 *    of this you should set it to NULL right after the function call.
 *
 ***/
int silc_config_main(SilcConfigEntity ent);

#endif	/* !SILCCONFIG_H */
