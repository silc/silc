/*

  silcdir.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Directory Interface
 *
 * DESCRIPTION
 *
 * The SILC Directory API provides portable way to open and read directories
 * and their content.
 *
 * EXAMPLE
 *
 * SilcDir dir;
 * SilcDirEntry entry;
 *
 * dir = silc_dir_open("foodir");
 *
 * while ((entry = silc_dir_read(dir, NULL)))
 *   printf("File name: %s", silc_dir_entry_name(entry));
 *
 * silc_dir_close(dir);
 *
 ***/

#ifndef SILCDIR_H
#define SILCDIR_H

/****s* silcutil/SilcDirAPI/SilcDir
 *
 * NAME
 *
 *    typedef struct SilcDirStruct *SilcDir;
 *
 * DESCRIPTION
 *
 *    The directory context.  This is allocated by silc_dir_open and
 *    freed by calling silc_dir_close.
 *
 ***/
typedef struct SilcDirStruct *SilcDir;

/****s* silcutil/SilcDirAPI/SilcDirEntry
 *
 * NAME
 *
 *    typedef struct SilcDirEntryStruct *SilcDirEntry;
 *
 * DESCRIPTION
 *
 *    The directory entry context.  The entry is usually a file in the
 *    directory.
 *
 ***/
typedef struct SilcDirEntryStruct *SilcDirEntry;

/****d* silcutil/SilcDirAPI/SilcDirEntryModen
 *
 * NAME
 *
 *    typedef enum { ... } SilcDirEntryMode;
 *
 * DESCRIPTION
 *
 *    The directory entry mode bits.  These bits specify the entry mode,
 *    type and protection.
 *
 ***/
typedef enum {
  /* Type */
  SILC_DIR_ENTRY_IFDIR     = 0x00000001,  /* Entry is directory */
  SILC_DIR_ENTRY_IFCHR     = 0x00000002,  /* Entry is character device */
  SILC_DIR_ENTRY_IFBLK     = 0x00000004,  /* Entry is block device */
  SILC_DIR_ENTRY_IFREG     = 0x00000008,  /* Entry is regular file */
  SILC_DIR_ENTRY_IFIFO     = 0x00000010,  /* Entry is FIFO */
  SILC_DIR_ENTRY_IFLNK     = 0x00000020,  /* Entry is symbolic link */
  SILC_DIR_ENTRY_IFSOCK    = 0x00000040,  /* Entry is socket */

  /* Protection */
  SILC_DIR_ENTRY_IRUSR     = 0x00000080,  /* Owner has read permission */
  SILC_DIR_ENTRY_IWUSR     = 0x00000100,  /* Owner has write permission */
  SILC_DIR_ENTRY_IXUSR     = 0x00000200,  /* Owner has execute permission */
  SILC_DIR_ENTRY_IRGRP     = 0x00000400,  /* Group has read permission */
  SILC_DIR_ENTRY_IWGRP     = 0x00000800,  /* Group has write permission */
  SILC_DIR_ENTRY_IXGRP     = 0x00001000,  /* Group has execute permission */
  SILC_DIR_ENTRY_IROTH     = 0x00002000,  /* Others have read permission */
  SILC_DIR_ENTRY_IWOTH     = 0x00004000,  /* Others have write permission */
  SILC_DIR_ENTRY_IXOTH     = 0x00008000,  /* Others have execute permission */
} SilcDirEntryMode;

/****s* silcutil/SilcDirAPI/SilcDirEntryStat
 *
 * NAME
 *
 *    typedef struct SilcDirEntryObject { ... } *SilcDirEntryStat,
 *                                               SilcDirEntryStatStruct;
 *
 * DESCRIPTION
 *
 *    The directory entry status information structure.  The structure
 *    contains various information about the entry in the directory.
 *    This context is returned by silc_dir_read or silc_dir_entry_stat.
 *
 ***/
typedef struct SilcDirEntryStatObject {
  SilcTimeStruct last_access;		/* Time of last access */
  SilcTimeStruct last_mod;	        /* Time of last modification */
  SilcTimeStruct last_change;	        /* Time of last status change */
  SilcUInt64 size;			/* Entry size in bytes */
  SilcUInt32 uid;			/* Owner ID of the entry */
  SilcUInt32 gid;			/* Group owner ID of the entry */
  SilcUInt32 dev;			/* Entry device number */
  SilcUInt32 nlink;			/* Number of hard links */
  SilcDirEntryMode mode;		/* Entry mode */
} *SilcDirEntryStat, SilcDirEntryStatStruct;

/****f* silcutil/SilcDirAPI/silc_dir_open
 *
 * SYNOPSIS
 *
 *    SilcDir silc_dir_open(const char *name);
 *
 * DESCRIPTION
 *
 *    Opens the directory named `name' and returns its context.  Returns NULL
 *    on error and sets the silc_errno.  This function must be called before
 *    being able to read the directory and its contents.
 *
 ***/
SilcDir silc_dir_open(const char *name);

/****f* silcutil/SilcDirAPI/silc_dir_close
 *
 * SYNOPSIS
 *
 *    void silc_dir_close(SilcDir dir);
 *
 * DESCRIPTION
 *
 *    Closes the directory `dir'.
 *
 ***/
void silc_dir_close(SilcDir dir);

/****f* silcutil/SilcDirAPI/silc_dir_read
 *
 * SYNOPSIS
 *
 *    SilcDirEntry silc_dir_read(SilcDir dir, SilcDirEntryStat *status);
 *
 * DESCRIPTION
 *
 *    Reads next entry (file) from the directory `dir'.  The silc_dir_open
 *    must be called first before reading from the directory.  Returns the
 *    next entry context or NULL if there are no more entries or error occurs.
 *    In case of error the silc_errno is also set.
 *
 *    If the `status' is non-NULL this will also call silc_dir_entry_stat
 *    and returns the status into the `status' pointer.
 *
 *    The returned context remains valid until the silc_dir_read is called
 *    again.
 *
 ***/
SilcDirEntry silc_dir_read(SilcDir dir, SilcDirEntryStat *status);

/****f* silcutil/SilcDirAPI/silc_dir_rewind
 *
 * SYNOPSIS
 *
 *    void silc_dir_rewind(SilcDir dir);
 *
 * DESCRIPTION
 *
 *    Rewinds the directory `dir' to the beginning of the directory.  Calling
 *    silc_dir_read after this will return the first entry in the directory.
 *
 ***/
void silc_dir_rewind(SilcDir dir);

/****f* silcutil/SilcDirAPI/silc_dir_name
 *
 * SYNOPSIS
 *
 *    const char *silc_dir_name(SilcDir dir);
 *
 * DESCRIPTION
 *
 *    Returns the name of the directory from `dir' context.
 *
 ***/
const char *silc_dir_name(SilcDir dir);

/****f* silcutil/SilcDirAPI/silc_dir_entry_name
 *
 * SYNOPSIS
 *
 *    const char *silc_dir_entry_name(SilcDirEntry entry);
 *
 * DESCRIPTION
 *
 *    Returns the name of the entry (file) `entry'.  The returned pointer
 *    remains valid until the silc_dir_read is called again.
 *
 ***/
const char *silc_dir_entry_name(SilcDirEntry entry);

/****f* silcutil/SilcDirAPI/silc_dir_entry_stat
 *
 * SYNOPSIS
 *
 *    SilcDirEntryStat silc_dir_entry_stat(SilcDir dir, SilcDirEntry entry);
 *
 * DESCRIPTION
 *
 *    Returns the status of the entry.  The status context contains details
 *    of the entry (file) in the directory.  Returns NULL on error and sets
 *    the silc_errno.
 *
 *    The returned contest is valid until the silc_dir_read is called again.
 *
 ***/
SilcDirEntryStat silc_dir_entry_stat(SilcDir dir, SilcDirEntry entry);

#endif /* SILCDIR_H */
