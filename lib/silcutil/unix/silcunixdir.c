/*

  silcunixdir.c

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

#include "silc.h"

/************************** Types and definitions ***************************/

/* Directory entry context */
struct SilcDirEntryStruct {
  struct dirent *entry;			  /* Entry */
  SilcDirEntryStatStruct status;	  /* Status */
};

/* The directory context */
struct SilcDirStruct {
  DIR *dir;			          /* Directory */
  char *name;				  /* Directory name */
  struct SilcDirEntryStruct entry;	  /* Current entry */
};

/****************************** SILC Dir API ********************************/

/* Open directory */

SilcDir silc_dir_open(const char *name)
{
  SilcDir dir;

  if (!name || !strlen(!name)) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    return NULL;
  }

  SILC_LOG_DEBUG(("Open directory '%s'", name));

  dir = silc_calloc(1, sizeof(*dir));
  if (!dir)
    return NULL;

  dir->name = silc_strdup(name);
  if (!dir->name) {
    silc_free(dir);
    return NULL;
  }

  if (dir->name[strlen(dir->name) - 1] == '/')
    dir->name[strlen(dir->name) - 1] = '\0';

  dir->dir = opendir(name);
  if (!dir->dir) {
    silc_set_errno_posix(errno);
    silc_free(dir->name);
    silc_free(dir);
    return NULL;
  }

  return dir;
}

/* Close directory */

void silc_dir_close(SilcDir dir)
{
  if (!dir)
    return;

  SILC_LOG_DEBUG(("Close directory '%s'", dir->name));

  closedir(dir->dir);
  silc_free(dir->name);
  silc_free(dir);
}

/* Read next entry in the directory */

SilcDirEntry silc_dir_read(SilcDir dir, SilcDirEntryStat *status)
{
  if (!dir) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    return NULL;
  }

  SILC_LOG_DEBUG(("Read directory '%s'", dir->name));

  dir->entry.entry = readdir(dir->dir);
  if (!dir->entry.entry) {
    if (errno)
      silc_set_errno_posix(errno);
    return NULL;
  }

  if (status)
    *status = silc_dir_entry_stat(dir, &dir->entry);

  return (SilcDirEntry)&dir->entry;
}

/* Rewind directory */

void silc_dir_rewind(SilcDir dir)
{
  if (!dir)
    return;

  SILC_LOG_DEBUG(("Rewind directory '%s'", dir->name));

  rewinddir(dir->dir);
}

/* Return directory name */

const char *silc_dir_name(SilcDir dir)
{
  if (!dir) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    return NULL;
  }

  return dir->name;
}

/* Return entry name */

const char *silc_dir_entry_name(SilcDirEntry entry)
{
  if (!entry) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    return NULL;
  }

  return (const char *)entry->entry->d_name;
}

/* Return entry status information */

SilcDirEntryStat silc_dir_entry_stat(SilcDir dir, SilcDirEntry entry)
{
  struct stat status;
  char *name = NULL;

  if (!dir || !entry) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    return NULL;
  }

  silc_asprintf(&name, "%s/%s", dir->name, entry->entry->d_name);
  if (!name)
    return NULL;

  SILC_LOG_DEBUG(("Get status for entry '%s'", name));

  if (lstat(name, &status) != 0) {
    silc_set_errno_posix(errno);
    silc_free(name);
    return NULL;
  }

  silc_free(name);

  memset(&entry->status, 0, sizeof(entry->status));

  silc_time_value(status.st_atime * 1000, &entry->status.last_access);
  silc_time_value(status.st_mtime * 1000, &entry->status.last_mod);
  silc_time_value(status.st_ctime * 1000, &entry->status.last_change);

  entry->status.dev = status.st_dev;
  entry->status.nlink = status.st_nlink;
  entry->status.gid = status.st_gid;
  entry->status.uid = status.st_uid;
  entry->status.size = status.st_size;

#if defined(S_IFSOCK)
  if (status.st_mode & S_IFSOCK)
    entry->status.mode |= SILC_DIR_ENTRY_IFSOCK;
#endif /* S_IFSOCK */
#if defined(S_IFLNK)
  if (status.st_mode & S_IFLNK)
    entry->status.mode |= SILC_DIR_ENTRY_IFLNK;
#endif /* S_IFLNK */
#if defined(S_IFREG)
  if (status.st_mode & S_IFREG)
    entry->status.mode |= SILC_DIR_ENTRY_IFREG;
#endif /* S_IFREG */
#if defined(S_IFBLK)
  if (status.st_mode & S_IFBLK)
    entry->status.mode |= SILC_DIR_ENTRY_IFBLK;
#endif /* S_IFBLK */
#if defined(S_IFDIR)
  if (status.st_mode & S_IFDIR)
    entry->status.mode |= SILC_DIR_ENTRY_IFDIR;
#endif /* S_IFDIR */
#if defined(S_IFCHR)
  if (status.st_mode & S_IFCHR)
    entry->status.mode |= SILC_DIR_ENTRY_IFCHR;
#endif /* S_IFCHR */
#if defined(S_IFIFO)
  if (status.st_mode & S_IFIFO)
    entry->status.mode |= SILC_DIR_ENTRY_IFIFO;
#endif /* S_IFIFO */
#if defined(S_IRUSR)
  if (status.st_mode & S_IRUSR)
    entry->status.mode |= SILC_DIR_ENTRY_IRUSR;
#endif /* S_IRUSR */
#if defined(S_IWUSR)
  if (status.st_mode & S_IWUSR)
    entry->status.mode |= SILC_DIR_ENTRY_IWUSR;
#endif /* S_IWUSR */
#if defined(S_IXUSR)
  if (status.st_mode & S_IXUSR)
    entry->status.mode |= SILC_DIR_ENTRY_IXUSR;
#endif /* S_IXUSR */
#if defined(S_IRGRP)
  if (status.st_mode & S_IRGRP)
    entry->status.mode |= SILC_DIR_ENTRY_IRGRP;
#endif /* S_IRGRP */
#if defined(S_IWGRP)
  if (status.st_mode & S_IWGRP)
    entry->status.mode |= SILC_DIR_ENTRY_IWGRP;
#endif /* S_IWGRP */
#if defined(S_IXGRP)
  if (status.st_mode & S_IXGRP)
    entry->status.mode |= SILC_DIR_ENTRY_IXGRP;
#endif /* S_IXGRP */
#if defined(S_IROTH)
  if (status.st_mode & S_IROTH)
    entry->status.mode |= SILC_DIR_ENTRY_IROTH;
#endif /* S_IROTH */
#if defined(S_IWOTH)
  if (status.st_mode & S_IWOTH)
    entry->status.mode |= SILC_DIR_ENTRY_IWOTH;
#endif /* S_IWOTH */
#if defined(S_IXOTH)
  if (status.st_mode & S_IXOTH)
    entry->status.mode |= SILC_DIR_ENTRY_IXOTH;
#endif /* S_IXOTH */

  return (SilcDirEntryStat)&entry->status;
}
