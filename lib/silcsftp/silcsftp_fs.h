/*

  silcsftp_fs.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCSFTP_FS_H
#define SILCSFTP_FS_H

/****h* silcsftp/SilcSFTPFSAPI
 *
 * DESCRIPTION
 *
 *    SILC SFTP Filesystem interface defines filesystems for the SFTP server
 *    usage.  The filesystems may be for example virtual memory filesystem
 *    or real filesystem access.
 *
 *    Currently only implemented filesystem is memory file system.
 *
 *    Memory Filesystem:
 *
 *    Memory filesystem is a virtual filesystem which provides safe access
 *    to files without actually revealing the underlaying physical filesystem
 *    hierarchy or real filenames. Virtual directories can be added to the
 *    filesystem and freely create filesystem hierarchy. The directories
 *    can have subdirectories and files. The filesystem also provides limited
 *    status information for files.  The files in the filesystem are
 *    virtual but they include the path to the real file.  The real path
 *    includes always a schema which indicates where the file really is
 *    available.  The only supported schema currently is "file://".  In
 *    the future it could support various others like "http://" and "ldap://".
 *
 *    The filesystem also provides security and permission handling for
 *    directories and files.  Normal POSIX style permissions can be set
 *    giving thus rights to reading, writing and/or executing.  They behave
 *    same way as defined in POSIX.  It is also guaranteed that if the
 *    writing to a file is not allowed in the memory filesystem, but it is
 *    allowed in real physical filesystem the file still cannot be written.
 *    However, the real physical filesystem permissions still matter, for
 *    example if writing is enabled in the memory filesystem but it is not
 *    enabled on physical filesystem, the file cannot be written.
 *
 *    The directories cannot be removed from remote access using the
 *    filesystem access function sftp_rmdir.  This is because the filesystem
 *    is one-user filesystem and differentiating between users is not 
 *    possible.  Thus, it would allow anyone to remove directories and
 *    their contents.  Removing directories is possible only locally using
 *    the silc_sftp_fs_memory_del_dir function.  The same thing is with
 *    removing files as well.  Files too can be removed only locally using
 *    the silc_sftp_fs_memory_del_file function.  Also, files can not ever
 *    be executed from remote access.
 *
 *    Also some of the file operation flags are not supported, such as 
 *    SILC_SFTP_FXF_CREAT, SILC_SFTP_FXF_TRUNC and SILC_SFTP_FXF_EXCL
 *    since they would require access to a real filesystem file which does
 *    not exist yet, or would mean destroying the file.  However, the
 *    SILC_SFTP_FXF_WRITE is supported since the file aready exists.
 *
 *    The memory filesystem does not provide symbolic links.
 *
 ***/

/* Available filesystems. These can be given as argument to the
   silc_sftp_server_start function. */
extern struct SilcSFTPFilesystemStruct silc_sftp_fs_memory;


/* Memory filesystem */

/****d* silcsftp/SilcSFTPFSAPI/SilcSFTPFSMemoryPerm
 *
 * NAME
 * 
 *    typedef enum { ... } SilcSFTPFSMemoryPerm;
 *
 * DESCRIPTION
 *
 *    Memory filesystem permission definition.  These enumerations can
 *    be used to set the permission mask for directories and files.
 *    The permissions behave in POSIX style.
 *
 * SOURCE
 */
typedef enum {
  SILC_SFTP_FS_PERM_READ    = 0x0001,    /* Reading allowed */
  SILC_SFTP_FS_PERM_WRITE   = 0x0002,	 /* Writing allowed */
  SILC_SFTP_FS_PERM_EXEC    = 0x0004,	 /* Execution allowed */
} SilcSFTPFSMemoryPerm;
/***/

/****f* silcsftp/SilcSFTPFSAPI/silc_sftp_fs_memory_alloc
 *
 * SYNOPSIS
 *
 *    void *silc_sftp_fs_memory_alloc(SilcSFTPFSMemoryPerm perm);
 *
 * DESCRIPTION
 *
 *    Allocates memory filesystem context and returns the context.  The
 *    context can be given as argument to the silc_sftp_server_start
 *    function. The context must be freed by the caller using the function
 *    silc_sftp_fs_memory_free. The `perm' is the permissions for the root
 *    directory of the filesystem (/ dir).
 *
 ***/
void *silc_sftp_fs_memory_alloc(SilcSFTPFSMemoryPerm perm);

/****f* silcsftp/SilcSFTPFSAPI/silc_sftp_fs_memory_free
 *
 * SYNOPSIS
 *
 *    void silc_sftp_fs_memory_free(void *context);
 *
 * DESCRIPTION
 *
 *    Frees the memory filesystem context.
 *
 ***/
void silc_sftp_fs_memory_free(void *context);

/****f* silcsftp/SilcSFTPFSAPI/silc_sftp_fs_memory_add_dir
 *
 * SYNOPSIS
 *
 *    void *silc_sftp_fs_memory_add_dir(void *context, void *dir,
 *                                      SilcSFTPFSMemoryPerm perm,
 *                                      const char *name);
 *
 * DESCRIPTION
 *
 *    Adds a new directory to the memory filesystem. Returns the directory
 *    context that can be used to add for example files to the directory
 *    or new subdirectories under the directory. The `dir' is the parent
 *    directory of the directory to be added. If this directory is to be
 *    added to the root directory the `dir' is NULL.  The `name' is the name
 *    of the directory. If error occurs this returns NULL. The `perm' will 
 *    indicate the permissions for the directory and they work in POSIX
 *    style. 
 *
 ***/
void *silc_sftp_fs_memory_add_dir(void *context, void *dir,
				  SilcSFTPFSMemoryPerm perm,
				  const char *name);

/****f* silcsftp/SilcSFTPFSAPI/silc_sftp_fs_memory_del_dir
 *
 * SYNOPSIS
 *
 *    bool silc_sftp_fs_memory_del_dir(void *context, void *dir);
 *
 * DESCRIPTION
 *
 *    Deletes a directory indicated by the `dir'. All files and
 *    subdirectories in this directory is also removed.  If the `dir' is
 *    NULL then all directories and files are removed from the filesystem.
 *    Returns TRUE if the removing was success. This is the only way to
 *    remove directories in memory file system. The filesystem does not
 *    allow removing directories with remote access using the filesystem
 *    access function sftp_rmdir.
 *
 ***/
bool silc_sftp_fs_memory_del_dir(void *context, void *dir);

/****f* silcsftp/SilcSFTPFSAPI/silc_sftp_fs_memory_add_file
 *
 * SYNOPSIS
 *
 *    bool silc_sftp_fs_memory_add_file(void *context, void *dir,
 *                                      SilcSFTPFSMemoryPerm perm,
 *                                      const char *filename,
 *                                      const char *realpath);
 *
 * DESCRIPTION
 *
 *    Adds a new file to the directory indicated by the `dir'.  If the `dir'
 *    is NULL the file is added to the root directory. The `filename' is the
 *    filename in the directory. The `realpath' is the real filepath in the
 *    physical filesystem. The real path must include the schema to
 *    indicate where the file is actually located.  The only supported
 *    schema currently is "file://".  It is used to actually access the fil
 *    from the memory filesystem. The `perm' will indicate the permissions
 *    for the file and they work in POSIX style. Returns TRUE if the file
 *    was added to the directory.
 *
 ***/
bool silc_sftp_fs_memory_add_file(void *context, void *dir,
				  SilcSFTPFSMemoryPerm perm,
				  const char *filename,
				  const char *realpath);

/****f* silcsftp/SilcSFTPFSAPI/silc_sftp_fs_memory_del_file
 *
 * SYNOPSIS
 *
 *    bool silc_sftp_fs_memory_del_file(void *context, void *dir,
 *                                      const char *filename);
 *
 * DESCRIPTION
 *
 *    Removes a file indicated by the `filename' from the directory
 *    indicated by the `dir'. Returns TRUE if the removing was success. This
 *    is the only way to remove files in the filesystem.  The filesystem does
 *    not allow removing files with remote access using the filesystem
 *    access function sftp_remove.
 *
 ***/
bool silc_sftp_fs_memory_del_file(void *context, void *dir,
				  const char *filename);

#endif /* SILCSFTP_FS_H */
