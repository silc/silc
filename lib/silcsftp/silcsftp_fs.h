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

/****h* silcsftp/SFTP Filesystems Interface
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

/****s* silcsftp/SilcSFTPFSAPI/SilcSFTPFilesystemOps
 *
 * NAME
 * 
 *    typedef struct SilcSFTPFilesystemOpsStruct { ... } 
 *                     *SilcSFTPFilesystemOps;
 *
 * DESCRIPTION
 *
 *    This structure defines the generic filesystem access.  When the
 *    filesystem is accessed these functions are called to do the requested
 *    filesystem operation.  The level that implements the actual filesystem
 *    must fill this structure with the callback functions providing the
 *    access to the filesystem.
 *
 * SOURCE
 */
typedef struct SilcSFTPFilesystemOpsStruct {
  /* Find a file handle by the file handle data indicated by the `data'. 
     If the handle is not found this returns NULL. */
  SilcSFTPHandle (*sftp_get_handle)(void *context, SilcSFTP sftp,
				    const unsigned char *data,
				    SilcUInt32 data_len);

  /* Return encoded handle of `handle' or NULL on error. The caller
     must free the returned buffer. */
  unsigned char *(*sftp_encode_handle)(void *context, SilcSFTP sftp,
				       SilcSFTPHandle handle,
				       SilcUInt32 *handle_len);

  /* Open a file indicated by the `filename' with flags indicated by the
     `pflags', and with attributes indicated by the `attr'.  Calls the
     `callback' to return the opened file handle. */
  void (*sftp_open)(void *context, SilcSFTP sftp, 
		    const char *filename, 
		    SilcSFTPFileOperation pflags,
		    SilcSFTPAttributes attr,
		    SilcSFTPHandleCallback callback,
		    void *callback_context);

  /* Closes the file indicated by the file handle `handle'.  Calls the
     `callback' to indicate the status of the closing. */
  void (*sftp_close)(void *context, SilcSFTP sftp, 
		     SilcSFTPHandle handle,
		     SilcSFTPStatusCallback callback,
		     void *callback_context);

  /* Reads data from the file indicated by the file handle `handle' starting
     from the offset of `offset' at most `len' bytes.  The `callback' is
     called to return the read data. */
  void (*sftp_read)(void *context, SilcSFTP sftp,
		    SilcSFTPHandle handle, 
		    SilcUInt64 offset, 
		    SilcUInt32 len,
		    SilcSFTPDataCallback callback,
		    void *callback_context);

  /* Writes to a file indicated by the file handle `handle' starting from
     offset of `offset' at most `data_len' bytes of `data'.  The `callback' 
     is called to indicate the status of the writing. */
  void (*sftp_write)(void *context, SilcSFTP sftp,
		     SilcSFTPHandle handle,
		     SilcUInt64 offset,
		     const unsigned char *data,
		     SilcUInt32 data_len,
		     SilcSFTPStatusCallback callback,
		     void *callback_context);

  /* Removes a file indicated by the `filename'.  Calls the `callback'
     to indicate the status of the removing. */
  void (*sftp_remove)(void *context, SilcSFTP sftp,
		      const char *filename,
		      SilcSFTPStatusCallback callback,
		      void *callback_context);

  /* Renames a file indicated by the `oldname' to the name `newname'.  The
     `callback' is called to indicate the status of the renaming. */
  void (*sftp_rename)(void *context, SilcSFTP sftp,
		      const char *oldname,
		      const char *newname,
		      SilcSFTPStatusCallback callback,
		      void *callback_context);

  /* Creates a new directory indicated by the `path' with attributes indicated
     by the `attrs'. The `callback' is called to indicate the status of the
     creation. */
  void (*sftp_mkdir)(void *context, SilcSFTP sftp,
		     const char *path,
		     SilcSFTPAttributes attrs,
		     SilcSFTPStatusCallback callback,
		     void *callback_context);

  /* Removes a directory indicated by the `path' and calls the `callback'
     to indicate the status of the removal. */
  void (*sftp_rmdir)(void *context, SilcSFTP sftp,
		     const char *path,
		     SilcSFTPStatusCallback callback,
		     void *callback_context);

  /* Opens a directory indicated by the `path'.  The `callback' is called
     to return the opened file handle. */
  void (*sftp_opendir)(void *context, SilcSFTP sftp,
		       const char *path,
		       SilcSFTPHandleCallback callback,
		       void *callback_context);

  /* Reads the contents of the directory indicated by the `handle' and
     calls the `callback' to return the read file(s) from the directory. */
  void (*sftp_readdir)(void *context, SilcSFTP sftp,
		       SilcSFTPHandle handle,
		       SilcSFTPNameCallback callback,
		       void *callback_context);

  /* Gets the file attributes for a file indicated by the `path'. This
     will follow symbolic links also. Calls the `callback' to return the
     file attributes. */
  void (*sftp_stat)(void *context, SilcSFTP sftp,
		    const char *path,
		    SilcSFTPAttrCallback callback,
		    void *callback_context);

  /* Gets the file attributes for a file indicated by the `path'. This
     will not follow symbolic links. Calls the `callback' to return the
     file attributes. */
  void (*sftp_lstat)(void *context, SilcSFTP sftp,
		     const char *path,
		     SilcSFTPAttrCallback callback,
		     void *callback_context);

  /* Gets a file attributes for a opened file indicated by the `handle'.
     Calls the `callback' to return the file attributes. */
  void (*sftp_fstat)(void *context, SilcSFTP sftp,
		     SilcSFTPHandle handle,
		     SilcSFTPAttrCallback callback,
		     void *callback_context);
  
  /* Sets a file attributes to a file indicated by the `path' with the
     attributes indicated by the `attrs'.  Calls the `callback' to indicate
     the status of the setting. */
  void (*sftp_setstat)(void *context, SilcSFTP sftp,
		       const char *path,
		       SilcSFTPAttributes attrs,
		       SilcSFTPStatusCallback callback,
		       void *callback_context);

  /* Sets a file attributes to a opened file indicated by the `handle' with
     the attributes indicated by the `attrs'.  Calls the `callback' to
     indicate the status of the setting. */
  void (*sftp_fsetstat)(void *context, SilcSFTP sftp,
			SilcSFTPHandle handle,
			SilcSFTPAttributes attrs,
			SilcSFTPStatusCallback callback,
			void *callback_context);

  /* Reads the target of a symbolic link indicated by the `path'.  The
     `callback' is called to return the target of the symbolic link. */
  void (*sftp_readlink)(void *context, SilcSFTP sftp,
			const char *path,
			SilcSFTPNameCallback callback,
			void *callback_context);

  /* Creates a new symbolic link indicated by the `linkpath' to the target
     indicated by the `targetpath'.  The `callback' is called to indicate
     the status of creation. */
  void (*sftp_symlink)(void *context, SilcSFTP sftp,
		       const char *linkpath,
		       const char *targetpath,
		       SilcSFTPStatusCallback callback,
		       void *callback_context);

  /* Canonicalizes the path indicated by the `path' to a absolute path.
     The `callback' is called to return the absolute path. */
  void (*sftp_realpath)(void *context, SilcSFTP sftp,
			const char *path,
			SilcSFTPNameCallback callback,
			void *callback_context);

  /* Performs an extended operation indicated by the `request' with 
     optional extended operation data indicated by the `data'.  The callback
     is called to return any data associated with the extended request. */
  void (*sftp_extended)(void *context, SilcSFTP sftp,
			const char *request,
			const unsigned char *data,
			SilcUInt32 data_len,
			SilcSFTPExtendedCallback callback,
			void *callback_context);
} *SilcSFTPFilesystemOps;
/****/

/****s* silcsftp/SilcSFTPFSAPI/SilcSFTPFilesystem
 *
 * NAME
 * 
 *    typedef struct { ... } *SilcSFTPFilesystem;
 *
 * DESCRIPTION
 *
 *    This context is allocated and returned by all filesystem allocation
 *    routines.  The returned context is given as argument to the
 *    silc_sftp_server_start function.  The caller must also free the
 *    context after the SFTP server is shutdown.
 *
 * SOURCE
 */
typedef struct {
  SilcSFTPFilesystemOps fs;
  void *fs_context;
} *SilcSFTPFilesystem;
/***/

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
SilcSFTPFilesystem silc_sftp_fs_memory_alloc(SilcSFTPFSMemoryPerm perm);

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
void silc_sftp_fs_memory_free(SilcSFTPFilesystem fs);

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
void *silc_sftp_fs_memory_add_dir(SilcSFTPFilesystem fs, void *dir,
				  SilcSFTPFSMemoryPerm perm,
				  const char *name);

/****f* silcsftp/SilcSFTPFSAPI/silc_sftp_fs_memory_del_dir
 *
 * SYNOPSIS
 *
 *    bool silc_sftp_fs_memory_del_dir(SilcSFTPFilesystem fs, void *dir);
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
bool silc_sftp_fs_memory_del_dir(SilcSFTPFilesystem fs, void *dir);

/****f* silcsftp/SilcSFTPFSAPI/silc_sftp_fs_memory_add_file
 *
 * SYNOPSIS
 *
 *    bool silc_sftp_fs_memory_add_file(SilcSFTPFilesystem fs, void *dir,
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
bool silc_sftp_fs_memory_add_file(SilcSFTPFilesystem fs, void *dir,
				  SilcSFTPFSMemoryPerm perm,
				  const char *filename,
				  const char *realpath);

/****f* silcsftp/SilcSFTPFSAPI/silc_sftp_fs_memory_del_file
 *
 * SYNOPSIS
 *
 *    bool silc_sftp_fs_memory_del_file(SilcSFTPFilesystem fs, void *dir,
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
bool silc_sftp_fs_memory_del_file(SilcSFTPFilesystem fs, void *dir,
				  const char *filename);

#endif /* SILCSFTP_FS_H */
