/*

  silcsftp.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCSFTP_H
#define SILCSFTP_H

/****h* silcsftp/SILC SFTP Interface
 *
 * DESCRIPTION
 *
 *    SILC SFTP Interface is the implementation of the Secure File Transfer
 *    Protocol.  The interface defines the SFTP client and the SFTP server.
 *    The SFTP is the mandatory file transfer protocol in the SILC protocol.
 *    The SFTP server implementation is filesystem independent and generic
 *    interface is defined to represent filesystem access.
 *
 *    The SilcSFTP context is the actual SFTP client or SFTP server, and
 *    each SFTP session (associated to a socket connection) must create
 *    own SFTP context.
 *
 ***/

/****s* silcsftp/SilcSFTPAPI/SilcSFTP
 *
 * NAME
 *
 *    typedef struct SilcSFTPStruct *SilcSFTP;
 *
 * DESCRIPTION
 *
 *    This context is the actual SFTP client and SFTP server, and is
 *    allocated by silc_sftp_client_start or silc_sftp_server_start and
 *    given as argument usually to all silc_sftp_* functions.  It is freed
 *    by the silc_sftp_client_shutdown or silc_sftp_server_shutdown
 *    functions.
 *
 ***/
typedef struct SilcSFTPStruct *SilcSFTP;

/****d* silcsftp/SilcSFTPAPI/SilcSFTPVersion
 *
 * NAME
 *
 *    typedef SilcUInt32 SilcSFTPVersion;
 *
 * DESCRIPTION
 *
 *    SFTP Version type.
 *
 * SOURCE
 */
typedef SilcUInt32 SilcSFTPVersion;
/***/

/* SFTP protocol version */
#define SILC_SFTP_PROTOCOL_VERSION       3

/****d* silcsftp/SilcSFTPAPI/SilcSFTPStatus
 *
 * NAME
 *
 *    typedef enum { ... } SilcSFTPStatus
 *
 * DESCRIPTION
 *
 *    SFTP protocol status types.  These enumerations is used to indicate
 *    the status of request.  The server can send these to the client when
 *    client has requested an operation.
 *
 * SOURCE
 */
typedef enum {
  SILC_SFTP_STATUS_OK                  = 0,  /* Operation successful */
  SILC_SFTP_STATUS_EOF                 = 1,  /* No more data available */
  SILC_SFTP_STATUS_NO_SUCH_FILE        = 2,  /* File does not exist */
  SILC_SFTP_STATUS_PERMISSION_DENIED   = 3,  /* No sufficient permissions */
  SILC_SFTP_STATUS_FAILURE             = 4,  /* Operation failed */
  SILC_SFTP_STATUS_BAD_MESSAGE         = 5,  /* Bad message received */
  SILC_SFTP_STATUS_NO_CONNECTION       = 6,  /* No connection to server */
  SILC_SFTP_STATUS_CONNECTION_LOST     = 7,  /* Connection lost to server */
  SILC_SFTP_STATUS_OP_UNSUPPORTED      = 8,  /* Operation unsupported */
  SILC_SFTP_STATUS_INVALID_HANDLE      = 9,  /* Invalid file handle */
  SILC_SFTP_STATUS_NO_SUCH_PATH        = 10, /* Path does not exist */
  SILC_SFTP_STATUS_FILE_ALREADY_EXIST  = 11, /* File already exists */
  SILC_SFTP_STATUS_WRITE_PROTECT       = 12, /* Read-only or protected */
  SILC_SFTP_STATUS_NO_MEDIA            = 13, /* No media available */
  SILC_SFTP_STATUS_NO_SPACE_ON_DEVICE  = 14, /* No space on device */
  SILC_SFTP_STATUS_QUOTA_EXCEEDED      = 15, /* Quota limit reached */
  SILC_SFTP_STATUS_UNKNOWN_PRINCIBLE   = 16, /* Unknown princible */
  SILC_SFTP_STATUS_LOCK_CONFLICT       = 17, /* File already locked */
  SILC_SFTP_STATUS_NOT_EMPTY           = 18, /* Directory not empty */
  SILC_SFTP_STATUS_NOT_A_DIRECTORY     = 19, /* Not a directory */
  SILC_SFTP_STATUS_INVALID_FILENAME    = 20, /* Invalid filename */
  SILC_SFTP_STATUS_LINK_LOOP           = 21, /* Too many symlinks */
  SILC_SFTP_STATUS_CANNOT_DELETE       = 22, /* Could not delete file */
  SILC_SFTP_STATUS_INVALID_PARAMETER   = 23, /* Invalid parameter */
  SILC_SFTP_STATUS_FILE_IS_A_DIRECTORY = 24, /* File is a directory file */
  SILC_SFTP_STATUS_BR_LOCK_CONFLICT    = 25, /* Byte range lock conflict */
  SILC_SFTP_STATUS_BR_LOCK_REFUSED     = 26, /* Byte range lock refused */
  SILC_SFTP_STATUS_DELETE_PENDING      = 27, /* File is being deleted */
  SILC_SFTP_STATUS_FILE_CORRUPT        = 28, /* File is corrupted */
} SilcSFTPStatus;
/***/

/****d* silcsftp/SilcSFTPAPI/SilcSFTPFileOperation
 *
 * NAME
 *
 *    typedef enum { ... } SilcSFTPFileOperation
 *
 * DESCRIPTION
 *
 *    SFTP protocol file operation flags.  These enumerations can be used
 *    by the client when client is opening an file, to indicate how it
 *    would like to open the file.
 *
 * SOURCE
 */
typedef enum {
  SILC_SFTP_FXF_READ           = 0x00000001, /* Reading */
  SILC_SFTP_FXF_WRITE          = 0x00000002, /* Writing */
  SILC_SFTP_FXF_APPEND         = 0x00000004, /* Appending to end of file */
  SILC_SFTP_FXF_CREAT          = 0x00000008, /* Create if doesn't exist */
  SILC_SFTP_FXF_TRUNC          = 0x00000010, /* Truncate if exists */
  SILC_SFTP_FXF_EXCL           = 0x00000020, /* Don't create if exists */
} SilcSFTPFileOperation;
/***/

/****s* silcsftp/SilcSFTPAPI/SilcSFTPAttributes
 *
 * NAME
 *
 *    typedef struct { ... } *SilcSFTPAttributes, SilcSFTPAttributesStruct;
 *
 * DESCRIPTION
 *
 *    SFTP File attributes structure represents the attributes for a file.
 *    This structure can be used by the client to send attributes to the
 *    server, and by server to return file attributes to the client.
 *
 ***/
typedef struct {
  SilcUInt32 flags;	       	/* Flags to indicate present attributes */
  SilcUInt64 size;	       	/* Sife of the file in bytes */
  SilcUInt32 uid;      	        /* Unix user ID */
  SilcUInt32 gid;      		/* Unix group ID */
  SilcUInt32 permissions;      	/* POSIX file permission bitmask */
  SilcUInt32 atime;    		/* Access time of file */
  SilcUInt32 mtime;	       	/* Modification time of file */

  SilcUInt32 extended_count;	/* Extended type and data count */
  SilcBuffer *extended_type;
  SilcBuffer *extended_data;
} *SilcSFTPAttributes, SilcSFTPAttributesStruct;

/****s* silcsftp/SilcSFTPAPI/SilcSFTPName
 *
 * NAME
 *
 *    typedef struct { ... } *SilcSFTPName, SilcSFTPNameStruct
 *
 * DESCRIPTION
 *
 *    SFTP Name structure represents the name reply received from the server.
 *    It includes the returned file(s) short and long file names and
 *    attributes for the file(s).  This is returned by the server for
 *    example when reading the contents of a directory.
 *
 ***/
typedef struct {
  char **filename;
  char **long_filename;
  SilcSFTPAttributes *attrs;
  SilcUInt32 count;			/* Number of files */
} *SilcSFTPName, SilcSFTPNameStruct;

/****s* silcsftp/SilcSFTPAPI/SilcSFTPHandle
 *
 * NAME
 *
 *    typedef struct SilcSFTPHandleStruct *SilcSFTPHandle;
 *
 * DESCRIPTION
 *
 *    This context represents an open file handle and is allocated by
 *    the library.  The application receives this context in the
 *    SilcSFTPHandleCallback function.
 *
 ***/
typedef struct SilcSFTPHandleStruct *SilcSFTPHandle;

/****f* silcsftp/SilcSFTPAPI/SilcSFTPSendPacketCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSFTPSendPacketCallback)(SilcBuffer packet,
 *                                               void *context);
 *
 * DESCRIPTION
 *
 *    Packet sending callback. The caller of this interface will provide this
 *    function for the library. The libary will call this function everytime
 *    it needs to send a packet to the remote host.
 *
 ***/
typedef void (*SilcSFTPSendPacketCallback)(SilcBuffer packet, void *context);

/****f* silcsftp/SilcSFTPAPI/SilcSFTPVersionCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSFTPVersionCallback)(SilcSFTP sftp,
 *                                            SilcSFTPStatus status,
 *                                            SilcSFTPVersion version,
 *                                            void *context);
 *
 * DESCRIPTION
 *
 *    Version callback is called at the protocol initialization phase when
 *    the server returns the version of the protocol. The `version' indicates
 *    the version of the protocol.
 *
 ***/
typedef void (*SilcSFTPVersionCallback)(SilcSFTP sftp,
					SilcSFTPStatus status,
					SilcSFTPVersion version,
					void *context);

/****f* silcsftp/SilcSFTPAPI/SilcSFTPStatusCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSFTPStatusCallback)(SilcSFTP sftp,
 *                                           SilcSFTPStatus status,
 *                                           const char *message,
 *                                           const char *language_tag,
 *                                           void *context);
 *
 * DESCRIPTION
 *
 *    Status callback is called every time server returns a status packet
 *    for a request the client has made. The `status' indicates the type
 *    of the status.  The `message' is optional error message received from
 *    the server, in language indicated by the `language_tag'.  Both of
 *    these pointers may be NULL.
 *
 ***/
typedef void (*SilcSFTPStatusCallback)(SilcSFTP sftp,
				       SilcSFTPStatus status,
				       const char *message,
				       const char *language_tag,
				       void *context);

/****f* silcsftp/SilcSFTPAPI/SilcSFTPHandleCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSFTPHandleCallback)(SilcSFTP sftp,
 *                                           SilcSFTPStatus status,
 *                                           SilcSFTPHandle handle,
 *                                           void *context);
 *
 * DESCRIPTION
 *
 *    Handle callback is called when the server returns a handle to the
 *    client as a result of some request client has made.  The `handle'
 *    is the file handle and the application can use it to perform file
 *    operations for the handle. Each of the returned handle must be
 *    also closed at some point with silc_sftp_close.
 *
 ***/
typedef void (*SilcSFTPHandleCallback)(SilcSFTP sftp,
				       SilcSFTPStatus status,
				       SilcSFTPHandle handle,
				       void *context);

/****f* silcsftp/SilcSFTPAPI/SilcSFTPDataCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSFTPDataCallback)(SilcSFTP sftp,
 *                                         SilcSFTPStatus status,
 *                                         const unsigned char *data,
 *                                         SilcUInt32 data_len,
 *                                         void *context);
 *
 * DESCRIPTION
 *
 *    Data callback is called when data packet is received from the server.
 *    This is called for example when application is reading a file from
 *    the server.  The `data' is the raw data of length of `data_len'.
 *
 ***/
typedef void (*SilcSFTPDataCallback)(SilcSFTP sftp,
				     SilcSFTPStatus status,
				     const unsigned char *data,
				     SilcUInt32 data_len,
				     void *context);

/****f* silcsftp/SilcSFTPAPI/SilcSFTPNameCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSFTPNameCallback)(SilcSFTP sftp,
 *                                         SilcSFTPStatus status,
 *                                         const SilcSFTPName name,
 *                                         void *context);
 *
 * DESCRIPTION
 *
 *    Name callback is called when directory is being read by the client.
 *    The server returns one or more file names in one reply.  These file
 *    names are saved in the `filename' structures with their short and
 *    long name format, and with file attributes.
 *
 ***/
typedef void (*SilcSFTPNameCallback)(SilcSFTP sftp,
				     SilcSFTPStatus status,
				     const SilcSFTPName name,
				     void *context);

/****f* silcsftp/SilcSFTPAPI/SilcSFTPAttrCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSFTPAttrCallback)(SilcSFTP sftp,
 *                                         SilcSFTPStatus status,
 *                                         const SilcSFTPAttributes attrs,
 *                                         void *context);
 *
 * DESCRIPTION
 *
 *    Attributes callback is called when the server returns the attributes
 *    for a file the client has requested.  The attributes are saved in
 *    the `attrs' structure.
 *
 ***/
typedef void (*SilcSFTPAttrCallback)(SilcSFTP sftp,
				     SilcSFTPStatus status,
				     const SilcSFTPAttributes attrs,
				     void *context);

/****f* silcsftp/SilcSFTPAPI/SilcSFTPExtendedCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSFTPExtendedCallback)(SilcSFTP sftp,
 *                                             SilcSFTPStatus status,
 *                                             const unsigned char *data,
 *                                             SilcUInt32 data_len,
 *                                             void *context);
 *
 * DESCRIPTION
 *
 *    Extended request callback is called when client sends extended
 *    request to the server. The `data' is arbitrary data returned by the
 *    server and its encoding is the extended request specific.
 *
 ***/
typedef void (*SilcSFTPExtendedCallback)(SilcSFTP sftp,
					 SilcSFTPStatus status,
					 const unsigned char *data,
					 SilcUInt32 data_len,
					 void *context);


/* SFTP Client Interface */

/****f* silcsftp/SilcSFTPAPI/silc_sftp_client_start
 *
 * SYNOPSIS
 *
 *    SilcSFTP silc_sftp_client_start(SilcStream stream,
 *                                    SilcSFTPVersionCallback callback,
 *                                    void *context);
 *
 * DESCRIPTION
 *
 *    Starts SFTP client and returns context to it.  The version callback
 *    indicated by the `callback' will be called after the SFTP session has
 *    been started and server has returned the version of the protocol.  The
 *    SFTP client context is returned in the callback too.  This returns the
 *    allocated SFTP client context or NULL on error.  The `stream' will be
 *    used to read from and write to the SFTP packets.
 *
 ***/
SilcSFTP silc_sftp_client_start(SilcStream stream,
				SilcSFTPVersionCallback callback,
				void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_client_shutdown
 *
 * SYNOPSIS
 *
 *    void silc_sftp_client_shutdown(SilcSFTP sftp);
 *
 * DESCRIPTION
 *
 *    Shutdown's the SFTP client.  The caller is responsible of closing
 *    the associated socket connection.  The SFTP context is freed and is
 *    invalid after this function returns.
 *
 ***/
void silc_sftp_client_shutdown(SilcSFTP sftp);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_open
 *
 * SYNOPSIS
 *
 *    void silc_sftp_open(SilcSFTP sftp,
 *                        const char *filename,
 *                        SilcSFTPFileOperation pflags,
 *                        SilcSFTPAttributes attrs,
 *                        SilcSFTPHandleCallback callback,
 *                        void *context);
 *
 * DESCRIPTION
 *
 *    Open a file indicated by the `filename' with flags indicated by the
 *    `pflags', and with attributes indicated by the `attsr'.  Calls the
 *    `callback' to return the opened file handle.
 *
 ***/
void silc_sftp_open(SilcSFTP sftp,
		    const char *filename,
		    SilcSFTPFileOperation pflags,
		    SilcSFTPAttributes attrs,
		    SilcSFTPHandleCallback callback,
		    void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_close
 *
 * SYNOPSIS
 *
 *    void silc_sftp_close(SilcSFTP sftp,
 *                         SilcSFTPHandle handle,
 *                         SilcSFTPStatusCallback callback,
 *                         void *context);
 *
 * DESCRIPTION
 *
 *    Closes the file indicated by the file handle `handle'.  Calls the
 *    `callback' to indicate the status of the closing.
 *
 ***/
void silc_sftp_close(SilcSFTP sftp,
		     SilcSFTPHandle handle,
		     SilcSFTPStatusCallback callback,
		     void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_read
 *
 * SYNOPSIS
 *
 *    void silc_sftp_read(SilcSFTP sftp,
 *                        SilcSFTPHandle handle,
 *                        SilcUInt64 offset,
 *                        SilcUInt32 len,
 *                        SilcSFTPDataCallback callback,
 *                        void *context);
 *
 * DESCRIPTION
 *
 *    Reads data from the file indicated by the file handle `handle' starting
 *    from the offset of `offset' at most `len' bytes.  The `callback' is
 *    called to return the read data.
 *
 ***/
void silc_sftp_read(SilcSFTP sftp,
		    SilcSFTPHandle handle,
		    SilcUInt64 offset,
		    SilcUInt32 len,
		    SilcSFTPDataCallback callback,
		    void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_write
 *
 * SYNOPSIS
 *
 *    void silc_sftp_write(SilcSFTP sftp,
 *                         SilcSFTPHandle handle,
 *                         SilcUInt64 offset,
 *                         const unsigned char *data,
 *                         SilcUInt32 data_len,
 *                         SilcSFTPStatusCallback callback,
 *                         void *context);
 *
 * DESCRIPTION
 *
 *    Writes to a file indicated by the file handle `handle' starting from
 *    offset of `offset' at most `data_len' bytes of `data'.  The `callback'
 *    is called to indicate the status of the writing.
 *
 ***/
void silc_sftp_write(SilcSFTP sftp,
		     SilcSFTPHandle handle,
		     SilcUInt64 offset,
		     const unsigned char *data,
		     SilcUInt32 data_len,
		     SilcSFTPStatusCallback callback,
		     void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_remove
 *
 * SYNOPSIS
 *
 *    void silc_sftp_remove(SilcSFTP sftp,
 *                          const char *filename,
 *                          SilcSFTPStatusCallback callback,
 *                          void *context);
 *
 * DESCRIPTION
 *
 *    Removes a file indicated by the `filename'.  Calls the `callback'
 *    to indicate the status of the removing.
 *
 ***/
void silc_sftp_remove(SilcSFTP sftp,
		      const char *filename,
		      SilcSFTPStatusCallback callback,
		      void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_rename
 *
 * SYNOPSIS
 *
 *    void silc_sftp_rename(SilcSFTP sftp,
 *                          const char *oldname,
 *                          const char *newname,
 *                          SilcSFTPStatusCallback callback,
 *                          void *context);
 *
 * DESCRIPTION
 *
 *    Renames a file indicated by the `oldname' to the name `newname'.  The
 *    `callback' is called to indicate the status of the renaming.
 *
 ***/
void silc_sftp_rename(SilcSFTP sftp,
		      const char *oldname,
		      const char *newname,
		      SilcSFTPStatusCallback callback,
		      void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_mkdir
 *
 * SYNOPSIS
 *
 *    void silc_sftp_mkdir(SilcSFTP sftp,
 *                         const char *path,
 *                         SilcSFTPAttributes attrs,
 *                         SilcSFTPStatusCallback callback,
 *                         void *context);
 *
 * DESCRIPTION
 *
 *    Creates a new directory indicated by the `path' with attributes indicated
 *    by the `attrs'. The `callback' is called to indicate the status of the
 *    creation.
 *
 ***/
void silc_sftp_mkdir(SilcSFTP sftp,
		     const char *path,
		     SilcSFTPAttributes attrs,
		     SilcSFTPStatusCallback callback,
		     void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_rmdir
 *
 * SYNOPSIS
 *
 *    void silc_sftp_rmdir(SilcSFTP sftp,
 *                         const char *path,
 *                         SilcSFTPStatusCallback callback,
 *                         void *context);
 *
 * DESCRIPTION
 *
 *    Removes a directory indicated by the `path' and calls the `callback'
 *    to indicate the status of the removal.
 *
 ***/
void silc_sftp_rmdir(SilcSFTP sftp,
		     const char *path,
		     SilcSFTPStatusCallback callback,
		     void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_opendir
 *
 * SYNOPSIS
 *
 *    void silc_sftp_opendir(SilcSFTP sftp,
 *                           const char *path,
 *                           SilcSFTPHandleCallback callback,
 *                           void *context);
 *
 * DESCRIPTION
 *
 *    Opens a directory indicated by the `path'.  The `callback' is called
 *    to return the opened file handle.
 *
 ***/
void silc_sftp_opendir(SilcSFTP sftp,
		       const char *path,
		       SilcSFTPHandleCallback callback,
		       void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_readdir
 *
 * SYNOPSIS
 *
 *    void silc_sftp_readdir(SilcSFTP sftp,
 *                           SilcSFTPHandle handle,
 *                           SilcSFTPNameCallback callback,
 *                           void *context);
 *
 * DESCRIPTION
 *
 *    Reads the contents of the directory indicated by the `handle' and
 *    calls the `callback' to return the read file(s) from the directory.
 *
 ***/
void silc_sftp_readdir(SilcSFTP sftp,
		       SilcSFTPHandle handle,
		       SilcSFTPNameCallback callback,
		       void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_stat
 *
 * SYNOPSIS
 *
 *    void silc_sftp_stat(SilcSFTP sftp,
 *                        const char *path,
 *                        SilcSFTPAttrCallback callback,
 *                        void *context);
 *
 * DESCRIPTION
 *
 *    Gets the file attributes for a file indicated by the `path'. This
 *    will follow symbolic links also. Calls the `callback' to return the
 *    file attributes.
 *
 ***/
void silc_sftp_stat(SilcSFTP sftp,
		    const char *path,
		    SilcSFTPAttrCallback callback,
		    void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_lstat
 *
 * SYNOPSIS
 *
 *    void silc_sftp_lstat(SilcSFTP sftp,
 *                         const char *path,
 *                         SilcSFTPAttrCallback callback,
 *                         void *context);
 *
 * DESCRIPTION
 *
 *    Gets the file attributes for a file indicated by the `path'. This
 *    will not follow symbolic links. Calls the `callback' to return the
 *    file attributes
 *
 ***/
void silc_sftp_lstat(SilcSFTP sftp,
		     const char *path,
		     SilcSFTPAttrCallback callback,
		     void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_fstat
 *
 * SYNOPSIS
 *
 *    void silc_sftp_fstat(SilcSFTP fstp,
 *                         SilcSFTPHandle handle,
 *                         SilcSFTPAttrCallback callback,
 *                         void *context);
 *
 * DESCRIPTION
 *
 *    Gets a file attributes for a opened file indicated by the `handle'.
 *    Calls the `callback' to return the file attributes.
 *
 ***/
void silc_sftp_fstat(SilcSFTP fstp,
		     SilcSFTPHandle handle,
		     SilcSFTPAttrCallback callback,
		     void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_setstat
 *
 * SYNOPSIS
 *
 *    void silc_sftp_setstat(SilcSFTP sftp,
 *                           const char *path,
 *                           SilcSFTPAttributes attrs,
 *                           SilcSFTPStatusCallback callback,
 *                           void *context);
 *
 * DESCRIPTION
 *
 *    Sets a file attributes to a file indicated by the `path' with the
 *    attributes indicated by the `attrs'.  Calls the `callback' to indicate
 *    the status of the setting.
 *
 ***/
void silc_sftp_setstat(SilcSFTP sftp,
		       const char *path,
		       SilcSFTPAttributes attrs,
		       SilcSFTPStatusCallback callback,
		       void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_fsetstat
 *
 * SYNOPSIS
 *
 *    void silc_sftp_fsetstat(SilcSFTP sftp,
 *                            SilcSFTPHandle handle,
 *                            SilcSFTPAttributes attrs,
 *                            SilcSFTPStatusCallback callback,
 *                            void *context);
 *
 * DESCRIPTION
 *
 *    Sets a file attributes to a opened file indicated by the `handle' with
 *    the attributes indicated by the `attrs'.  Calls the `callback' to
 *    indicate the status of the setting.
 *
 ***/
void silc_sftp_fsetstat(SilcSFTP sftp,
			SilcSFTPHandle handle,
			SilcSFTPAttributes attrs,
			SilcSFTPStatusCallback callback,
			void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_readlink
 *
 * SYNOPSIS
 *
 *    void silc_sftp_readlink(SilcSFTP sftp,
 *                            const char *path,
 *                            SilcSFTPNameCallback callback,
 *                            void *context);
 *
 * DESCRIPTION
 *
 *    Reads the target of a symbolic link indicated by the `path'.  The
 *    `callback' is called to return the target of the symbolic link.
 *
 ***/
void silc_sftp_readlink(SilcSFTP sftp,
			const char *path,
			SilcSFTPNameCallback callback,
			void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_symlink
 *
 * SYNOPSIS
 *
 *    void silc_sftp_symlink(SilcSFTP sftp,
 *                           const char *linkpath,
 *                           const char *targetpath,
 *                           SilcSFTPStatusCallback callback,
 *                           void *context);
 *
 * DESCRIPTION
 *
 *    Creates a new symbolic link indicated by the `linkpath' to the target
 *    indicated by the `targetpath'.  The `callback' is called to indicate
 *    the status of creation.
 *
 ***/
void silc_sftp_symlink(SilcSFTP sftp,
		       const char *linkpath,
		       const char *targetpath,
		       SilcSFTPStatusCallback callback,
		       void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_realpath
 *
 * SYNOPSIS
 *
 *    void silc_sftp_realpath(SilcSFTP sftp,
 *                            const char *path,
 *                            SilcSFTPNameCallback callback,
 *                            void *context);
 *
 * DESCRIPTION
 *
 *    Canonicalizes the path indicated by the `path' to a absolute path.
 *    The `callback' is called to return the absolute path.
 *
 ***/
void silc_sftp_realpath(SilcSFTP sftp,
			const char *path,
			SilcSFTPNameCallback callback,
			void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_extended
 *
 * SYNOPSIS
 *
 *    void silc_sftp_extended(SilcSFTP sftp,
 *                            const char *request,
 *                            const unsigned char *data,
 *                            SilcUInt32 data_len,
 *                            SilcSFTPExtendedCallback callback,
 *                            void *context);
 *
 * DESCRIPTION
 *
 *    Performs an extended operation indicated by the `request' with
 *    optional extended operation data indicated by the `data'.  The callback
 *    is called to return any data associated with the extended request.
 *
 ***/
void silc_sftp_extended(SilcSFTP sftp,
			const char *request,
			const unsigned char *data,
			SilcUInt32 data_len,
			SilcSFTPExtendedCallback callback,
			void *context);


/* SFTP Server Interface */

#include "silcsftp_fs.h"

/****f* silcsftp/SilcSFTPAPI/silc_sftp_server_start
 *
 * SYNOPSIS
 *
 *    SilcSFTP silc_sftp_server_start(SilcSFTPSendPacketCallback send_packet,
 *                                    void *send_context,
 *                                    SilcSFTPFilesystem fs);
 *
 * DESCRIPTION
 *
 *    Starts SFTP server and returns a context to it.  This function returns
 *    the allocated SFTP server context or NULL on error. The `send_packet'
 *    is called by the library when it needs to send a packet. The `fs' is the
 *    filesystem context allocated by the application.  Each socket connection
 *    should start its own server by calling this function.
 *
 ***/
SilcSFTP silc_sftp_server_start(SilcSFTPSendPacketCallback send_packet,
				void *send_context,
				SilcSFTPFilesystem fs);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_server_shutdown
 *
 * SYNOPSIS
 *
 *    void silc_sftp_server_shutdown(SilcSFTP sftp);
 *
 * DESCRIPTION
 *
 *    Shutdown's the SFTP server.  The caller is responsible of closing
 *    the associated socket connection.  The SFTP context is freed and is
 *    invalid after this function returns.
 *
 ***/
void silc_sftp_server_shutdown(SilcSFTP sftp);

/****d* silcsftp/SilcSFTPAPI/SilcSFTPMonitors
 *
 * NAME
 *
 *    typedef enum { ... } SilcSFTPMonitors;
 *
 * DESCRIPTION
 *
 *    SFTP server monitor types. These can be masked together to monitor
 *    various client requests.
 *
 * SOURCE
 */
typedef enum {
  SILC_SFTP_MONITOR_INIT        = 0x0001,
  SILC_SFTP_MONITOR_OPEN        = 0x0002,
  SILC_SFTP_MONITOR_CLOSE       = 0x0004,
  SILC_SFTP_MONITOR_READ        = 0x0008,
  SILC_SFTP_MONITOR_WRITE       = 0x0010,
  SILC_SFTP_MONITOR_REMOVE      = 0x0020,
  SILC_SFTP_MONITOR_RENAME      = 0x0040,
  SILC_SFTP_MONITOR_MKDIR       = 0x0080,
  SILC_SFTP_MONITOR_RMDIR       = 0x0100,
  SILC_SFTP_MONITOR_OPENDIR     = 0x0200,
  SILC_SFTP_MONITOR_READDIR     = 0x0400,
  SILC_SFTP_MONITOR_STAT        = 0x0800,
  SILC_SFTP_MONITOR_LSTAT       = 0x1000,
  SILC_SFTP_MONITOR_FSTAT       = 0x2000,
  SILC_SFTP_MONITOR_SETSTAT     = 0x4000,
  SILC_SFTP_MONITOR_FSETSTAT    = 0x8000,
  SILC_SFTP_MONITOR_READLINK    = 0x10000,
  SILC_SFTP_MONITOR_SYMLINK     = 0x20000,
  SILC_SFTP_MONITOR_REALPATH    = 0x40000,
  SILC_SFTP_MONITOR_EXTENDED    = 0x80000,
} SilcSFTPMonitors;
/***/

/****s* silcsftp/SilcSFTPAPI/SilcSFTPMonitorData
 *
 * NAME
 *
 *    typedef struct { ... } *SilcSFTPMonitorData, SilcSFTPMonitorDataStruct;
 *
 * DESCRIPTION
 *
 *    This structure includes the monitor type specific data.  The
 *    application can check what the client has requested from this
 *    structure.
 *
 * SOURCE
 */
typedef struct {
  SilcSFTPVersion version;	/* _INIT */
  char *name;			/* _OPEN, _REMOVE, _RENAME, _MKDIR,
				   _RMDIR, _OPENDIR, _STAT, _LSTAT,
				   _SETSTAT, _READLINK, _SYMLINK, _REALPATH */
  char *name2;			/* _RENAME, _SYMLINK */
  SilcSFTPFileOperation pflags;	/* _OPEN */
  SilcUInt64 offset;		/* _READ, _WRITE */
  SilcUInt32 data_len;		/* _READ, _WRITE */
  SilcSFTPName names;		/* _READDIR, _READLINK, _REALPATH */
} *SilcSFTPMonitorData, SilcSFTPMonitorDataStruct;
/***/

/****f* silcsftp/SilcSFTPAPI/SilcSFTPMonitor
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSFTPMonitor)(SilcSFTP sftp
 *                                    SilcSFTPMonitors type,
 *                                    const SilcSFTPMonitorData data,
 *                                    void *context);
 *
 * DESCRIPTION
 *
 *    Monitor callback that is called when an specified request is
 *    received from client.  The `type' is the requested type that
 *    was being monitored.
 *
 ***/
typedef void (*SilcSFTPMonitor)(SilcSFTP sftp,
				SilcSFTPMonitors type,
				const SilcSFTPMonitorData data,
				void *context);

/****f* silcsftp/SilcSFTPAPI/silc_sftp_server_set_monitor
 *
 * SYNOPSIS
 *
 *    void silc_sftp_server_set_monitor(SilcSFTP sftp,
 *                                      SilcSFTPMonitors monitors,
 *                                      SilcSFTPMonitor monitor,
 *                                      void *context);
 *
 * DESCRIPTION
 *
 *    Sets monitor callback to monitor various request sent by a client.
 *    When request that has been set in the `monitors' is received the
 *    monitor callback will be called to notify the caller.
 *
 ***/
void silc_sftp_server_set_monitor(SilcSFTP sftp,
				  SilcSFTPMonitors monitors,
				  SilcSFTPMonitor monitor,
				  void *context);

#endif /* SILCSFTP_H */
