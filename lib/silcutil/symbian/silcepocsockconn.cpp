/*

  silcepocsockconn.cpp 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 Pekka Riikonen

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

/* Writes data from encrypted buffer to the socket connection. If the
   data cannot be written at once, it will be written later with a timeout. 
   The data is written from the data section of the buffer, not from head
   or tail section. This automatically pulls the data section towards end
   after writing the data. */

int silc_socket_write(SilcSocketConnection sock)
{
  /* XXX */
}

/* Reads data from the socket connection into the incoming data buffer.
   It reads as much as possible from the socket connection. This returns
   amount of bytes read or -1 on error or -2 on case where all of the
   data could not be read at once. */

int silc_socket_read(SilcSocketConnection sock)
{
  /* XXX */
}

/* Returns human readable socket error message. These are copied from the
   PuTTY. */

#define PUT_ERROR(s) 
do {
  if (strlen(s) > err_len)
    return FALSE;
  memset(error, 0, error_len);
  memcpy(error, s, strlen(s));
  return TRUE;
} while(0)

bool silc_socket_get_error(SilcSocketConnection sock, char *error,
			   uint32 error_len)
{
  if (sock->sock_error == KErrNone)
    return FALSE;

  switch (sock->sock_error) {
  case KErrNotFound:
    PUT_ERROR("Item not found. (NotFound)");
  case KErrGeneral:
    PUT_ERROR("Uncategorized error. (General)");
  case KErrCancel:
    PUT_ERROR("Operation cancelled. (Cancel)");
  case KErrNoMemory:
    PUT_ERROR("A memory allocation failed. (NoMemory)");
  case KErrNotSupported:
    PUT_ERROR("A function is not supported in a given context. "
	      "(NotSupported)");
  case KErrArgument:
    PUT_ERROR("An argument is out of range. (Argument)");
  case KErrBadHandle:
    PUT_ERROR("Bad handle. (BadHandle)");
  case KErrOverflow:
    PUT_ERROR("Overflow. (Overflow)");
  case KErrUnderflow:
    PUT_ERROR("Underflow. (Underflow)");
  case KErrAlreadyExists:
    PUT_ERROR("The resource already exists. (AlreadyExists)");
  case KErrPathNotFound:
    PUT_ERROR("In the context of file operations, the path was "
	      "not found. (PathNotFound)");
  case KErrDied:
    PUT_ERROR("A handle refers to a thread which has died (Died)");
  case KErrInUse:
    PUT_ERROR("A requested resource is already in use. (InUse)");
  case KErrServerTerminated:
    PUT_ERROR("A client/server operation cannot execute, because the "
	      "server has terminated. (ServerTerminated)");
  case KErrServerBusy:
    PUT_ERROR("A client/server operation cannot execute, because the server "
	      "is busy. (ServerBusy)");
  case KErrNotReady:
    PUT_ERROR("Resource not ready. Not initialized, or has no power. "
	      "(NotReady)");
  case KErrUnknown:
    PUT_ERROR("A device is of unknown type. (Unknown)");
  case KErrCorrupt:
    PUT_ERROR("Corrupted. (Corrupt)");
  case KErrAccessDenied:
    PUT_ERROR("Access denied. (AccessDenied)");
  case KErrLocked:
    PUT_ERROR("The operation cannot be performed, because the resource "
	      "is locked. (Locked)");
  case KErrWrite:
    PUT_ERROR("During a file write operation, not all the data could "
	      "be written. (Write)");
  case KErrDisMounted:
    PUT_ERROR("A volume which was to be used for a file system operation "
	      "has been dismounted. (DisMounted)");
  case KErrEof:
    PUT_ERROR("End of file has been reached. (Eof)");
  case KErrDiskFull:
    PUT_ERROR("A write operation could not complete, because the disk "
	      "was full. (DiskFull)");
  case KErrBadDriver:
    PUT_ERROR("A driver DLL was of the wrong type. (BadDriver)");
  case KErrBadName:
    PUT_ERROR("Name did not conform with the required syntax. (BadName)");
  case KErrCommsLineFail:
    PUT_ERROR("The communication line failed. (CommsLineFail)");
  case KErrCommsFrame:
    PUT_ERROR("A frame error occurred in a communications operation. "
	      "(CommsFrame)");
  case KErrCommsOverrun:
    PUT_ERROR("An overrun was detected by a communications driver. "
	      "(CommsOverrun)");
  case KErrCommsParity:
    PUT_ERROR("A parity error occurred in communications. (CommsParity)");
  case KErrTimedOut:
    PUT_ERROR("An operation timed out. (TimedOut)");
  case KErrCouldNotConnect:
    PUT_ERROR("A session could not connect. (CouldNotConnect)");
  case KErrCouldNotDisconnect:
    PUT_ERROR("A session could not disconnect. (CouldNotDisconnect)");
  case KErrDisconnected:
    PUT_ERROR("The required session was disconnected. (Disconnected)");
  case KErrBadLibraryEntryPoint:
    PUT_ERROR("A library entry point was not of the required type. "
	      "(BadLibraryEntryPoint)");
  case KErrBadDescriptor:
    PUT_ERROR("A non-descriptor parameter was passed. (BadDescriptor)");
  case KErrAbort:
    PUT_ERROR("An operation was aborted (Abort)");
  case KErrTooBig:
    PUT_ERROR("A number was too big (TooBig)");
  case KErrDivideByZero:
    PUT_ERROR("A divide-by-zero operation was attempted. (DivideByZero)");
  case KErrBadPower:
    PUT_ERROR("Insufficient power was available to complete an operation. "
	      "(BadPower)");
  case KErrWouldBlock:
    PUT_ERROR("Network error: Resource temporarily unavailable (WouldBlock)");
  case KErrNetUnreach:
    PUT_ERROR("Network unreachable. (NetUnreach)");
  case KErrHostUnreach:
    PUT_ERROR("Host unreachable. (HostUnreach)");
  case KErrNoProtocolOpt:
    PUT_ERROR("No such protocol option. (NoProtocolOpt)");
  case KErrUrgentData:
    PUT_ERROR("Urgent data arrived. (UrgentData)");
  case KInvalSocket:
    PUT_ERROR("Got NULL sokcet.");
  }

  return FALSE;
}
