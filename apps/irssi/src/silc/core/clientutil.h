/*

  client.h

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

#ifndef CLIENTUTIL_H
#define CLIENTUTIL_H

#include "signals.h"

/* Prototypes */
void silc_client_list_ciphers();
void silc_client_list_hash_funcs();
void silc_client_list_hmacs();
void silc_client_list_pkcs();
int silc_client_check_silc_dir();
int silc_client_load_keys(SilcClient client);

typedef enum
{
	KeyboardCompletionSuccess, /* Success; keyboard data returned to callback. */
	KeyboardCompletionAborted, /* Operation was aborted after starting successfully. */
	KeyboardCompletionFailed /* Operation was not started successfully. */
} SilcKeyboardPromptStatus;

typedef void (*SILC_KEYBOARD_PROMPT_PROC)(
	const char *line,
	void *context,
	SilcKeyboardPromptStatus reason);

/*
 * Prompt for keyboard input.
 *
 * If the function returns FALSE, then the prompt operation could not be
 * initiated and the user supplied callback is called to indicate that the
 * operation was not started (reason KeyboardCompletionFailed).  This can be
 * used to centralize all cleanup work in the callback function.
 *
 * If the function returns TRUE, then the operation was initiated successfully
 * and the prompt callback is guaranteed to be called sometime in the future.
 * Note that it is posssible for the completion callback to have been already
 * called by the time the function returns TRUE.  In this instance, the
 * callback will eventually be called with KeyboardCompletionSuccess, unless
 * the operation is aborted before then.
 *
 * If the function returns TRUE, then a SilcAsyncOperation context may be
 * returned.  If an async operation context is returned, then the operation has
 * not been completed immediately, and may be canceled with a call to
 * silc_async_abort(*async).
 *
 * Note that the SilcAsyncOperation object's lifetime is managed internally.  A
 * user may call silc_async_abort exactly once, after which it can never touch
 * the async context again.  Additionally, the async context may not be
 * referenced after the user callback returns.  The recommended way to handle
 * the async operation context is to remove the reference to it when the user
 * callback is called, either for an abort or regular completion.  If the
 * callback is called with a KeyboardCompletionFailed reason, then no async
 * context object was allocated.
 *
 * If an abort is requested, then the user callback is called with reason code
 * KeyboardCompletionAborted.  In this case, the user should clean up all
 * associated callback data and perform the handling expected in the abort case,
 * such as the associated server connection going away while the operation was
 * in progress.
 *
 * There can only be one keyboard redirect operation in progress.  If a
 * keyboard redirect operation is aborted while we are still waiting for data,
 * then we abort all callbacks until that callback returns.
 */
bool silc_keyboard_entry_redirect(
	SILC_KEYBOARD_PROMPT_PROC prompt_func,
	const char *entry,
	int flags,
	void *data,
	SilcAsyncOperation *async);

#ifdef SILC_PLUGIN
typedef struct {
  char *old, *passphrase, *file, *pkcs;
  int bits;
} CREATE_KEY_REC;

void create_key_passphrase(const char *answer, CREATE_KEY_REC *rec);
void change_private_key_passphrase(const char *answer, CREATE_KEY_REC *rec);
#endif

#endif
