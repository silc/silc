/*

  softacc.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SOFTACC_H
#define SOFTACC_H

/* The software accelerator */
extern DLLAPI const SilcAcceleratorStruct softacc;

SilcBool silc_softacc_init(SilcSchedule schedule, va_list va);
SilcBool silc_softacc_uninit(void);
SILC_PKCS_ALG_IMPORT_PUBLIC_KEY(silc_softacc_acc_public_key);
SILC_PKCS_ALG_PUBLIC_KEY_FREE(silc_softacc_free_public_key);
SILC_PKCS_ALG_IMPORT_PRIVATE_KEY(silc_softacc_acc_private_key);
SILC_PKCS_ALG_PRIVATE_KEY_FREE(silc_softacc_free_private_key);
SILC_PKCS_ALG_ENCRYPT(silc_softacc_encrypt);
SILC_PKCS_ALG_DECRYPT(silc_softacc_decrypt);
SILC_PKCS_ALG_SIGN(silc_softacc_sign);
SILC_PKCS_ALG_VERIFY(silc_softacc_verify);

#endif /* SOFTACC_H */
