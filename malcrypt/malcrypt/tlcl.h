/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

This micro TLCL library is based on Microsoft's PCP-Key Attestation
code reference library.

Copyright (c) Microsoft Corporation. (MSR-LA)  All rights reserved.
Stefan Thom, stefanth@Microsoft.com, 2011/06/09

--*/

#include <bcrypt.h>
#include <ncrypt.h>
#include <Cryptuiapi.h>
#include <Wincrypt.h>
#include <Winscard.h>
#include <Cryptuiapi.h>
#include <wincred.h>
#include <Objbase.h>
#include <Shlobj.h>
#include <TBS.h>
#include <wbcl.h>

HRESULT
TlclCreateKey(
	PCWSTR keyName,
	PCWSTR usageAuth = NULL,
	UINT32 pcrMask = 0,
	PCWSTR pcrsName = NULL
);

HRESULT
TlclDeleteKey(
	PCWSTR keyName
);

HRESULT
TlclGetPubKey(
_In_ PCWSTR lpKeyName,   /* Input TPM key name. */
_Out_ PUINT32 pcbPubKey, /* Output, number of bytes of public key read (1024). */
_Out_ PBYTE *pbPubKey    /* Output, public key data. */
);

HRESULT
TlclDecrypt(
	_In_ PCWSTR keyName,
	_In_ UINT32 encDataSize,
	_In_ PBYTE encData,
	_Out_ PUINT32 *decDataSize,
	_Out_ PBYTE *decData,
	_In_opt_ PCWSTR keyAuthValue = NULL
);
