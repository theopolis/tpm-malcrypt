// tpm-keyextract.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
	HRESULT status;
	PCWSTR keyName = L"MalcryptKey0";

	/* Create the key on the TPM. */
	status = TlclCreateKey(keyName);

	PBYTE pubKeyData;
	UINT32 pubKeySize;

	/* Output the public key (to exfiltrate). */
	status = TlclGetPubKey(keyName, &pubKeySize, &pubKeyData);
	if (!FAILED(status)) {
		ZeroAndFree((PVOID*)&pubKeyData, pubKeySize);
	}

	return status;
}

