// tpm-keyextract.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
	HRESULT status;
	PCWSTR keyName = L"MalcryptKey0";

	/* Create the key on the TPM. */
	status = TlclCreateKey(keyName);
	/* Output the public key to a file (for exfiltration). */
	status = TlclGetPubKey(keyName, L"output.txt");
	return status;
}

