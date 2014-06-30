// malcrypt.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
	HRESULT status;
	PCWSTR keyName = L"MalcryptKey0";

	status = TlclCreateKey(keyName);
	status = TlclGetPubKey(keyName);
	status = TlclDeleteKey(keyName);
}

