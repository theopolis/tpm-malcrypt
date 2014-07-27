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

#include "stdafx.h"

HRESULT
TlclCreateKey(
	PCWSTR keyName,
	PCWSTR usageAuth, /* Optional */
	UINT32 pcrMask, /* Optional */
	PCWSTR pcrsName) /* Optional */
{
	HRESULT hr = S_OK;
	NCRYPT_PROV_HANDLE hProv = NULL;
	NCRYPT_KEY_HANDLE hKey = NULL;
	
	PBYTE pbPcrTable = NULL;
	UINT32 cbPcrTable = 0;
	BYTE pbKeyPub[1024] = { 0 };
	DWORD cbKeyPub = 0;
	BOOLEAN tUIRequested = false;
	
	LPCWSTR optionalPIN = L"This key requires usage consent and an optional PIN.";
	LPCWSTR mandatoryPIN = L"This key has a mandatory PIN.";
	NCRYPT_UI_POLICY rgbUiPolicy = { 1, 0x0 /* flags */, NULL, NULL, NULL };


	// Optional parameter: usageAuth
	if (usageAuth != NULL && wcslen(usageAuth) != 0) {
		if (!wcscmp(usageAuth, L"@")) {
			// Caller requested UI
			usageAuth = NULL;
			tUIRequested = TRUE;
			rgbUiPolicy.pszFriendlyName = keyName;
			rgbUiPolicy.dwFlags = NCRYPT_UI_PROTECT_KEY_FLAG;
			rgbUiPolicy.pszDescription = optionalPIN;
		}
		else if (!wcscmp(usageAuth, L"!")) {
			// Caller requested UI
			usageAuth = NULL;
			tUIRequested = TRUE;
			rgbUiPolicy.pszFriendlyName = keyName;
			rgbUiPolicy.dwFlags = NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG;
			rgbUiPolicy.pszDescription = mandatoryPIN;
		}
	}

	// Optional parameter: pcrTable
	if (pcrsName != NULL && wcslen(usageAuth) != 0) {
		if (FAILED(hr = PcpToolReadFile(pcrsName, NULL, 0, &cbPcrTable))) {
			goto Cleanup;
		}
		if (FAILED(hr = AllocateAndZero((PVOID*)&pbPcrTable, cbPcrTable))) {
			goto Cleanup;
		}
		if (FAILED(hr = PcpToolReadFile(
			pcrsName,
			pbPcrTable,
			cbPcrTable,
			&cbPcrTable))) {
			goto Cleanup;
		}
	}

	// Create the key
	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
		&hProv,
		MS_PLATFORM_CRYPTO_PROVIDER,
		0)))) {
		goto Cleanup;
	}

	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptCreatePersistedKey(
		hProv,
		&hKey,
		BCRYPT_RSA_ALGORITHM,
		keyName,
		0,
		NCRYPT_OVERWRITE_KEY_FLAG)))) {
		goto Cleanup;
	}

	if (tUIRequested == FALSE) {
		if ((usageAuth != NULL) && (wcslen(usageAuth) != 0)) {
			if (FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
				hKey,
				NCRYPT_PIN_PROPERTY,
				(PBYTE)usageAuth,
				(DWORD)((wcslen(usageAuth) + 1) * sizeof(WCHAR)),
				0)))) {
				goto Cleanup;
			}
		}
	}
	else {
		if (FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
			hKey,
			NCRYPT_UI_POLICY_PROPERTY,
			(PBYTE)&rgbUiPolicy,
			sizeof(NCRYPT_UI_POLICY),
			0)))) {
			goto Cleanup;
		}
	}

	// Optional pcrMask (bind to the selected PCRs)
	if (pcrMask != 0) {
		if (FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
			hKey,
			NCRYPT_PCP_PLATFORM_BINDING_PCRMASK_PROPERTY,
			(PBYTE)&pcrMask,
			0x00000003,
			0)))) {
			goto Cleanup;
		}
		if ((pbPcrTable != NULL) && (cbPcrTable == (24 * 20))) {
			if (FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
				hKey,
				NCRYPT_PCP_PLATFORM_BINDING_PCRDIGESTLIST_PROPERTY,
				pbPcrTable,
				cbPcrTable,
				0)))) {
				goto Cleanup;
			}
		}
	}

	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptFinalizeKey(hKey, 0)))) {
		goto Cleanup;
	}

	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(hKey,
		NULL,
		BCRYPT_RSAPUBLIC_BLOB,
		NULL,
		pbKeyPub,
		sizeof(pbKeyPub),
		&cbKeyPub,
		0)))) {
		goto Cleanup;
	}

	// Output results
	if (FAILED(hr = PcpToolDisplayKey(keyName, pbKeyPub, cbKeyPub, 0))) {
		goto Cleanup;
	}

Cleanup:
	if (hKey != NULL) {
		NCryptFreeObject(hKey);
		hKey = NULL;
	}
	if (hProv != NULL) {
		NCryptFreeObject(hProv);
		hProv = NULL;
	}
	ZeroAndFree((PVOID*)&pbPcrTable, cbPcrTable);
	return hr;
}

HRESULT
TlclDeleteKey(
	PCWSTR keyName)
{
	HRESULT hr = S_OK;
	NCRYPT_PROV_HANDLE hProv = NULL;
	NCRYPT_KEY_HANDLE hKey = NULL;

	// Open the key
	if (FAILED(hr = (NCryptOpenStorageProvider(
		&hProv,
		MS_PLATFORM_CRYPTO_PROVIDER,
		0)))) {
		goto Cleanup;
	}

	if (FAILED(hr = (NCryptOpenKey(
		hProv,
		&hKey,
		keyName,
		0,
		0)))) {
		goto Cleanup;
	}

	// Delete the key
	if (FAILED(hr = (NCryptDeleteKey(hKey, 0)))) {
		goto Cleanup;
	}
	hKey = NULL;

	wprintf(L"Ok.\n");

Cleanup:
	if (hKey != NULL) {
		NCryptFreeObject(hKey);
		hKey = NULL;
	}
	if (hProv != NULL) {
		NCryptFreeObject(hProv);
		hProv = NULL;
	}
	return hr;
}

HRESULT
TlclGetPubKey(
	_In_ PCWSTR lpKeyName,
	_Out_ PUINT32 pcbPubKey,
	_Out_ PBYTE *pbPubKey)
{
	HRESULT hr = S_OK;
	NCRYPT_PROV_HANDLE hProv = NULL;
	NCRYPT_KEY_HANDLE hKey = NULL;
	//BYTE pbPubKey[1024] = { 0 };
	DWORD cbPubKey = 0;

	// Open key
	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
		&hProv,
		MS_PLATFORM_CRYPTO_PROVIDER,
		0)))) {
		goto Cleanup;
	}

	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(hProv, 
		&hKey, 
		lpKeyName, 
		0, 
		0)))) {
		goto Cleanup;
	}

	/* Create output pointer/memory. */
	*pcbPubKey = 0;
	if (FAILED(hr = AllocateAndZero((PVOID *) pbPubKey, 1024))) {
		goto Cleanup;
	}

	// Export public key
	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
		hKey,
		NULL,
		BCRYPT_RSAPUBLIC_BLOB,
		NULL,
		*pbPubKey,
		1024,
		&cbPubKey,
		0)))) {
		goto Cleanup;
	}

	/* Set size of key (helpful for caller). */
	*pcbPubKey = 1024;

Cleanup:
	if (hKey != NULL) {
		NCryptFreeObject(hKey);
		hKey = NULL;
	}
	if (hProv != NULL) {
		NCryptFreeObject(hProv);
		hProv = NULL;
	}
	return hr;
}

HRESULT
TlclDecrypt(
	_In_ PCWSTR keyName,
	_In_ UINT32 encDataSize,
	_In_ PBYTE encData,
	_Out_ PUINT32 decDataSize,
	_Out_ PBYTE *decData,
	_In_opt_ PCWSTR keyAuthValue)
{
	HRESULT hr = S_OK;
	NCRYPT_PROV_HANDLE hProv = NULL;
	NCRYPT_KEY_HANDLE hKey = NULL;
	UINT32 cbSecret = 0;

	// Open key
	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
		&hProv,
		MS_PLATFORM_CRYPTO_PROVIDER,
		0)))) {
		goto Cleanup;
	}
	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
		hProv,
		&hKey,
		keyName,
		0,
		(keyAuthValue != 0) ? NCRYPT_SILENT_FLAG : 0)))) {
		goto Cleanup;
	}

	if ((keyAuthValue != NULL) && (wcslen(keyAuthValue) != 0)) {
		if (FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
			hKey,
			NCRYPT_PIN_PROPERTY,
			(PBYTE)keyAuthValue,
			(DWORD)((wcslen(keyAuthValue) + 1) * sizeof(WCHAR)),
			0)))) {
			goto Cleanup;
		}
	}

	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptDecrypt(
		hKey,
		encData,
		encDataSize,
		NULL,
		NULL,
		0,
		(PDWORD) &cbSecret,
		NCRYPT_PAD_PKCS1_FLAG)))) {
		goto Cleanup;
	}

	*decDataSize = 0;
	if (FAILED(hr = AllocateAndZero((PVOID*) decData, cbSecret))) {
		goto Cleanup;
	}
	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptDecrypt(
		hKey,
		encData,
		encDataSize,
		NULL,
		*decData,
		cbSecret,
		(PDWORD)&cbSecret,
		BCRYPT_PAD_PKCS1)))) {
		goto Cleanup;
	}

	*decDataSize = cbSecret;

Cleanup:
	if (hKey != NULL) {
		NCryptFreeObject(hKey);
		hKey = NULL;
	}
	if (hProv != NULL) {
		NCryptFreeObject(hProv);
		hProv = NULL;
	}

	return hr;
}

HRESULT
TlclEncrypt(
	PCWSTR keyFile,
	PCWSTR decData,
	PCWSTR blobFile /* Optional write output */
) {
	HRESULT hr = S_OK;
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	UINT32 cbPubkey = 0;
	PBYTE pbPubkey = NULL;
	UINT32 cbBlob = 0;
	PBYTE pbBlob = NULL;

	if (FAILED(hr = PcpToolReadFile(keyFile, NULL, 0, &cbPubkey))) {
		goto Cleanup;
	}
	if (FAILED(hr = AllocateAndZero((PVOID*)&pbPubkey, cbPubkey))) {
		goto Cleanup;
	}
	if (FAILED(hr = PcpToolReadFile(keyFile, pbPubkey, cbPubkey, &cbPubkey))) {
		goto Cleanup;
	}

	// Open the key
	if (FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_RSA_ALGORITHM,
		MS_PRIMITIVE_PROVIDER,
		0)))) {
		goto Cleanup;
	}

	if (FAILED(hr = HRESULT_FROM_NT(BCryptImportKeyPair(
		hAlg,
		NULL,
		BCRYPT_RSAPUBLIC_BLOB,
		&hKey,
		pbPubkey,
		cbPubkey,
		0)))) {
		goto Cleanup;
	}

	if (FAILED(hr = HRESULT_FROM_NT(BCryptEncrypt(
		hKey,
		(PBYTE)decData,
		(DWORD)((wcslen(decData) + 1) * sizeof(WCHAR)),
		NULL,
		NULL,
		0,
		NULL,
		0,
		(PULONG)&cbBlob,
		BCRYPT_PAD_PKCS1)))) {
		goto Cleanup;
	}
	if (FAILED(hr = AllocateAndZero((PVOID*)&pbBlob, cbBlob))) {
		goto Cleanup;
	}
	if (FAILED(hr = HRESULT_FROM_NT(BCryptEncrypt(
		hKey,
		(PBYTE)decData,
		(DWORD)((wcslen(decData) + 1) * sizeof(WCHAR)),
		NULL,
		NULL,
		0,
		pbBlob,
		cbBlob,
		(PULONG)&cbBlob,
		BCRYPT_PAD_PKCS1)))) {
		goto Cleanup;
	}

	if (blobFile != NULL) {
		if (FAILED(hr = PcpToolWriteFile(blobFile, pbBlob, cbBlob))) {
			goto Cleanup;
		}
	}

Cleanup:
	if (hKey != NULL) {
		BCryptDestroyKey(hKey);
		hKey = NULL;
	}
	if (hAlg != NULL) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		hAlg = NULL;
	}
	ZeroAndFree((PVOID*)&pbBlob, cbBlob);
	ZeroAndFree((PVOID*)&pbPubkey, cbPubkey);

	return hr;
}
