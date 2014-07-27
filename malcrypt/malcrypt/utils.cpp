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

void
PcpToolLevelPrefix(
	UINT32 level)
{
	for (UINT32 n = 0; n < level; n++)
	{
		wprintf(L"  ");
	}
}

HRESULT
PcpToolReadFile(
	_In_ PCWSTR lpFileName,
	_In_reads_opt_(cbData) PBYTE pbData,
	UINT32 cbData,
	__out PUINT32 pcbData)
{
	HRESULT hr = S_OK;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	LARGE_INTEGER dataSize = { 0 };
	DWORD bytesRead = 0;

	if (pcbData == NULL)
	{
		hr = E_INVALIDARG;
		goto Cleanup;
	}

	hFile = CreateFileW(
		lpFileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto Cleanup;
	}

	if (!GetFileSizeEx(hFile, &dataSize))
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto Cleanup;
	}

	if (dataSize.HighPart != 0)
	{
		hr = NTE_BAD_DATA;
		goto Cleanup;
	}

	*pcbData = dataSize.LowPart;
	if ((pbData == NULL) || (cbData == 0))
	{
		goto Cleanup;
	}
	else if (cbData < *pcbData)
	{
		hr = NTE_BUFFER_TOO_SMALL;
		goto Cleanup;
	}
	else
	{
		while (cbData > bytesRead)
		{
			DWORD bytesReadLast = 0;
			if (!ReadFile(hFile,
				&pbData[bytesRead],
				(DWORD)(cbData - bytesRead),
				&bytesReadLast,
				NULL))
			{
				hr = HRESULT_FROM_WIN32(GetLastError());
				goto Cleanup;
			}
			bytesRead += bytesReadLast;
		}
	}

Cleanup:
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}
	return hr;
}

HRESULT
PcpToolWriteFile(
	_In_ PCWSTR lpFileName,
	_In_reads_opt_(cbData) PBYTE pbData,
	UINT32 cbData)
{
	HRESULT hr = S_OK;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD bytesWritten = 0;

	hFile = CreateFile(
		lpFileName,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto Cleanup;
	}


	while (cbData > bytesWritten)
	{
		DWORD bytesWrittenLast = 0;
		if (!WriteFile(hFile,
			&pbData[bytesWritten],
			(DWORD)(cbData - bytesWritten),
			&bytesWrittenLast,
			NULL))
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
			goto Cleanup;
		}
		bytesWritten += bytesWrittenLast;
	}

Cleanup:
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}
	return hr;
}


HRESULT
PcpToolDisplayKey(
	_In_ PCWSTR lpKeyName,
	_In_reads_(cbKey) PBYTE pbKey,
	DWORD cbKey,
	UINT32 level)
{
	HRESULT hr = S_OK;
	BCRYPT_RSAKEY_BLOB* pKey = (BCRYPT_RSAKEY_BLOB*)pbKey;
	BYTE pubKeyDigest[20] = { 0 };
	UINT32 cbRequired = 0;

#ifndef DEBUG
	/* No ouput text when not debugging. */
	return hr;
#endif

	// Parameter check
	if ((pbKey == NULL) ||
		(cbKey < sizeof(BCRYPT_RSAKEY_BLOB)) ||
		(cbKey < (sizeof(BCRYPT_RSAKEY_BLOB) +
		pKey->cbPublicExp +
		pKey->cbModulus +
		pKey->cbPrime1 +
		pKey->cbPrime2)))
	{
		hr = E_INVALIDARG;
		goto Cleanup;
	}
	if (FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
		NULL,
		0,
		&pbKey[sizeof(BCRYPT_RSAKEY_BLOB) +
		pKey->cbPublicExp],
		pKey->cbModulus,
		pubKeyDigest,
		sizeof(pubKeyDigest),
		&cbRequired)))
	{
		hr = E_INVALIDARG;
		goto Cleanup;
	}

	PcpToolLevelPrefix(level);
	wprintf(L"<RSAKey size=\"%u\"", cbKey);
	if ((lpKeyName != NULL) &&
		(wcslen(lpKeyName) != 0))
	{
		wprintf(L" keyName=\"%s\"", lpKeyName);
	}
	wprintf(L">\n");

	PcpToolLevelPrefix(level + 1);
	wprintf(L"<Magic>%c%c%c%c<!-- 0x%08x --></Magic>\n",
		((PBYTE)&pKey->Magic)[0],
		((PBYTE)&pKey->Magic)[1],
		((PBYTE)&pKey->Magic)[2],
		((PBYTE)&pKey->Magic)[3],
		pKey->Magic);

	PcpToolLevelPrefix(level + 1);
	wprintf(L"<BitLength>%u</BitLength>\n", pKey->BitLength);

	PcpToolLevelPrefix(level + 1);
	wprintf(L"<PublicExp size=\"%u\">\n", pKey->cbPublicExp);
	PcpToolLevelPrefix(level + 2);
	for (UINT32 n = 0; n < pKey->cbPublicExp; n++)
	{
		wprintf(L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) + n]);
	}
	wprintf(L"\n");
	PcpToolLevelPrefix(level + 1);
	wprintf(L"</PublicExp>\n");

	PcpToolLevelPrefix(level + 1);
	wprintf(L"<Modulus size=\"%u\" digest=\"", pKey->cbModulus);
	for (UINT32 n = 0; n < sizeof(pubKeyDigest); n++)
	{
		wprintf(L"%02x", pubKeyDigest[n]);
	}
	wprintf(L"\">\n", pKey->cbModulus);
	PcpToolLevelPrefix(level + 2);
	for (UINT32 n = 0; n < pKey->cbModulus; n++)
	{
		wprintf(L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) +
			pKey->cbPublicExp +
			n]);
	}
	wprintf(L"\n");
	PcpToolLevelPrefix(level + 1);
	wprintf(L"</Modulus>\n");

	PcpToolLevelPrefix(level + 1);
	if (pKey->cbPrime1 == 0)
	{
		wprintf(L"<Prime1/>\n");
	}
	else
	{
		wprintf(L"<Prime1 size=\"%u\">\n", pKey->cbPrime1);
		PcpToolLevelPrefix(level + 2);
		for (UINT32 n = 0; n < pKey->cbPrime1; n++)
		{
			wprintf(L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) +
				pKey->cbPublicExp +
				pKey->cbModulus +
				n]);
		}
		wprintf(L"\n");
		PcpToolLevelPrefix(level + 1);
		wprintf(L"</Prime1>\n");
	}
	PcpToolLevelPrefix(level + 1);
	if (pKey->cbPrime2 == 0)
	{
		wprintf(L"<Prime2/>\n");
	}
	else
	{
		wprintf(L"<Prime2 size=\"%u\">\n", pKey->cbPrime2);
		PcpToolLevelPrefix(level + 2);
		for (UINT32 n = 0; n < pKey->cbPrime2; n++)
		{
			wprintf(L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) +
				pKey->cbPublicExp +
				pKey->cbModulus +
				pKey->cbPrime1 +
				n]);
		}
		wprintf(L"\n");
		PcpToolLevelPrefix(level + 1);
		wprintf(L"</Prime2>\n");
	}
	PcpToolLevelPrefix(level);
	wprintf(L"</RSAKey>\n");

Cleanup:
	return hr;
}

HRESULT
DerEncodeKey(
	_In_ UINT32 cbRsaKeySize,
	_In_ PBYTE pbRsaKeyData,
	_Out_ PUINT32 pcbDerKeySize,
	_Out_ PBYTE *pbDerKeyData
) {

	BOOL result = true;

	/* The blob contain the modulus/keystruct/and data. */
	PBYTE keyBlob;
	BLOBHEADER *keyHeader;

	*pcbDerKeySize = 0;
	AllocateAndZero((PVOID *) &keyBlob, sizeof(BLOBHEADER) + cbRsaKeySize);
	keyHeader = (BLOBHEADER *)keyBlob;

	keyHeader->bType = PUBLICKEYBLOB;
	keyHeader->bVersion = CUR_BLOB_VERSION;
	keyHeader->reserved = 0;
	keyHeader->aiKeyAlg = CALG_RSA_KEYX;

	memcpy(keyBlob + sizeof(BLOBHEADER), pbRsaKeyData, cbRsaKeySize);

	result= CryptEncodeObject(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		RSA_CSP_PUBLICKEYBLOB,
		keyBlob,
		NULL,
		(DWORD *)pcbDerKeySize);

	if (!result) {
		return S_FALSE;
	}

	AllocateAndZero((PVOID *)pbDerKeyData, *pcbDerKeySize);
	result = CryptEncodeObject(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		RSA_CSP_PUBLICKEYBLOB,
		keyBlob,
		*pbDerKeyData,
		(DWORD *)pcbDerKeySize);

	if (!result) {
		return S_FALSE;
	}

	return S_OK;
}

// Global hash handles are kept open for performance reasons
BCRYPT_ALG_HANDLE g_hSHA1HashAlg = NULL;
BCRYPT_ALG_HANDLE g_hSHA1HmacAlg = NULL;
BCRYPT_ALG_HANDLE g_hSHA256HashAlg = NULL;
BCRYPT_ALG_HANDLE g_hSHA256HmacAlg = NULL;
BCRYPT_ALG_HANDLE g_hSHA384HashAlg = NULL;
BCRYPT_ALG_HANDLE g_hSHA384HmacAlg = NULL;

/// <summary>
///    Calculate SHA hash or HMAC.
/// </summary>
/// <param name="pszAlgId">BCrypt algorithm string.</param>
/// <param name="pbKey">pointer to Optional HMAC key.</param>
/// <param name="cbKey">size of Optional HMAC key.</param>
/// <param name="pbData">pointer to Data to be hashed.</param>
/// <param name="cbData">size of Data to be hashed.</param>
/// <param name="pbResult">Upon successful return, pointer to the digest.</param>
/// <param name="cbResult">Initial size of digest buffer.</param>
/// <param name="pcbResult">pointer to actually used size of digest buffer.</param>
/// <returns>
///    S_OK - Success.
///    E_INVALIDARG - Parameter error.
///    E_FAIL - Internal consistency error.
///    Others as propagated by called functions.
///</returns>
HRESULT TpmAttiShaHash(
	LPCWSTR pszAlgId,
	_In_reads_opt_(cbKey) PBYTE pbKey,
	UINT32 cbKey,
	_In_reads_(cbData) PBYTE pbData,
	UINT32 cbData,
	_Out_writes_to_opt_(cbResult, *pcbResult) PBYTE pbResult,
	UINT32 cbResult,
	_Out_ PUINT32 pcbResult)
{
	HRESULT hr = S_OK;
	BCRYPT_ALG_HANDLE* phAlg = NULL;
	BCRYPT_ALG_HANDLE  hTempAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	DWORD dwFlags = 0;
	DWORD hashSize = 0;
	DWORD cbHashSize = 0;

	if ((cbKey == 0) || (pbKey == NULL))
	{
		if (wcscmp(pszAlgId, BCRYPT_SHA1_ALGORITHM) == 0)
		{
			phAlg = &g_hSHA1HashAlg;
		}
		else if (wcscmp(pszAlgId, BCRYPT_SHA256_ALGORITHM) == 0)
		{
			phAlg = &g_hSHA256HashAlg;
		}
		else if (wcscmp(pszAlgId, BCRYPT_SHA384_ALGORITHM) == 0)
		{
			phAlg = &g_hSHA384HashAlg;
		}
		else
		{
			hr = E_INVALIDARG;
			goto Cleanup;
		}
	}
	else
	{
		if (wcscmp(pszAlgId, BCRYPT_SHA1_ALGORITHM) == 0)
		{
			phAlg = &g_hSHA1HmacAlg;
		}
		else if (wcscmp(pszAlgId, BCRYPT_SHA256_ALGORITHM) == 0)
		{
			phAlg = &g_hSHA256HmacAlg;
		}
		else if (wcscmp(pszAlgId, BCRYPT_SHA384_ALGORITHM) == 0)
		{
			phAlg = &g_hSHA384HmacAlg;
		}
		else
		{
			hr = E_INVALIDARG;
			goto Cleanup;
		}
		dwFlags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
	}

	// Open the provider if not already open
	if (*phAlg == NULL)
	{
		if (FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
			&hTempAlg,
			pszAlgId,
			MS_PRIMITIVE_PROVIDER,
			dwFlags))))
		{
			goto Cleanup;
		}
		if (InterlockedCompareExchangePointer((volatile PVOID *)phAlg, (PVOID)hTempAlg, NULL) != NULL)
		{
			BCryptCloseAlgorithmProvider(hTempAlg, 0);
		}
	}

	// Check output buffer size
	if (FAILED(hr = HRESULT_FROM_NT(BCryptGetProperty(
		*phAlg,
		BCRYPT_HASH_LENGTH,
		(PUCHAR)&hashSize,
		sizeof(hashSize),
		&cbHashSize,
		0))))
	{
		goto Cleanup;
	}

	// Size check?
	if ((pbResult == NULL) || (cbResult == 0))
	{
		*pcbResult = hashSize;
		goto Cleanup;
	}
	else if (cbResult < hashSize)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
		*pcbResult = hashSize;
		goto Cleanup;
	}

	// Create the hash
	if (FAILED(hr = HRESULT_FROM_NT(BCryptCreateHash(
		*phAlg,
		&hHash,
		NULL,
		0,
		pbKey,
		(ULONG)cbKey,
		0))))
	{
		goto Cleanup;
	}

	// Hash the data
	if (FAILED(hr = HRESULT_FROM_NT(BCryptHashData(
		hHash,
		pbData,
		(ULONG)cbData,
		0))))
	{
		goto Cleanup;
	}

	// Calculate the digesst
	if (FAILED(hr = HRESULT_FROM_NT(BCryptFinishHash(
		hHash,
		pbResult,
		(ULONG)cbResult,
		0))))
	{
		goto Cleanup;
	}
	*pcbResult = hashSize;

Cleanup:
	if (hHash != NULL)
	{
		BCryptDestroyHash(hHash);
		hHash = NULL;
	}
	return hr;
}
