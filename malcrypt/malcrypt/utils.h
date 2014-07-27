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

HRESULT
PcpToolReadFile(
	_In_ PCWSTR lpFileName,
	_In_reads_opt_(cbData) PBYTE pbData,
	UINT32 cbData,
	__out PUINT32 pcbData
);

HRESULT
PcpToolWriteFile(
	_In_ PCWSTR lpFileName,
	_In_reads_opt_(cbData) PBYTE pbData,
	UINT32 cbData
);

HRESULT
PcpToolDisplayKey(
	_In_ PCWSTR lpKeyName,
	_In_reads_(cbKey) PBYTE pbKey,
	DWORD cbKey,
	UINT32 level
);

HRESULT
DerEncodeKey(
	_In_ UINT32 cbRsaKeySize,
	_In_ PBYTE pbRsaKeyData,
	_Out_ PUINT32 pcbDerKeySize,
	_Out_ PBYTE *pbDerKeyData
);

HRESULT
TpmAttiShaHash(
	LPCWSTR pszAlgId,
	_In_reads_opt_(cbKey) PBYTE pbKey,
	UINT32 cbKey,
	_In_reads_(cbData) PBYTE pbData,
	UINT32 cbData,
	_Out_writes_to_opt_(cbResult, *pcbResult) PBYTE pbResult,
	UINT32 cbResult,
	_Out_ PUINT32 pcbResult
);
