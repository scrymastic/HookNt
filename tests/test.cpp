#pragma comment(lib, "ntdll.lib")

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>

// Add these prototypes
extern "C" NTSTATUS NTAPI NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

extern "C" NTSTATUS NTAPI NtClose(HANDLE Handle);

int main() {
    // Test WriteFile
    HANDLE hFile = CreateFileA("C:\\Users\\Public\\Downloads\\test.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFileA failed with error %d\n", GetLastError());
        return 1;
    }
    WriteFile(hFile, "Hello from WriteFile\n", 23, NULL, NULL);
    printf("WriteFile done\n");

    // Test NtWriteFile
    NtWriteFile(hFile, NULL, NULL, NULL, NULL, (PVOID)"Hello from NtWriteFile\n", 23, NULL, NULL);
    printf("NtWriteFile done\n");
    
    CloseHandle(hFile);

    return 0;
}