// ntdllN.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "ntdllN.h"

#include <winternl.h>
#include <psapi.h>
#include <stdio.h>


typedef int(*vprintf_proc)(const char *format, va_list args);
typedef HMODULE(*LoadLibraryA_proc)(const char* lpLibFileName);
typedef PVOID(*GetProcAddress_proc)(HMODULE hModule, LPCSTR lpProcName);


extern "C" NTSTATUS sys_NtCreateFile(HANDLE* FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, 
                    IO_STATUS_BLOCK* IoStatusBlock, PVOID AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, 
                    ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

extern "C" NTSTATUS sys_NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, 
                    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, 
                    ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

extern "C" NTSTATUS sys_NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, 
                    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, 
                    ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

vprintf_proc gp_vprintf = NULL;

PVOID GetModuleHandleN(const WCHAR* fullModuleName) {
    PPEB peb = 0;  
    // Get PEB address
#ifdef _WIN64
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    // Read PEB_LDR_DATA
    PPEB_LDR_DATA ldr = peb->Ldr;

    // Traverse module list
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;
    PLIST_ENTRY mark = entry;
    do {
        entry = entry - 1;
        PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)entry;
        int i;
        if (module->FullDllName.Buffer && module->FullDllName.Length > 0) {
            for (i = 0; i < module->FullDllName.Length / sizeof(WCHAR); i++) {
                WCHAR c = ((WCHAR*)module->FullDllName.Buffer)[i];
                if (c >= L'A' && c <= L'Z') c += 32;
                WCHAR t = fullModuleName[i];
                if (t >= L'A' && t <= L'Z') t += 32;
                if (c != t) break;
            }
            if (i == module->FullDllName.Length / sizeof(WCHAR)) 
                return module->DllBase;
        }

        entry = entry + 1;
        entry = module->InMemoryOrderLinks.Flink;
    } while (entry != mark);

    return 0;
}

PVOID GetProcAddressN(void* dllBase, const char* functionName) {
    // Get the DOS header and verify its signature.
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    
    // Get the NT headers using the offset stored in the DOS header.
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    
    // Get the export directory information.
    IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir.VirtualAddress == 0) {
        return NULL;
    }
    
    // Calculate the address of the export directory.
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*) dllBase + exportDataDir.VirtualAddress);
    DWORD* addressOfFunctions = (DWORD*)((BYTE*) dllBase + exportDir->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((BYTE*) dllBase + exportDir->AddressOfNames);
    WORD*  addressOfNameOrdinals = (WORD*)((BYTE*) dllBase + exportDir->AddressOfNameOrdinals);
    
    // Iterate over all named exports.
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        // Get the function name:
        char* currentFunctionName = (char*)((BYTE*) dllBase + addressOfNames[i]);
    
        // Get the ordinal corresponding to this name.
        WORD ordinal = addressOfNameOrdinals[i];
    
        // Get the function's RVA and compute its absolute address.
        DWORD functionRVA = addressOfFunctions[ordinal];
        void* procAddress = (BYTE*) dllBase + functionRVA;
    
        bool isMatch = true;
        int j = 0;
        for (j = 0; currentFunctionName[j] != '\0' && functionName[j] != '\0'; j++) {
            if (currentFunctionName[j] != functionName[j]) {
                isMatch = false;
                break;
            }
        }
        
        if (isMatch && currentFunctionName[j] == '\0' && functionName[j] == '\0') {
            return procAddress;
        }
    }

    return NULL;
}

int printfN(const char* format, ...) {
    if (!gp_vprintf) {
        // Attempt to get the base address of msvcrt.dll
        PVOID msvcrtBase = GetModuleHandleN(L"C:\\Windows\\System32\\msvcrt.dll");
        if (msvcrtBase) {
            // Try to get the address of vprintf
            PVOID p_vprintf = GetProcAddressN(msvcrtBase, "vprintf");
            if (p_vprintf) {
                gp_vprintf = (vprintf_proc)p_vprintf;
            }
        }

        // If gp_vprintf is still not set, try loading msvcrt.dll using kernel32.dll
        if (!gp_vprintf) {
            PVOID kernel32Base = GetModuleHandleN(L"C:\\Windows\\System32\\kernel32.dll");
            if (kernel32Base) {
                PVOID p_LoadLibraryA = GetProcAddressN(kernel32Base, "LoadLibraryA");
                if (p_LoadLibraryA) {
                    HMODULE msvcrt = ((LoadLibraryA_proc)p_LoadLibraryA)("msvcrt.dll");
                    if (msvcrt) {
                        PVOID p_vprintf = GetProcAddressN((PVOID)msvcrt, "vprintf");
                        if (p_vprintf) {
                            gp_vprintf = (vprintf_proc)p_vprintf;
                        }
                    }
                }
            }
        }

        // If gp_vprintf is still not set, print an error and return
        if (!gp_vprintf) {
            // printf("vprintf not found\n");
            return 0;
        }
    }

    // Use gp_vprintf to print the formatted string
    va_list args;
    va_start(args, format);
    int result = gp_vprintf(format, args);
    va_end(args);
    return result;
}

void HexDump(const char* prefix, const void* data, size_t size) {
    printfN("  \\%s: ", prefix);
    for (size_t i = 0; i < size; i++) {
        printfN("%02X ", ((const unsigned char*)data)[i]);
    }
    printfN("\n");
}


extern "C" __declspec(dllexport) NTSTATUS NtCreateFileN(HANDLE* FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, 
                    IO_STATUS_BLOCK* IoStatusBlock, PVOID AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, 
                    ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    printfN("\n[*] NtCreateFile\n");
    printfN("  \\FileHandle       : %p\n", FileHandle);
    printfN("  \\DesiredAccess    : %lu\n", DesiredAccess);
    printfN("  \\ObjectAttributes : %p\n", ObjectAttributes);
    printfN("  \\IoStatusBlock    : %p\n", IoStatusBlock);
    printfN("  \\AllocationSize   : %p\n", AllocationSize);
    printfN("  \\FileAttributes   : %lu\n", FileAttributes);
    printfN("  \\ShareAccess      : %lu\n", ShareAccess);
    printfN("  \\CreateDisposition: %lu\n", CreateDisposition);
    printfN("  \\CreateOptions    : %lu\n", CreateOptions);
    printfN("  \\EaBuffer         : %p\n", EaBuffer);
    printfN("  \\EaLength         : %lu\n", EaLength);

    NTSTATUS result = sys_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    printfN("  ────────> %p\n", result);
    return result;
}


extern "C" __declspec(dllexport) NTSTATUS NtReadFileN(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, 
                    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, 
                    ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    printfN("\n[*] NtReadFile\n");
    printfN("  \\FileHandle   : %p\n", FileHandle);
    printfN("  \\Event        : %p\n", Event);
    printfN("  \\ApcRoutine   : %p\n", ApcRoutine);
    printfN("  \\ApcContext   : %p\n", ApcContext);
    printfN("  \\IoStatusBlock: %p\n", IoStatusBlock);
    printfN("  \\Buffer       : %s\n", (char*)Buffer);
    printfN("  \\Length       : %lu\n", Length);
    printfN("  \\ByteOffset   : %p\n", ByteOffset);
    printfN("  \\Key          : %p\n", Key);

    NTSTATUS result = sys_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    printfN("  ────────> %p\n", result);
    return result;
}


extern "C" __declspec(dllexport) NTSTATUS NtWriteFileN(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, 
                    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, 
                    ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    printfN("\n[*] NtWriteFile\n");
    printfN("  \\FileHandle   : %p\n", FileHandle);
    printfN("  \\Event        : %p\n", Event);
    printfN("  \\ApcRoutine   : %p\n", ApcRoutine);
    printfN("  \\ApcContext   : %p\n", ApcContext);
    printfN("  \\IoStatusBlock: %p\n", IoStatusBlock);
    printfN("  \\Buffer       : %s\n", (char*)Buffer);
    printfN("  \\Length       : %lu\n", Length);
    printfN("  \\ByteOffset   : %p\n", ByteOffset);
    printfN("  \\Key          : %p\n", Key);

    NTSTATUS result = sys_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    printfN("  ────────> %p\n", result);
    return result;
}

