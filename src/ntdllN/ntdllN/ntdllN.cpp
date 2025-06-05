// ntdllN.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "ntdllN.h"

#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <intrin.h>  // For __nop()

// Forward declarations
class ModuleResolver;
class FunctionResolver;
class Logger;

// Function type definitions
typedef int(*vprintf_proc)(const char* format, va_list args);
typedef HMODULE(*LoadLibraryA_proc)(const char* lpLibFileName);
typedef PVOID(*GetProcAddress_proc)(HMODULE hModule, LPCSTR lpProcName);

// Global variables
vprintf_proc gp_vprintf = NULL;

// Class to handle module resolution
class ModuleResolver {
public:
    static PVOID GetModuleHandleN(const WCHAR* fullModuleName) {
        PPEB peb = GetPEB();
        if (!peb) return nullptr;

        PPEB_LDR_DATA ldr = peb->Ldr;
        if (!ldr) return nullptr;

        return FindModuleInList(ldr, fullModuleName);
    }

private:
    static PPEB GetPEB() {
#ifdef _WIN64
        return (PPEB)__readgsqword(0x60);
#else
        return (PPEB)__readfsdword(0x30);
#endif
    }

    static PVOID FindModuleInList(PPEB_LDR_DATA ldr, const WCHAR* fullModuleName) {
        PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
        PLIST_ENTRY entry = head->Flink;
        PLIST_ENTRY mark = entry;

        do {
            entry = entry - 1;
            PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)entry;
            
            if (IsModuleMatch(module, fullModuleName)) {
                return module->DllBase;
            }

            entry = entry + 1;
            entry = module->InMemoryOrderLinks.Flink;
        } while (entry != mark);

        return nullptr;
    }

    static bool IsModuleMatch(PLDR_DATA_TABLE_ENTRY module, const WCHAR* fullModuleName) {
        if (!module->FullDllName.Buffer || module->FullDllName.Length <= 0) {
            return false;
        }

        for (int i = 0; i < module->FullDllName.Length / sizeof(WCHAR); i++) {
            WCHAR c = ((WCHAR*)module->FullDllName.Buffer)[i];
            WCHAR t = fullModuleName[i];
            
            // Case-insensitive comparison
            if (c >= L'A' && c <= L'Z') c += 32;
            if (t >= L'A' && t <= L'Z') t += 32;
            
            if (c != t) return false;
        }

        return true;
    }
};

// Class to handle function resolution
class FunctionResolver {
public:
    static PVOID GetProcAddressN(void* dllBase, const char* functionName) {
        if (!ValidateHeaders(dllBase)) {
            return nullptr;
        }

        PIMAGE_EXPORT_DIRECTORY exportDir = GetExportDirectory(dllBase);
        if (!exportDir) {
            return nullptr;
        }

        return FindFunctionInExports(dllBase, exportDir, functionName);
    }

private:
    static bool ValidateHeaders(void* dllBase) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllBase + dosHeader->e_lfanew);
        return ntHeaders->Signature == IMAGE_NT_SIGNATURE;
    }

    static PIMAGE_EXPORT_DIRECTORY GetExportDirectory(void* dllBase) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBase;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllBase + dosHeader->e_lfanew);
        
        IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDataDir.VirtualAddress == 0) {
            return nullptr;
        }

        return (PIMAGE_EXPORT_DIRECTORY)((BYTE*)dllBase + exportDataDir.VirtualAddress);
    }

    static PVOID FindFunctionInExports(void* dllBase, PIMAGE_EXPORT_DIRECTORY exportDir, const char* functionName) {
        DWORD* addressOfFunctions = (DWORD*)((BYTE*)dllBase + exportDir->AddressOfFunctions);
        DWORD* addressOfNames = (DWORD*)((BYTE*)dllBase + exportDir->AddressOfNames);
        WORD* addressOfNameOrdinals = (WORD*)((BYTE*)dllBase + exportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            char* currentFunctionName = (char*)((BYTE*)dllBase + addressOfNames[i]);
            if (strcmp(currentFunctionName, functionName) == 0) {
                WORD ordinal = addressOfNameOrdinals[i];
                DWORD functionRVA = addressOfFunctions[ordinal];
                return (BYTE*)dllBase + functionRVA;
            }
        }

        return nullptr;
    }
};

// Class to handle logging
class Logger {
public:
    static int printfN(const char* format, ...) {
        if (!InitializeVPrintf()) {
            return 0;
        }

        va_list args;
        va_start(args, format);
        int result = gp_vprintf(format, args);
        va_end(args);
        return result;
    }

    static void HexDump(const char* prefix, const void* data, size_t size) {
        printfN("  \\%s: ", prefix);
        for (size_t i = 0; i < size; i++) {
            printfN("%02X ", ((const unsigned char*)data)[i]);
        }
        printfN("\n");
    }

private:
    static bool InitializeVPrintf() {
        if (gp_vprintf) {
            return true;
        }

        // Try to get vprintf from msvcrt.dll
        if (TryGetVPrintfFromMsvcrt()) {
            return true;
        }

        // Try to load msvcrt.dll and get vprintf
        if (TryLoadMsvcrtAndGetVPrintf()) {
            return true;
        }

        return false;
    }

    static bool TryGetVPrintfFromMsvcrt() {
        PVOID msvcrtBase = ModuleResolver::GetModuleHandleN(L"C:\\Windows\\System32\\msvcrt.dll");
        if (!msvcrtBase) {
            return false;
        }

        PVOID p_vprintf = FunctionResolver::GetProcAddressN(msvcrtBase, "vprintf");
        if (p_vprintf) {
            gp_vprintf = (vprintf_proc)p_vprintf;
            return true;
        }

        return false;
    }

    static bool TryLoadMsvcrtAndGetVPrintf() {
        PVOID kernel32Base = ModuleResolver::GetModuleHandleN(L"C:\\Windows\\System32\\kernel32.dll");
        if (!kernel32Base) {
            return false;
        }

        PVOID p_LoadLibraryA = FunctionResolver::GetProcAddressN(kernel32Base, "LoadLibraryA");
        if (!p_LoadLibraryA) {
            return false;
        }

        HMODULE msvcrt = ((LoadLibraryA_proc)p_LoadLibraryA)("msvcrt.dll");
        if (!msvcrt) {
            return false;
        }

        PVOID p_vprintf = FunctionResolver::GetProcAddressN((PVOID)msvcrt, "vprintf");
        if (p_vprintf) {
            gp_vprintf = (vprintf_proc)p_vprintf;
            return true;
        }

        return false;
    }
};

// Export trampoline variables
extern "C" __declspec(dllexport) PVOID NtCreateFileTrampoline = nullptr;
extern "C" __declspec(dllexport) PVOID NtReadFileTrampoline = nullptr;
extern "C" __declspec(dllexport) PVOID NtWriteFileTrampoline = nullptr;

// Hooked NT functions
extern "C" __declspec(dllexport) NTSTATUS NtCreateFileN(
    HANDLE* FileHandle,
    ACCESS_MASK DesiredAccess,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    IO_STATUS_BLOCK* IoStatusBlock,
    PVOID AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    Logger::printfN("\n[*] NtCreateFile\n");
    Logger::printfN("  \\FileHandle       : %p\n", FileHandle);
    Logger::printfN("  \\DesiredAccess    : %lu\n", DesiredAccess);
    Logger::printfN("  \\ObjectAttributes : %p\n", ObjectAttributes);
    Logger::printfN("  \\IoStatusBlock    : %p\n", IoStatusBlock);
    Logger::printfN("  \\AllocationSize   : %p\n", AllocationSize);
    Logger::printfN("  \\FileAttributes   : %lu\n", FileAttributes);
    Logger::printfN("  \\ShareAccess      : %lu\n", ShareAccess);
    Logger::printfN("  \\CreateDisposition: %lu\n", CreateDisposition);
    Logger::printfN("  \\CreateOptions    : %lu\n", CreateOptions);
    Logger::printfN("  \\EaBuffer         : %p\n", EaBuffer);
    Logger::printfN("  \\EaLength         : %lu\n", EaLength);

    typedef NTSTATUS(NTAPI* NtCreateFile_proc)(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*, IO_STATUS_BLOCK*, PVOID, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    NtCreateFile_proc trampoline = (NtCreateFile_proc)NtCreateFileTrampoline;
    NTSTATUS result = trampoline(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    Logger::printfN("  ---------------> %p\n", result);
    return result;
}

extern "C" __declspec(dllexport) NTSTATUS NtReadFileN(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
) {
    Logger::printfN("\n[*] NtReadFile\n");
    Logger::printfN("  \\FileHandle   : %p\n", FileHandle);
    Logger::printfN("  \\Event        : %p\n", Event);
    Logger::printfN("  \\ApcRoutine   : %p\n", ApcRoutine);
    Logger::printfN("  \\ApcContext   : %p\n", ApcContext);
    Logger::printfN("  \\IoStatusBlock: %p\n", IoStatusBlock);
    Logger::printfN("  \\Buffer       : %s\n", (char*)Buffer);
    Logger::printfN("  \\Length       : %lu\n", Length);
    Logger::printfN("  \\ByteOffset   : %p\n", ByteOffset);
    Logger::printfN("  \\Key          : %p\n", Key);

    typedef NTSTATUS(NTAPI* NtReadFile_proc)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    NtReadFile_proc trampoline = (NtReadFile_proc)NtReadFileTrampoline;
    NTSTATUS result = trampoline(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    Logger::printfN("  ---------------> %p\n", result);
    return result;
}

extern "C" __declspec(dllexport) NTSTATUS NtWriteFileN(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
) {
    Logger::printfN("\n[*] NtWriteFile\n");
    Logger::printfN("  \\FileHandle   : %p\n", FileHandle);
    Logger::printfN("  \\Event        : %p\n", Event);
    Logger::printfN("  \\ApcRoutine   : %p\n", ApcRoutine);
    Logger::printfN("  \\ApcContext   : %p\n", ApcContext);
    Logger::printfN("  \\IoStatusBlock: %p\n", IoStatusBlock);
    Logger::printfN("  \\Buffer       : %s\n", (char*)Buffer);
    Logger::printfN("  \\Length       : %lu\n", Length);
    Logger::printfN("  \\ByteOffset   : %p\n", ByteOffset);
    Logger::printfN("  \\Key          : %p\n", Key);

    typedef NTSTATUS(NTAPI* NtWriteFile_proc)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    NtWriteFile_proc trampoline = (NtWriteFile_proc)NtWriteFileTrampoline;
    NTSTATUS result = trampoline(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    Logger::printfN("  ---------------> %p\n", result);
    return result;
}

