#include "function_resolver.h"
#include "memory_utils.h"

bool ValidateHeaders(void* dllBase) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllBase + dosHeader->e_lfanew);
    return ntHeaders->Signature == IMAGE_NT_SIGNATURE;
}

PIMAGE_EXPORT_DIRECTORY GetExportDirectory(void* dllBase) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllBase + dosHeader->e_lfanew);
    
    IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir.VirtualAddress == 0) {
        return nullptr;
    }

    return (PIMAGE_EXPORT_DIRECTORY)((BYTE*)dllBase + exportDataDir.VirtualAddress);
}

PVOID FindFunctionInExports(void* dllBase, PIMAGE_EXPORT_DIRECTORY exportDir, const char* functionName) {
    DWORD* addressOfFunctions = (DWORD*)((BYTE*)dllBase + exportDir->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((BYTE*)dllBase + exportDir->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)dllBase + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* currentFunctionName = (char*)((BYTE*)dllBase + addressOfNames[i]);
        if (CustomStrCmp(currentFunctionName, functionName) == 0) {
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD functionRVA = addressOfFunctions[ordinal];
            return (BYTE*)dllBase + functionRVA;
        }
    }

    return nullptr;
}

PVOID GetProcAddressN(void* dllBase, const char* functionName) {
    if (!ValidateHeaders(dllBase)) {
        return nullptr;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = GetExportDirectory(dllBase);
    if (!exportDir) {
        return nullptr;
    }

    return FindFunctionInExports(dllBase, exportDir, functionName);
} 