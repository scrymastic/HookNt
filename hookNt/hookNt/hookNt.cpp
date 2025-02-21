#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <string>


typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* NtQueryVirtualMemory_proc)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

bool Patch2Jmp(HANDLE hProcess, PVOID address, PVOID newAddress) {
    // Shellcode to move the address into RAX and jump to it
    BYTE shellcode[] = {
        0x48, 0xB8,                   // mov rax, immediate_value
        0x00, 0x00, 0x00, 0x00,       // placeholder for newAddress (low 4 bytes)
        0x00, 0x00, 0x00, 0x00,       // placeholder for newAddress (high 4 bytes)
        0xFF, 0xE0                    // jmp rax
    };

    // Insert the newAddress into the shellcode
    *(PVOID*)&shellcode[2] = newAddress;

    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, address, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("VirtualProtectEx failed: %d\n", GetLastError());
        return false;
    }

    // Copy the shellcode to the target address
    WriteProcessMemory(hProcess, address, shellcode, sizeof(shellcode), NULL);

    // Restore the original protection
    VirtualProtectEx(hProcess, address, sizeof(shellcode), oldProtect, &oldProtect);

    return true;
}

// Helper function to map section characteristics to memory protection flags.
DWORD GetMemoryProtection(DWORD characteristics) {
    BOOL isExecutable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOL isReadable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    BOOL isWritable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    if (isExecutable && isWritable) return PAGE_EXECUTE_READWRITE;
    else if (isExecutable && !isWritable && isReadable) return PAGE_EXECUTE_READ;
    else if (isExecutable && !isWritable && !isReadable) return PAGE_EXECUTE;
    else if (!isExecutable && isWritable) return PAGE_READWRITE;
    else if (!isExecutable && !isWritable && isReadable) return PAGE_READONLY;
    else return PAGE_NOACCESS;
}

// Function to perform reflective DLL injection
PVOID ReflectiveDLLInject(HANDLE hProcess, PBYTE lpDllBuffer) {
    // Step 1: Parse the DLL headers.
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpDllBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS signature.\n");
        return nullptr;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(lpDllBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT signature.\n");
        return nullptr;
    }
    
    // Step 2: Allocate memory for the DLL in the remote process.
    SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;
    PBYTE remoteDllBase = (PBYTE)VirtualAllocEx(hProcess, NULL, dllImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteDllBase) {
        printf("[!] VirtualAllocEx failed: %d\n", GetLastError());
        return nullptr;
    }

    // Perform loading in current process is easier, instead of muiltiple Read/Write remote ProcessMemory
    PBYTE localDllBase = (PBYTE)VirtualAlloc(NULL, dllImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!localDllBase) {
        printf("[!] VirtualAlloc failed: %d\n", GetLastError());
        return nullptr;
    }

    // Step 4: Copy the headers and sections of the DLL to the current process.
    memcpy(localDllBase, lpDllBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);
    
    // Step 5: Copy each section.
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        BYTE* dest = (BYTE*)localDllBase + section[i].VirtualAddress;
        BYTE* src = (BYTE*)lpDllBuffer + section[i].PointerToRawData;
        memcpy(dest, src, section[i].SizeOfRawData);
    }

    // Step 6: Perform relocations if the allocated base is different from the preferred base.
    // Remember that the base address of the DLL in the remote process is remoteDllBase
    SIZE_T delta = (SIZE_T)(remoteDllBase - ntHeaders->OptionalHeader.ImageBase);
    if (delta != 0 && ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(localDllBase +
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (reloc->VirtualAddress) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* relocData = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < count; i++) {
                DWORD type = relocData[i] >> 12;
                DWORD offset = relocData[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    SIZE_T* patchAddr = (SIZE_T*)(localDllBase + reloc->VirtualAddress + offset);
                    *patchAddr += delta;
                }
            }
            reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }
    
    // Ignore the import table

    // Step 7: Copy the DLL to the remote process.
    if (!WriteProcessMemory(hProcess, remoteDllBase, localDllBase, dllImageSize, NULL)) {
        printf("[!] WriteProcessMemory failed: %d\n", GetLastError());
        VirtualFree(localDllBase, 0, MEM_RELEASE);
        return nullptr;
    }

    // Step 8: Set the appropriate protection for the DLL in the remote process.
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        DWORD oldProtect;
        DWORD newProtect = GetMemoryProtection(section[i].Characteristics);
        if (!VirtualProtectEx(hProcess, (PBYTE)remoteDllBase + section[i].VirtualAddress, section[i].SizeOfRawData, newProtect, &oldProtect)) {
            printf("[!] VirtualProtectEx failed: %d\n", GetLastError());
            VirtualFree(localDllBase, 0, MEM_RELEASE);
            return nullptr;
        }
    }
    
    // Step 9: Return the base address of the DLL in the remote process.
    return remoteDllBase;
}

// Function to resolve a function address from a module in a remote process
PVOID GetProcAddressRemoteN(HANDLE hProcess, PBYTE dllBase, const char* functionName) {
    // Read the DOS header from the remote process
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(hProcess, dllBase, &dosHeader, sizeof(dosHeader), nullptr)) {
        printf("[!] Failed to read DOS header. Error: %lu\n", GetLastError());
        return nullptr;
    }

    // Verify the DOS signature
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS signature.\n");
        return nullptr;
    }

    // Read the NT headers from the remote process
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(hProcess, (BYTE*)dllBase + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), nullptr)) {
        printf("[!] Failed to read NT headers. Error: %lu\n", GetLastError());
        return nullptr;
    }

    // Verify the NT signature
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT signature.\n");
        return nullptr;
    }

    // Get the export directory information
    IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir.VirtualAddress == 0) {
        printf("[!] No export directory found.\n");
        return nullptr;
    }

    // Read the export directory from the remote process
    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!ReadProcessMemory(hProcess, (BYTE*)dllBase + exportDataDir.VirtualAddress, &exportDir, sizeof(exportDir), nullptr)) {
        printf("[!] Failed to read export directory. Error: %lu\n", GetLastError());
        return nullptr;
    }

    // Read the array of function addresses, names, and ordinals
    PDWORD addressOfFunctions = new DWORD[exportDir.NumberOfFunctions];
    PDWORD addressOfNames = new DWORD[exportDir.NumberOfNames];
    PWORD addressOfNameOrdinals = new WORD[exportDir.NumberOfNames];

    if (!ReadProcessMemory(hProcess, (BYTE*)dllBase + exportDir.AddressOfFunctions, addressOfFunctions, exportDir.NumberOfFunctions * sizeof(DWORD), nullptr) ||
        !ReadProcessMemory(hProcess, (BYTE*)dllBase + exportDir.AddressOfNames, addressOfNames, exportDir.NumberOfNames * sizeof(DWORD), nullptr) ||
        !ReadProcessMemory(hProcess, (BYTE*)dllBase + exportDir.AddressOfNameOrdinals, addressOfNameOrdinals, exportDir.NumberOfNames * sizeof(WORD), nullptr)) {
        printf("[!] Failed to read export tables. Error: %lu\n", GetLastError());
        delete[] addressOfFunctions;
        delete[] addressOfNames;
        delete[] addressOfNameOrdinals;
        return nullptr;
    }

    // Iterate over all named exports
    for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
        // Read the function name from the remote process
        char currentFunctionName[256];
        if (!ReadProcessMemory(hProcess, (BYTE*)dllBase + addressOfNames[i], currentFunctionName, sizeof(currentFunctionName), nullptr)) {
            printf("[!] Failed to read function name. Error: %lu\n", GetLastError());
            continue;
        }

        // Compare the function name with the target name
        if (strcmp(currentFunctionName, functionName) == 0) {
            // Get the ordinal corresponding to this name
            WORD ordinal = addressOfNameOrdinals[i];

            // Get the function's RVA and compute its absolute address
            DWORD functionRVA = addressOfFunctions[ordinal];
            PVOID procAddress = (PBYTE)dllBase + functionRVA;

            // Clean up
            delete[] addressOfFunctions;
            delete[] addressOfNames;
            delete[] addressOfNameOrdinals;

            return procAddress;
        }
    }

    // Clean up
    delete[] addressOfFunctions;
    delete[] addressOfNames;
    delete[] addressOfNameOrdinals;

    return nullptr;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: hookNt.exe <target program> <list of NT functions to hook>\n");
        return 1;
    }

    // Extract the target program and NT functions from command-line arguments
    std::string targetProgram = argv[1];
    std::wstring targetProgramW(targetProgram.begin(), targetProgram.end());

    std::vector<std::string> ntFunctionsToHook;

    for (int i = 2; i < argc; ++i) {
        ntFunctionsToHook.push_back(argv[i]);
    }
    // Create a new process, suspend it and get its PID
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcess(
        targetProgramW.c_str(),
        NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[!] CreateProcess failed (%d)\n", GetLastError());
        return 1;
    }
    DWORD pid = pi.dwProcessId;

    printf("[+] Process created, PID: %d\n", pid);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[!] OpenProcess failed (%d)\n", GetLastError());
        return 1;
    }

    // Starting scan from the known base address of ntdll.dll
    NtQueryVirtualMemory_proc NtQueryVirtualMemory = 
        (NtQueryVirtualMemory_proc)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryVirtualMemory");
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = 0;
    SIZE_T returnLength;
    WCHAR name[MAX_PATH];
    bool found = false;

    while (NT_SUCCESS(NtQueryVirtualMemory(hProcess, address, MemoryBasicInformation, &mbi, sizeof(mbi), &returnLength))) {
        if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE) {
            address = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
            continue;
        }
        if (GetMappedFileNameW(hProcess, mbi.BaseAddress, name, MAX_PATH) <= 0) {
            address = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
            continue;
        }
        if (wcsstr(name, L"ntdll.dll")) {
            PVOID ntdllBase = mbi.AllocationBase;
            printf("[+] Found ntdll.dll at 0x%p\n", ntdllBase);
            
            printf("[+] Injecting DLL\n");
            WCHAR dllPath[] = L".\\ntdllN.dll";
            // Load the DLL into memory
            HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) {
                printf("[!] CreateFileA failed: %d\n", GetLastError());
                CloseHandle(hProcess);
                return 1;
            }

            DWORD dwDllSize = GetFileSize(hFile, NULL);
            LPVOID lpDllBuffer = VirtualAlloc(NULL, dwDllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!lpDllBuffer) {
                printf("[!] VirtualAlloc failed: %d\n", GetLastError());
                CloseHandle(hFile);
                CloseHandle(hProcess);
                return 1;
            }

            if (!ReadFile(hFile, lpDllBuffer, dwDllSize, NULL, NULL)) {
                printf("[!] ReadFile failed: %d\n", GetLastError());
                VirtualFree(lpDllBuffer, 0, MEM_RELEASE);
                CloseHandle(hFile);
                CloseHandle(hProcess);
                return 1;
            }

            CloseHandle(hFile);

            PVOID ntdllNBase = ReflectiveDLLInject(hProcess, (PBYTE)lpDllBuffer);
            if (ntdllNBase) {
                printf("[+] DLL injected at 0x%p\n", ntdllNBase);
            } else {
                printf("[!] DLL injection failed\n");
                VirtualFree(lpDllBuffer, 0, MEM_RELEASE);
                CloseHandle(hProcess);
                return 1;
            }
            
            // Iterate over the list of NT functions to hook
            for (const auto& functionName : ntFunctionsToHook) {
                // Get the address of the original NT function
                PVOID originalFunction = GetProcAddressRemoteN(hProcess, (PBYTE)ntdllBase, functionName.c_str());
                if (originalFunction) {
                    printf("[+] Found %s at 0x%p\n", functionName.c_str(), originalFunction);
                } else {
                    printf("[!] Not found %s\n", functionName.c_str());
                    continue;
                }

                // Get the address of the hooked NT function
                std::string hookedFunctionName = functionName + "N";
                PVOID hookedFunction = GetProcAddressRemoteN(hProcess, (PBYTE)ntdllNBase, hookedFunctionName.c_str());
                if (hookedFunction) {
                    printf("[+] Found %s at 0x%p\n", hookedFunctionName.c_str(), hookedFunction);
                } else {
                    printf("[!] Not found %s\n", hookedFunctionName.c_str());
                    continue;
                }

                // Patch the original NT function to jump to the hooked function
                Patch2Jmp(hProcess, originalFunction, hookedFunction);
            }

            printf("[+] Setup done, resuming thread\n");

            ResumeThread(pi.hThread);
            CloseHandle(pi.hThread);
            CloseHandle(hProcess);
            found = true;
            break;
        }
        address = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
    }

    if (!found) {
        printf("[!] ntdll.dll not found\n");
        CloseHandle(hProcess);
    }

    return 1;
}

