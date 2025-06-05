#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <string>
#include <distorm.h>

// Forward declarations
struct ProcessContext;
class HookManager;

// Memory information class definition
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

// NtQueryVirtualMemory function declaration
typedef NTSTATUS(NTAPI* NtQueryVirtualMemory_proc)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

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

// Helper function to map section characteristics to memory protection flags
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
    // Step 1: Parse the DLL headers
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
    
    // Step 2: Allocate memory for the DLL in the remote process
    SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;
    PBYTE remoteDllBase = (PBYTE)VirtualAllocEx(hProcess, NULL, dllImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteDllBase) {
        printf("[!] VirtualAllocEx failed: %d\n", GetLastError());
        return nullptr;
    }

    // Step 3: Allocate memory for the DLL in the current process
    PBYTE localDllBase = (PBYTE)VirtualAlloc(NULL, dllImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!localDllBase) {
        printf("[!] VirtualAlloc failed: %d\n", GetLastError());
        return nullptr;
    }

    // Step 4: Copy the headers and sections of the DLL to the current process
    memcpy(localDllBase, lpDllBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);

    // Step 5: Copy each section
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        BYTE* dest = (BYTE*)localDllBase + section[i].VirtualAddress;
        BYTE* src = (BYTE*)lpDllBuffer + section[i].PointerToRawData;
        memcpy(dest, src, section[i].SizeOfRawData);
    }

    // Step 6: Perform relocations if the allocated base is different from the preferred base
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
    
    // Step 7: Copy the DLL to the remote process
    if (!WriteProcessMemory(hProcess, remoteDllBase, localDllBase, dllImageSize, NULL)) {
        printf("[!] WriteProcessMemory failed: %d\n", GetLastError());
        VirtualFree(localDllBase, 0, MEM_RELEASE);
        return nullptr;
    }

    // Step 8: Set the appropriate protection for the DLL in the remote process
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        DWORD oldProtect;
        DWORD newProtect = GetMemoryProtection(section[i].Characteristics);
        if (!VirtualProtectEx(hProcess, (PBYTE)remoteDllBase + section[i].VirtualAddress, section[i].SizeOfRawData, newProtect, &oldProtect)) {
            printf("[!] VirtualProtectEx failed: %d\n", GetLastError());
            VirtualFree(localDllBase, 0, MEM_RELEASE);
            return nullptr;
        }
    }

    // Step 9: Return the base address of the DLL in the remote process
    return remoteDllBase;
}

// Process context to hold all process-related information
struct ProcessContext {
    HANDLE hProcess;
    PVOID ntdllBase;
    PVOID ntdllNBase;
    DWORD pid;

    ProcessContext(HANDLE hProc, PVOID ntdll, PVOID ntdllN, DWORD processId) 
        : hProcess(hProc), ntdllBase(ntdll), ntdllNBase(ntdllN), pid(processId) {}
};

// Class to handle function hooking
class HookManager {
private:
    ProcessContext& ctx;

    // Calculate the size of instructions that will be overwritten by our patch
    size_t CalculatePatchSize(PVOID address) {
        // Read the first few bytes of the function
        BYTE buffer[32];
        if (!ReadProcessMemory(ctx.hProcess, address, buffer, sizeof(buffer), nullptr)) {
            printf("[!] Failed to read memory at %p\n", address);
            return 0;
        }

        // Disassemble the instructions
        _DecodedInst decodedInstructions[10];
        unsigned int decodedInstructionsCount = 0;
        _DecodeResult res = distorm_decode64((_OffsetType)address, buffer, sizeof(buffer), Decode64Bits, decodedInstructions, 10, &decodedInstructionsCount);
        
        if (res != DECRES_SUCCESS) {
            printf("[!] Failed to disassemble instructions\n");
            return 0;
        }

        // Calculate the size needed for our patch (14 bytes for the absolute jump)
        size_t totalSize = 0;
        size_t i = 0;
        while (totalSize < 14 && i < decodedInstructionsCount) {
            totalSize += decodedInstructions[i].size;
            i++;
        }

        return totalSize;
    }

    // Create a trampoline for the original function
    bool CreateTrampoline(PVOID originalFunction, PVOID trampolineAddress, size_t patchSize) {
        // Read the instructions that will be overwritten
        BYTE* originalBytes = new BYTE[patchSize];
        if (!ReadProcessMemory(ctx.hProcess, originalFunction, originalBytes, patchSize, nullptr)) {
            printf("[!] Failed to read original instructions\n");
            delete[] originalBytes;
            return false;
        }

        // Calculate the jump back address (original function + patch size)
        PVOID jumpBackAddress = (PBYTE)originalFunction + patchSize;

        // Create the trampoline code
        // 1. Copy the original instructions
        // 2. Add an absolute jump back to the original function using push+ret
        BYTE* trampolineCode = new BYTE[patchSize + 14]; // 14 bytes for the absolute jump
        memcpy(trampolineCode, originalBytes, patchSize);

        // Add the absolute jump back instruction using push+ret
        trampolineCode[patchSize] = 0x68; // push imm32 (low 32 bits)
        *(DWORD*)&trampolineCode[patchSize + 1] = (DWORD)((UINT64)jumpBackAddress & 0xFFFFFFFF);
        trampolineCode[patchSize + 5] = 0xC7; // mov [rsp+4], imm32 (high 32 bits)
        trampolineCode[patchSize + 6] = 0x44;
        trampolineCode[patchSize + 7] = 0x24;
        trampolineCode[patchSize + 8] = 0x04;
        *(DWORD*)&trampolineCode[patchSize + 9] = (DWORD)((UINT64)jumpBackAddress >> 32);
        trampolineCode[patchSize + 13] = 0xC3; // ret

        // Write the trampoline code
        DWORD oldProtect;
        if (!VirtualProtectEx(ctx.hProcess, trampolineAddress, patchSize + 14, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            printf("[!] VirtualProtectEx failed: %d\n", GetLastError());
            delete[] originalBytes;
            delete[] trampolineCode;
            return false;
        }

        if (!WriteProcessMemory(ctx.hProcess, trampolineAddress, trampolineCode, patchSize + 14, nullptr)) {
            printf("[!] WriteProcessMemory failed: %d\n", GetLastError());
            VirtualProtectEx(ctx.hProcess, trampolineAddress, patchSize + 14, oldProtect, &oldProtect);
            delete[] originalBytes;
            delete[] trampolineCode;
            return false;
        }

        VirtualProtectEx(ctx.hProcess, trampolineAddress, patchSize + 14, oldProtect, &oldProtect);
        delete[] originalBytes;
        delete[] trampolineCode;
        return true;
    }

    // Patch the original function to jump to our hook
    bool PatchFunction(PVOID originalFunction, PVOID newAddress, PVOID trampolineAddress) {
        // Calculate the size of instructions that will be overwritten
        size_t patchSize = CalculatePatchSize(originalFunction);
        if (patchSize == 0) {
            printf("[!] Failed to calculate patch size\n");
            return false;
        }

        // Create the trampoline
        if (!CreateTrampoline(originalFunction, trampolineAddress, patchSize)) {
            printf("[!] Failed to create trampoline\n");
            return false;
        }

        // Create the absolute jump to our hook using push+ret
        BYTE shellcode[] = {
            0x68, 0x00, 0x00, 0x00, 0x00,       // push imm32 (low 32 bits)
            0xC7, 0x44, 0x24, 0x04,             // mov [rsp+4], imm32 (high 32 bits)
            0x00, 0x00, 0x00, 0x00,             // high 32 bits placeholder
            0xC3                                // ret
        };

        // Insert the target address into the shellcode
        *(DWORD*)&shellcode[1] = (DWORD)((UINT64)newAddress & 0xFFFFFFFF);
        *(DWORD*)&shellcode[9] = (DWORD)((UINT64)newAddress >> 32);

        DWORD oldProtect;
        if (!VirtualProtectEx(ctx.hProcess, originalFunction, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            printf("VirtualProtectEx failed: %d\n", GetLastError());
            return false;
        }

        // Copy the shellcode to the target address
        WriteProcessMemory(ctx.hProcess, originalFunction, shellcode, sizeof(shellcode), NULL);

        // Restore the original protection
        VirtualProtectEx(ctx.hProcess, originalFunction, sizeof(shellcode), oldProtect, &oldProtect);

        return true;
    }

public:
    HookManager(ProcessContext& context) : ctx(context) {}

    // Hook a single function
    bool HookFunction(const std::string& functionName) {
        // Get the address of the original NT function
        PVOID originalFunction = GetProcAddressRemoteN(ctx.hProcess, (PBYTE)ctx.ntdllBase, functionName.c_str());
        if (!originalFunction) {
            printf("[!] Not found %s\n", functionName.c_str());
            return false;
        }
        printf("[+] Found %s at 0x%p\n", functionName.c_str(), originalFunction);

        // Get the address of the hooked NT function
        std::string hookedFunctionName = functionName + "N";
        PVOID hookedFunction = GetProcAddressRemoteN(ctx.hProcess, (PBYTE)ctx.ntdllNBase, hookedFunctionName.c_str());
        if (!hookedFunction) {
            printf("[!] Not found %s\n", hookedFunctionName.c_str());
            return false;
        }
        printf("[+] Found %s at 0x%p\n", hookedFunctionName.c_str(), hookedFunction);

        // Get the address of the trampoline variable
        std::string trampolineVarName = functionName + "Trampoline";
        PVOID trampolineVarAddr = GetProcAddressRemoteN(ctx.hProcess, (PBYTE)ctx.ntdllNBase, trampolineVarName.c_str());
        if (!trampolineVarAddr) {
            printf("[!] Not found %s\n", trampolineVarName.c_str());
            return false;
        }

        // Allocate memory for the trampoline
        PVOID trampolineMemory = VirtualAllocEx(ctx.hProcess, NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampolineMemory) {
            printf("[!] Failed to allocate trampoline memory\n");
            return false;
        }
        printf("[+] Allocated trampoline memory at 0x%p\n", trampolineMemory);

        // Write the trampoline address to the variable
        if (!WriteProcessMemory(ctx.hProcess, trampolineVarAddr, &trampolineMemory, sizeof(PVOID), nullptr)) {
            printf("[!] Failed to write trampoline address\n");
            VirtualFreeEx(ctx.hProcess, trampolineMemory, 0, MEM_RELEASE);
            return false;
        }

        // Patch the original NT function to jump to the hooked function
        return PatchFunction(originalFunction, hookedFunction, trampolineMemory);
    }
};

// Helper function to find ntdll.dll in the target process
PVOID FindNtdllBase(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = 0;
    SIZE_T returnLength;
    WCHAR name[MAX_PATH];

    // Get the NtQueryVirtualMemory function address
    NtQueryVirtualMemory_proc NtQueryVirtualMemory = 
        (NtQueryVirtualMemory_proc)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryVirtualMemory");

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
            return mbi.AllocationBase;
        }
        address = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    return nullptr;
}

// Helper function to inject the DLL
PVOID InjectDll(HANDLE hProcess, const WCHAR* dllPath) {
    // Load the DLL into memory
    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW failed: %d\n", GetLastError());
        return nullptr;
    }

    DWORD dwDllSize = GetFileSize(hFile, NULL);
    LPVOID lpDllBuffer = VirtualAlloc(NULL, dwDllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!lpDllBuffer) {
        printf("[!] VirtualAlloc failed: %d\n", GetLastError());
        CloseHandle(hFile);
        return nullptr;
    }

    if (!ReadFile(hFile, lpDllBuffer, dwDllSize, NULL, NULL)) {
        printf("[!] ReadFile failed: %d\n", GetLastError());
        VirtualFree(lpDllBuffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return nullptr;
    }

    CloseHandle(hFile);

    PVOID dllBase = ReflectiveDLLInject(hProcess, (PBYTE)lpDllBuffer);
    VirtualFree(lpDllBuffer, 0, MEM_RELEASE);
    return dllBase;
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

    // Find ntdll.dll in the target process
    PVOID ntdllBase = FindNtdllBase(hProcess);
    if (!ntdllBase) {
        printf("[!] ntdll.dll not found\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Found ntdll.dll at 0x%p\n", ntdllBase);

    // Inject our DLL
    printf("[+] Injecting DLL\n");
#ifdef _DEBUG
    WCHAR dllPath[] = L"C:\\Users\\sonx\\projects\\hookNt\\src\\ntdllN\\x64\\Debug\\ntdllN.dll";
#else
    WCHAR dllPath[] = L".\\ntdllN.dll";
#endif
    PVOID ntdllNBase = InjectDll(hProcess, dllPath);
    if (!ntdllNBase) {
        printf("[!] DLL injection failed\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] DLL injected at 0x%p\n", ntdllNBase);

    // Create process context and hook manager
    ProcessContext ctx(hProcess, ntdllBase, ntdllNBase, pid);
    HookManager hookManager(ctx);

    // Hook each function
    for (const auto& functionName : ntFunctionsToHook) {
        hookManager.HookFunction(functionName);
    }

    printf("[+] Setup done, resuming thread\n");
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(hProcess);

    return 0;
}

