#include "common.h"
#include "process_manager.h"
#include "hook_manager.h"
#include <iostream>
#include <vector>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: hooknt.exe <target program> <list of NT functions to hook>\n");
        printf("Example: hooknt.exe notepad.exe NtCreateFile NtReadFile NtWriteFile\n");
        return 1;
    }

    // Extract the target program and NT functions from command-line arguments
    std::string targetProgram = argv[1];
    std::wstring targetProgramW(targetProgram.begin(), targetProgram.end());

    std::vector<std::string> ntFunctionsToHook;
    for (int i = 2; i < argc; ++i) {
        ntFunctionsToHook.push_back(argv[i]);
    }

    printf("[+] HookNt - NT API Function Hooker\n");
    printf("[+] Target: %s\n", targetProgram.c_str());
    printf("[+] Functions to hook: ");
    for (const auto& func : ntFunctionsToHook) {
        printf("%s ", func.c_str());
    }
    printf("\n\n");

    // Create a new process, suspend it and get its PID
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    if (!CreateProcessW(
        targetProgramW.c_str(),
        NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[!] CreateProcess failed (%d)\n", GetLastError());
        return 1;
    }
    
    DWORD pid = pi.dwProcessId;
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;
    printf("[+] Process created, PID: %d\n", pid);

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
    const wchar_t* dllPath = L"ntdlln.dll";  // Assume DLL is in the same directory
#else
    const wchar_t* dllPath = L"ntdlln.dll";
#endif
    PVOID ntdllNBase = InjectDll(hProcess, dllPath);
    if (!ntdllNBase) {
        printf("[!] DLL injection failed\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] DLL injected at 0x%p\n", ntdllNBase);

    // Hook each function
    bool allHooksSuccessful = true;
    for (const auto& functionName : ntFunctionsToHook) {
        if (!HookFunction(hProcess, ntdllBase, ntdllNBase, functionName.c_str())) {
            printf("[!] Failed to hook %s\n", functionName.c_str());
            allHooksSuccessful = false;
        }
    }

    if (allHooksSuccessful) {
        printf("[+] All hooks installed successfully\n");
    } else {
        printf("[!] Some hooks failed to install\n");
    }

    printf("[+] Setup done, resuming process...\n");
    
    // Resume the main thread
    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    return 0;
} 