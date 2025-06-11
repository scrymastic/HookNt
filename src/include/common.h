#pragma once

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdarg.h>

// Common type definitions
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

// Function type definitions for dynamic loading
typedef int(*vprintf_proc)(const char* format, va_list args);
typedef HMODULE(*LoadLibraryA_proc)(const char* lpLibFileName);
typedef PVOID(*GetProcAddress_proc)(HMODULE hModule, LPCSTR lpProcName);

// Common constants
#define MAX_FUNCTION_NAME 256
#define TRAMPOLINE_SIZE 1024
#define PATCH_SIZE 14

// Export/Import macros
#ifdef NTDLLN_EXPORTS
#define NTDLLN_API __declspec(dllexport)
#else
#define NTDLLN_API __declspec(dllimport)
#endif

// Utility macros
#ifdef _WIN64
#define POINTER_SIZE 8
#else
#define POINTER_SIZE 4
#endif 