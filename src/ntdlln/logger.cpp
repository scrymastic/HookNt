#include "logger.h"
#include "module_resolver.h"
#include "function_resolver.h"

// Global variables
static vprintf_proc gp_vprintf = NULL;

bool TryGetVPrintfFromMsvcrt() {
    PVOID msvcrtBase = GetModuleHandleN(L"C:\\Windows\\System32\\msvcrt.dll");
    if (!msvcrtBase) {
        return false;
    }

    PVOID p_vprintf = GetProcAddressN(msvcrtBase, "vprintf");
    if (p_vprintf) {
        gp_vprintf = (vprintf_proc)p_vprintf;
        return true;
    }

    return false;
}

bool TryLoadMsvcrtAndGetVPrintf() {
    PVOID kernel32Base = GetModuleHandleN(L"C:\\Windows\\System32\\kernel32.dll");
    if (!kernel32Base) {
        return false;
    }

    PVOID p_LoadLibraryA = GetProcAddressN(kernel32Base, "LoadLibraryA");
    if (!p_LoadLibraryA) {
        return false;
    }

    HMODULE msvcrt = ((LoadLibraryA_proc)p_LoadLibraryA)("msvcrt.dll");
    if (!msvcrt) {
        return false;
    }

    PVOID p_vprintf = GetProcAddressN((PVOID)msvcrt, "vprintf");
    if (p_vprintf) {
        gp_vprintf = (vprintf_proc)p_vprintf;
        return true;
    }

    return false;
}

bool InitializeVPrintf() {
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

int printfN(const char* format, ...) {
    if (!InitializeVPrintf()) {
        return 0;
    }

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