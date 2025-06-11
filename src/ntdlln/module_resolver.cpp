#include "module_resolver.h"
#include "memory_utils.h"

#ifdef _WIN64
#include <intrin.h>
#endif

PPEB GetPEB() {
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

bool IsModuleMatch(PLDR_DATA_TABLE_ENTRY module, const WCHAR* fullModuleName) {
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

PVOID FindModuleInList(PPEB_LDR_DATA ldr, const WCHAR* fullModuleName) {
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

PVOID GetModuleHandleN(const WCHAR* fullModuleName) {
    PPEB peb = GetPEB();
    if (!peb) return nullptr;

    PPEB_LDR_DATA ldr = peb->Ldr;
    if (!ldr) return nullptr;

    return FindModuleInList(ldr, fullModuleName);
} 