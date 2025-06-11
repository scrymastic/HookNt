#pragma once

#include "common.h"

// Module resolution functions
PVOID GetModuleHandleN(const WCHAR* fullModuleName);
PPEB GetPEB();
PVOID FindModuleInList(PPEB_LDR_DATA ldr, const WCHAR* fullModuleName);
bool IsModuleMatch(PLDR_DATA_TABLE_ENTRY module, const WCHAR* fullModuleName); 