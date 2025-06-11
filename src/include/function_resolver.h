#pragma once

#include "common.h"

// Function resolution functions
PVOID GetProcAddressN(void* dllBase, const char* functionName);
bool ValidateHeaders(void* dllBase);
PIMAGE_EXPORT_DIRECTORY GetExportDirectory(void* dllBase);
PVOID FindFunctionInExports(void* dllBase, PIMAGE_EXPORT_DIRECTORY exportDir, const char* functionName); 