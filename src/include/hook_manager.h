#pragma once

#include "common.h"
#include <distorm.h>

// Hook management functions
bool HookFunction(HANDLE hProcess, PVOID ntdllBase, PVOID ntdllNBase, const char* functionName);
size_t CalculatePatchSize(HANDLE hProcess, PVOID address);
bool CreateTrampoline(HANDLE hProcess, PVOID originalFunction, PVOID trampolineAddress, size_t patchSize);
bool PatchFunction(HANDLE hProcess, PVOID originalFunction, PVOID newAddress, PVOID trampolineAddress); 