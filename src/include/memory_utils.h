#pragma once

#include "common.h"

// Memory utility functions
int CustomStrCmp(const char* str1, const char* str2);
void* CustomMemCpy(void* dest, const void* src, size_t count);
void* CustomMemSet(void* dest, int value, size_t count); 