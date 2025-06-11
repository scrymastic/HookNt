#pragma once

#include "common.h"

// Export trampoline variables
extern "C" __declspec(dllexport) PVOID NtCreateFileTrampoline;
extern "C" __declspec(dllexport) PVOID NtReadFileTrampoline;
extern "C" __declspec(dllexport) PVOID NtWriteFileTrampoline;

// Hooked NT functions
extern "C" __declspec(dllexport) NTSTATUS NTAPI NtCreateFileN(
    HANDLE* FileHandle,
    ACCESS_MASK DesiredAccess,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    IO_STATUS_BLOCK* IoStatusBlock,
    PVOID AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

extern "C" __declspec(dllexport) NTSTATUS NTAPI NtReadFileN(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

extern "C" __declspec(dllexport) NTSTATUS NTAPI NtWriteFileN(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);
