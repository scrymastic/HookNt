#include "ntdlln.h"
#include "module_resolver.h"
#include "function_resolver.h"
#include "logger.h"

// Export trampoline variables
extern "C" __declspec(dllexport) PVOID NtCreateFileTrampoline = nullptr;
extern "C" __declspec(dllexport) PVOID NtReadFileTrampoline = nullptr;
extern "C" __declspec(dllexport) PVOID NtWriteFileTrampoline = nullptr;

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
) {
    printfN("\n[*] NtCreateFile\n");
    printfN("  \\FileHandle       : %p\n", FileHandle);
    printfN("  \\DesiredAccess    : %lu\n", DesiredAccess);
    printfN("  \\ObjectAttributes : %p\n", ObjectAttributes);
    printfN("  \\IoStatusBlock    : %p\n", IoStatusBlock);
    printfN("  \\AllocationSize   : %p\n", AllocationSize);
    printfN("  \\FileAttributes   : %lu\n", FileAttributes);
    printfN("  \\ShareAccess      : %lu\n", ShareAccess);
    printfN("  \\CreateDisposition: %lu\n", CreateDisposition);
    printfN("  \\CreateOptions    : %lu\n", CreateOptions);
    printfN("  \\EaBuffer         : %p\n", EaBuffer);
    printfN("  \\EaLength         : %lu\n", EaLength);

    typedef NTSTATUS(NTAPI* NtCreateFile_proc)(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*, IO_STATUS_BLOCK*, PVOID, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    NtCreateFile_proc trampoline = (NtCreateFile_proc)NtCreateFileTrampoline;
    NTSTATUS result = trampoline(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    printfN("  ---------------> %p\n", result);
    return result;
}

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
) {
    printfN("\n[*] NtReadFile\n");
    printfN("  \\FileHandle   : %p\n", FileHandle);
    printfN("  \\Event        : %p\n", Event);
    printfN("  \\ApcRoutine   : %p\n", ApcRoutine);
    printfN("  \\ApcContext   : %p\n", ApcContext);
    printfN("  \\IoStatusBlock: %p\n", IoStatusBlock);
    printfN("  \\Buffer       : %s\n", (char*)Buffer);
    printfN("  \\Length       : %lu\n", Length);
    printfN("  \\ByteOffset   : %p\n", ByteOffset);
    printfN("  \\Key          : %p\n", Key);

    typedef NTSTATUS(NTAPI* NtReadFile_proc)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    NtReadFile_proc trampoline = (NtReadFile_proc)NtReadFileTrampoline;
    NTSTATUS result = trampoline(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    printfN("  ---------------> %p\n", result);
    return result;
}

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
) {
    printfN("\n[*] NtWriteFile\n");
    printfN("  \\FileHandle   : %p\n", FileHandle);
    printfN("  \\Event        : %p\n", Event);
    printfN("  \\ApcRoutine   : %p\n", ApcRoutine);
    printfN("  \\ApcContext   : %p\n", ApcContext);
    printfN("  \\IoStatusBlock: %p\n", IoStatusBlock);
    printfN("  \\Buffer       : %s\n", (char*)Buffer);
    printfN("  \\Length       : %lu\n", Length);
    printfN("  \\ByteOffset   : %p\n", ByteOffset);
    printfN("  \\Key          : %p\n", Key);

    typedef NTSTATUS(NTAPI* NtWriteFile_proc)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    NtWriteFile_proc trampoline = (NtWriteFile_proc)NtWriteFileTrampoline;
    NTSTATUS result = trampoline(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    printfN("  ---------------> %p\n", result);
    return result;
} 