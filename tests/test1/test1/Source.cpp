#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>



int main() {
    // Test WriteFile
    HANDLE hFile = CreateFileA("C:\\Users\\Public\\Downloads\\test.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFileA failed with error %d\n", GetLastError());
        return 1;
    }
    WriteFile(hFile, "Hello from WriteFile\n", 23, NULL, NULL);
    printf("WriteFile done\n");

    // Move file pointer back to start
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

    // Test ReadFile
    char buffer[1024];
    DWORD bytesRead;
    ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL);
    printf("ReadFile done: %s\n", buffer);

    CloseHandle(hFile);

    return 0;
}