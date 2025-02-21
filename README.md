<div align="center">

<h1 align="center" style="font-family: 'Segoe UI', sans-serif; font-size: 48px;">
  HookNt
</h1>

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows-blue)

A Windows NT API hooking tool for intercepting and monitoring system calls

</div>

This project is a demonstration of API hooking, specifically targeting NT functions on the Windows operating system.

## Components

### ntdllN

- **Type**: Dynamic Link Library (DLL)
- **Purpose**: Provides hooked versions of NT functions such as `NtCreateFile`, `NtReadFile`, and `NtWriteFile`.
- **Key Files**:
  - `ntdllN.cpp`: Defines the exported functions for the DLL.
  - `syscall.asm`: Contains assembly code for system call interception.

### hookNt

- **Type**: Application
- **Purpose**: Injects the `ntdllN` DLL into a target process and patches NT functions to redirect calls to the hooked versions.
- **Key Files**:
  - `hookNt.cpp`: Contains the main logic for process creation, DLL injection, and function patching.

## Features

- **Reflective DLL Injection**: The application can inject the `ntdllN` DLL into a target process using reflective DLL injection techniques.
- **Function Hooking**: The project hooks NT functions by patching the original function to jump to the hooked version.
- **Custom Logging**: The hooked functions log their parameters and return values for monitoring purposes.

## How it works

The `hookNt` application works by:

1. Creating a target process in a suspended state
2. Injecting the `ntdllN` DLL into the process memory
3. Patching the original NT functions to redirect to the hooked versions
4. Resuming the process execution

When the process makes NT system calls, they are intercepted by the hooked functions in `ntdllN`. These hooked functions:

- Log all input parameters and return values
- Call the original NT function via syscall
- Allow monitoring of low-level system operations

This provides visibility into NT API usage at the earliest stages of process execution, before higher-level Windows APIs are involved.

## Usage

1. **Build the Project**: Compile both the `ntdllN` DLL and the `hookNt` application using Visual Studio.
2. **Run the Application**: Execute `hookNt.exe` with the target program and a list of NT functions to hook as command-line arguments.

   ```bash
   hookNt.exe <target_program> <nt_function1> <nt_function2> ...
   ```

3. **Monitor Output**: The application will log the hooking process and the parameters of the hooked functions.

## Example

```bash
hookNt.exe test.exe NtWriteFile NtCreateFile
```
![Example output showing hooked NtWriteFile calls](./imgs/image-1.png)

## Code Overview

### Hooking Logic

The hooking logic is implemented in the `hookNt.cpp` file, where the application creates a suspended process, injects the DLL, and patches the NT functions.

### DLL Exported Functions

The `ntdllN.cpp` file defines the exported functions for the DLL, which are the hooked versions of the NT functions.

### Limitations
- Currently only supports x64 architecture
- Target process must have a console window/terminal
- Output formatting may be inconsistent in some cases and needs refinement

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Disclaimer

This project is for educational purposes only. Use it responsibly and ensure you have permission to hook into any target processes.
