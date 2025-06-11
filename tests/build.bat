@echo off
setlocal

:: Create build directory
if not exist build mkdir build
cd build

:: Configure with CMake
cmake .. -G "Visual Studio 17 2022" -A x64

:: Build
cmake --build . --config Release

:: Copy executable to parent directory
copy Release\test_file_ops.exe ..

echo Build complete. Test program is in tests\test_file_ops.exe 