@echo off
echo Building HookNt project with CMake...

if not exist build mkdir build
cd build

echo Generating build files...
cmake .. -A x64

if %errorlevel% neq 0 (
    echo CMake generation failed!
    pause
    exit /b 1
)

echo Building project...
cmake --build . --config Release

if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)

echo Build completed successfully!
echo.
echo Executables are in: build\bin\
echo.
pause 