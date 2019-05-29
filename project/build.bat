@echo off
echo ~~~~~~~~~~~~~~~~~~~~~~~
echo   Building project...
echo ~~~~~~~~~~~~~~~~~~~~~~~

rem // Path of the parent directory to this script
set DIR=%~dp0
cd /D %DIR%

rem // Command line parameters for CL build tool
set OUTPUT=debug
set TARGET=main
set PLATFORM=x64

set INCLUDES=/I include
set SOURCES=source/**
set EXTLIBPATH=libraries
set LIBRARIES=

rem // Build, compilation, and link variables
if /i %OUTPUT% equ debug (
	set OUTPUT=debug
	set FLAGS=/Od /W4 /EHsc /ZI /MTd
	set SUBSYS=CONSOLE
) else if /i %OUTPUT% equ release (
	set OUTPUT=release
	set FLAGS=/O2 /MT /GA
	set SUBSYS=WINDOWS
) else (
	echo Invalid build mode!
	"cmd /c exit /b 1" & rem // Set %errorlevel% to 1
	goto end_banner
)

rem Find build variables from Visual Studio installation
for /F "tokens=* usebackq" %%I IN (`vswhere -latest -find **\vcvarsall.bat`) do set VARS="%%I"

rem // Additional variables
set RESOURCES=resources

rem // Create the output directory if it does not exist
if not exist %OUTPUT%\nul mkdir %OUTPUT%

rem // Copy necessary files to where they belong
echo Copying resource files...
robocopy %RESOURCES% %OUTPUT% /S >nul

rem // Load build variables from vcvarsall.bat
echo Loading build variables...
call %VARS% %PLATFORM% 1>nul

echo.

rem // Build project
echo Building project...
call cl %FLAGS% %INCLUDES% ^
	/Fo:%OUTPUT%\ /Fd:%OUTPUT%\ %SOURCES% ^
	/link /LIBPATH:%EXTLIBPATH% ^
	/OUT:%OUTPUT%\%TARGET%.exe /PDB:%OUTPUT%\%TARGET%.pdb ^
	/INCREMENTAL /SUBSYSTEM:%SUBSYS% ^
	%LIBRARIES% ^
	2>&1

rem // Clean project
if %OUTPUT% == release (
	echo Cleaning project...
	del /q %OUTPUT%\*.ilk %OUTPUT%\*.obj
)

:end_banner
echo ~~~~~~~~~~~~~~~~~~~
if %errorlevel% == 0 (
	echo   Build complete!
) else (
	echo    Build failed!
)
echo ~~~~~~~~~~~~~~~~~~~

rem // Pause the script if it was launched via double-click, then exit
set TEMP_ERRORLEVEL=%errorlevel%
echo %cmdcmdline% | find /i """%~f0""">nul && pause || "cmd /c exit /b %TEMP_ERRORLEVEL%"
exit /b %errorlevel%
