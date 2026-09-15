@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" >nul
cd /d "%~dp0"
cl /nologo /EHsc /std:c++20 /I. /I"%~dp0..\..\GMSave" "%~dp0diff3_test.cpp" "%~dp0..\..\GMSave\diff3.cpp"
if errorlevel 1 exit /b 1
"%~dp0diff3_test.exe"
