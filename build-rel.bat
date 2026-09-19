@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" >nul 2>&1
cd /d C:\Project\C++\GMSave
MSBuild GMSave.sln -p:Configuration=Release -p:Platform=x86 -m -v:m
