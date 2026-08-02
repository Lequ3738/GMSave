// GM80 save format: multi-file project save (mirrors gm82save for GM 8.0)
// Reads Delphi objects directly from GM arrays and writes .gm80 directory.
#pragma once
#include <string>

// Save project to .gm80 directory
// gm_base: GetModuleHandle(NULL) of GameMaker.exe
// path: full path to .gm80 file (e.g. "C:\project.gm80")
bool gm80_save_to_path(void* gm_base, const std::wstring& path);
