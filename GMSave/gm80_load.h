// GM80 multi-file load — direct Delphi object creation
#pragma once
#include <filesystem>
namespace fs = std::filesystem;

// Direct Delphi object creation (covers scripts, fonts, triggers, settings, etc.)
// gm_base: GetModuleHandle(NULL) of GameMaker.exe
bool gm80_load_project(void* gm_base, const std::wstring& path);
