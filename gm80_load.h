// GM80 multi-file load — direct Delphi object creation + .gmk fallback
#pragma once
#include "gmk_format.h"
#include <filesystem>
namespace fs = std::filesystem;

// Direct Delphi object creation (partial — covers scripts, fonts, triggers, settings)
// gm_base: GetModuleHandle(NULL) of GameMaker.exe
bool gm80_load_project(void* gm_base, const std::wstring& path);

// Fallback: .gm80 → GMKProject → .gmk → GM built-in loader (reliable, full coverage)
bool gm80_load_from_path(GMKProject& out, const std::wstring& path);
