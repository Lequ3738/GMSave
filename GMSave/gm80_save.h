// GM80 save format: multi-file project save (mirrors gm82save for GM 8.0)
// Reads Delphi objects directly from GM arrays and writes .gm80 directory.
#pragma once
#include <string>

// Save project to .gm80 directory
// gm_base: GetModuleHandle(NULL) of GameMaker.exe
// path: full path to .gm80 file (e.g. "C:\project.gm80")
bool gm80_save_to_path(void* gm_base, const std::wstring& path);

// If gm80_save_to_path returned false, this holds the human-readable reason
// (currently: a resource-name validation error). The caller should close any
// progress form before displaying it.
const std::string& gm80_save_last_error();

// Capture the resource tree's expanded-folder state into
// <projDir>\cache\tree_state.yyd. Called at the end of every save and just
// before a watcher-triggered reload so the tree isn't collapsed after
// reload/reopen (GM 8.0 persists no tree state). cache/ is generated IDE
// state — safe to ignore in git.
bool gm80_capture_tree_state(void* gm_base, const std::wstring& projDir);
