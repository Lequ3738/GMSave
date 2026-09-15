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

// Access to the smart-save watermark. merge_flow temporarily zeroes it so a
// staging save into an empty directory produces the COMPLETE file tree (the
// smart-skip would otherwise omit resources untouched since the last real
// save), then restores it so the next real save still skips correctly.
double gm80_save_last_save_time();
void gm80_save_set_last_save_time(double t);
