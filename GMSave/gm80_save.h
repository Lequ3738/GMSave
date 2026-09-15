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

// Staging-save mode for the merge flow. While on, gm80_save_to_path writes
// EVERY type regardless of the smart-skip baseline (name hashes + per-resource
// timestamps) and FREEZES the baseline: the watermark, name hashes and the
// stale-file cleanup are not touched, so the next real Ctrl+S still sees the
// user's unsaved edits. The old trick — zeroing the watermark only — broke
// after a reload: with the per-resource timestamps at 0 and the name-hash
// baseline already established, the save skipped every type and shipped a
// stub tree whose "missing" files read as IDE-side deletions (2026-09-15).
void gm80_save_set_force_full(bool on);
