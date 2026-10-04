// GM80 save format: multi-file project save (mirrors gm82save for GM 8.0)
// Reads Delphi objects directly from GM arrays and writes .gm80 directory.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

// FNV-1a 64 over raw bytes (standard offset basis). Shared with the merge
// flow's snapshot hashing — the write journal and the snapshot manifest must
// agree on the digest of the same content.
inline uint64_t gm80_fnv1a64(const char* d, size_t n)
{
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < n; i++)
    {
        h ^= (unsigned char)d[i];
        h *= 1099511628211ULL;
    }
    return h;
}

// One file written by the last save: path relative to the save target, byte
// size, content hash. The post-save snapshot refresh joins these against its
// tree enumeration and skips re-reading what the save just wrote.
struct Gm80WrittenFile
{
    std::wstring rel;
    unsigned long long size = 0;
    unsigned long long hash = 0;
};
const std::vector<Gm80WrittenFile>& gm80_save_written_files();

// ==== Save-pass progress ====
// The entry point that owns the native progress form (the Ctrl+S hook, the
// merge flow's staging save) installs a sink with the percentage window
// [lo,hi] the pass may fill. The pass reports its own 0..100 progress; the
// sink receives mapped absolute positions, monotonic, repeats dropped. The
// snapshot refresh that runs after the save reports through the same sink
// (the caller re-installs a window for it). No sink installed → dropped.
typedef void (*Gm80ProgressSink)(int pct);
void gm80_save_progress_install(Gm80ProgressSink sink, int lo, int hi);
void gm80_save_progress_uninstall();
void gm80_save_progress_report(int selfPct);

// Stage-boundary report: selfLo + (selfHi-selfLo)*done/total. Loop bodies call
// this once per resource so the bar keeps moving inside the long types.
inline void gm80_save_progress_stage(int selfLo, int selfHi, int done, int total)
{
    if (total <= 0) total = 1;
    if (done > total) done = total;
    gm80_save_progress_report(selfLo + (selfHi - selfLo) * done / total);
}

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
