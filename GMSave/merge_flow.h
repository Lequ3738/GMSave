// Three-way merge flow for external .gm80 changes (the "modern IDE" layer).
//
// Model (git-like): base = snapshot of the files as last loaded/saved
// (cache\gmsave-base\), local = current IDE memory (full staging save),
// remote = current disk. Per-file: clean merges auto-apply silently,
// conflicts launch the GMSaveMerge tool, results are written to disk and the
// project is reloaded through the existing GM80_LoadRecentProject path.
#pragma once
#include <string>
#include <vector>

struct Gm80WrittenFile;

// ==== Base snapshot ====
// Refresh after every successful load AND every successful real save: re-copy
// all text files under <projDir>\cache\gmsave-base\root\ and rewrite
// manifest.json (per-file size + mtime + FNV-1a-64 hash for every project
// file; binary files are hashed, not copied). cache\ is watcher-filtered and
// git-ignored.
// `written` (when given) carries the save's own write journal: files listed
// there skip the re-read + re-hash, and their base copy is refreshed from a
// read-back only when its recorded content changed.
void merge_flow_snapshot_refresh(
    const std::wstring& projDir, const std::vector<Gm80WrittenFile>* written = nullptr);

// True when any project file on disk differs from the snapshot (size/mtime
// fast path, hash fallback). Used by the save-side conflict prompt. With no
// snapshot on file this returns false — an unknown, not a verified match.
bool merge_flow_disk_differs(const std::wstring& projDir);

// True when a readable base snapshot manifest exists. merge_flow_run's
// pre-check needs this tri-state split: without it, "disk_differs == false"
// would fold the no-baseline case (a real problem — nothing can be merged)
// into a verified nothing-to-do.
bool merge_flow_snapshot_exists(const std::wstring& projDir);

// ==== The flow (main thread: the watcher tick, the save-side hook, or the
// unattended force-sync entry) ====
// Cheap stat pre-check → pass-1 analysis (the GATE, taken with editor windows
// untouched) → FAST PATH: open editors that are all modeless with GM's dirty
// flags (the title-'*' array) all zero have nothing unapplied — the pass-1
// staging is authoritative; no question, no editor closing (the reload frees
// them): identical to the no-editors case, one analysis → otherwise the
// editor gate (one prompt per variant; "review the changes" is folded into
// the clean variant's 否 — no second question anywhere; the conflict variant
// asks apply/discard of the unapplied editor content, the tool doubles as the
// review) → pass-2 analysis ALWAYS follows the gate (freeing modeless editors
// applies their content into the resources, so the staging may be stale; the
// stat shortcut keeps it cheap) → merge tool for conflicts and reviews (its
// confirm is the FINAL action; clean+unreviewed changes apply silently) →
// apply + reload through GM80_LoadRecentProject, which retitles the
// already-open native progress form in place. review=true opens the tool
// even for clean merges.
enum class MergeFlowResult
{
    RELOADED,      // applied and reloaded from disk
    NOTHING_TO_DO, // disk matches the base snapshot, or the analysis found no
                   // difference — IDE memory already equals the disk, so the
                   // caller may treat this as "synced"
    NO_RELOAD,     // the flow ran but ended without reloading: a stage/tool
                   // failure, a user cancel, an aborted apply — the disk may
                   // still hold unapplied external changes
    REBASED,       // no baseline snapshot existed: one was re-created from the
                   // current disk and this round was skipped — the external
                   // change was NOT applied (redoing it merges it normally)
};

// Reporting a NO_RELOAD/REBASED round as NOTHING_TO_DO is what lets an
// unattended caller compile a binary built from a half-stale project, so the
// force-sync entry maps them to distinct statuses. Foreground callers (tick,
// save hook) only need the RELOADED vs everything-else split.
// `unattended` (the force-sync entry) pops no dialogs at all: its caller
// polls a status block, and a modal box nobody answers would stall the loop
// forever — every refusal stays in the log and the result status instead.
MergeFlowResult merge_flow_run(const std::wstring& projDir, bool review,
    bool unattended = false);

// ==== Editor-window helpers (shared with the watcher tick) ====
// One editor form instance per resource lives in the resource "forms" arrays.
int merge_flow_count_editor_windows();
// A modal form that is NOT one of the resource editors (message boxes, file
// dialogs, preferences…) → the tick should defer, not stack prompts on it.
bool merge_flow_non_editor_modal_open();
// A standalone code editor ("执行代码") is open. These block the main window
// through raw Win32 disabling (never ShowModal) and live outside the resource
// forms arrays, so they are invisible to both checks above — yet reloading
// with one open corrupts its singleton state. Defer while it is open.
bool merge_flow_code_editor_open();
// Close every open editor. Modal ones (fsModal set — stuck inside ShowModal)
// get ModalResult = modalResult (1 mrOk = apply / 2 mrCancel = discard) and
// unwind on their own over the next message cycles; modeless ones are freed
// via GM's own TObject.Free (the exact treatment InitializeProject applies to
// these forms — script editors apply their content on destroy, verified).
// Returns the number of modeless forms freed immediately.
int merge_flow_close_editors(int modalResult);
// GM's global unsaved-changes state: the 16 per-category title-'*' flags.
// true when ANY category is dirty (memory unreadable also counts as dirty —
// callers take the safe route). Zero everywhere is what makes the merge flow
// provably silent: local == base, so no per-file conflict can exist.
bool merge_flow_global_dirty();
// Any resource editor currently stuck inside ShowModal (its content hasn't
// reached the dirty flags yet, so zero flags prove nothing while one is up).
bool merge_flow_any_modal_editor_open();
