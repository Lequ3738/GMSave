// Three-way merge flow for external .gm80 changes (the "modern IDE" layer).
//
// Model (git-like): base = snapshot of the files as last loaded/saved
// (cache\gmsave-base\), local = current IDE memory (full staging save),
// remote = current disk. Per-file: clean merges auto-apply silently,
// conflicts launch the GMSaveMerge tool, results are written to disk and the
// project is reloaded through the existing GM80_LoadRecentProject path.
#pragma once
#include <string>

// ==== Base snapshot ====
// Refresh after every successful load AND every successful real save: re-copy
// all text files under <projDir>\cache\gmsave-base\root\ and rewrite
// manifest.json (per-file size + mtime + FNV-1a-64 hash for every project
// file; binary files are hashed, not copied). cache\ is watcher-filtered and
// git-ignored.
void merge_flow_snapshot_refresh(const std::wstring& projDir);

// True when any project file on disk differs from the snapshot (size/mtime
// fast path, hash fallback). Used by the save-side conflict prompt.
bool merge_flow_disk_differs(const std::wstring& projDir);

// ==== The flow (main thread, from the watcher tick) ====
// Assumes editor windows were already closed by the caller. Performs staging
// save → classification → silent auto-apply of clean results → merge tool for
// conflicts → apply + reload. Returns true when the project was reloaded.
bool merge_flow_run(const std::wstring& projDir);

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
