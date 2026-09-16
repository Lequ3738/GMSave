// File watcher for .gm80 projects — IDE-style external-change handling
// (silent reload when the user hasn't made changes; Yes/No prompt on conflict)
#pragma once
#include <string>

// Start watching a project directory recursively (stops any previous watch).
// Call on the main thread. Records SAVE_END = now so the load itself isn't seen
// as a foreign change.
void project_watcher_start(const std::wstring& path);

// Stop watching and clear the pending-foreign-change flag.
void project_watcher_stop();

// Set the pending-foreign-change flag while the watcher keeps running: the
// next tick re-runs the whole flow against the current disk. Used by
// merge_flow when an apply was aborted because the disk moved under the tool
// session — the newer disk content must be re-classified, not clobbered.
// No-op in effect if the watcher is stopped (the flag is cleared on the next
// start/stop); the save-side disk_differs check covers that path.
void project_watcher_rearm_pending();

// Record SAVE_END = now (call after our own save completes so our writes aren't
// treated as foreign changes).
void project_watcher_mark_saved();

// Ensure the hidden timer window exists (creates it on the main thread). Call
// once from ide_hooks_install. The timer drives project_watcher_tick every 1s.
void project_watcher_ensure_timer_window();

// Called every second on the main thread (hidden-window WM_TIMER).
// Modern-IDE external-change flow (see merge_flow.h):
//   - defer while a non-editor modal dialog is up (don't stack prompts)
//   - editor windows open → ask once (apply / discard / cancel), close them,
//     wait a tick for the modal loops to unwind
//   - then: staging save → three-way classify → silent auto-apply of clean
//     results → GMSaveMerge tool for conflicts → reload
void project_watcher_tick();

// Stop the watcher, capture tree state, and reload the current project via
// GM80_LoadRecentProject (RVA 0x19B860). Exposed for merge_flow's apply step.
void project_watcher_reload_project();

bool project_watcher_is_running();

// Main-window HWND for modal dialog owners (FindWindow("TMainForm"), falling
// back to the foreground window). Share ONE implementation across all plugin
// message boxes so the dialog stays in front of the IDE and disables it.
HWND gm80_prompt_owner();
