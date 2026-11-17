// File watcher for .gm80 projects — IDE-style external-change handling
// (silent reload when the user hasn't made changes; Yes/No prompt on conflict)
#pragma once
#include <cstdint>
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

// Quiet lease: while active, every user-visible prompt is replaced by a log
// line plus a counter bump, so an external agent driving the IDE never faces
// a modal box. Granted by the "GMSave.SetQuiet" window message (wParam = lease
// ms, 0 = clear) or by the GMSAVE_QUIET_MS environment variable at startup.
bool gm80_ui_quiet();

// Grant the startup lease from GMSAVE_QUIET_MS. Called from ide_hooks_install
// so the very first project load is already covered — the hidden window and its
// message channel are created later, on the first project_watcher_start.
void project_watcher_init_quiet_from_env();

// Record one suppressed prompt of `kind` (1 = save disk-differs choice,
// 2 = save failure box, 3 = load diagnostics summary, 4 = load fatal error box,
// 5 = merge editor gate) and bump the suppression counter the external agent
// polls.
void gm80_ui_suppressed(uint32_t kind);
