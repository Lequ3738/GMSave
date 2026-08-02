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

// Record SAVE_END = now (call after our own save completes so our writes aren't
// treated as foreign changes).
void project_watcher_mark_saved();

// Ensure the hidden timer window exists (creates it on the main thread). Call
// once from ide_hooks_install. The timer drives project_watcher_tick every 1s.
void project_watcher_ensure_timer_window();

// Called every second on the main thread (hidden-window WM_TIMER).
// If a foreign change is pending AND it is safe (no modal, no editor form open):
//   - user has unsaved changes  -> Yes/No prompt (Yes: reload)
//   - user has NO unsaved changes -> silent reload
void project_watcher_tick();

bool project_watcher_is_running();
