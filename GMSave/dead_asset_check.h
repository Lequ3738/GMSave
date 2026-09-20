// Dead-asset check: adds a "Check for dead assets" entry to the IDE main menu
// bar and scans the project folders for asset files that are registered in
// neither index.yyd nor tree.yyd.
#pragma once

// Store the GM module base (called once from ide_hooks_install).
void dead_asset_check_install(uint8_t* gm_base);

// Idempotent: no-op after the first success. Called from the watcher tick
// because the main form does not exist yet during DLL attach; once the
// project is open (watcher running) the menu bar exists and the entry is
// injected exactly once.
void dead_asset_check_ensure_menu();

// True once the menu entry is in place (successfully or given up).
bool dead_asset_check_menu_ready();

// Sync the entry's enabled state with project presence (called from the load
// hooks). No-op until the entry exists — the injection reads the project path
// itself to pick the initial state.
void dead_asset_check_set_project(bool loaded);
