// File watcher for .gm80 projects
// Monitors the project directory for external changes and reloads assets.
#pragma once
#include <string>

void project_watcher_start(const std::wstring& path);
void project_watcher_stop();
bool project_watcher_is_running();
