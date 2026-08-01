// IDE hook definitions for GM 8.0
// These functions intercept GM's save/load/project-init to add .gm80 support.
#pragma once
#include <windows.h>

// Install all IDE hooks. Call once from DllMain.
bool ide_hooks_install(HMODULE gm_base);

// Remove all hooks.
void ide_hooks_uninstall();
