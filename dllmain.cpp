// GMSave — Multi-file project save for GameMaker 8.0 (.gm80 format)
// DLL entry point. Hooks into the Delphi IDE on load.
#include "pch.h"
#include "delphi.h"
#include "gm80_addresses.h"
#include "ide_hooks.h"
#include "project_watcher.h"
#include "gm_log.h"

static HMODULE g_gm_base = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_gm_base = GetModuleHandle(NULL);
        DisableThreadLibraryCalls(hinstDLL);

        // Verify FoxPlugin.txt configuration
        char gm_path[MAX_PATH];
        GetModuleFileNameA(NULL, gm_path, sizeof(gm_path));
        char* last_slash = strrchr(gm_path, '\\');
        if (last_slash) *(last_slash + 1) = '\0';
        strcat_s(gm_path, "FoxPlugin.txt");

        bool config_ok = (GetFileAttributesA(gm_path) != INVALID_FILE_ATTRIBUTES);
        bool hooks_ok = ide_hooks_install(g_gm_base);

        gm_log("GMSave v5 loaded | FoxPlugin.txt: %s | Hooks: %s | Base: 0x%p",
               config_ok ? "FOUND" : "MISSING",
               hooks_ok ? "OK" : "FAIL",
               g_gm_base);
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        project_watcher_stop();
        ide_hooks_uninstall();
        gm_log("GMSave unloaded");
    }
    return TRUE;
}

// Required export for FoxPluginLoader DLL injection mechanism
extern "C" __declspec(dllexport) void Fake() {}
