// GMSave — Multi-file project save for GameMaker 8.0 (.gm80 format)
// DLL entry point. Hooks into the Delphi IDE on load.
#include "pch.h"
#include "delphi.h"
#include "gm80_addresses.h"
#include "ide_hooks.h"
#include "project_watcher.h"

static HMODULE g_gm_base = NULL;

// Write a one-line log to %TEMP%\GMSave.log for diagnostics
static void log_init(const char* msg) {
    char path[MAX_PATH];
    GetEnvironmentVariableA("TEMP", path, sizeof(path));
    strcat_s(path, "\\GMSave.log");
    FILE* f = fopen(path, "a");
    if (f) {
        time_t now = time(NULL);
        char* ts = ctime(&now);
        if (ts) ts[24] = '\0'; // strip newline
        fprintf(f, "[%s] %s\n", ts ? ts : "???", msg);
        fclose(f);
    }
}

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

        // Log status
        char buf[256];
        snprintf(buf, sizeof(buf),
            "GMSave v5 loaded | FoxPlugin.txt: %s | Hooks: %s | Base: 0x%p",
            config_ok ? "FOUND" : "MISSING",
            hooks_ok ? "OK" : "FAIL",
            g_gm_base);
        log_init(buf);

        // MessageBoxA(NULL, buf, "GMSave Loaded", MB_OK | MB_ICONINFORMATION);

    } else if (fdwReason == DLL_PROCESS_DETACH) {
        project_watcher_stop();
        ide_hooks_uninstall();
        log_init("GMSave unloaded");
    }
    return TRUE;
}

// Required export for FoxPluginLoader DLL injection mechanism
extern "C" __declspec(dllexport) void Fake() {}
