// File watcher for .gm80 projects — IDE-style external-change handling.
// Modeled on gm82save's regular/project_watcher.rs, adapted to GM 8.0:
//   - A background thread watches the project directory recursively.
//   - Foreign changes (file mtime > SAVE_END) set a pending flag.
//   - A hidden-window timer (1s) on the main thread polls the flag and acts:
//       * user has NO unsaved changes  -> silent reload (GM80_LoadRecentProject)
//       * user HAS unsaved changes     -> Yes/No prompt (conflict)
//   - Safety gate: only act when no modal dialog is focused and no resource
//     editor form is open, so the reload never runs while UI references
//     resources that InitializeProject is about to free.
#include "pch.h"
#include "project_watcher.h"
#include "gm80_addresses.h"
#include "gm_log.h"
#include <windows.h>
#include <string>

// ==== Shared state ====
static HANDLE g_watch_thread = NULL;
static volatile bool g_watching = false;
static std::wstring g_watch_path;

// SAVE_END as FILETIME (64-bit): any file whose last-write time is <= this was
// written by us and is NOT a foreign change. Set at end of our saves/loads.
static volatile ULONGLONG g_save_end_ft = 0;

// Set by the watcher thread when a foreign change is seen; consumed (and reset)
// by the main-thread timer.
static volatile LONG g_pending_foreign = 0;

static ULONGLONG now_ft() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

void project_watcher_mark_saved() {
    g_save_end_ft = now_ft();
    gm_log("Watcher: SAVE_END updated");
}

// ==== Watcher thread ====
// ReadDirectoryChangesW (recursive). For each FILE_NOTIFY_INFORMATION:
//   ignore FILE_ACTION_ADDED (gm82save parity);
//   FILE_ACTION_MODIFIED -> foreign only if file mtime > SAVE_END;
//   FILE_ACTION_REMOVED / RENAMED -> foreign.
static DWORD WINAPI watch_thread(LPVOID) {
    HANDLE hDir = CreateFileW(g_watch_path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL);
    if (hDir == INVALID_HANDLE_VALUE) {
        gm_log("Watcher: cannot open dir err=%u", GetLastError());
        return 1;
    }
    uint8_t buf[64 * 1024];
    OVERLAPPED ov = {};
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    gm_log("Watcher: started on '%S'", g_watch_path.c_str());

    while (g_watching) {
        DWORD bytes = 0;
        if (!ReadDirectoryChangesW(hDir, buf, sizeof(buf), TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
            &bytes, &ov, NULL)) {
            // e.g. ERROR_NOTIFY_ENUM_DIR (buffer overflow from a big batch of
            // changes). Retry instead of dying silently, so the watcher survives.
            gm_log("Watcher: ReadDirectoryChangesW failed err=%u — retrying", GetLastError());
            Sleep(500);
            continue;
        }
        DWORD wait = WaitForSingleObject(ov.hEvent, 2000);
        ResetEvent(ov.hEvent);
        if (!g_watching) break;
        if (wait == WAIT_TIMEOUT) continue;
        DWORD got = 0;
        if (!GetOverlappedResult(hDir, &ov, &got, FALSE)) continue;
        if (got == 0) continue;

        uint8_t* p = buf;
        while (p < buf + got) {
            FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)p;
            bool foreign = false;
            switch (fni->Action) {
                case FILE_ACTION_ADDED:
                    break; // gm82save: ignore create (our own saves stop the watcher anyway)
                case FILE_ACTION_REMOVED:
                    foreign = true;
                    break;
                case FILE_ACTION_RENAMED_OLD_NAME:
                case FILE_ACTION_RENAMED_NEW_NAME:
                    foreign = true;
                    break;
                case FILE_ACTION_MODIFIED: {
                    std::wstring name(fni->FileName, fni->FileNameLength / 2);
                    std::wstring full = g_watch_path + L"\\" + name;
                    WIN32_FILE_ATTRIBUTE_DATA fd;
                    if (GetFileAttributesExW(full.c_str(), GetFileExInfoStandard, &fd)) {
                        ULONGLONG mtime =
                            ((ULONGLONG)fd.ftLastWriteTime.dwHighDateTime << 32) | fd.ftLastWriteTime.dwLowDateTime;
                        if (mtime > g_save_end_ft) foreign = true;
                    } else {
                        foreign = true; // file gone mid-notify — treat as foreign
                    }
                    break;
                }
                default:
                    break;
            }
            if (foreign) {
                if (InterlockedExchange(&g_pending_foreign, 1) == 0)
                    gm_log("Watcher: foreign change detected");
            }
            if (!fni->NextEntryOffset) break;
            p += fni->NextEntryOffset;
        }
    }
    CloseHandle(ov.hEvent);
    CloseHandle(hDir);
    gm_log("Watcher: thread exited");
    return 0;
}

void project_watcher_stop() {
    g_watching = false;
    if (g_watch_thread) {
        WaitForSingleObject(g_watch_thread, 2000);
        CloseHandle(g_watch_thread);
        g_watch_thread = NULL;
    }
    InterlockedExchange(&g_pending_foreign, 0);
    gm_log("Watcher: stopped");
}

void project_watcher_start(const std::wstring& path) {
    // Lazy-create the main-thread timer window here (first start). Called on the
    // main thread during a project load/save — never from DllMain, so creating a
    // window is safe (no loader lock).
    project_watcher_ensure_timer_window();
    project_watcher_stop();
    InterlockedExchange(&g_pending_foreign, 0);
    g_watch_path = path;
    g_save_end_ft = now_ft(); // everything we load/read predates now → not foreign
    g_watching = true;
    g_watch_thread = CreateThread(NULL, 0, watch_thread, NULL, 0, NULL);
    gm_log("Watcher: start requested for '%S'", path.c_str());
}

bool project_watcher_is_running() {
    return g_watching;
}

void project_watcher_ensure_timer_window(); // defined below (lazy, main thread)

// ==== Safety gate ====
// 1) No resource editor form may be open. GM stores one editor form instance per
//    resource in the resource "forms" arrays (arr[1] of each AssetList — verified:
//    rooms 0x1E9298 holds the room editor instance, sub_554354). If any slot is
//    non-null, an editor is open (even if not focused) → defer.
// 2) No modal dialog may be focused. Delphi forms register their class name as the
//    Win32 window class at runtime (no static string ref in the binary), so
//    FindWindow("TMainForm") locates the main window; a focused modal/editor has a
//    different foreground window → defer.
static bool editor_form_open() {
    uint8_t* b = (uint8_t*)GetModuleHandle(NULL);
    if (!b) return false;
    const struct { uint32_t arr; uint32_t cnt; } F[] = {
        {0x1E910C, 0x1E911C}, // sprites
        {0x1E927C, 0x1E9288}, // sounds
        {0x1E9098, 0x1E90A8}, // backgrounds
        {0x1E92B0, 0x1E92BC}, // paths
        {0x1E92D8, 0x1E92E4}, // scripts
        {0x1E92C4, 0x1E92D0}, // fonts
        {0x1E9304, 0x1E9310}, // timelines
        {0x1E9358, 0x1E9364}, // objects
        {0x1E9298, 0x1E92A4}, // rooms
    };
    for (auto& f : F) {
        uint32_t cnt = *(uint32_t*)(b + f.cnt);
        uint32_t* arr = *(uint32_t**)(b + f.arr);
        // Guard the 0xFFFFFFFF "uninitialized dynamic array" sentinel too.
        if (!arr || (uintptr_t)arr == 0xFFFFFFFF || cnt == 0 || cnt > 50000) continue;
        for (uint32_t i = 0; i < cnt; i++)
            if (arr[i]) return true;
    }
    return false;
}

static bool safe_to_act() {
    if (editor_form_open()) return false;
    HWND main = FindWindowW(L"TMainForm", NULL);
    if (!main) return false;
    return GetForegroundWindow() == main;
}

// ==== "User has unsaved changes" via the 16 updated/dirty flags ====
static bool user_has_unsaved_changes() {
    uint8_t* b = (uint8_t*)GetModuleHandle(NULL);
    if (!b) return false;
    static const uint32_t flags[] = ADDR_DIRTY_FLAGS;
    for (uint32_t f : flags)
        if (*(uint8_t*)(b + f)) return true;
    return false;
}

// ==== Reload ====
// GM80_LoadRecentProject (RVA 0x19B860) with the current project path: it checks
// the path, shows the progress form, runs InitializeProject, then our hook at
// 0x59B91B routes .gm80 → gm80_load_project, then reloads action libraries.
// Our load hook re-starts the watcher (project_watcher_start) after a successful
// load, so no explicit re-arm is needed here.
static void do_reload() {
    project_watcher_stop();
    project_watcher_mark_saved();
    uint8_t* b = (uint8_t*)GetModuleHandle(NULL);
    if (!b) return;
    char** pp = (char**)(b + 0x1EA27C);
    if (!pp || !*pp) { gm_log("Watcher: reload aborted, no project path"); return; }
    char* path = *pp;
    uint32_t fn = (uint32_t)b + 0x19B860; // GM80_LoadRecentProject
    uint32_t pathVal = (uint32_t)path;
    gm_log("Watcher: reloading project '%s'", path);
    __asm {
        mov eax, pathVal
        xor ebx, ebx
        xor edi, edi
        xor esi, esi
        mov ecx, fn
        call ecx
    }
    gm_log("Watcher: reload returned");
}

// ==== Main-thread timer ====
// The main window as MessageBox owner: the prompt is then modal to the IDE
// (main window + its controls are disabled while it is up) and stays in front.
// Falls back to the foreground window (the gate already requires it == main).
HWND gm80_prompt_owner() {
    HWND main = FindWindowW(L"TMainForm", NULL);
    if (!main) main = GetForegroundWindow();
    return main;
}

static void project_watcher_act() {
    if (user_has_unsaved_changes()) {
        gm_log("Watcher: unsaved changes present → prompting");
        int r = MessageBoxW(gm80_prompt_owner(),
            L"Project files have been modified outside Game Maker. Reload project? "
            L"Unsaved changes will be lost.\r\n"
            L"If you click \"No\", saving will overwrite any foreign changes.",
            L"Game Maker 8.0", MB_YESNO | MB_ICONQUESTION | MB_SETFOREGROUND);
        if (r == IDYES) {
            do_reload();
        } else {
            gm_log("Watcher: user chose No — keeping unsaved changes");
        }
    } else {
        gm_log("Watcher: no unsaved changes → silent reload");
        do_reload();
    }
}

// The watcher watches g_watch_path (a .gm80 project folder). If the current
// project (GM80_ProjectPath, 0x1EA27C — the metadata FILE inside that folder) no
// longer resolves to the same folder, the project changed (e.g. File > New) and
// a stale watch must not reload the old one.
static bool watcher_path_current() {
    uint8_t* b = (uint8_t*)GetModuleHandle(NULL);
    if (!b) return false;
    char** pp = (char**)(b + 0x1EA27C);
    if (!pp || !*pp) return false; // no current project → not our .gm80
    std::string proj(pp[0]);
    if (proj.size() < 6) return false;
    if (_stricmp(proj.c_str() + proj.size() - 5, ".gm80") != 0) return false;
    size_t slash = proj.find_last_of("\\/");
    std::wstring wdir;
    if (slash != std::string::npos)
        wdir.assign(proj.begin(), proj.begin() + slash);
    else
        wdir.assign(proj.begin(), proj.end());
    return _wcsicmp(wdir.c_str(), g_watch_path.c_str()) == 0;
}

void project_watcher_tick() {
    if (!g_pending_foreign) return;
    if (!g_watching) { InterlockedExchange(&g_pending_foreign, 0); return; }
    // The project changed under us (File > New / switched project) → stop watching.
    if (!watcher_path_current()) { project_watcher_stop(); return; }
    if (!safe_to_act()) return; // defer: modal focused or an editor is open
    InterlockedExchange(&g_pending_foreign, 0);
    project_watcher_act();
}

// ==== Hidden timer window (main-thread polling, self-contained) ====
// A message-only window with a 1s WM_TIMER. The thread's message pump
// (Application.Run → DispatchMessage) delivers WM_TIMER to it, so project_watcher_tick
// runs on the main thread even while GM idles. No GM window is touched.
static const wchar_t* kWatcherWndClass = L"GMSave.Watcher";
static HWND g_timer_wnd = NULL;
static const UINT kTimerId = 1;

static LRESULT CALLBACK watcher_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_TIMER && wp == kTimerId) {
        project_watcher_tick();
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

void project_watcher_ensure_timer_window() {
    if (g_timer_wnd) return;
    HINSTANCE inst = (HINSTANCE)GetModuleHandle(NULL);
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = watcher_wndproc;
    wc.hInstance = inst;
    wc.lpszClassName = kWatcherWndClass;
    RegisterClassExW(&wc); // harmless if already registered
    g_timer_wnd = CreateWindowExW(0, kWatcherWndClass, L"",
        0, 0, 0, 0, 0, HWND_MESSAGE, NULL, inst, NULL);
    if (g_timer_wnd) {
        SetTimer(g_timer_wnd, kTimerId, 1000, NULL);
        gm_log("Watcher: timer window created");
    } else {
        gm_log("Watcher: timer window create FAILED err=%u", GetLastError());
    }
}
