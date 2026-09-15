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
#include "gm80_save.h"
#include "merge_flow.h"
#include "gm_log.h"
#include <windows.h>
#include <string>

// ==== Shared state ====
static HANDLE g_watch_thread = NULL;
static volatile bool g_watching = false;
static std::wstring g_watch_path; // only mutated while NO watcher thread is alive

// Opened by the watcher thread, cancelled AND closed by project_watcher_stop()
// (after joining the thread). Letting stop() own the close removes the
// handle-recycle race of an in-thread CloseHandle.
static volatile HANDLE g_watch_dir = NULL;

// Manual-reset event, created once and reused across start/stop cycles.
// Set by stop() to break the thread out of every wait, so shutdown is
// deterministic (no polling timeout that a slow loop can outlive — the old
// 2s-timeout join could leave a zombie thread reading g_watch_path while the
// next start() reassigned it: use-after-free read).
static HANDLE g_watch_wake = NULL;

// SAVE_END as FILETIME (64-bit): any file whose last-write time is <= this was
// written by us and is NOT a foreign change. Set at end of our saves/loads.
static volatile ULONGLONG g_save_end_ft = 0;

// Set by the watcher thread when a foreign change is seen; consumed (and reset)
// by the main-thread timer.
static volatile LONG g_pending_foreign = 0;

static ULONGLONG now_ft()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

void project_watcher_mark_saved()
{
    g_save_end_ft = now_ft();
    gm_log("Watcher: SAVE_END updated");
}

// ==== Watcher thread ====
// ReadDirectoryChangesW (recursive). For each FILE_NOTIFY_INFORMATION:
//   ignore FILE_ACTION_ADDED (gm82save parity);
//   FILE_ACTION_MODIFIED -> foreign only if file mtime > SAVE_END;
//   FILE_ACTION_REMOVED / RENAMED -> foreign.
static DWORD WINAPI watch_thread(LPVOID)
{
    // Private copy of the path: the shared g_watch_path is only reassigned by
    // project_watcher_start after stop() has JOINED this thread, but the local
    // copy guarantees a cross-thread std::wstring race is impossible even if
    // that invariant ever slips.
    std::wstring watchPath = g_watch_path;
    HANDLE hDir = CreateFileW(watchPath.c_str(), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (hDir == INVALID_HANDLE_VALUE)
    {
        gm_log("Watcher: cannot open dir err=%u", GetLastError());
        return 1;
    }
    g_watch_dir = hDir;
    uint8_t buf[64 * 1024];
    OVERLAPPED ov = {};
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent)
    {
        // Without the event, WaitForMultipleObjects returns WAIT_FAILED and the
        // loop would re-issue ReadDirectoryChangesW while the previous one is
        // still pending. Bail — hDir is already owned by stop() via g_watch_dir.
        gm_log("Watcher: CreateEvent failed err=%u", GetLastError());
        return 1;
    }
    HANDLE wake = g_watch_wake;
    HANDLE hs[2] = {ov.hEvent, wake};
    gm_log("Watcher: started on '%S'", watchPath.c_str());

    while (g_watching)
    {
        DWORD bytes = 0;
        if (!ReadDirectoryChangesW(hDir, buf, sizeof(buf), TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_SIZE,
            &bytes, &ov, NULL))
        {
            // e.g. ERROR_NOTIFY_ENUM_DIR (buffer overflow from a big batch of
            // changes) — the call FAILED, nothing is pending. Retry instead of
            // dying silently, but wait on the wake event (not Sleep) so stop()
            // stays responsive.
            gm_log("Watcher: ReadDirectoryChangesW failed err=%u — retrying",
                GetLastError());
            if (WaitForSingleObject(wake, 500) != WAIT_TIMEOUT) break;
            continue;
        }
        // Blocking wait, woken by either a change or the stop() event. No
        // polling timeout → the loop can never outlive stop() and re-issue
        // ReadDirectoryChangesW while a previous operation is still pending.
        DWORD wait = WaitForMultipleObjects(2, hs, FALSE, INFINITE);
        ResetEvent(ov.hEvent);
        if (!g_watching || wait == WAIT_OBJECT_0 + 1) break;
        if (wait != WAIT_OBJECT_0) continue;
        DWORD got = 0;
        if (!GetOverlappedResult(hDir, &ov, &got, FALSE)) continue;
        if (got == 0) continue;

        uint8_t* p = buf;
        while (p < buf + got)
        {
            FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)p;
            // Ignore the generated cache/ directory (IDE state, e.g.
            // tree_state.yyd) — foreign changes to it must not count as
            // project modifications.
            std::wstring name(fni->FileName, fni->FileNameLength / 2);
            if (name == L"cache" ||
                (name.size() > 6 && name.compare(0, 6, L"cache\\") == 0))
            {
                if (!fni->NextEntryOffset) break;
                p += fni->NextEntryOffset;
                continue;
            }
            bool foreign = false;
            switch (fni->Action)
            {
            case FILE_ACTION_ADDED:
                break;     // gm82save: ignore create (our own saves stop the watcher anyway)
            case FILE_ACTION_REMOVED:
                foreign = true;
                break;
            case FILE_ACTION_RENAMED_OLD_NAME:
            case FILE_ACTION_RENAMED_NEW_NAME:
                foreign = true;
                break;
            case FILE_ACTION_MODIFIED:
            {
                std::wstring full = watchPath + L"\\" + name;
                WIN32_FILE_ATTRIBUTE_DATA fd;
                if (GetFileAttributesExW(full.c_str(), GetFileExInfoStandard, &fd))
                {
                    ULONGLONG mtime = ((ULONGLONG)fd.ftLastWriteTime.dwHighDateTime
                        << 32) |
                        fd.ftLastWriteTime.dwLowDateTime;
                    if (mtime > g_save_end_ft) foreign = true;
                }
                else
                {
                    foreign = true;     // file gone mid-notify — treat as foreign
                }
                break;
            }
            default:
                break;
            }
            if (foreign)
            {
                if (InterlockedExchange(&g_pending_foreign, 1) == 0)
                    gm_log("Watcher: foreign change detected");
            }
            if (!fni->NextEntryOffset) break;
            p += fni->NextEntryOffset;
        }
    }
    CloseHandle(ov.hEvent);
    // hDir is NOT closed here — project_watcher_stop() owns it after the join.
    gm_log("Watcher: thread exited");
    return 0;
}

void project_watcher_stop()
{
    g_watching = false;
    if (g_watch_wake) SetEvent(g_watch_wake);
    // Cancel any pending directory read so the thread's wait completes now
    // (harmless no-op when nothing is pending).
    if (g_watch_dir) CancelIoEx((HANDLE)g_watch_dir, NULL);
    if (g_watch_thread)
    {
        // Unbounded join is safe: every blocking wait in the thread is released
        // by the wake event / CancelIoEx above, and the notify loop is bounded
        // (64KB buffer), so the thread always makes progress towards exit.
        DWORD w = WaitForSingleObject(g_watch_thread, INFINITE);
        if (w != WAIT_OBJECT_0)
            gm_log("Watcher: join FAILED err=%u", GetLastError());
        CloseHandle(g_watch_thread);
        g_watch_thread = NULL;
    }
    if (g_watch_dir)
    {
        CloseHandle((HANDLE)g_watch_dir);
        g_watch_dir = NULL;
    }
    InterlockedExchange(&g_pending_foreign, 0);
    gm_log("Watcher: stopped");
}

void project_watcher_start(const std::wstring& path)
{
    // Lazy-create the main-thread timer window here (first start). Called on the
    // main thread during a project load/save — never from DllMain, so creating a
    // window is safe (no loader lock).
    project_watcher_ensure_timer_window();
    project_watcher_stop();
    if (!g_watch_wake)
        g_watch_wake = CreateEventW(NULL, TRUE, FALSE, NULL);
    ResetEvent(g_watch_wake);
    InterlockedExchange(&g_pending_foreign, 0);
    // Safe to mutate: stop() guarantees the previous thread has fully exited.
    g_watch_path = path;
    g_save_end_ft = now_ft(); // everything we load/read predates now → not foreign
    g_watching = true;
    g_watch_thread = CreateThread(NULL, 0, watch_thread, NULL, 0, NULL);
    gm_log("Watcher: start requested for '%S'", path.c_str());
}

bool project_watcher_is_running()
{
    return g_watching;
}

void project_watcher_ensure_timer_window(); // defined below (lazy, main thread)

// (The old safety gate — "main window foreground + no editor form open" — was
// replaced by the merge_flow model: non-editor modals defer the tick, editor
// windows are closed through merge_flow_close_editors after one prompt, and
// everything else runs regardless of focus. See merge_flow.h.)

// ==== Reload ====
// GM80_LoadRecentProject (RVA 0x19B860) with the current project path: it checks
// the path, shows the progress form, runs InitializeProject, then our hook at
// 0x59B91B routes .gm80 → gm80_load_project, then reloads action libraries.
// Our load hook re-starts the watcher (project_watcher_start) after a successful
// load, so no explicit re-arm is needed here.
void project_watcher_reload_project()
{
    project_watcher_stop();
    project_watcher_mark_saved();
    uint8_t* b = (uint8_t*)GetModuleHandle(NULL);
    if (!b) return;
    char** pp = (char**)(b + 0x1EA27C);
    if (!pp || !*pp)
    {
        gm_log("Watcher: reload aborted, no project path");
        return;
    }
    char* path = *pp;
    uint32_t fn = (uint32_t)b + 0x19B860; // GM80_LoadRecentProject
    uint32_t pathVal = (uint32_t)path;
    // Preserve the resource tree's expanded folders across the reload — GM 8.0
    // persists no tree state, so capture the current expansion into
    // tree_state.yyd now; load_resource_tree restores it after the reload.
    if (!g_watch_path.empty())
        gm80_capture_tree_state(b, g_watch_path);
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
HWND gm80_prompt_owner()
{
    HWND main = FindWindowW(L"TMainForm", NULL);
    if (!main) main = GetForegroundWindow();
    return main;
}

// ==== Flow state (main thread only; g_flow_active also blocks re-entrant
// ticks while our dialogs / the merge tool pump messages) ====
static bool g_flow_active = false;
static bool g_close_flow = false; // closing editors, waiting for modal unwind
static int g_close_modal_result = 1; // 1 = mrOk (apply) / 2 = mrCancel (discard)

// The watcher watches g_watch_path (a .gm80 project folder). If the current
// project (GM80_ProjectPath, 0x1EA27C — the metadata FILE inside that folder) no
// longer resolves to the same folder, the project changed (e.g. File > New) and
// a stale watch must not reload the old one.
static bool watcher_path_current()
{
    uint8_t* b = (uint8_t*)GetModuleHandle(NULL);
    if (!b) return false;
    char** pp = (char**)(b + 0x1EA27C);
    if (!pp || !*pp) return false; // no current project → not our .gm80
    std::string proj(pp[0]);
    if (proj.size() < 6) return false;
    if (_stricmp(proj.c_str() + proj.size() - 5, ".gm80") != 0) return false;
    size_t slash = proj.find_last_of("\\/");
    std::wstring wdir;
    {
        // proj is CP_ACP (GBK on Chinese systems). A per-char char→wchar_t
        // assign SIGN-EXTENDS bytes ≥ 0x80 (0xC4 → 0xFFC4), so a Chinese
        // project path never matched the real wide watch dir and the watcher
        // silently stopped. Convert through CP_ACP like the load path does.
        size_t dlen = (slash != std::string::npos) ? slash : proj.size();
        int wl = MultiByteToWideChar(CP_ACP, 0, proj.c_str(), (int)dlen, NULL, 0);
        if (wl > 0)
        {
            wdir.resize(wl);
            MultiByteToWideChar(CP_ACP, 0, proj.c_str(), (int)dlen, &wdir[0], wl);
        }
    }
    if (wdir.empty()) return false;
    return _wcsicmp(wdir.c_str(), g_watch_path.c_str()) == 0;
}

void project_watcher_tick()
{
    if (!g_pending_foreign) return;
    if (g_flow_active) return; // re-entrant tick while our UI pumps messages
    if (!g_watching)
    {
        InterlockedExchange(&g_pending_foreign, 0);
        return;
    }
    // The project changed under us (File > New / switched project) → stop watching.
    if (!watcher_path_current())
    {
        project_watcher_stop();
        return;
    }
    // A modal that is not a resource editor (message box, file dialog,
    // preferences…) — defer politely; the pending flag stays set.
    if (merge_flow_non_editor_modal_open()) return;

    // Claim the event from here on.
    g_flow_active = true;
    InterlockedExchange(&g_pending_foreign, 0);

    // Editor windows open → ask once how to treat their unapplied content.
    if (!g_close_flow && merge_flow_count_editor_windows() > 0)
    {
        int r = MessageBoxW(gm80_prompt_owner(),
            L"Project files have been modified outside Game Maker and the "
            L"project must be reloaded.\r\n"
            L"Resource editor windows are open.\r\n\r\n"
            L"Yes = APPLY the changes in those windows and continue\r\n"
            L"No = DISCARD the unapplied changes in those windows and continue\r\n"
            L"Cancel = keep editing for now (you will be asked again on save)",
            L"Game Maker 8.0", MB_YESNOCANCEL | MB_ICONQUESTION | MB_SETFOREGROUND);
        if (r == IDCANCEL)
        {
            gm_log("Watcher: user cancelled — keeping IDE state");
            g_flow_active = false;
            return; // pending stays cleared; the save-side hook still guards
        }
        g_close_modal_result = (r == IDYES) ? 1 : 2; // mrOk / mrCancel
        g_close_flow = true;
        merge_flow_close_editors(g_close_modal_result);
        g_flow_active = false;
        return; // modal loops unwind over the next message cycles
    }
    if (g_close_flow)
    {
        if (merge_flow_count_editor_windows() > 0)
        {
            // Keep closing (stacked modals unwind one message-loop at a time).
            merge_flow_close_editors(g_close_modal_result);
            g_flow_active = false;
            return;
        }
        g_close_flow = false;
    }

    merge_flow_run(g_watch_path);
    g_flow_active = false;
}

// ==== Hidden timer window (main-thread polling, self-contained) ====
// A message-only window with a 1s WM_TIMER. The thread's message pump
// (Application.Run → DispatchMessage) delivers WM_TIMER to it, so project_watcher_tick
// runs on the main thread even while GM idles. No GM window is touched.
static const wchar_t* kWatcherWndClass = L"GMSave.Watcher";
static HWND g_timer_wnd = NULL;
static const UINT kTimerId = 1;

static LRESULT CALLBACK watcher_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_TIMER && wp == kTimerId)
    {
        project_watcher_tick();
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

void project_watcher_ensure_timer_window()
{
    if (g_timer_wnd) return;
    HINSTANCE inst = (HINSTANCE)GetModuleHandle(NULL);
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = watcher_wndproc;
    wc.hInstance = inst;
    wc.lpszClassName = kWatcherWndClass;
    RegisterClassExW(&wc); // harmless if already registered
    g_timer_wnd = CreateWindowExW(
        0, kWatcherWndClass, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, inst, NULL);
    if (g_timer_wnd)
    {
        SetTimer(g_timer_wnd, kTimerId, 1000, NULL);
        gm_log("Watcher: timer window created");
    }
    else
    {
        gm_log("Watcher: timer window create FAILED err=%u", GetLastError());
    }
}
