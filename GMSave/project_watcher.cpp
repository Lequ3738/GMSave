// File watcher for .gm80 projects — IDE-style external-change handling.
// Modeled on gm82save's regular/project_watcher.rs, adapted to GM 8.0:
//   - A background thread watches the project directory recursively.
//   - Foreign changes (file mtime > SAVE_END) set a pending flag.
//   - A hidden-window timer (1s) on the main thread polls the flag and acts:
//       * user has NO unsaved changes  -> silent reload (GM80_LoadRecentProject)
//       * user HAS unsaved changes     -> Yes/No prompt (conflict)
//   - Safety gates: the flow only starts while the IDE is the foreground
//     process (an external editor keeps itself focused for the whole duration
//     of an edit session, so this waits out mid-edit batches), and merge_flow
//     further defers while non-editor modals or standalone code editors are
//     open, so the reload never runs while UI references resources that
//     InitializeProject is about to free.
#include "pch.h"
#include "project_watcher.h"
#include "gm80_addresses.h"
#include "gm80_load.h"
#include "gm80_save.h"
#include "merge_flow.h"
#include "dead_asset_check.h"
#include "gm_log.h"
#include "i18n.h"
#include "mm_audit.h"
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

void project_watcher_rearm_pending()
{
    InterlockedExchange(&g_pending_foreign, 1);
    gm_log("Watcher: pending re-armed — flow will re-run");
}

void project_watcher_start(const std::wstring& path)
{
    // Lazy-create the main-thread timer window here (first start). Called on the
    // main thread during a project load/save — never from DllMain, so creating a
    // window is safe (no loader lock).
    project_watcher_ensure_timer_window();
    // Main-menu entry for the dead-asset scan (idempotent; the main form
    // exists by now, which is why this can't run from DLL attach).
    dead_asset_check_ensure_menu();
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
    // Unattended reload: keep load warnings (missing extension packages) in the
    // log — a modal box here would stall the silent flow. A manual open reports
    // them.
    gm80_load_set_quiet(true);
    __asm {
        mov eax, pathVal
        xor ebx, ebx
        xor edi, edi
        xor esi, esi
        mov ecx, fn
        call ecx
    }
    gm80_load_set_quiet(false);
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

// True when the foreground window belongs to this process (the IDE itself).
// The "user is back in Game Maker" gate: while an external editor is the
// foreground app its saves are still arriving — acting then would reload a
// half-finished edit batch. Any IDE-owned window counts (main form, a GM
// dialog, an editor), so the gate only blocks while the user is genuinely
// working somewhere else.
static bool ide_foreground()
{
    HWND fg = GetForegroundWindow();
    if (!fg) return false;
    DWORD pid = 0;
    GetWindowThreadProcessId(fg, &pid);
    return pid == GetCurrentProcessId();
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
    // Act only while the IDE is frontmost. The pending flag survives this gate
    // untouched — the flow runs on the first tick after the user switches back
    // to Game Maker.
    {
        static bool was_fg = true;
        bool fg = ide_foreground();
        if (fg != was_fg)
        {
            gm_log("Watcher: %s", fg ? "IDE foreground — resuming flow"
                                     : "IDE not foreground — deferring");
            was_fg = fg;
        }
        if (!fg) return;
    }
    // A modal that is not a resource editor (message box, file dialog,
    // preferences…) — defer politely; the pending flag stays set.
    if (merge_flow_non_editor_modal_open()) return;
    // Standalone code editors are invisible to both the modal stack and the
    // forms arrays (raw Win32 blocking, no resource array slot), but a reload
    // with one open corrupts its state — defer the same way.
    if (merge_flow_code_editor_open())
    {
        gm_log("Watcher: standalone code editor open — deferring");
        return;
    }
    // A wedged Delphi MM pool lock (see mm_audit.h) makes the next MM op spin
    // forever INSIDE GM's own CAS loop — the merge flow (staging save + reload)
    // is by far the heaviest MM user, so starting it now is what turns a latent
    // wedge into the permanent "加载游戏数据 未响应". Defer; the pending flag
    // stays set and the flow resumes once the audit reads clean.
    {
        mm_audit::StuckPool sp = {};
        bool wedged = mm_audit::any_stuck_sustained(&sp);
        if (!wedged) wedged = mm_audit::last_nonzero(&sp); // tick 兜底（池信息同源）
        if (wedged)
        {
            gm_log("Watcher: MM pool lock wedged (idx=%u size=%u value=0x%02X) — deferring merge flow",
                sp.index, sp.block_size, sp.value);
            return;
        }
    }

    // Claim the event and run the whole merge flow. Analysis, the editor gate
    // (which fires only once a reload is imminent), the merge tool and the
    // reload itself all live in merge_flow_run; it pumps messages itself
    // where needed (editor modal unwinds, the tool wait), so the old
    // cross-tick close-flow state machine is gone (2026-09-20).
    g_flow_active = true;
    InterlockedExchange(&g_pending_foreign, 0);
    merge_flow_run(g_watch_path, false);
    g_flow_active = false;
}

// ==== Force-sync entry for external agents (unattended) ====
// The tick only acts while the IDE is the foreground process: its model is
// "the user alt-tabs back to Game Maker, then we catch up". An AI coding loop
// driven by the gm8 MCP server has no such moment — it edits the project
// while the IDE sits in the background and wants the very same merge flow on
// demand, right after its edit batch is complete and before triggering run.
//
// Protocol (see GMEnhance mcp/server.mjs for the caller side): the agent
// RegisterWindowMessageW's "GMSave.ForceSync" (same string → same message id
// system-wide), finds this process's hidden "GMSave.Watcher" window by pid,
// PostMessages the id in wParam, then polls a small named file mapping
//
//     Local\GMSave.SyncStatus.<pid>   (16 bytes: magic 'GMS1', reqId, status, detail)
//
// until reqId matches its own (written last, as the commit marker). The
// mapping doubles as the capability probe: no mapping ⇒ deployed GMSave
// predates force-sync. Status codes:
//   1 reloaded       — merge flow ran and the project was reloaded from disk
//   2 nothing-to-do  — disk matches the base snapshot
//   3 deferred       — retry later; detail: 1 flow already active,
//                      2 non-editor modal dialog open, 3 standalone code
//                      editor open, 4 resource editor stuck in ShowModal
//   4 needs-manual   — refused WITHOUT running anything or popping any UI;
//                      a human must handle the IDE. detail 2 = unsaved
//                      in-IDE edits present (the editor-gate prompts would
//                      fire). detail 3 = Delphi MM pool lock wedged (an
//                      internal heap lock was never released; restart the
//                      IDE — %TEMP%\GMSave_MMBroken.txt carries the record).
//                      detail 1 is unused (modal editors defer as 3:4
//                      instead — closing one may clear the block on its own).
//   5 not-watching   — no .gm80 project watched, or it changed under us
//   6 failed         — reserved (flow ran but did not reload)
//
// Unattended safety: the flow is allowed to proceed only when it is provably
// silent. Zero dirty flags + no modal editor ⇒ IDE memory == base snapshot ⇒
// every difference is remote-only ⇒ the fast path auto-applies with no
// prompt and no conflict tool, guaranteed. Any other state refuses with a
// status instead of surfacing a dialog nobody will answer.
#pragma pack(push, 4)
struct GmSyncResultBlock
{
    uint32_t magic;
    volatile uint32_t reqId;  // written LAST: its match is the completion signal
    volatile uint32_t status;
    volatile uint32_t detail;
};
#pragma pack(pop)
static const uint32_t kSyncMagic = 0x47534D31; // 'GMS1'
static HANDLE g_sync_map = NULL;
static GmSyncResultBlock* g_sync_view = NULL;
static UINT g_msgForceSync = 0;

static void force_sync_report(uint32_t reqId, uint32_t status, uint32_t detail)
{
    if (g_sync_view)
    {
        g_sync_view->status = status;
        g_sync_view->detail = detail;
        InterlockedExchange((volatile LONG*)&g_sync_view->reqId, (LONG)reqId);
    }
    gm_log("ForceSync: req=%u -> status=%u detail=%u", reqId, status, detail);
}

// Runs on the main thread — the timer window's wndproc dispatches it, the
// same thread the WM_TIMER tick and merge_flow_run itself live on.
static void project_watcher_force_sync(uint32_t reqId)
{
    if (!g_watching || !watcher_path_current())
    {
        force_sync_report(reqId, 5, 0);
        return;
    }
    if (g_flow_active)
    {
        force_sync_report(reqId, 3, 1);
        return;
    }
    if (merge_flow_non_editor_modal_open())
    {
        force_sync_report(reqId, 3, 2);
        return;
    }
    if (merge_flow_code_editor_open())
    {
        force_sync_report(reqId, 3, 3);
        return;
    }
    if (merge_flow_any_modal_editor_open())
    {
        force_sync_report(reqId, 3, 4);
        return;
    }
    // Delphi MM pool lock already wedged (mm_audit.h): running the flow would
    // spin forever inside GM's own CAS loop. Refuse without touching anything.
    {
        mm_audit::StuckPool sp = {};
        bool wedged = mm_audit::any_stuck_sustained(&sp);
        if (!wedged) wedged = mm_audit::last_nonzero(&sp);
        if (wedged)
        {
            gm_log("ForceSync: req=%u refused — MM pool lock wedged (idx=%u size=%u value=0x%02X)",
                reqId, sp.index, sp.block_size, sp.value);
            force_sync_report(reqId, 4, 3);
            return;
        }
    }
    if (merge_flow_global_dirty())
    {
        force_sync_report(reqId, 4, 2);
        return;
    }
    gm_log("ForceSync: req=%u running merge flow on '%S'", reqId, g_watch_path.c_str());
    g_flow_active = true;
    InterlockedExchange(&g_pending_foreign, 0);
    bool ok = merge_flow_run(g_watch_path, false);
    g_flow_active = false;
    force_sync_report(reqId, ok ? 1 : 2, 0);
}

// ==== Hidden timer window (main-thread polling, self-contained) ====
// A message-only window with a 1s WM_TIMER. The thread's message pump
// (Application.Run → DispatchMessage) delivers WM_TIMER to it, so project_watcher_tick
// runs on the main thread even while GM idles. No GM window is touched.
static const wchar_t* kWatcherWndClass = L"GMSave.Watcher";
static HWND g_timer_wnd = NULL;
static const UINT kTimerId = 1;
static const UINT kMenuTimerId = 2; // dead-asset menu injection poll

static LRESULT CALLBACK watcher_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (g_msgForceSync && msg == g_msgForceSync)
    {
        project_watcher_force_sync((uint32_t)wp);
        return 0;
    }
    if (msg == WM_TIMER && wp == kTimerId)
    {
        // Pool-lock health first: read-only, nanoseconds — catches a wedged
        // Delphi MM lock while the IDE is still idle (see mm_audit.h).
        mm_audit::tick(g_flow_active);
        project_watcher_tick();
        return 0;
    }
    if (msg == WM_TIMER && wp == kMenuTimerId)
    {
        // Idempotent; stops itself once the entry is in (or given up + logged).
        if (dead_asset_check_menu_ready()) KillTimer(hwnd, kMenuTimerId);
        else dead_asset_check_ensure_menu();
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

void project_watcher_ensure_timer_window()
{
    if (g_timer_wnd) return;
    // Force-sync channel: registered message id + per-pid named mapping (the
    // agent's capability probe and result block). Created once, on the main
    // thread, together with the window — both live until process exit.
    g_msgForceSync = RegisterWindowMessageW(L"GMSave.ForceSync");
    if (!g_sync_map)
    {
        const std::wstring mapName =
            L"Local\\GMSave.SyncStatus." + std::to_wstring(GetCurrentProcessId());
        g_sync_map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
            0, sizeof(GmSyncResultBlock), mapName.c_str());
        if (g_sync_map)
        {
            g_sync_view = (GmSyncResultBlock*)MapViewOfFile(
                g_sync_map, FILE_MAP_ALL_ACCESS, 0, 0, 0);
            if (g_sync_view)
            {
                g_sync_view->magic = kSyncMagic;
                g_sync_view->reqId = 0;
                g_sync_view->status = 0;
                g_sync_view->detail = 0;
            }
        }
        gm_log("Watcher: sync mapping '%S' %s", mapName.c_str(),
            g_sync_view ? "created" : "FAILED");
    }
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
        SetTimer(g_timer_wnd, kMenuTimerId, 1000, NULL);
        gm_log("Watcher: timer window created");
    }
    else
    {
        gm_log("Watcher: timer window create FAILED err=%u", GetLastError());
    }
}
