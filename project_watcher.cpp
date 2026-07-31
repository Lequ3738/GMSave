// File watcher for .gm80 projects
#include "pch.h"
#include "project_watcher.h"

static HANDLE g_watch_thread = NULL;
static volatile bool g_watching = false;
static std::wstring g_watch_path;

static DWORD WINAPI watch_thread(LPVOID) {
    HANDLE hDir = CreateFileW(g_watch_path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL);
    if (hDir == INVALID_HANDLE_VALUE) return 1;

    uint8_t buf[4096];
    OVERLAPPED ov = {};
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    while (g_watching) {
        DWORD bytes;
        if (ReadDirectoryChangesW(hDir, buf, sizeof(buf), TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytes, &ov, NULL)) {
            WaitForSingleObject(ov.hEvent, 1000);
            // TODO: Detect changed files, reload into IDE
        }
    }
    CloseHandle(ov.hEvent);
    CloseHandle(hDir);
    return 0;
}

void project_watcher_start(const std::wstring& path) {
    project_watcher_stop();
    g_watch_path = path;
    g_watching = true;
    g_watch_thread = CreateThread(NULL, 0, watch_thread, NULL, 0, NULL);
}

void project_watcher_stop() {
    g_watching = false;
    if (g_watch_thread) {
        WaitForSingleObject(g_watch_thread, 2000);
        CloseHandle(g_watch_thread);
        g_watch_thread = NULL;
    }
}

bool project_watcher_is_running() {
    return g_watching;
}
