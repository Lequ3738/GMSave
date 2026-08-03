#include "pch.h"
#include "gm80_diag.h"
#include "project_watcher.h" // gm80_prompt_owner
#include <set>
#include <string>
#include <vector>
#include <cstdarg>
#include <cstdio>

static std::vector<std::string> g_diag;
static std::set<std::string>    g_diag_seen;

void gm80_diag_reset() {
    g_diag.clear();
    g_diag_seen.clear();
}

void gm80_diag_add(const char* fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    if (g_diag_seen.insert(buf).second)
        g_diag.push_back(buf);
}

bool gm80_diag_any() {
    return !g_diag.empty();
}

void gm80_diag_show(const char* title) {
    if (g_diag.empty()) return;
    const size_t kMaxShown = 15;
    std::string msg;
    for (size_t i = 0; i < g_diag.size() && i < kMaxShown; i++)
        msg += "\r\n" + g_diag[i];
    if (g_diag.size() > kMaxShown)
        msg += "\r\n\r\n... and " + std::to_string(g_diag.size() - kMaxShown) + " more";
    MessageBoxA(gm80_prompt_owner(), msg.c_str(), title, MB_OK | MB_ICONWARNING);
}
