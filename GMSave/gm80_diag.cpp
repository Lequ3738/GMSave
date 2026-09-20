#include "pch.h"
#include "gm80_diag.h"
#include "i18n.h"
#include "project_watcher.h" // gm80_prompt_owner
#include <set>
#include <string>
#include <vector>
#include <cstdarg>
#include <cwchar>

static std::vector<std::wstring> g_diag;
static std::set<std::wstring> g_diag_seen;

void gm80_diag_reset()
{
    g_diag.clear();
    g_diag_seen.clear();
}

void gm80_diag_add(const wchar_t* fmt, ...)
{
    wchar_t buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, 512, fmt, ap);
    va_end(ap);
    buf[511] = 0;
    if (g_diag_seen.insert(buf).second) g_diag.push_back(buf);
}

bool gm80_diag_any()
{
    return !g_diag.empty();
}

void gm80_diag_show()
{
    if (g_diag.empty()) return;
    const size_t kMaxShown = 15;
    std::wstring msg = tr(L"Issues found during this operation:",
                          L"本次操作中发现以下问题：");
    for (size_t i = 0; i < g_diag.size() && i < kMaxShown; i++)
        msg += L"\r\n" + g_diag[i];
    if (g_diag.size() > kMaxShown)
    {
        wchar_t more[64];
        _snwprintf(more, 64,
            tr(L"\r\n... and %zu more", L"\r\n……另有 %zu 条未列出"),
            g_diag.size() - kMaxShown);
        more[63] = 0;
        msg += more;
    }
    MessageBoxW(gm80_prompt_owner(), msg.c_str(), L"Game Maker 8.0",
        MB_OK | MB_ICONWARNING);
}
