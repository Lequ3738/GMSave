// UI language for user-facing message boxes: follow the OS UI locale
// (Chinese system → Chinese copy, everything else → English). GMSaveMerge
// makes the same decision from navigator.language. Resolved once, cached.
#pragma once
#include <windows.h>
#include <string>

inline bool ui_lang_chinese()
{
    static const bool zh =
        PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_CHINESE;
    return zh;
}

inline const wchar_t* tr(const wchar_t* en, const wchar_t* zh)
{
    return ui_lang_chinese() ? zh : en;
}

// ANSI (CP_ACP / GBK) text — asset names, file names — → wide for
// user-facing wide-char message boxes. Byte-copy fallback keeps something
// readable when the conversion fails.
inline std::wstring ansi_to_wide(const std::string& s)
{
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), NULL, 0);
    if (n <= 0) return std::wstring(s.begin(), s.end());
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}
