// UI language for user-facing message boxes: follow the OS UI locale
// (Chinese system → Chinese copy, everything else → English). GMSaveMerge
// makes the same decision from navigator.language. Resolved once, cached.
#pragma once
#include <windows.h>

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
