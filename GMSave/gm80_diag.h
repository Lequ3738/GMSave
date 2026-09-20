// User-facing diagnostics collected during a save/load, presented once in a
// single modal message box afterwards. Tolerant by design: the operation always
// succeeds — these are warnings, not errors. Identical messages are
// de-duplicated so a broken reference used in many places yields one line.
// Messages are wide-char so copy can be localized via tr(); asset names arrive
// as ANSI bytes and go through ansi_to_wide() at the call site.
#pragma once

void gm80_diag_reset();
void gm80_diag_add(const wchar_t* fmt, ...);
bool gm80_diag_any();
void gm80_diag_show(); // title fixed inside ("Game Maker 8.0")
