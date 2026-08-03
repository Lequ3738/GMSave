// User-facing diagnostics collected during a save/load, presented once in a
// single modal MessageBox afterwards. Tolerant by design: the operation always
// succeeds — these are warnings, not errors. Identical messages are
// de-duplicated so a broken reference used in many places yields one line.
#pragma once

void gm80_diag_reset();
void gm80_diag_add(const char* fmt, ...);
bool gm80_diag_any();
void gm80_diag_show(const char* title);
