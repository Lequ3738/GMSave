// Plugin-wide logging. Compiled OUT of Release builds: in Release every call
// becomes a no-op and its arguments are not evaluated, so the plugin carries
// zero logging cost. In Debug builds each call appends one line to
// %TEMP%\GMSave.log.
#pragma once
#include <cstdarg>

#ifdef _DEBUG
void gm_log(const char* fmt, ...);
#else
#define gm_log(...) ((void)0)
#endif
