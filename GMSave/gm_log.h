// Plugin-wide logging. gm_log, gm_perf and the GmPerfSpan timer are compiled
// OUT of Release builds: in Release every call becomes a no-op and its
// arguments are not evaluated, and GmPerfSpan is an empty struct the compiler
// eliminates — the plugin carries zero logging/timing cost. In Debug builds:
//   gm_log      appends one line to %TEMP%\GMSave.log
//   gm_perf     appends one line to %TEMP%\GMSave.perf.log (truncated at the
//               first write of a process, so the file holds the current
//               session only) — load/save/merge stage timing; re-enable a
//               Release build of these only while actually measuring.
#pragma once
#include <cstdarg>

#ifdef _DEBUG
void gm_log(const char* fmt, ...);

// QPC milliseconds since an arbitrary origin (process lifetime is enough —
// only deltas between gm_perf lines are meaningful).
double gm_perf_ms();

// Always-compiled perf log. Single line per call, %TEMP%\GMSave.perf.log.
void gm_perf(const char* fmt, ...);

// Times its own scope and logs "<name> <elapsed>ms" on destruction. Declare
// inside the block to be timed; nested spans log inner-first.
struct GmPerfSpan
{
    const char* name;
    double t0;
    explicit GmPerfSpan(const char* n) : name(n), t0(gm_perf_ms()) {}
    ~GmPerfSpan() { gm_perf("%s %.1fms", name, gm_perf_ms() - t0); }
    GmPerfSpan(const GmPerfSpan&) = delete;
    GmPerfSpan& operator=(const GmPerfSpan&) = delete;
};
#else
#define gm_log(...) ((void)0)
#define gm_perf(...) ((void)0)
struct GmPerfSpan
{
    explicit GmPerfSpan(const char*) {}
};
#endif
