// Shared log implementation (see gm_log.h). gm_log is compiled only in Debug
// builds (in Release it is a no-op macro, so nothing references it); gm_perf
// and gm_perf_ms are always compiled — the perf log is the Release-visible
// window into load/save stage timing.
#include "pch.h"
#include "gm_log.h"

#ifdef _DEBUG
void gm_log(const char* fmt, ...)
{
    char path[MAX_PATH], buf[1024];
    GetEnvironmentVariableA("TEMP", path, sizeof(path));
    strcat_s(path, "\\GMSave.log");
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    FILE* f = fopen(path, "a");
    if (f)
    {
        fprintf(f, "%s\n", buf);
        fclose(f);
    }
}
#endif

double gm_perf_ms()
{
    static LARGE_INTEGER freq = [] {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        return f;
    }();
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1000.0 / (double)freq.QuadPart;
}

void gm_perf(const char* fmt, ...)
{
    char path[MAX_PATH], buf[512];
    GetEnvironmentVariableA("TEMP", path, sizeof(path));
    strcat_s(path, "\\GMSave.perf.log");
    // First write of the process truncates: the file describes the session
    // that is running now, not every session since install.
    static bool first = true;
    FILE* f = fopen(path, first ? "w" : "a");
    first = false;
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(f, "%9.1f %s\n", gm_perf_ms(), buf);
    fclose(f);
}
