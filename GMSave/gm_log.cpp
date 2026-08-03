// Shared log implementation (see gm_log.h). Compiled only in Debug builds;
// in Release gm_log is a no-op macro, so this TU is empty.
#include "pch.h"
#include "gm_log.h"

#ifdef _DEBUG
void gm_log(const char* fmt, ...) {
    char path[MAX_PATH], buf[1024];
    GetEnvironmentVariableA("TEMP", path, sizeof(path));
    strcat_s(path, "\\GMSave.log");
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    FILE* f = fopen(path, "a");
    if (f) { fprintf(f, "%s\n", buf); fclose(f); }
}
#endif
