// IDE hooks for GM 8.0 — verified injection points from IDA analysis
#include "pch.h"
#include "ide_hooks.h"
#include "gm80_addresses.h"
#include "delphi.h"
#include "gm80_save.h"
#include "gmk_format.h"
#include "gm80_load.h"
#include <cstdarg>
#include <ctime>
#include <filesystem>
#include <exception>
#include <mutex>
#include <string>
#include <commdlg.h>
#include <winnt.h>

// Verified injection points from IDA:
//   Save: 0x5DAE36 in sub_5DAD60 — CALL sub_59BA38 (dialog save) → save_thunk
//   Save: 0x5DAD19 in sub_5DACB8 — CALL sub_59BA38 (direct save) → save_thunk
//   Load: 0x5D484A in sub_5D47BC — CALL sub_5D453C (load/open project) → load_thunk
//   Load: 0x5D496E in sub_5D489C — CALL sub_5D453C (import/build)
//   CmpTxt: 0x5DACEC in sub_5DACB8 — CALL CompareText(ext, ".gmk") → gmk_or_gm80_thunk

// Extension check strategy (mirrors gm82save's gm81_or_gm82):
//   1. Hook CompareText call at 0x5DACEC → test BOTH ".gmk" and ".gm80"
//   2. Hook BOTH save call sites (dialog + direct) → intercept .gm80 saves
//   This makes Ctrl+S directly save .gm80 without opening the dialog.

static void* g_gm_base = NULL;
static uint8_t g_orig_save_call[5] = {0};       // bytes at 0x5DAE36 (dialog save)
static uint8_t g_orig_direct_save[5] = {0};     // bytes at 0x5DAD19 (direct save)
static uint8_t g_orig_load_call[5] = {0};       // bytes at 0x5D484A
static uint8_t g_orig_cmptext_call[5] = {0};    // bytes at 0x5DACEC
static uint8_t g_orig_sub_5D453C[6] = {0};      // first 6 bytes of sub_5D453C
static void*  g_trampoline_5D453C = nullptr;    // trampoline: orig 6 bytes + JMP back

// CompareText hook: makes GM 8.0 recognize .gm80 as valid project extension
// Installed by patching the CALL CompareText at 0x5DACEC in sub_5DACB8.
// Strategy mirrors gm82save's gm81_or_gm82_inj: our hook tests BOTH ".gmk" AND ".gm80".

// Delphi AnsiStrings for compatibility — CompareText reads [ptr-4] for length
// Layout: [refcount=-1:4][length:4:4][data:N+padding]
#pragma pack(push, 1)
static const struct {
    int32_t refcount;
    uint32_t length;
    char data[8];
} s_gm80_delphi_str = { -1, 5, ".gm80" };
static const struct {
    int32_t refcount;
    uint32_t length;
    char data[8];
} s_gmk_delphi_str = { -1, 4, ".gmk" };
#pragma pack(pop)
static const char* const s_gm80_ext_ptr = s_gm80_delphi_str.data;
static const char* const s_gmk_ext_ptr = s_gmk_delphi_str.data;

// Variables referenced by naked asm — MUST be declared before the thunks that reference them
void* g_gm_base_ptr = NULL;
static uint32_t g_save_outer_addr = ADDR_SAVE_OUTER;
static uint32_t g_load_addr = ADDR_LOAD_PROJECT;

// Forward decl for debug logging (defined later in this file)
static void dbg_log(const char* fmt, ...);
static int  __stdcall check_and_do_gm80_load();

// CompareText hook — tests BOTH ".gm80" (our own constant; the binary string
// patch is disabled) and ".gmk" (backward compatibility with old .gmk
// projects). NOTE: this is what keeps Ctrl+S on a .gm80 project on the
// direct-save path (sub_5DACB8 compares the extension at 0x5DACEC and falls
// back to the save dialog when it doesn't match).
static int __stdcall gmk_or_gm80_hook(void* ext_data) {
    int result;
    // Test ".gm80" first
    __asm {
        mov eax, ext_data
        mov edx, dword ptr [s_gm80_ext_ptr]
        mov ecx, dword ptr [g_gm_base_ptr]
        add ecx, ADDR_COMPARETEXT
        call ecx
        mov result, eax
    }
    if (result == 0) return 0;
    // Test ".gmk" for backward compatibility
    __asm {
        mov eax, ext_data
        mov edx, dword ptr [s_gmk_ext_ptr]
        mov ecx, dword ptr [g_gm_base_ptr]
        add ecx, ADDR_COMPARETEXT
        call ecx
        mov result, eax
    }
    return result;
}

// Naked thunk — replaces "call sub_40A0C8" at 0x5DACEC
// On entry: EAX = extension string data ptr, EDX = ".gmk" string data ptr
// On exit:  EAX = 0 if extension matches ".gmk" or ".gm80"
__declspec(naked) static void gmk_or_gm80_thunk() {
    __asm {
        pushad                      // save ALL registers (EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI)
        push eax                    // push ext_data as __stdcall argument
        call gmk_or_gm80_hook       // returns result in EAX, cleans up arg with ret 4
        mov [esp+28], eax           // store result in saved EAX slot (offset 28 in pushad layout)
        popad                       // restore all registers, EAX now has our result
        ret
    }
}

// ==== Thunk for save interception ====
// Replaces the CALL to sub_59BA38 at 0x5DAE36.
// When GM's save dialog handler calls the save function, we intercept:
//   - If project path ends with .gm80: do multi-file save
//   - Otherwise: call original save function
// ==== Runtime debug logging ====
static void dbg_log(const char* fmt, ...) {
    char path[MAX_PATH], buf[1024];
    GetEnvironmentVariableA("TEMP", path, sizeof(path));
    strcat_s(path, "\\GMSave.log");
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    FILE* f = fopen(path, "a");
    if (f) { fprintf(f, "%s\n", buf); fclose(f); }
}

// Read a Delphi AnsiString from a pointer-to-pointer
// Returns "" if invalid
static std::string read_delphi_str(void** ppStr) {
    if (!ppStr || IsBadReadPtr(ppStr, 4)) return "(null ptr)";
    void* p = *ppStr;
    if (!p || IsBadReadPtr(p, 8)) return "(null str)";
    uint32_t* hdr = (uint32_t*)p;
    int32_t refcnt = (int32_t)hdr[0];
    uint32_t len = hdr[1];
    if (len > 4096 || refcnt < -10 || refcnt > 1000000)
        return "(invalid str header)";
    const char* data = (const char*)(hdr + 2);
    return std::string(data, len);
}

// Called on every save attempt. Returns 1 if we handled it.
// Flag set by check_* before original save runs
static bool g_is_gm80_save = false;
static std::wstring g_gm80_save_path;

static int __stdcall check_and_do_gm80_save() {
    g_is_gm80_save = false;
    uint8_t* base = (uint8_t*)g_gm_base;

    char** ppProjPath = (char**)(base + 0x1EA27C);
    if (!ppProjPath || !*ppProjPath) return 0;
    char* projPath = *ppProjPath;
    size_t len = strlen(projPath);
    if (len < 6) return 0;

    bool is_gm80 = (_stricmp(projPath + len - 5, ".gm80") == 0);
    if (!is_gm80 && len > 9)
        is_gm80 = (_strnicmp(projPath + len - 9, ".gm80.gmk", 9) == 0);

    if (!is_gm80) return 0;

    // Strip .gmk suffix so title bar shows ".gm80" natively
    // Must update BOTH the null terminator AND the Delphi AnsiString length field
    if (_strnicmp(projPath + len - 9, ".gm80.gmk", 9) == 0) {
        len -= 4;
        projPath[len] = '\0';                     // C string null terminator
        *(int32_t*)(projPath - 4) = (int32_t)len; // Delphi AnsiString length field
    }

    int cch = MultiByteToWideChar(CP_ACP, 0, projPath, (int)len, NULL, 0);
    if (cch > 0) {
        g_gm80_save_path.resize(cch);
        MultiByteToWideChar(CP_ACP, 0, projPath, (int)len, &g_gm80_save_path[0], cch);
    }
    // GM80_ProjectPath carries the metadata FILE path (…\folder.gm80\name.gm80)
    // since that's GM's project-file semantics, but the save target is the
    // project FOLDER — normalize (…\X.gm80\Y.gm80 → …\X.gm80) so the save
    // doesn't silently write into the metadata file treated as a directory.
    {
        fs::path sp(g_gm80_save_path);
        std::wstring fn = sp.filename().wstring();
        std::wstring pn = sp.parent_path().filename().wstring();
        if (fn.size() > 5 && fn.compare(fn.size() - 5, 5, L".gm80") == 0 &&
            pn.size() > 5 && pn.compare(pn.size() - 5, 5, L".gm80") == 0) {
            g_gm80_save_path = sp.parent_path().wstring();
            dbg_log("Save: normalized save path to folder '%S'",
                    g_gm80_save_path.c_str());
        }
    }
    g_is_gm80_save = true;
    return 1; // no .gmk save needed (we'll delete .gm80.gmk ourselves)
}

// Delete .gm80.gmk left by GM's save dialog filter
static void __stdcall cleanup_gm80_gmk() {
    if (!g_is_gm80_save) return;
    std::wstring gmkPath = g_gm80_save_path + L".gmk";
    if (GetFileAttributesW(gmkPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        DeleteFileW(gmkPath.c_str());
        g_is_gm80_save = false;
    }
}

// Read a Delphi AnsiString from a global.
// Delphi AnsiString layout: [refcount:4][length:4][data:len][null]
// The global holds a pointer to the DATA (NOT the header).
// We verify by checking if p-4 contains a valid length.
static std::string read_global_str(uint32_t off) {
    uint8_t* base = (uint8_t*)g_gm_base;
    char** pp = (char**)(base + off);
    if (!pp || IsBadReadPtr(pp, 4) || !*pp) return "";
    char* data = *pp;
    // data points to string chars; length is at data-4
    if (IsBadReadPtr(data - 4, 8)) return "";
    uint32_t len = *(uint32_t*)(data - 4);
    if (len > 2000) return ""; // invalid length, probably not a Delphi string
    if (IsBadReadPtr(data, len)) return "";
    return std::string(data, len);
}

// Read Delphi AnsiString from object field — direct memory access (no IsBadReadPtr)
static std::string obj_str(void* obj, int off) {
    if (!obj || (uintptr_t)obj < 0x10000) return "";
    char** pp = (char**)((uint8_t*)obj + off);
    char* data = *pp;
    if (!data) return "";
    uint32_t len = (uint32_t)*(int32_t*)(data - 4);
    if (len == 0) return "";
    if (len > 200000) return std::string(data); // C string fallback
    return std::string(data, len);
}

// Read names from a separate parallel name array — direct memory access
static void read_name_array(uint8_t* base, uint32_t name_off, uint32_t cnt_off,
                             std::vector<std::string>& out) {
    uint32_t* names = *(uint32_t**)(base + name_off);
    uint32_t  cnt   = *(uint32_t*)(base + cnt_off);
    if (!names || !cnt || cnt > 50000) return;
    out.reserve(cnt);
    for (uint32_t i = 0; i < cnt; i++) {
        char* p = (char*)(uintptr_t)names[i];
        if (!p || (uintptr_t)p < 0x10000) { out.push_back(""); continue; }
        uint32_t len = (uint32_t)*(int32_t*)(p - 4);
        if (len == 0 || len > 200000) { out.push_back(std::string(p)); continue; }
        out.push_back(std::string(p, len));
    }
}

// Populate GMKProject from IDE globals
static void read_ide_project(GMKProject& proj) {
    uint8_t* base = (uint8_t*)g_gm_base;
    proj.game_id = *(uint32_t*)(base + ADDR_GAME_ID);

    // Settings verified from GM80_SaveSettings/LoadSettings disasm (2026-08-02):
    // fullscreen=0x1E93A0(byte), scaling=0x1E93B0(i32), clear_color=0x1E93BC(u32),
    // priority=0x1E93F8(u32), loading_bar=0x1E93FC(u32). Previously all shifted.
    auto u32 = [&](uint32_t off) -> uint32_t { return *(uint32_t*)(base + off); };
    auto u8  = [&](uint32_t off) -> uint32_t { return *(uint8_t*)(base + off); };
    proj.settings.fullscreen         = u8(ADDR_SETTING_FULLSCREEN) != 0;
    proj.settings.interpolate_pixels = u8(ADDR_SETTING_INTERPOLATE) != 0;
    proj.settings.color_depth        = u32(ADDR_SETTING_COLOR_DEPTH);
    proj.settings.resolution         = u32(ADDR_SETTING_RESOLUTION);
    proj.settings.frequency          = u32(ADDR_SETTING_FREQUENCY);
    proj.settings.scaling            = (int32_t)u32(ADDR_SETTING_SCALING);
    proj.settings.clear_color        = u32(ADDR_SETTING_CLEAR_COLOR);
    proj.settings.loading_bar        = u32(ADDR_SETTING_LOADING_BAR);
    proj.settings.priority           = u32(ADDR_SETTING_PRIORITY);

    // Read resource counts
    proj.trigger_count = *(uint32_t*)(base + 0x1E92EC);
    proj.sound_count   = *(uint32_t*)(base + 0x1E9288);
    proj.sprite_count  = *(uint32_t*)(base + 0x1E911C);
    proj.bg_count      = *(uint32_t*)(base + 0x1E90A8);
    proj.path_count    = *(uint32_t*)(base + 0x1E92BC);
    proj.script_count  = *(uint32_t*)(base + 0x1E92E4);
    proj.font_count    = *(uint32_t*)(base + 0x1E92D0);
    proj.tl_count      = *(uint32_t*)(base + 0x1E9310);
    proj.object_count  = *(uint32_t*)(base + 0x1E9364);
    proj.room_count    = *(uint32_t*)(base + 0x1E92A4);

    // Read resource names and populate vectors
    // Resource names from verified parallel name arrays (all at obj_array+8)
    read_name_array(base, 0x1E9110, 0x1E911C, proj.sprite_names);
    read_name_array(base, 0x1E92DC, 0x1E92E4, proj.script_names);
    read_name_array(base, 0x1E935C, 0x1E9364, proj.object_names);
    read_name_array(base, 0x1E929C, 0x1E92A4, proj.room_names);
    read_name_array(base, 0x1E92B4, 0x1E92BC, proj.path_names);
    read_name_array(base, 0x1E909C, 0x1E90A8, proj.bg_names);
    // Triggers: names in object at +4 (different from other resources)
    read_name_array(base, 0x1E92C8, 0x1E92D0, proj.font_names);
    read_name_array(base, 0x1E9308, 0x1E9310, proj.tl_names); // triggers use object array as name source
    // Triggers: names are inside objects at +4
    {
        uint32_t* arr = *(uint32_t**)(base + 0x1E92E8);
        uint32_t cnt  = *(uint32_t*)(base + 0x1E92EC);
        if (arr && cnt && cnt < 500) {
            for (uint32_t i = 0; i < cnt; i++) {
                void* obj = (void*)(uintptr_t)arr[i];
                std::string name = obj ? obj_str(obj, 4) : "";
                proj.trigger_names.push_back(name);
            }
        }
    }

    // Script sources from object+4
    {
        uint32_t* arr = *(uint32_t**)(base + 0x1E92D4);
        uint32_t cnt  = *(uint32_t*)(base + 0x1E92E4);
        if (arr && cnt && cnt < 50000) {
            proj.script_sources.reserve(cnt);
            for (uint32_t i = 0; i < cnt; i++) {
                void* obj = (void*)(uintptr_t)arr[i];
                std::string src = obj ? obj_str(obj, 4) : "";
                proj.script_sources.push_back(src);
            }
        }
    }

    {
        uint32_t* tarr = *(uint32_t**)(base + 0x1E92E8);
        uint32_t tcnt = *(uint32_t*)(base + 0x1E92EC);
        if (tarr && tcnt && tcnt < 500) {
            proj.trigger_conditions.reserve(tcnt);
            proj.trigger_constants.reserve(tcnt);
            for (uint32_t i = 0; i < tcnt; i++) {
                void* o = (void*)(uintptr_t)tarr[i];
                if (o) {
                    proj.trigger_conditions.push_back(obj_str(o, 8));
                    proj.trigger_constants.push_back(obj_str(o, 12));
                } else {
                    proj.trigger_conditions.push_back("");
                    proj.trigger_constants.push_back("");
                }
            }
        }
    }
    proj.object_count  = *(uint32_t*)(base + 0x1E9364); // 126
    proj.room_count    = *(uint32_t*)(base + 0x1E92A4); // 16

    dbg_log(" IDE resources: trig=%u snd=%u sp=%u bg=%u pth=%u sc=%u fn=%u tl=%u obj=%u rm=%u",
        proj.trigger_count, proj.sound_count, proj.sprite_count, proj.bg_count,
        proj.path_count, proj.script_count, proj.font_count, proj.tl_count,
        proj.object_count, proj.room_count);

    // Dump first object of each type to discover field layouts
}

// Clear the 16 "updated/dirty" 1-byte bool flags that sub_59BA38 clears after save.
// Also strips ' *' from the GM IDE window title since the caption isn't auto-refreshed.
static void clear_updated_flags() {
    uint8_t* base = (uint8_t*)g_gm_base;
    static const uint32_t flag_rvas[] = ADDR_DIRTY_FLAGS;
    for (int i = 0; i < 16; i++) {
        *(uint8_t*)(base + flag_rvas[i]) = 0;
    }

    // GM doesn't auto-refresh the title bar after flags are cleared.
    // Find the IDE window and strip ' *' from its caption.
    HWND hWnd = GetForegroundWindow();
    if (hWnd) {
        char caption[512];
        int len = GetWindowTextA(hWnd, caption, sizeof(caption));
        if (len > 2) {
            // Look for " * - Game Maker" pattern and remove " *"
            char* star = strstr(caption, " * - Game Maker");
            if (star) {
                memmove(star, star + 2, strlen(star + 2) + 1);
                SetWindowTextA(hWnd, caption);
            }
        }
    }
}

static void gm80_progress_show();
static void gm80_progress_step(int pos);
static void gm80_progress_close();

static void __stdcall do_gm80_save_if_needed() {
    dbg_log("Save: writing .gm80 to '%S'", g_gm80_save_path.c_str());
    gm80_progress_show();
    gm80_progress_step(25);
    try {
        if (!gm80_save_to_path(g_gm_base, g_gm80_save_path))
            dbg_log("Save: ERROR");
        else {
            dbg_log("Save: .gm80 complete");
            clear_updated_flags();
        }
    } catch (std::exception& e) {
        dbg_log("Save: EXCEPTION: %s", e.what());
    } catch (...) {
        dbg_log("Save: UNKNOWN EXCEPTION");
    }
    gm80_progress_step(100);
    gm80_progress_close();
}
// .gmk save prep: GM's save inner writes via RELATIVE paths (it relies on
// the open dialog having set the cwd to the project folder — verified: the
// save failure surfaces as a Delphi EFCreateError caught by Outer's SEH →
// "cannot create file"). Set the cwd to the project file's folder before
// handing control back to GM, and log the context.
static void __stdcall log_gmk_save_ctx() {
    char cwd[MAX_PATH];
    GetCurrentDirectoryA(sizeof(cwd), cwd);
    uint8_t* base = (uint8_t*)GetModuleHandle(NULL);
    char** pp = (char**)(base + 0x1EA27C);
    dbg_log("GMK save ctx: cwd='%s' projPath='%s'",
            cwd, (pp && *pp && !IsBadStringPtrA(*pp, 1024)) ? *pp : "(null/bad)");
    if (pp && *pp && !IsBadStringPtrA(*pp, 1024)) {
        char dir[MAX_PATH];
        strcpy_s(dir, *pp);
        char* slash = strrchr(dir, '\\');
        if (slash) {
            *slash = '\0';
            if (SetCurrentDirectoryA(dir))
                dbg_log("GMK save ctx: cwd set to '%s'", dir);
        }
        DWORD attrs = GetFileAttributesA(*pp);
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            dbg_log("GMK save ctx: target file attrs FAIL err=%u", GetLastError());
        } else {
            dbg_log("GMK save ctx: target attrs=0x%X readonly=%d",
                    attrs, (attrs & FILE_ATTRIBUTE_READONLY) ? 1 : 0);
        }
    }
}

// Progress form helpers (GM 8.0): sub_599620 shows the form + sets title +
// resets the bar; sub_5996B8 steps it; sub_5996D8 closes it.
static void gm80_progress_show() {
    uint8_t* base = (uint8_t*)GetModuleHandle(NULL);
    uint32_t fn = (uint32_t)base + 0x199620;
    uint32_t title = (uint32_t)base + 0x19BCD0;  // GM's save title string var
    __asm {
        mov eax, title
        call fn
    }
}
static void gm80_progress_step(int pos) {
    // Position is passed in EAX (PBM_SETPOS via sub_49C530).
    if (pos < 0) pos = 0;
    if (pos > 100) pos = 100;
    uint8_t* base = (uint8_t*)GetModuleHandle(NULL);
    uint32_t fn = (uint32_t)base + 0x1996B8;
    __asm {
        mov eax, pos
        call fn
    }
}
static void gm80_progress_close() {
    uint8_t* base = (uint8_t*)GetModuleHandle(NULL);
    uint32_t fn = (uint32_t)base + 0x1996D8;
    __asm { call fn }
}

// gm82save-style .gmk save: create the stream the same way Outer does
// (ClassCreate on off_4EA854), run GM's save Inner on it, then dump the
// stream memory to the project file. Bypasses Outer entirely — its SEH
// turns exceptions from the post-Inner backup-file handling (which gets a
// NULL path argument on our call path) into the "cannot create file" dialog.
// Verified: Inner alone returns 1 with a full 0xACC54-byte stream.
static void __stdcall do_gmk_save_direct() {
    uint8_t* base = (uint8_t*)GetModuleHandle(NULL);
    if (!base) return;
    char** pp = (char**)(base + 0x1EA27C);
    if (!pp || !*pp || IsBadStringPtrA(*pp, 1024)) {
        dbg_log("GMK direct save: no project path");
        return;
    }
    const char* gmkPath = *pp;

    gm80_progress_show();               // "saving" progress form
    uint32_t cls = *(uint32_t*)(base + 0xEA854);
    if (cls < 0x400000) cls = *(uint32_t*)(base + 0xEA8A0);
    void* stream = nullptr;
    __asm {
        mov dl, 1
        mov eax, cls
        mov ecx, 0x404560               // @ClassCreate
        call ecx
        mov stream, eax
    }
    if (!stream) {
        dbg_log("GMK direct save: stream create failed");
        gm80_progress_close();
        return;
    }
    gm80_progress_step(30);
    int ok = 0;
    __try {
        __asm {
            mov eax, stream
            mov ecx, 0x59B620           // GM80_SaveProject_Inner
            call ecx
            mov ok, eax
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dbg_log("GMK direct save: Inner exception code=0x%X",
                GetExceptionCode());
        gm80_progress_close();
        return;
    }
    if (!ok) {
        dbg_log("GMK direct save: Inner returned 0");
        gm80_progress_close();
        return;
    }
    // Stream layout (verified by probing for the .gmk magic 0x12D591):
    // +0 vtable, +4 FMemory (data pointer), +8 FSize.
    uint8_t* mem = *(uint8_t**)((uint8_t*)stream + 4);    // FMemory
    uint32_t size = *(uint32_t*)((uint8_t*)stream + 8);   // FSize
    dbg_log("GMK direct save: stream mem=0x%X size=%u", (uint32_t)mem, size);
    if (!mem || size == 0 || size > 64 * 1024 * 1024) {
        dbg_log("GMK direct save: bad stream content");
        gm80_progress_close();
        return;
    }
    gm80_progress_step(60);
    FILE* f = fopen(gmkPath, "wb");
    if (!f) {
        dbg_log("GMK direct save: fopen fail err=%u", GetLastError());
        gm80_progress_close();
        return;
    }
    size_t w = fwrite(mem, 1, size, f);
    fclose(f);
    gm80_progress_step(90);
    gm80_progress_close();
    dbg_log("GMK direct save: wrote %u bytes to '%s'", (uint32_t)w, gmkPath);
    if (w == size) {
        clear_updated_flags();
    }
}

__declspec(naked) static void save_thunk() {
    __asm {
        pushad
        call check_and_do_gm80_save     // returns 1 if .gm80, 0 if normal
        mov dword ptr [esp+28], eax     // stash result in pushad's EAX slot
        popad
        test eax, eax
        jnz gm80_save

        // Normal .gmk: gm82save-style direct save (bypasses Outer's SEH trap)
        pushad
        call log_gmk_save_ctx
        call do_gmk_save_direct
        popad
        jmp done

    gm80_save:
        pushad
        call do_gm80_save_if_needed      // .gm80 multi-file save
        popad
        pushad
        call cleanup_gm80_gmk             // delete .gm80.gmk if present
        popad
        xor eax, eax                      // return 0 (success) to GM

    done:
        ret
    }
}

// Static to pass file path from naked thunk to C function
static const char* g_load_file_path = nullptr;
static void* g_lrp_trampoline = nullptr;
static void* g_msg_trampoline = nullptr;          // trampoline for ShowMessage hook
static const char* g_msg_text = nullptr;          // EAX passed to ShowMessage

// Log function for ShowMessage hook — callerAddr is the ORIGINAL return address
static void __stdcall msg_log(void* callerAddr) {
    uint8_t* base = (uint8_t*)GetModuleHandle(NULL);
    uint32_t callerRva = base ? (uint32_t)((uint8_t*)callerAddr - base) : 0;

    // Read message string (Delphi AnsiString)
    const char* msg = g_msg_text;
    char buf[256] = {0};
    if (msg && !IsBadStringPtrA(msg, 512)) {
        uint32_t len = *(uint32_t*)(msg - 4);
        if (len < 250) { memcpy(buf, msg, len); buf[len] = 0; }
    }
    dbg_log("ShowMessage called: text='%s' callerRVA=0x%X (callerAddr=0x%p)",
        buf, callerRva, callerAddr);
}

// Thunk for ShowMessage hook — logs message + original caller RVA
__declspec(naked) static void msg_hook_thunk() {
    __asm {
        push eax                         // Save message ptr
        mov g_msg_text, eax              // Static for log function
        push ecx
        push edx
        push dword ptr [esp+12]          // Original return addr (at esp+12: after eax,ecx,edx pushes)
        call msg_log                     // msg_log(original_caller_addr)
        pop edx                          // Clean up
        pop ecx
        pop eax                          // Restore EAX (message string)
        jmp dword ptr [g_msg_trampoline] // Execute original ShowMessage
    }
}

// Called at 0x59B91B (replaces call sub_59B28C).
// At this point: InitializeProject has run, Delphi MM is ready.
// EAX = TStream containing loaded file data.
// Must return AL=1 (success) or AL=0 (failure).
__declspec(naked) static void parse_gmk_or_gm80_thunk() {
    __asm {
        push eax                        // Save stream
        // Read project path from GM80_ProjectPath global
        push ebx
        mov ebx, dword ptr [g_gm_base_ptr]
        mov eax, dword ptr [ebx + 0x1EA27C]  // GM80_ProjectPath
        pop ebx
        mov g_load_file_path, eax
        // Check if it's .gm80
        pushad
        call check_and_do_gm80_load     // Returns 1 if .gm80 & loaded OK
        mov [esp+28], eax               // Store in pushad EAX slot
        popad
        pop ecx                         // Clean up saved stream
        cmp eax, 0
        je call_original
        // .gm80 handled successfully: AL=1
        mov al, 1
        ret

    call_original:
        // Not .gm80: call original sub_59B28C(EAX=stream).
        // EAX was clobbered by check_and_do_gm80_load; the saved stream is in
        // ECX (popped above) — restore it into EAX before the call.
        mov eax, ecx                    // EAX = saved stream (original call arg)
        mov ecx, dword ptr [g_gm_base_ptr]
        add ecx, 0x19B28C               // sub_59B28C
        call ecx
        ret                             // AL = original result
    }
}

// OLD: SAFE entry hook for GM80_LoadRecentProject — replaced by call-site hook above
__declspec(naked) static void lrp_safe_thunk() {
    __asm {
        cmp eax, 0x10000                // Reject low addresses (invalid ptrs)
        jb pass_through
        cmp eax, 0x80000000             // Reject kernel addresses
        ja pass_through
        push eax
        mov g_load_file_path, eax
        pushad
        call check_and_do_gm80_load     // Safe: checks IsBadStringPtrA first
        popad
        pop eax                         // EAX = result (0=not handled, 1=handled)
        cmp eax, 0
        je pass_through
        // Handled: g_load_file_path has temp .gmk, update EAX and jump to trampoline
        mov eax, dword ptr [g_load_file_path]
        jmp dword ptr [g_lrp_trampoline]
    pass_through:
        jmp dword ptr [g_lrp_trampoline]  // Same trampoline, original EAX preserved
    }
}

// Call-site hook for "call GM80_LoadRecentProject" at 0x5DAB0C (drag-drop path)
// On entry: EAX = project path. Returns AL = load success (0/1)
// If .gm80 detected: generates temp .gmk, updates path global, calls original loader
__declspec(naked) static void lrp_call_thunk() {
    __asm {
        cmp eax, 0
        je call_original
        push eax
        mov g_load_file_path, eax
        pushad
        call check_and_do_gm80_load     // Returns 1 if .gm80 handled (temp .gmk created)
        mov [esp+28], eax               // Store result in pushad EAX slot
        popad
        pop eax                         // EAX = original path
        cmp eax, 0                      // Was it handled?
        je call_original

        // .gm80 handled: update EAX to temp .gmk path, call original, then restore
        push ebx
        push esi
        mov esi, eax                    // save original path
        mov eax, dword ptr [g_load_file_path]  // EAX = temp .gmk path
        // Update GM80_ProjectPath global to temp .gmk
        mov ebx, dword ptr [g_gm_base_ptr]
        mov dword ptr [ebx + 0x1EA27C], eax
        // Call original GM80_LoadRecentProject(temp .gmk path)
        add ebx, 0x19B860              // GM80_LoadRecentProject RVA
        call ebx                        // Load the temp .gmk!
        // Save result, restore original .gm80 path
        push eax                        // save AL result
        mov eax, esi                    // restore original .gm80 path
        mov ebx, dword ptr [g_gm_base_ptr]
        mov dword ptr [ebx + 0x1EA27C], eax
        pop eax                         // restore AL result
        pop esi
        pop ebx
        ret

    call_original:
        // Not .gm80: call original GM80_LoadRecentProject(EAX) directly
        push ecx
        mov ecx, dword ptr [g_gm_base_ptr]
        add ecx, 0x19B860
        call ecx
        pop ecx
        ret
    }
}

// OLD: Dedicated thunk for GM80_LoadRecentProject (0x59B860) — kept for reference
__declspec(naked) static void lrp_thunk() {
    __asm {
        push eax                        // Save original path
        mov g_load_file_path, eax       // Pass to C function
        push ecx
        push edx
        pushad
        call check_and_do_gm80_load     // Will detect .gm80 and create temp .gmk
        popad
        pop edx
        pop ecx
        pop eax                         // Original path back in EAX (will be overwritten if .gm80)
        // If check_and_do_gm80_load handled it, use the updated path
        push eax
        mov eax, dword ptr [g_load_file_path]  // Get possibly-updated file path
        mov [esp], eax                  // Store on stack
        pop eax                         // EAX = updated path
        // Jump to trampoline which runs orig function with updated EAX
        jmp dword ptr [g_lrp_trampoline]
    }
}

// Check if the file path (passed in EAX to sub_5D453C) is a .gm80 project
static int __stdcall check_and_do_gm80_load() {
    const char* projPath = g_load_file_path;
    if (!projPath) return 0;
    // Validate pointer before using it (prevent crash on garbage ptr during startup)
    if (IsBadStringPtrA(projPath, 512)) return 0;
    size_t len = strlen(projPath);
    if (len < 6) { dbg_log("check_gm80: len=%u path='%s' -> 0", (uint32_t)len, projPath); return 0; }
    bool is_gm80 = (_stricmp(projPath + len - 5, ".gm80") == 0);
    if (!is_gm80) { dbg_log("check_gm80: not .gm80 path='%s' -> 0", projPath); return 0; }

    dbg_log("Load: .gm80 detected '%s'", projPath);

    int wlen = MultiByteToWideChar(CP_ACP, 0, projPath, (int)len, NULL, 0);
    if (wlen <= 0) return 0;
    std::wstring wpath(wlen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, projPath, (int)len, &wpath[0], wlen);

    // The path points to the .gm80 metadata FILE. Use parent directory.
    fs::path loadPath(wpath);
    if (fs::is_regular_file(loadPath)) {
        dbg_log("Load: path is file, using parent dir");
        loadPath = loadPath.parent_path();
    }
    std::wstring dirPath = loadPath.wstring();

    GMKProject proj;
    if (!gm80_load_from_path(proj, dirPath)) {
        dbg_log("Load: failed to parse .gm80");
        return 0;
    }

    // Direct Delphi object creation via gm80_load_project
    // (Delphi MM is ready — InitializeProject already ran at this point)
    if (gm80_load_project(g_gm_base, dirPath)) {
        dbg_log("Load: .gm80 direct Delphi objects — SUCCESS");
        return 1;
    }

    dbg_log("Load: gm80_load_project failed");
    return 0;
}

// ==== Function-level hook for sub_5D453C (load project) ====
// Hooks the FUNCTION ENTRY itself, catching ALL call paths to sub_5D453C
// (both open-project and compile). For .gm80 projects it routes to our
// loader; otherwise the trampoline runs the original function.
// Trampoline: executes original first 6 bytes, then JMPs back to sub_5D453C+6.
__declspec(naked) static void load_func_hook() {
    __asm {
        // On entry: [esp]=ret_addr, EAX=path, EDX=arg1, ECX=arg2
        push eax                        // Save file path
        mov g_load_file_path, eax       // Static for C function
        push ecx                        // Save arg2
        push edx                        // Save arg1
        pushad
        call check_and_do_gm80_load     // Returns 1 if handled
        mov [esp+28], eax               // Store in pushad EAX slot
        popad                           // EAX=result; EDX/ECX restored
        pop edx                         // EDX = original arg1
        pop ecx                         // ECX = original arg2
        // [esp] = original EAX (file path), [esp+4] = ret_addr
        test eax, eax                   // Handled?
        jnz handled

        // Not handled: jump to the trampoline with the original registers.
        pop eax                         // Discard original file path
        mov eax, dword ptr [g_load_file_path]  // EAX = path (a1)
        // EAX=path, EDX=arg1, ECX=arg2, [esp]=ret_addr — perfect for trampoline
        jmp dword ptr [g_trampoline_5D453C]

    handled:
        // [esp] = original EAX, [esp+4] = ret_addr
        pop eax                         // Discard saved file path
        ret                             // Return directly to sub_5D453C's caller
    }
}

// Compile-time project path override. sub_5DBEAC's run-game flow loads the
// project path with `mov eax, GM80_ProjectPath` at 0x5DBF14 (compile, feeds
// the exe) and 0x5DBF2B (game command-line arg, from which the running game
// derives working_directory — verified: double-clicking the exe with no
// argument makes working_directory = exe folder). Both call sites are
// patched to `call compile_path_eax`, which returns the .gm80 FOLDER for
// .gm80 projects (…\X.gm80 instead of the metadata file …\X.gm80\Y.gm80)
// so the game resolves the project root. 0x1EA27C itself is never modified
// — IDE semantics (history, open, save) stay on the metadata-file path.
// The embed flow reads the path as a Delphi AnsiString (length at [ptr-4]),
// so the returned pointer MUST be a real Delphi string — a bare C buffer
// makes the embed read garbage and the game falls back to the exe folder.
static const char* __stdcall get_compile_folder() {
    uint8_t* base = (uint8_t*)GetModuleHandle(NULL);
    static struct { int32_t refcount; uint32_t length; char data[MAX_PATH + 8]; } s_str = { -1, 0, "" };
    if (!base) return s_str.data;
    char** pp = (char**)(base + 0x1EA27C);
    if (!pp || !*pp || IsBadStringPtrA(*pp, 1024)) return s_str.data;
    strcpy_s(s_str.data, *pp);
    char* slash = strrchr(s_str.data, '\\');
    if (slash) {
        *slash = '\0';
        const char* leaf = strrchr(s_str.data, '\\');
        leaf = leaf ? leaf + 1 : s_str.data;
        if (!(strlen(leaf) > 5 && _stricmp(leaf + strlen(leaf) - 5, ".gm80") == 0)) {
            // not a .gm80 folder — keep the original path (.gmk etc.)
            strcpy_s(s_str.data, *pp);
        }
    }
    s_str.length = (uint32_t)strlen(s_str.data);
    dbg_log("compile eax: project path -> '%s'", s_str.data);
    return s_str.data;
}

__declspec(naked) static void compile_path_eax() {
    __asm {
        pushad
        call get_compile_folder
        mov dword ptr [esp+28], eax
        popad
        ret
    }
}

// g_gm_base_ptr and address variables are declared at the top of this file

// ==== Save/Open dialog filter hooks ====
// GM's project dialogs only offer "*.gmk". Patch the IAT entries for
// GetSaveFileNameA/GetOpenFileNameA so project dialogs also offer .gm80
// (mirrors gm82save's dialog adaptation; GM 8.1 offers .gm81/.gm82).
static BOOL (WINAPI* g_real_GetSaveFileNameA)(LPOPENFILENAMEA) = nullptr;
static BOOL (WINAPI* g_real_GetOpenFileNameA)(LPOPENFILENAMEA) = nullptr;

// OPENFILENAME.lpstrFilter is NUL-separated pairs, double-NUL terminated
// ("Name\0*.ext\0Name2\0*.ext2\0\0") — NOT Delphi's '|' format.
static const char k_gm80_filter[] =
    "GameMaker 8.0 files (*.gmk)\0*.gmk\0"
    "GameMaker 8.0 project (*.gm80)\0*.gm80\0"
    "All files (*.*)\0*.*\0\0";

static BOOL WINAPI gm80_get_save_file_name(LPOPENFILENAMEA ofn) {
    if (ofn && ofn->lpstrFilter &&
        strstr(ofn->lpstrFilter, "Game Maker")) {
        ofn->lpstrFilter = k_gm80_filter;
        if (ofn->lpstrDefExt && ofn->lpstrDefExt[0])
            ofn->lpstrDefExt = "gm80";
    }
    return g_real_GetSaveFileNameA(ofn);
}

static BOOL WINAPI gm80_get_open_file_name(LPOPENFILENAMEA ofn) {
    if (ofn && ofn->lpstrFilter &&
        strstr(ofn->lpstrFilter, "Game Maker")) {
        ofn->lpstrFilter = k_gm80_filter;
    }
    return g_real_GetOpenFileNameA(ofn);
}

// Patch the comdlg32 IAT entries in the target image.
static void hook_comdlg32_iat(HMODULE gm_base) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)gm_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint8_t*)gm_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    DWORD impRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impRva) return;
    IMAGE_IMPORT_DESCRIPTOR* imp =
        (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)gm_base + impRva);
    for (; imp->Name; imp++) {
        const char* dll = (const char*)((uint8_t*)gm_base + imp->Name);
        if (_stricmp(dll, "comdlg32.dll") != 0) continue;
        IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((uint8_t*)gm_base + imp->FirstThunk);
        IMAGE_THUNK_DATA* orig = (IMAGE_THUNK_DATA*)((uint8_t*)gm_base + imp->OriginalFirstThunk);
        for (; thunk->u1.AddressOfData; thunk++, orig++) {
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;
            IMAGE_IMPORT_BY_NAME* ibn =
                (IMAGE_IMPORT_BY_NAME*)((uint8_t*)gm_base + orig->u1.AddressOfData);
            if (strcmp(ibn->Name, "GetSaveFileNameA") == 0 && !g_real_GetSaveFileNameA) {
                g_real_GetSaveFileNameA = (BOOL(WINAPI*)(LPOPENFILENAMEA))thunk->u1.Function;
                DWORD oldp;
                if (VirtualProtect(&thunk->u1.Function, 4, PAGE_READWRITE, &oldp)) {
                    thunk->u1.Function = (uintptr_t)gm80_get_save_file_name;
                    VirtualProtect(&thunk->u1.Function, 4, oldp, &oldp);
                    dbg_log("IAT: GetSaveFileNameA hooked");
                }
            } else if (strcmp(ibn->Name, "GetOpenFileNameA") == 0 && !g_real_GetOpenFileNameA) {
                g_real_GetOpenFileNameA = (BOOL(WINAPI*)(LPOPENFILENAMEA))thunk->u1.Function;
                DWORD oldp;
                if (VirtualProtect(&thunk->u1.Function, 4, PAGE_READWRITE, &oldp)) {
                    thunk->u1.Function = (uintptr_t)gm80_get_open_file_name;
                    VirtualProtect(&thunk->u1.Function, 4, oldp, &oldp);
                    dbg_log("IAT: GetOpenFileNameA hooked");
                }
            }
        }
    }
}

// ==== Hook installation ====
bool ide_hooks_install(HMODULE gm_base) {
    g_gm_base = gm_base;
    g_gm_base_ptr = gm_base;
    uint8_t* base = (uint8_t*)gm_base;
    hook_comdlg32_iat(gm_base);

    // Save hook 1: patch CALL at 0x5DAE36 (dialog save path in sub_5DAD60)
    void* save_call_addr = base + 0x1DAE36;
    memcpy(g_orig_save_call, save_call_addr, 5);
    patch_call(save_call_addr, (void*)save_thunk);

    // Save hook 2: patch CALL at 0x5DAD19 (direct save path in sub_5DACB8)
    // This is the path taken when CompareText(ext, ".gmk") returns 0 (Ctrl+S)
    void* direct_save_addr = base + ADDR_DIRECT_SAVE_CALL;
    memcpy(g_orig_direct_save, direct_save_addr, 5);
    patch_call(direct_save_addr, (void*)save_thunk);

    // NOTE: Diagnostic test hooks removed — they were never triggered and some
    // caused startup crashes. See GMSave_load_analysis.md for findings.
    // The actual load function is GM80_LoadRecentProject (RVA 0x19B860).
    // Hook TBD via call-site patches at 0x5DAB0C, 0x5D9A19 etc.

    // NOTE: the 4 ".gmk"→".gm80" string patches are DISABLED — they broke
    // .gmk saving (GM's save path reads these strings and misbehaves with
    // ".gm80" content). Their functions are fully covered by other hooks:
    //   0x1DAD58 direct-save check  → CompareText hook (gmk_or_gm80_hook)
    //   0x1DAE90 save dialog filter → IAT hook (GetSaveFileNameA)
    //   0x1DA590 open dialog check  → IAT hook (GetOpenFileNameA)
    //   0x1DACB0 drag-drop check    → thunk (check_and_do_gm80_load)

    // CompareText hooks: patch ALL extension-check call sites
    // Each site now tests ".gm80" (patched) AND ".gmk" (our DLL) for backward compat
    static const uint32_t cmptext_sites[] = {
        ADDR_CMPTEXT_SAVE_HOOK,   // 0x1DACEC — save check (sub_5DACB8)
        0x1DA2CC,                  // 0x5DA2CC — open dialog ".gm6" check
        0x1DA2DD,                  // 0x5DA2DD — open dialog ".gmk" check
        0x1DAB52,                  // 0x5DAB52 — drag-drop ".gmk" check
    };
    for (auto rva : cmptext_sites) {
        void* call_addr = base + rva;
        patch_call(call_addr, (void*)gmk_or_gm80_thunk);
    }
    dbg_log("CompareText hooks installed at %u sites", (uint32_t)(sizeof(cmptext_sites)/sizeof(cmptext_sites[0])));

    // ==== Hook sub_5D453C entry (load project AND compile core) ====
    // sub_5D453C is both the open-project loader and the compile core
    // (sub_5D489C calls it with EAX=.exe output, EDX=project path which gets
    // embedded into the exe). load_func_hook fixes EDX to the .gm80 FOLDER
    // for .gm80 projects so the running game's working_directory
    // (ExtractFilePath of the embedded path) resolves to the project root.
    {
        void* fn453C = base + 0x1D453C;
        memcpy(g_orig_sub_5D453C, fn453C, 6);
        g_trampoline_5D453C = VirtualAlloc(NULL, 32, MEM_COMMIT | MEM_RESERVE,
                                           PAGE_EXECUTE_READWRITE);
        if (g_trampoline_5D453C) {
            uint8_t* t = (uint8_t*)g_trampoline_5D453C;
            memcpy(t, g_orig_sub_5D453C, 6);
            t[6] = 0xE9;
            int32_t rel = (int32_t)((uint8_t*)fn453C + 6 - (t + 11));
            memcpy(t + 7, &rel, 4);
        }
        patch_jmp(fn453C, (void*)load_func_hook);
        FlushInstructionCache(GetCurrentProcess(), fn453C, 6);
        dbg_log("Hooked sub_5D453C entry (load + compile)");
    }

    // ==== Patch `mov eax, GM80_ProjectPath` at 0x5DBF14 / 0x5DBF2B ====
    // (run-game flow, sub_5DBEAC). Replaced with `call compile_path_eax` —
    // EAX gets the .gm80 FOLDER for .gm80 projects instead of the metadata
    // FILE path. 0x5DBF14 feeds the compile (embedded into the exe);
    // 0x5DBF2B feeds the game's command-line argument, from which the game
    // derives working_directory (verified: double-clicking the exe with no
    // argument makes working_directory = exe folder). 0x1EA27C itself keeps
    // the metadata-file path for IDE semantics.
    {
        void* dest = base + 0x1DBF14;
        patch_call(dest, (void*)compile_path_eax);
        dbg_log("Patched 0x5DBF14 (compile project path -> folder)");
    }
    {
        void* dest = base + 0x1DBF2B;
        patch_call(dest, (void*)compile_path_eax);
        dbg_log("Patched 0x5DBF2B (run command-line project path -> folder)");
    }

    // NOTE: hooking sub_521D84 (game launch) crashed Softwrap.dll (GM 8.0's
    // DRM DLL watches process creation) — do NOT inline-hook that function.
    // The .gm80 game cwd is instead set during compile (see
    // fix_compile_project_path), which is on our existing hook path.

    // ==== Hook sub_59B28C call at 0x59B91B (INSIDE GM80_LoadRecentProject) ====
    // At this point: InitializeProject has run, MM is ready, stream loaded.
    // If .gm80: parse from directory files, create objects via Delphi ctor.
    // If not .gm80: call original sub_59B28C(stream).
    {
        void* callSite = base + 0x19B91B;
        patch_call(callSite, (void*)parse_gmk_or_gm80_thunk);
        dbg_log("Hooked sub_59B28C call at 0x19B91B (post-InitializeProject, MM ready)");
    }

    // ==== Message hook on sub_4518B0 (ShowMessage/MessageDlg) ====
    {
        void* fnMsg = base + 0x518B0;
        static uint8_t msgOrig[6] = {0};
        memcpy(msgOrig, fnMsg, 6);
        g_msg_trampoline = VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (g_msg_trampoline) {
            uint8_t* t = (uint8_t*)g_msg_trampoline;
            memcpy(t, msgOrig, 6);
            t[6] = 0xE9;
            int32_t rel = (int32_t)((uint8_t*)fnMsg + 6 - (t + 11));
            memcpy(t + 7, &rel, 4);
        }
        patch_jmp(fnMsg, (void*)msg_hook_thunk);
        FlushInstructionCache(GetCurrentProcess(), fnMsg, 6);
        dbg_log("Hooked ShowMessage (sub_4518B0) to trace 'Not a GameMaker file' origin");
    }

    dbg_log("Working hooks: save x2 + strings x4 + CompareText x4 — GM should start OK");

    return true;
}

void ide_hooks_uninstall() {
    uint8_t* base = (uint8_t*)g_gm_base;
    if (base) {
        patch_bytes(base + 0x1DAE36, g_orig_save_call, 5);
        patch_bytes(base + ADDR_DIRECT_SAVE_CALL, g_orig_direct_save, 5);
        dbg_log("Hooks uninstalled");
    }
}
