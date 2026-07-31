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
static uint8_t g_orig_save_call[5] = {0};      // bytes at 0x5DAE36 (dialog save)
static uint8_t g_orig_direct_save[5] = {0};    // bytes at 0x5DAD19 (direct save)
static uint8_t g_orig_load_call[5] = {0};      // bytes at 0x5D484A
static uint8_t g_orig_cmptext_call[5] = {0};   // bytes at 0x5DACEC

// CompareText hook: makes GM 8.0 recognize .gm80 as valid project extension
// Installed by patching the CALL CompareText at 0x5DACEC in sub_5DACB8.
// Strategy mirrors gm82save's gm81_or_gm82_inj: our hook tests BOTH ".gmk" AND ".gm80".

// Delphi AnsiString for ".gm80" — CompareText reads [ptr-4] for length
// Layout: [refcount=-1:4][length=4:4][data=".gm80":5+padding]
#pragma pack(push, 1)
static const struct {
    int32_t refcount;
    uint32_t length;
    char data[8];
} s_gm80_delphi_str = { -1, 4, ".gm80" };
#pragma pack(pop)
static const char* const s_gm80_ext_ptr = s_gm80_delphi_str.data; // for inline asm

// Variables referenced by naked asm — MUST be declared before the thunks that reference them
void* g_gm_base_ptr = NULL;
static uint32_t g_save_outer_addr = ADDR_SAVE_OUTER;
static uint32_t g_load_addr = ADDR_LOAD_PROJECT;

// Naked thunk — replaces "call sub_40A0C8" at 0x5DACEC
// Tests BOTH ".gmk" and ".gm80" against the project extension.
// On entry: EAX = extension string data ptr, EDX = ".gmk" string data ptr
// Must return 0 in EAX if extension matches either ".gmk" or ".gm80"
__declspec(naked) static void gmk_or_gm80_thunk() {
    __asm {
        // Save extension pointer and test against ".gmk" first
        push ebx
        mov ebx, eax                    // ebx = extension data ptr
        // EAX = ext, EDX = ".gmk" (already set by caller)
        mov ecx, dword ptr [g_gm_base_ptr]
        add ecx, ADDR_COMPARETEXT
        call ecx                        // CompareText(ext, ".gmk")
        test eax, eax
        jz matched                      // .gmk matched → return 0

        // Test against ".gm80" (in our DLL)
        mov eax, ebx                    // restore extension
        mov edx, offset s_gm80_delphi_str
        add edx, 8                      // skip refcount+length to get to data
        mov ecx, dword ptr [g_gm_base_ptr]
        add ecx, ADDR_COMPARETEXT
        call ecx                        // CompareText(ext, ".gm80")

    matched:
        pop ebx
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

// Dump a memory region as hex
static std::string hex_dump(void* addr, size_t len) {
    if (IsBadReadPtr(addr, (UINT)len)) return "(unreadable)";
    std::string r;
    char buf[8];
    unsigned char* p = (unsigned char*)addr;
    for (size_t i = 0; i < len; i++) {
        snprintf(buf, sizeof(buf), "%02X ", p[i]);
        r += buf;
    }
    return r;
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
    if (_strnicmp(projPath + len - 9, ".gm80.gmk", 9) == 0) {
        len -= 4;
        projPath[len] = '\0';
    }

    int cch = MultiByteToWideChar(CP_ACP, 0, projPath, (int)len, NULL, 0);
    if (cch > 0) {
        g_gm80_save_path.resize(cch);
        MultiByteToWideChar(CP_ACP, 0, projPath, (int)len, &g_gm80_save_path[0], cch);
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

    // Settings verified from GM80_SaveSettings disasm (many are bytes, not u32!)
    auto u32 = [&](uint32_t off) -> uint32_t { return *(uint32_t*)(base + off); };
    auto u8  = [&](uint32_t off) -> uint32_t { return *(uint8_t*)(base + off); };
    proj.settings.fullscreen         = u32(0x1E93B0) != 0;
    proj.settings.interpolate_pixels = u8(0x1E93B4) != 0;
    proj.settings.color_depth        = u32(0x1E93BC);
    proj.settings.resolution         = u32(0x1E93C4);
    proj.settings.frequency          = u32(0x1E93C8);
    proj.settings.scaling            = (int32_t)u32(0x1E93CC);
    proj.settings.clear_color        = u8(0x1E93D0);
    proj.settings.loading_bar        = u8(0x1E93D4);
    proj.settings.priority           = u8(0x1E93D8);

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
                if (i < 2) dbg_log(" trigger[%u] obj=0x%p name='%s'", i, obj, name.c_str());
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
                if (i < 2) dbg_log(" script[%u] obj=0x%p src_len=%zu", i, obj, src.size());
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

static void __stdcall do_gm80_save_if_needed() {
    dbg_log("Save: writing .gm80 to '%S'", g_gm80_save_path.c_str());
    try {
        if (!gm80_save_to_path(g_gm_base, g_gm80_save_path))
            dbg_log("Save: ERROR");
        else
            dbg_log("Save: .gm80 complete");
    } catch (std::exception& e) {
        dbg_log("Save: EXCEPTION: %s", e.what());
    } catch (...) {
        dbg_log("Save: UNKNOWN EXCEPTION");
    }
}
static int __stdcall check_and_do_gm80_load() {
    uint8_t* base = (uint8_t*)g_gm_base;
    char** ppProjPath = (char**)(base + 0x1EA27C);
    if (!ppProjPath || !*ppProjPath) return 0;
    char* projPath = *ppProjPath;
    size_t len = strlen(projPath);
    if (len < 6) return 0;
    bool is_gm80 = (_stricmp(projPath + len - 5, ".gm80") == 0);
    if (!is_gm80) return 0;

    dbg_log("Load: .gm80 detected '%s', converting...", projPath);

    // 1. Parse .gm80 directory
    int wlen = MultiByteToWideChar(CP_ACP, 0, projPath, (int)len, NULL, 0);
    if (wlen <= 0) return 0;
    std::wstring wpath(wlen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, projPath, (int)len, &wpath[0], wlen);

    GMKProject proj;
    if (!gm80_load_from_path(proj, wpath)) {
        dbg_log("Load: failed to parse .gm80");
        return 0;
    }

    // 2. Serialize to .gmk binary
    std::vector<uint8_t> gmkData = gmk_serialize(proj);
    if (gmkData.empty()) {
        dbg_log("Load: failed to serialize .gmk");
        return 0;
    }

    // 3. Write to temp file
    char tempPath[MAX_PATH], tempFile[MAX_PATH];
    GetTempPathA(sizeof(tempPath), tempPath);
    GetTempFileNameA(tempPath, "GM8", 0, tempFile);
    // Remove the .tmp and add .gmk
    std::string gmkPath(tempFile);
    gmkPath = gmkPath.substr(0, gmkPath.size() - 4) + ".gmk";

    FILE* f = fopen(gmkPath.c_str(), "wb");
    if (!f) { dbg_log("Load: cannot write temp .gmk"); return 0; }
    fwrite(gmkData.data(), 1, gmkData.size(), f);
    fclose(f);

    dbg_log("Load: temp .gmk written (%zu bytes) → %s", gmkData.size(), gmkPath.c_str());

    // 4. Replace the project path with temp .gmk path
    // Allocate a new C string that lives long enough for GM to use it
    static char g_temp_path_buf[MAX_PATH];
    strcpy_s(g_temp_path_buf, gmkPath.c_str());
    *ppProjPath = g_temp_path_buf;

    // 5. Return 0 — let GM's original loader process the temp .gmk
    return 0;
}

__declspec(naked) static void save_thunk() {
    __asm {
        pushad
        call check_and_do_gm80_save     // returns 1 if .gm80, 0 if normal
        popad
        test eax, eax
        jnz gm80_save

        // Normal .gmk: call original save
        mov ecx, dword ptr [g_gm_base_ptr]
        add ecx, dword ptr [g_save_outer_addr]
        call ecx
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

// ==== Thunk for load interception ====
__declspec(naked) static void load_thunk() {
    __asm {
        pushad                          // save all registers
        call check_and_do_gm80_load     // returns 1 if handled
        test eax, eax
        jnz handled
        popad

        // Call original load function
        mov ecx, dword ptr [g_gm_base_ptr]
        add ecx, dword ptr [g_load_addr]
        call ecx
        ret
handled:
        popad                           // restore registers and return
        ret
    }
}

// g_gm_base_ptr and address variables are declared at the top of this file

// Project path global — stored by GM after save/load dialog
// In Delphi 7, the project path is accessed through TMainForm or a global string.
// We can find it by looking at what sub_59BA38 reads.
// For now, we use a backup approach: read from Delphi's global state.

// TODO: Read project path from Delphi AnsiString global
//   global at base+0x1EA27C (dword_5EA27C) contains path or flag

// ==== Hook installation ====
bool ide_hooks_install(HMODULE gm_base) {
    g_gm_base = gm_base;
    g_gm_base_ptr = gm_base;
    uint8_t* base = (uint8_t*)gm_base;

    // Save hook 1: patch CALL at 0x5DAE36 (dialog save path in sub_5DAD60)
    void* save_call_addr = base + 0x1DAE36;
    memcpy(g_orig_save_call, save_call_addr, 5);
    patch_call(save_call_addr, (void*)save_thunk);

    // Save hook 2: patch CALL at 0x5DAD19 (direct save path in sub_5DACB8)
    // This is the path taken when CompareText(ext, ".gmk") returns 0 (Ctrl+S)
    void* direct_save_addr = base + ADDR_DIRECT_SAVE_CALL;
    memcpy(g_orig_direct_save, direct_save_addr, 5);
    patch_call(direct_save_addr, (void*)save_thunk);

    // Load hook: patch CALL at 0x5D484A
    void* load_call_addr = base + 0x1D484A;
    memcpy(g_orig_load_call, load_call_addr, 5);
    patch_call(load_call_addr, (void*)load_thunk);

    // CompareText hook: patch CALL at 0x5DACEC in sub_5DACB8
    // Makes direct save (Ctrl+S) work for .gm80 projects by also testing ".gm80"
    void* cmptext_call_addr = base + ADDR_CMPTEXT_SAVE_HOOK;
    memcpy(g_orig_cmptext_call, cmptext_call_addr, 5);
    patch_call(cmptext_call_addr, (void*)gmk_or_gm80_thunk);

    dbg_log("Hooks installed: save=0x%p load=0x%p cmptext=0x%p",
        save_call_addr, load_call_addr, cmptext_call_addr);

    return true;
}

void ide_hooks_uninstall() {
    uint8_t* base = (uint8_t*)g_gm_base;
    if (base) {
        patch_bytes(base + 0x1DAE36, g_orig_save_call, 5);
        patch_bytes(base + ADDR_DIRECT_SAVE_CALL, g_orig_direct_save, 5);
        patch_bytes(base + 0x1D484A, g_orig_load_call, 5);
        patch_bytes(base + ADDR_CMPTEXT_SAVE_HOOK, g_orig_cmptext_call, 5);
        dbg_log("Hooks uninstalled");
    }
}
