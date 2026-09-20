// "Scripts" menu entry "Check for dead assets" + the scan itself.
//
// A dead asset is a file under one of the per-type resource folders that is
// registered in NEITHER index.yyd NOR tree.yyd. (One-sided registrations are
// covered by the load-time diagnostics in gm80_load.cpp: tree-only rows are
// silently dropped, index-only assets load but stay invisible — both get
// flagged there. Files missing from both registries never load at all and are
// invisible to every GMSave merge path, so they get their own on-demand scan
// instead of a per-load pass: the scan is cheap, but a separate entry keeps
// load-time noise at zero and gives room for a fuller report.)
//
// ==== IDE integration (verified 2026-09-20; full recipe: ../VCL菜单注入指南.md) ====
//   GM80_MainFormPtrPtr    RVA 0x1EA5AC — DOUBLE pointer: *(base+..) = &slot
//                          (0x60ADE8), *slot = TMainForm instance (written by
//                          CreateForm; GM's 35 read sites all deref twice).
//   TMenuItem classref     ds:off_453EA0 (value 0x453EEC = TMenuItem VMT)
//   TMenuItem.Create       0x455414 — mov dl,1; mov eax,classref; xor ecx,ecx
//                          (ecx=AOwner: garbage → InsertComponent derefs it →
//                          crash); FImageIndex defaults to -1 at +0x40, so no
//                          SetImageIndex call is needed.
//   TMenuItem.SetCaption   0x4573F8 (eax=item, edx=pseudo-AnsiString; writes
//                          the AnsiString field at +0x30 via GM80_LStrAsg)
//   TMenuItem.Add          0x457914 = Insert(GetCount(self), item)
//   OnClick TNotifyEvent   +0x88 method / +0x8C self — RTTI property table,
//                          cross-checked vs SetCaption(+0x30) and the Create
//                          default (+0x40=-1). The +0x80/+0x84 written at GM
//                          0x45884D are PRIVATE fields: parking a thunk there
//                          makes the menu system call it while painting, i.e.
//                          the handler fires on hover. Never write there.
// Target selection: the FieldTable's "Scripts1 @ +0x52C" is off by one slot in
// practice (an entry added there landed under "Import scripts"), so the target
// is picked at runtime by caption match ("脚本"/"Scripts") among the form's
// TMenuItem-typed fields around that area. See item_caption() below.
// The menu bar is streamed from the DFM during form creation, so the entry is
// injected on the form's first show (SetWinEventHook, registered at DLL
// attach) with project_watcher_start as a second idempotent chance.
#include "pch.h"
#include "dead_asset_check.h"
#include "delphi.h"
#include "gm_log.h"
#include "i18n.h"
#include "project_watcher.h" // gm80_prompt_owner
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <vector>

namespace fs = std::filesystem;

#define DAC_MAINFORM_PTR      0x1EA5AC // DOUBLE pointer — see header comment
#define DAC_MENUITEM_VMT      0x53EA0  // classref; its value = TMenuItem VMT
#define DAC_MENUITEM_CREATE   0x55414  // dl=1, ecx=nil, eax=classref → eax=item
#define DAC_SETCAPTION        0x573F8  // eax=item, edx=pseudo-AnsiString
#define DAC_SETENABLED        0x574C0  // TMenuItem.SetEnabled (RTTI: Enabled
                                       // setter): eax=item, dl=0/1
#define DAC_ADD               0x57914  // eax=self menu item, edx=new item
#define DAC_ITEM_TAG          0x0C
#define DAC_ITEM_CAPTION      0x30    // AnsiString; RTTI-verified twice (see below)
#define DAC_ITEM_ONCLICK      0x88    // TNotifyEvent method ptr (8.0; 8.1 same —
#define DAC_ITEM_ONCLICK_DATA 0x8C    // RTTI: OnClick field = +0x88; the 0x80/0x84
                                      // seen at GM 0x45884D are PRIVATE fields —
                                      // writing there corrupts the item: the menu
                                      // system derefs them while painting, so the
                                      // thunk fired on hover. Do not "fix" back.)
#define DAC_PROJECT_PATH      0x1EA27C // char* — current project path (.gm80)

static uint8_t* s_base;
static HWINEVENTHOOK s_wevent_hook;
static bool s_menu_done = false; // injected, or given up for a logged reason
static void* s_menu_item = nullptr; // our entry, once injected (for Enable sync)

static void dead_asset_check_run();

// TNotifyEvent: Self arrives in EAX, no stack args. We ignore it and never
// touch the popup selection global, so a click just runs the scan.
// (Defined after dead_asset_check_run — naked asm needs the symbol defined.)
static void onclick_thunk();

static void __stdcall wevent_proc(HWINEVENTHOOK hook, DWORD event, HWND hwnd,
                                  LONG idObject, LONG idChild,
                                  DWORD tid, DWORD time)
{
    (void)hook; (void)event; (void)idChild; (void)tid; (void)time;
    if (idObject != OBJID_WINDOW || !hwnd) return;
    wchar_t cls[32];
    if (GetClassNameW(hwnd, cls, 32) && _wcsicmp(cls, L"TMainForm") == 0)
        dead_asset_check_ensure_menu();
}

void dead_asset_check_install(uint8_t* base)
{
    s_base = base;
    // Inject as soon as the main form exists — GM creates it after DLL
    // attach, so watch its first show instead of patching a startup address.
    // WINEVENT_OUTOFCONTEXT callbacks arrive on this thread (the main one,
    // via its message pump). project_watcher_start re-runs the idempotent
    // ensure() as a second chance.
    s_wevent_hook = SetWinEventHook(EVENT_OBJECT_SHOW, EVENT_OBJECT_SHOW,
                                    NULL, wevent_proc, 0, 0,
                                    WINEVENT_OUTOFCONTEXT);
    gm_log("DeadAssetCheck: WinEvent hook %s",
           s_wevent_hook ? "installed" : "FAILED (menu falls back to the "
                                         "watcher-start poll)");
}

bool dead_asset_check_menu_ready()
{
    return s_menu_done;
}

// A project counts as open when GM's project-path global holds a path — set
// by gm80_load_project (and the native loader) on success.
static bool project_path_present()
{
    const char* p = *(const char**)(s_base + DAC_PROJECT_PATH);
    return p && !IsBadStringPtrA(p, 2) && p[0] != '\0';
}

void dead_asset_check_set_project(bool loaded)
{
    void* item = s_menu_item;
    if (!item || !s_base) return; // not injected yet: the injection path picks
                                  // the initial state from the same global
    uint32_t fn = (uint32_t)s_base + DAC_SETENABLED;
    uint8_t v = loaded ? 1 : 0;
    __asm {
        mov dl, v
        mov eax, item
        call fn
    }
}

// Logs a transient failure once (the watcher/timer paths keep retrying
// silently — the menu may simply not be wired up yet on the first attempt).
static void fail_transient(const char* why)
{
    static const char* last = nullptr;
    if (last != why)
    {
        gm_log("DeadAssetCheck: %s — will retry", why);
        last = why;
    }
}

// Caption of a TMenuItem (+0x30 AnsiString, '&' accelerators stripped).
static std::wstring item_caption(void* item)
{
    const char* capA = *(const char**)((uint8_t*)item + DAC_ITEM_CAPTION);
    if (!capA || IsBadStringPtrA(capA, 256)) return L"";
    std::wstring cap = ansi_to_wide(capA);
    std::wstring clean;
    for (wchar_t c : cap)
        if (c != L'&') clean += c;
    return clean;
}

void dead_asset_check_ensure_menu()
{
    if (s_menu_done || !s_base) return;

    // GM80_MainForm holds the ADDRESS of the form-pointer slot, not the form:
    // *(base+0x1EA5AC) = 0x60ADE8, and *(0x60ADE8) = the TMainForm instance
    // (CreateForm writes through the var Reference). Two derefs, like GM does.
    void** formSlot = *(void***)(s_base + DAC_MAINFORM_PTR);
    void* mainForm = formSlot ? *formSlot : nullptr;
    if (!mainForm || (uintptr_t)mainForm < 0x10000)
    {
        fail_transient("main form not created yet (slot null)");
        return;
    }

    // The Scripts menu is one of the form's published TMenuItem fields. The
    // FieldTable claims Scripts1 sits at +0x52C, but the entry added there
    // landed under "Import scripts" — so trust captions, not the table: read
    // each candidate's caption (+0x30, RTTI-verified) and match the text.
    uint32_t itemVmt = *(uint32_t*)(s_base + DAC_MENUITEM_VMT);
    static const int offs[] = { 0x524, 0x528, 0x52C, 0x530, 0x534,
                                0x380, 0x384, 0x388 };
    std::wstring want = tr(L"Scripts", L"脚本");
    void* scriptsMenu = nullptr;
    for (int off : offs)
    {
        void* p = *(void**)((uint8_t*)mainForm + off);
        if (!p || (uintptr_t)p < 0x10000 || IsBadReadPtr(p, 4) ||
            *(uint32_t*)p != itemVmt)
            continue;
        std::wstring cap = item_caption(p);
        if (cap.size() >= want.size() &&
            _wcsnicmp(cap.c_str(), want.c_str(), want.size()) == 0 &&
            (cap.size() == want.size() || cap[want.size()] == L'('))
        {
            scriptsMenu = p;
            break;
        }
    }
    if (!scriptsMenu)
    {
        gm_log("DeadAssetCheck: no candidate field captioned Scripts — "
               "menu entry unavailable");
        s_menu_done = true;
        return;
    }

    // Pseudo AnsiString constant: refcnt -1 at data-8, length at data-4 —
    // LStrAsg stores the pointer as-is for constants. GBK bytes match the
    // IDE's own ANSI strings.
    static char capBuf[8 + 128];
    std::wstring cap = tr(L"Check for dead assets", L"检测死资源");
    int n = WideCharToMultiByte(CP_ACP, 0, cap.c_str(), (int)cap.size(),
                                NULL, 0, NULL, NULL);
    if (n <= 0 || n > 120) return;
    WideCharToMultiByte(CP_ACP, 0, cap.c_str(), (int)cap.size(),
                        capBuf + 8, 120, NULL, NULL);
    capBuf[8 + n] = 0;
    *(int32_t*)(capBuf) = -1;
    *(int32_t*)(capBuf + 4) = n;
    const char* capStr = capBuf + 8;

    void* item = nullptr;
    uint32_t classref = itemVmt;
    uint32_t fnCreate = (uint32_t)s_base + DAC_MENUITEM_CREATE;
    __asm {
        mov dl, 1
        mov eax, classref
        xor ecx, ecx           // ecx = AOwner; garbage here makes Create's
        call fnCreate          // InsertComponent deref it (crash). nil = safe.
        mov item, eax
    }
    if (!item)
    {
        gm_log("DeadAssetCheck: TMenuItem.Create failed");
        s_menu_done = true;
        return;
    }

    uint32_t fnCaption = (uint32_t)s_base + DAC_SETCAPTION;
    __asm {
        mov edx, capStr
        mov eax, item
        call fnCaption
    }
    *(uint32_t*)((uint8_t*)item + DAC_ITEM_TAG) = 0xFFFFFFFF;
    *(uint32_t*)((uint8_t*)item + DAC_ITEM_ONCLICK) = (uint32_t)&onclick_thunk;
    *(uint32_t*)((uint8_t*)item + DAC_ITEM_ONCLICK_DATA) = (uint32_t)item;

    uint32_t fnAdd = (uint32_t)s_base + DAC_ADD;
    __asm {
        mov edx, item
        mov eax, scriptsMenu
        call fnAdd
    }
    s_menu_done = true;
    s_menu_item = item;
    // Grey the entry out while no project is open (scanning does nothing).
    dead_asset_check_set_project(project_path_present());
    if (s_wevent_hook)
    {
        UnhookWinEvent(s_wevent_hook); // one-shot: the menu bar is done
        s_wevent_hook = NULL;
    }
    gm_log("DeadAssetCheck: entry added to the Scripts menu");
}

// ==== The scan ====
static void dead_asset_check_run()
{
    uint8_t* base = (uint8_t*)GetModuleHandle(NULL);
    if (!base) return;
    const char* projA = *(const char**)(base + DAC_PROJECT_PATH);
    if (!projA || IsBadStringPtrA(projA, 1024)) return;
    int wlen = MultiByteToWideChar(CP_ACP, 0, projA, (int)strlen(projA), NULL, 0);
    if (wlen <= 0) return;
    std::wstring wpath(wlen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, projA, (int)strlen(projA), &wpath[0], wlen);
    fs::path projDir(wpath);
    if (fs::is_regular_file(projDir)) projDir = projDir.parent_path();

    static const struct
    {
        const wchar_t* dir;
        const wchar_t* label;
    } kinds[] = {
        {L"sprites", L"sprites"},         {L"sounds", L"sounds"},
        {L"backgrounds", L"backgrounds"}, {L"paths", L"paths"},
        {L"scripts", L"scripts"},         {L"fonts", L"fonts"},
        {L"timelines", L"timelines"},     {L"objects", L"objects"},
        {L"rooms", L"rooms"},             {L"triggers", L"triggers"},
    };

    std::vector<std::wstring> dead;
    for (auto& k : kinds)
    {
        fs::path dir = projDir / k.dir;
        if (!fs::is_directory(dir)) continue;

        // Registered names: non-empty index.yyd lines (GBK → wide).
        std::set<std::wstring> names;
        std::ifstream f(dir / L"index.yyd", std::ios::binary);
        if (f)
        {
            std::string line;
            while (std::getline(f, line))
            {
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                    line.pop_back();
                if (!line.empty()) names.insert(ansi_to_wide(line));
            }
        }

        // Top-level entries: file stems / directory names. Works for every
        // per-type layout (single file or one folder per asset).
        for (auto& e : fs::directory_iterator(dir))
        {
            std::wstring name = e.path().filename().wstring();
            if (name == L"index.yyd" || name == L"tree.yyd") continue;
            std::wstring stem = e.path().stem().wstring();
            if (names.count(stem)) continue;
            dead.push_back(std::wstring(k.label) + L": " + stem);
        }
    }

    if (dead.empty())
    {
        MessageBoxW(gm80_prompt_owner(),
            tr(L"No dead assets found — every file in the resource folders is "
               L"registered in index.yyd.",
               L"未发现死资源——资源文件夹中的所有文件都已在 index.yyd 中注册。"),
            L"Game Maker 8.0", MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
        return;
    }

    const size_t kMaxShown = 15;
    std::wstring msg = tr(
        L"These files are registered in neither index.yyd nor tree.yyd, so "
        L"they never load. The files themselves are still on disk — delete "
        L"them manually or restore their registry lines:\r\n",
        L"以下文件未在 index.yyd / tree.yyd 中注册，不会被载入。文件本身仍"
        L"在磁盘上——可手工删除，或恢复其注册行：\r\n");
    for (size_t i = 0; i < dead.size() && i < kMaxShown; i++)
        msg += L"\r\n" + dead[i];
    if (dead.size() > kMaxShown)
    {
        wchar_t more[64];
        _snwprintf(more, 64,
            tr(L"\r\n... and %zu more", L"\r\n……另有 %zu 条未列出"),
            dead.size() - kMaxShown);
        more[63] = 0;
        msg += more;
    }
    MessageBoxW(gm80_prompt_owner(), msg.c_str(), L"Game Maker 8.0",
        MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
}

// TNotifyEvent: Self arrives in EAX, no stack args. We ignore it and never
// touch the popup selection global, so a click just runs the scan.
__declspec(naked) static void onclick_thunk()
{
    __asm {
        pushad
        call dead_asset_check_run
        popad
        retn
    }
}
