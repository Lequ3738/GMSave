// GM80 multi-file load — direct Delphi object creation (matches gm82save approach)
// Creates Delphi objects and inserts them into GM's resource arrays
#include "pch.h"
#include "gm80_load.h"
#include "gm80_addresses.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <functional>
#include <map>
#include <vector>
#include <array>
#include <algorithm>

// PNG decoding via stb_image (single-header, same approach as gm82save's png crate)
#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#include "stb_image.h"
namespace fs = std::filesystem;

static void* g_load_base = nullptr; // GM base address

// ==== UTF-8 → ANSI conversion for GML files ====
// GM 8.0 uses AnsiString (CP_ACP/GBK). .gml files use UTF-8.
static std::string utf8_to_ansi(const std::string& utf8) {
    if (utf8.empty()) return "";
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), NULL, 0);
    if (wlen <= 0) return utf8;
    std::wstring wide(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &wide[0], wlen);
    int alen = WideCharToMultiByte(CP_ACP, 0, wide.c_str(), wlen, NULL, 0, NULL, NULL);
    if (alen <= 0) return utf8;
    std::string ansi(alen, '\0');
    WideCharToMultiByte(CP_ACP, 0, wide.c_str(), wlen, &ansi[0], alen, NULL, NULL);
    return ansi;
}

// ==== File I/O ====
static std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return "";
    std::ostringstream ss; ss << f.rdbuf(); return ss.str();
}
static bool file_exists(const fs::path& p) {
    return fs::exists(p);
}

static void parse_kv(const std::string& txt,
    std::function<void(const std::string&,const std::string&)> cb) {
    std::istringstream ss(txt); std::string line;
    while (std::getline(ss, line)) {
        if (line.empty()) continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        cb(line.substr(0, eq), line.substr(eq + 1));
    }
}

// ==== GML processing ====
// Decode YYD delimiters: *\/ to */, \n to newline, \r to CR, \\ to backslash
static std::string yyd_decode(const char* s) {
    std::string out;
    if (!s) return out;
    out.reserve(strlen(s));
    for (const char* p = s; *p; p++) {
        if (*p == '\\' && *(p+1)) {
            char next = *(p+1);
            if (next == '\\') { out += '\\'; p++; }
            else if (next == 'r') { out += '\r'; p++; }
            else if (next == 'n') { out += '\n'; p++; }
            else out += *p;
        } else if (*p == '*' && *(p+1) == '\\' && *(p+2) == '/') {
            out += "*/"; p += 2;
        } else {
            out += *p;
        }
    }
    return out;
}
static std::string decode_delimit(const std::string& s) {
    return yyd_decode(s.c_str());
}

// Load GML: convert CRLF to LF, UTF-8→ANSI, handle YYD tokens
static std::string load_gml(const std::string& code) {
    // Convert raw text → normalized GML for Delphi
    std::string buf;
    std::istringstream ss(code);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        buf += line + "\r\n";
    }
    return utf8_to_ansi(buf);
}

// ==== Delphi object creation helpers ====

// Delphi RTL addresses for AnsiString management (verified from IDA)
#define ADDR_LSTR_FROM_PCHAR_LEN  0x55C4   // sub_4055C4: EAX=output_ptr, EDX=src, ECX=len
#define ADDR_LSTR_ASG             0x5528   // @LStrAsg: EAX=dest, EDX=src (refcounted assign)
#define ADDR_LSTR_CLR             0x54D4   // @LStrClr: EAX=ptr_to_string (free)
                                           // VERIFIED 0x4054D4: clears *EAX first, then
                                           // decrements refcount (-1 literal = skip free).
                                           // (0x4047E8 was a nullsub — never freed!)

// Create Delphi AnsiString from C string using Delphi RTL (@LStrFromPCharLen)
static char* make_delphi_str(const char* cstr) {
    if (!cstr || !*cstr) return nullptr;
    char* result = nullptr;
    size_t len = strlen(cstr);
    uint32_t func = (uint32_t)g_load_base + ADDR_LSTR_FROM_PCHAR_LEN;
    __asm {
        lea eax, result          // EAX = where to store the new string pointer
        mov edx, cstr            // EDX = source C string
        mov ecx, len             // ECX = length
        call func                // @LStrFromPCharLen
    }
    return result;
}
static char* make_delphi_str(const std::string& s) { return make_delphi_str(s.c_str()); }

// Free Delphi AnsiString using Delphi RTL (@LStrClr)
static void free_delphi_str(char** pp) {
    if (!pp || !*pp) return;
    uint32_t func = (uint32_t)g_load_base + ADDR_LSTR_CLR;
    __asm {
        mov eax, pp
        call func                // @LStrClr
    }
}

// Set a Delphi AnsiString field on an object
static void set_obj_str(void* obj, int off, const std::string& val) {
    if (!obj) return;
    char** dest = (char**)((uint8_t*)obj + off);
    free_delphi_str(dest);
    if (!val.empty()) *dest = make_delphi_str(val);
}
static void set_obj_u32(void* obj, int off, uint32_t val) {
    *(uint32_t*)((uint8_t*)obj + off) = val;
}
static void set_obj_i32(void* obj, int off, int32_t val) {
    *(int32_t*)((uint8_t*)obj + off) = val;
}
static void set_obj_bool(void* obj, int off, bool val) {
    *(uint8_t*)((uint8_t*)obj + off) = val ? 1 : 0;
}
static void set_obj_f64(void* obj, int off, double val) {
    *(double*)((uint8_t*)obj + off) = val;
}
static void set_obj_ptr(void* obj, int off, void* val) {
    *(void**)((uint8_t*)obj + off) = val;
}

// Write to global variables
static uint8_t* glob_base() {
    uint8_t* b = (uint8_t*)g_load_base;
    return b ? b : (uint8_t*)GetModuleHandle(NULL);
}

// Debug logging from DLL context (gm80_load.cpp has no direct dbg_log)
static void gm80l_log(const char* fmt, ...) {
    char path[MAX_PATH], buf[1024];
    GetEnvironmentVariableA("TEMP", path, sizeof(path));
    strcat_s(path, "\\GMSave.log");
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    FILE* f = fopen(path, "a");
    if (f) { fprintf(f, "%s\n", buf); fclose(f); }
}

// Naked wrapper to call Delphi constructors with proper register convention.
// Takes class_ref and ctor_addr via __cdecl stack, sets EAX/EDX, calls, returns EAX.
__declspec(naked) static void* delphi_ctor(uint32_t class_ref, uint32_t ctor_addr) {
    __asm {
        mov eax, [esp+4]    // class_ref (first __cdecl arg)
        mov edx, 1           // alloc flag
        mov ecx, [esp+8]    // ctor_addr (second __cdecl arg)
        call ecx
        ret
    }
}


// Allocate memory using Delphi's memory manager
static void* delphi_alloc(uint32_t sz) {
    uint8_t* b = glob_base();
    void* result = nullptr;
    __asm {
        mov eax, dword ptr [sz]
        mov ecx, dword ptr [b]
        add ecx, 0x2DDC
        call ecx
        mov dword ptr [result], eax
    }
    if ((uint32_t)result < 0x10000) return nullptr;
    memset(result, 0, sz);
    return result;
}

// Free memory using Delphi's memory manager
static void delphi_free(void* p) {
    if (!p) return;
    uint8_t* b = glob_base();
    uint32_t fn = (uint32_t)b + 0x2DF8; // sub_402DF8 = FreeMem
    __asm {
        mov eax, p
        mov ecx, fn
        call ecx
    }
}

// Construct a Delphi object: reads VMT from data offset, calls constructor via naked wrapper
// Read REAL VMT from GM's own blank object in the resource array.
// InitializeProject already ran before our hook, so arrays have blank entries.
// Defined below (needs s_resInfo); cached from GM's own array at load start
static uint32_t lookup_cached_vmt(uint32_t arrObjOff);

static uint32_t get_real_vmt(uint32_t arrObjOff, uint32_t fallbackVmtRva) {
    uint8_t* b = glob_base();
    uint32_t vmt = 0;
    // Prefer VMT cached from GM's own array before we replaced it
    vmt = lookup_cached_vmt(arrObjOff);
    if (!vmt && arrObjOff != 0) { // arrObjOff=0 means "no array" (e.g. Frame objects)
        uint32_t* arr = *(uint32_t**)(b + arrObjOff);
        // GM uses 0xFFFFFFFF as "uninitialized array" sentinel — guard it
        if (arr && arr != (uint32_t*)-1 && arr[0]) vmt = *(uint32_t*)arr[0]; // object[0] = VMT pointer
    }
    if (!vmt) vmt = *(uint32_t*)(b + fallbackVmtRva);
    return vmt;
}

static void* make_obj_with_arr(uint32_t arrObjOff, uint32_t vmt_rva, uint32_t ctor_rva) {
    uint32_t class_ref = get_real_vmt(arrObjOff, vmt_rva);
    if (class_ref < 0x400000) return nullptr;
    void* obj = delphi_ctor(class_ref, (uint32_t)glob_base() + ctor_rva);
    if (obj == (void*)class_ref) return nullptr;
    return obj;
}

// Create a Delphi TMemoryStream containing raw data.
// Layout (verified from gm80_save.cpp + GM80_LoadRecentProject asm):
//   +0 vmt, +4 memory, +8 size, +12 position, +16 capacity
// VMT read from off_4EA854 (mov eax, ds:off_4EA854 before sub_404560 call),
// ctor sub_404560 = standard NewInstance+InitInstance (empty body).
// NOTE: 0x4EA854 is the ABSOLUTE address (base 0x400000 + RVA 0xEA854); the code
// adds g_load_base, so the macro must be the RVA. (Was wrongly 0x4EA854 → read
// 0x8EA854 → access violation. Fixed 2026-08-02.)
#define ADDR_TSTREAM_VMT_DATA 0xEA854
#define ADDR_TSTREAM_CREATE   0x4560
static void* make_delphi_stream(const void* data, uint32_t size) {
    uint8_t* base = glob_base();
    uint32_t msVmt = *(uint32_t*)(base + ADDR_TSTREAM_VMT_DATA);
    void* ms = delphi_ctor(msVmt, (uint32_t)base + ADDR_TSTREAM_CREATE);
    if (!ms || ms == (void*)msVmt) return nullptr;
    void* mem = delphi_alloc(size);
    if (mem && data && size) memcpy(mem, data, size);
    set_obj_ptr(ms, 4, mem);
    set_obj_u32(ms, 8, size);
    set_obj_u32(ms, 12, 0);
    set_obj_u32(ms, 16, size);
    return ms;
}

static void write_glob_u8(uint32_t off, uint8_t v)  { *(uint8_t*)(glob_base() + off) = v; }
static void write_glob_u32(uint32_t off, uint32_t v) { *(uint32_t*)(glob_base() + off) = v; }
static void write_glob_bool(uint32_t off, bool v)    { write_glob_u8(off, v ? 1 : 0); }
static void write_glob_i32(uint32_t off, int32_t v)  { *(int32_t*)(glob_base() + off) = v; }
static void write_glob_f64(uint32_t off, double v)   { *(double*)(glob_base() + off) = v; }
static void write_glob_str(uint32_t off, const std::string& val) {
    uint8_t* base = (uint8_t*)g_load_base;
    if (!base) base = (uint8_t*)GetModuleHandle(NULL);  // fallback
    if (!base) return;
    char** dest = (char**)(base + off);
    if (!dest) return;
    free_delphi_str(dest);
    if (!val.empty()) *dest = make_delphi_str(val);
}

// ==== Resource array helpers ====
// Each resource type has: object array, name array, count

// Look up a name in an index map
static int name_to_index(const std::vector<std::string>& names, const std::string& name) {
    // Empty name = no reference (GM 8.0 semantics: -1 for "none"). index.yyd may
    // contain blank lines for empty array slots; matching those would write the
    // slot index instead of -1 (e.g. objPlayer parent=27 from a blank line).
    if (name.empty()) return -1;
    for (size_t i = 0; i < names.size(); i++)
        if (names[i] == name) return (int)i;
    return -1;
}

// ==== Resource type layout info ====
struct ResInfo {
    uint32_t arrObjOff;   // object array ptr offset
    uint32_t arrNameOff;  // name array ptr offset
    uint32_t countOff;    // count offset
    uint32_t vmtRva;      // where to read VMT class reference
    uint32_t ctorRva;     // constructor RVA
    const char* dir;
    int kind;             // resource kind (for tree.yyd)
    uint32_t cachedVmt;   // filled at load start from GM's own array [0]
};

// Array addresses VERIFIED from save side (gm80_save.cpp reads these exact
// globals when serializing). VMT offsets verified from "mov eax, ds:off_XXXX"
// before each constructor call; ctor addresses verified from IDA lookup.
static ResInfo s_resInfo[] = {
    // kind=2: sprites   arr=0x1E9108 name=0x1E9110 cnt=0x1E911C off_4F8508
    {0x1E9108, 0x1E9110, 0x1E911C, 0xF8508,  0xF8930,  "sprites", 2, 0},
    // kind=3: sounds    arr=0x1E9278 name=0x1E9280 cnt=0x1E9288 off_544660
    // (corrected 2026-08-02: was 0x1E92FC/0x1E932C, which are CONSTANTS globals;
    //  real sound array/names verified from GM80_SaveSounds/LoadSounds)
    {0x1E9278, 0x1E9280, 0x1E9288, 0x144660, 0x144768, "sounds", 3, 0},
    // kind=6: backgrounds arr=0x1E9094 name=0x1E909C cnt=0x1E90A8 off_5207B4
    {0x1E9094, 0x1E909C, 0x1E90A8, 0x1207B4, 0x12084C, "backgrounds", 6, 0},
    // kind=8: paths     arr=0x1E92AC name=0x1E92B4 cnt=0x1E92BC off_54695C
    {0x1E92AC, 0x1E92B4, 0x1E92BC, 0x14695C, 0x147054, "paths", 8, 0},
    // kind=7: scripts   arr=0x1E92D4 name=0x1E92DC cnt=0x1E92E4 off_559B9C
    {0x1E92D4, 0x1E92DC, 0x1E92E4, 0x159B9C, 0x159C2C, "scripts", 7, 0},
    // kind=9: fonts     arr=0x1E92C0 name=0x1E92C8 cnt=0x1E92D0 off_55742C
    {0x1E92C0, 0x1E92C8, 0x1E92D0, 0x15742C, 0x157A78, "fonts", 9, 0},
    // kind=12: timelines arr=0x1E9300 name=0x1E9308 cnt=0x1E9310 off_559298
    {0x1E9300, 0x1E9308, 0x1E9310, 0x159298, 0x1593D4, "timelines", 12, 0},
    // kind=1: objects   arr=0x1E9354 name=0x1E935C cnt=0x1E9364 off_596CE0
    {0x1E9354, 0x1E935C, 0x1E9364, 0x196CE0, 0x196D70, "objects", 1, 0},
    // kind=4: rooms     arr=0x1E9294 name=0x1E929C cnt=0x1E92A4 off_547D00
    {0x1E9294, 0x1E929C, 0x1E92A4, 0x147D00, 0x14803C, "rooms", 4, 0},
    // kind=0: triggers  arr=0x1E92E8 (name inside object at +4) cnt=0x1E92EC
    {0x1E92E8, 0,          0x1E92EC, 0x15C2B8, 0x15C358, "triggers", 0, 0},
};

// Cache real VMTs from GM's own array objects BEFORE we replace the arrays
// with SetLength (the arrays may hold blank objects created by InitializeProject)
static void cache_vmts() {
    uint8_t* b = (uint8_t*)g_load_base;
    for (auto& ri : s_resInfo) {
        if (!ri.arrObjOff) continue;
        uint32_t* arr = *(uint32_t**)(b + ri.arrObjOff);
        // GM uses 0xFFFFFFFF as "uninitialized array" sentinel — guard it
        if (arr && arr != (uint32_t*)-1 && arr[0]) {
            ri.cachedVmt = *(uint32_t*)arr[0]; // object[0] = VMT pointer
            gm80l_log("cache_vmts: %s VMT=0x%X (from GM obj 0x%X)", ri.dir, ri.cachedVmt, arr[0]);
        }
    }
}

static uint32_t lookup_cached_vmt(uint32_t arrObjOff) {
    for (auto& ri : s_resInfo)
        if (ri.arrObjOff && ri.arrObjOff == arrObjOff && ri.cachedVmt)
            return ri.cachedVmt;
    return 0;
}

static const ResInfo* find_res(const char* dir) {
    for (auto& ri : s_resInfo)
        if (strcmp(ri.dir, dir) == 0) return &ri;
    return nullptr;
}
static const ResInfo* find_res_by_kind(int kind) {
    for (auto& ri : s_resInfo)
        if (ri.kind == kind) return &ri;
    return nullptr;
}

// ==== Resource tree (tree.yyd) loading ====
// RT_* TTreeNode globals from IDA sub_59EC84
#define RT_OBJECTS       0x1F6258
#define RT_SPRITES       0x1F625C
#define RT_SOUNDS        0x1F6260
#define RT_ROOMS         0x1F6264
#define RT_BACKGROUNDS   0x1F6268
#define RT_PATHS         0x1F626C
#define RT_SCRIPTS       0x1F6270
#define RT_FONTS         0x1F6274
#define RT_TIMELINES     0x1F6278

static uint32_t rt_node_for_kind(int kind) {
    switch (kind) {
        case 1: return RT_OBJECTS;
        case 2: return RT_SPRITES;
        case 3: return RT_SOUNDS;
        case 4: return RT_ROOMS;
        case 6: return RT_BACKGROUNDS;
        case 7: return RT_SCRIPTS;
        case 8: return RT_PATHS;
        case 9: return RT_FONTS;
        case 12: return RT_TIMELINES;
        default: return 0;
    }
}

// TTreeNode functions (Delphi 7 VCL) — verified from GM 8.0's own tree code:
//   sub_497254 GetCount, sub_497178 get_Item, sub_59EB64 node creation,
//   sub_457914 attach(parent,node), sub_4573F8 set name, sub_4575EC set image
// Node layout (confirmed by GM's tree writer sub_5A0594 + save side):
//   +8 name (AnsiString), +12 data (TreeNodeData: unknown/rtype/kind/index)

// Create + attach a tree node exactly like GM's own .gmk tree reader
// (verified from sub_59F10C disassembly):
//   mov eax, ds:dword_5F6288
//   mov eax, [eax+2B4h]        ; eax = tree node container
//   mov ecx, [ebp+var_4]       ; ecx = 0
//   mov edx, edi               ; edx = parent node
//   call sub_497D00            ; → new node (control-level insert + VCL node)
//   sub_4967EC(node, data)     ; attach TreeNodeData
//   sub_49699C(node, -1)       ; init
// TreeNodeData is a real Delphi object: sub_404560(dword_59EB3C value),
// fields [1]=rtype [2]=kind [3]=index (matches save side td[1..3]).
// Name lives at +8 (AnsiString, verified by save side + GM's sub_5A0594).
static void* tree_add_child(void* nodes, void* parent, const std::string& name,
                            uint32_t rtype, uint32_t kind, uint32_t index) {
    uint8_t* b = glob_base();
    if (!nodes || (uintptr_t)nodes < 0x10000) {
        gm80l_log("tree_add_child: bad nodes container, skipping");
        return nullptr;
    }

    // 1. TreeNodeData: inline 16-byte {unknown, rtype, kind, index}.
    //    GM's tree writer (sub_5A0594) and the save side only read td[1..3],
    //    so an inline block is fully compatible — avoids the unreliable
    //    off_59EAF0 class ref (runtime value differs from static IDB).
    uint32_t* td = (uint32_t*)delphi_alloc(16);
    if (!td) return nullptr;
    td[0] = 0; td[1] = rtype; td[2] = kind; td[3] = index;

    // 2. Create node: sub_497D00(nodes, parent, 0) (RVA 0x97D00)
    uint32_t fnCreate = (uint32_t)b + 0x97D00;
    void* node = nullptr;
    __asm {
        mov eax, nodes
        mov edx, parent
        xor ecx, ecx
        call fnCreate
        mov node, eax
    }
    if (!node) return nullptr;

    // 3. name at +8 (AnsiString)
    set_obj_str(node, 8, name);

    // 4. attach data: sub_4967EC(node, td) (RVA 0x967EC)
    uint32_t fnAttach = (uint32_t)b + 0x967EC;
    __asm {
        mov eax, node
        mov edx, td
        call fnAttach
    }

    // 5. init: sub_49699C(node, -1) (RVA 0x9699C)
    uint32_t fnInit = (uint32_t)b + 0x9699C;
    __asm {
        mov eax, node
        mov edx, 0xFFFFFFFF
        call fnInit
    }

    return node;
}

// Read a tree.yyd file and build TTreeNode hierarchy (matches gm82save's
// read_resource_tree: AddChild per line, rtype 2=folder 3=leaf, stack depth)
static void load_resource_tree(
    const std::vector<std::string>& names,
    int kind,
    const char* dirName,
    const fs::path& root)
{
    if (names.empty()) return;
    auto treePath = root / dirName / "tree.yyd";
    std::string txt = read_file(treePath);
    if (txt.empty()) {
        // No tree.yyd (older .gm80 files saved before sounds got tree.yyd):
        // build a flat tree from the index names so the IDE tree still shows them.
        for (auto& n : names) { if (!n.empty()) txt += "|" + n + "\n"; }
    }
    if (txt.empty()) return;

    uint8_t* base = (uint8_t*)g_load_base;
    uint32_t rtOff = rt_node_for_kind(kind);
    if (!rtOff) return;

    // Get root TTreeNode
    void* rootNode = *(void**)(base + rtOff);
    if (!rootNode || (uintptr_t)rootNode < 0x10000) {
        gm80l_log("load_resource_tree %s: no root node at 0x%X", dirName, rtOff);
        return;
    }

    // Tree node container (verified from sub_59F10C):
    //   mov eax, ds:dword_5F6288 ; mov eax, [eax+2B4h]
    void* treeView = *(void**)(base + 0x1F6288);               // dword_5F6288
    void* nodes = treeView ? *(void**)((uint8_t*)treeView + 0x2B4) : nullptr;
    if (!nodes || (uintptr_t)nodes < 0x10000) {
        gm80l_log("load_resource_tree %s: no nodes container (tv=0x%p)", dirName, treeView);
        return;
    }

    // Parse tree.yyd: tab-indented, + for group (rtype=2), | for leaf (rtype=3)
    std::vector<void*> stack;
    stack.push_back(rootNode);

    std::istringstream ss(txt);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty()) continue;
        size_t trimmedStart = line.find_first_not_of('\t');
        size_t level = (trimmedStart == std::string::npos) ? 0 : trimmedStart;
        std::string trimmed = (trimmedStart == std::string::npos) ? "" : line.substr(trimmedStart);
        if (trimmed.empty()) continue;

        char rtype = trimmed[0];
        std::string name = trimmed.substr(1);
        int idx = name_to_index(names, name);

        while (stack.size() > level + 1) stack.pop_back();
        if (stack.empty()) continue;

        void* parent = stack.back();
        void* childNode = nullptr;

        if (rtype == '+') {
            childNode = tree_add_child(nodes, parent, name, 2, (uint32_t)kind, 0);
            if (childNode) stack.push_back(childNode);
        } else if (rtype == '|' && idx >= 0) {
            tree_add_child(nodes, parent, name, 3, (uint32_t)kind, (uint32_t)idx);
        }
    }
}

// ==== Initialize project ====
static void init_project() {
    uint32_t func = (uint32_t)g_load_base + 0x19B7EC; // GM80_InitializeProject (verified from sub_59B905 call)
    __asm { call func }
}

// ==== Load settings ====
// Loading-bar bitmaps + icon: read a Delphi image file (BMP/ICO) into a
// TMemoryStream, create the image object (TBitmap from off_42D15C /
// TIcon from off_42D248) and LoadFromStream (vtable+0x54 — verified from
// sub_59DCD0). Target globals: dword_5E940C back / 5E9408 front /
// 5E9404 loader / 5E941C icon.
// Read a Delphi image file (BMP/ICO) into a TMemoryStream, create the image
// object and LoadFromStream (vtable+0x54 — verified from sub_59DCD0).
// NOTE: inline asm must reference only LOCAL variables — MSVC misreads
// function parameters inside __asm blocks.
static void load_image_file_core(const fs::path& root, const char* fname,
                                 uint32_t globOff, uint32_t imgCls) {
    std::string data = read_file(root / "settings" / fname);
    if (data.empty()) return;
    uint8_t* base = (uint8_t*)g_load_base;
    // TMemoryStream (same class chain as GM's Outer: off_4EA854 → 0x4EA8A0)
    uint32_t streamCls = *(uint32_t*)(base + 0xEA854);
    if (streamCls < 0x400000) streamCls = *(uint32_t*)(base + 0xEA8A0);
    void* stream = nullptr;
    __asm {
        mov dl, 1
        mov eax, streamCls
        mov ecx, 0x404560
        call ecx
        mov stream, eax
    }
    if (!stream) return;
    // TStream.WriteBuffer (sub_41F8E8: eax=stream, edx=buf, ecx=len)
    char* bufPtr = (char*)data.data();
    uint32_t bufLen = (uint32_t)data.size();
    __asm {
        mov eax, stream
        mov edx, bufPtr
        mov ecx, bufLen
        mov ebx, 0x41F8E8
        call ebx
    }
    // Image object ctor (eax=class ref, dl=1 allocate) — local copies only.
    // GM loads the class-ref VALUE at the global (sub_4EAC48: `mov eax, ds:off_42D110`
    // for loading-bar bitmaps), NOT the global's address. imgCls is the absolute
    // addr of the class-ref global.
    void* img = nullptr;
    uint32_t imgClsVal = *(uint32_t*)((uint8_t*)g_load_base + (imgCls - 0x400000));
    __asm {
        mov eax, imgClsVal
        mov dl, 1
        xor ecx, ecx
        mov ebx, 0x434230          // GM80_TBitmap_Create
        call ebx
        mov img, eax
    }
    if (!img) return;
    // Rewind the stream to the start — WriteBuffer left the Position at the
    // end; LoadFromStream reads from the current position.
    // Direct FPosition write (+12, per sub_41FD90 = TStream.Read which uses
    // a1+8=Size / a1+12=Position). The vtable+0x18 "Seek" was WRONG — that
    // slot is SetSize (sub_41F840) whose Int64 range check raised a Delphi
    // exception on our garbage args.
    *(uint32_t*)((uint8_t*)stream + 12) = 0;
    // LoadFromStream(stream) — vtable+0x54 (verified sub_59DCD0)
    __asm {
        mov eax, img
        mov edx, stream
        mov ecx, [eax]
        call dword ptr [ecx+0x54]
    }
    *(uint32_t*)(base + globOff) = (uint32_t)img;
    gm80l_log("load_image: %s -> 0x%X at 0x%X", fname, (uint32_t)img, globOff);
}

// TIcon variant — same but the icon ctor (0x435F68, class ref off_42D248).
static void load_icon_file(const fs::path& root, const char* fname,
                           uint32_t globOff) {
    std::string data = read_file(root / "settings" / fname);
    if (data.empty()) return;
    uint8_t* base = (uint8_t*)g_load_base;
    uint32_t streamCls = *(uint32_t*)(base + 0xEA854);
    if (streamCls < 0x400000) streamCls = *(uint32_t*)(base + 0xEA8A0);
    void* stream = nullptr;
    __asm {
        mov dl, 1
        mov eax, streamCls
        mov ecx, 0x404560
        call ecx
        mov stream, eax
    }
    if (!stream) return;
    char* bufPtr = (char*)data.data();
    uint32_t bufLen = (uint32_t)data.size();
    __asm {
        mov eax, stream
        mov edx, bufPtr
        mov ecx, bufLen
        mov ebx, 0x41F8E8
        call ebx
    }
    // GM80_InitializeProject → sub_59DAC4 already created a default TIcon at
    // dword_5E941C (0x1E941C). GM's own load (GM80_LoadSettings 0x59e4df) uses
    // THAT object directly and LoadFromStreams into it. Prefer it if present.
    void* img = nullptr;
    uint32_t existingIcon = *(uint32_t*)(base + globOff);
    if (existingIcon >= 0x10000) {
        img = (void*)existingIcon;
    } else {
        // GM: sub_59DAC4 `mov eax, ds:off_42D258` — class ref is the VALUE at
        // 0x42D258 (= 0x42D2A4), not the global address.
        uint32_t iconCls = *(uint32_t*)(base + 0x2D258);
        __asm {
            mov eax, iconCls
            mov dl, 1
            xor ecx, ecx
            mov ebx, 0x435F68          // TIcon ctor
            call ebx
            mov img, eax
        }
    }
    if (!img) return;
    // Rewind: TMemoryStream.FPosition = +12 (see load_image_file_core).
    *(uint32_t*)((uint8_t*)stream + 12) = 0;
    __asm {
        mov eax, img
        mov edx, stream
        mov ecx, [eax]
        call dword ptr [ecx+0x54]
    }
    *(uint32_t*)(base + globOff) = (uint32_t)img;
    gm80l_log("load_image: %s -> 0x%X at 0x%X", fname, (uint32_t)img, globOff);
}

// Safe wrappers — the icon/loading-bar bitmaps are cosmetic; a failure here must
// never crash the whole project load (GM tolerates a null icon / no custom bar).
static void load_image_file_safe(const fs::path& root, const char* fname,
                                 uint32_t globOff, uint32_t imgCls) {
    __try { load_image_file_core(root, fname, globOff, imgCls); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        gm80l_log("load_image FAILED %s code=0x%X", fname, GetExceptionCode());
    }
}
static void load_icon_file_safe(const fs::path& root, const char* fname,
                                uint32_t globOff) {
    __try { load_icon_file(root, fname, globOff); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        gm80l_log("load_icon FAILED %s code=0x%X", fname, GetExceptionCode());
    }
}

static void load_settings(const fs::path& root) {
    fs::path settPath = root / "settings" / "settings.txt";
    std::string txt = read_file(settPath);
    if (txt.empty()) return;

    // Offsets corrected 2026-08-02 from GM80_SaveSettings/LoadSettings:
    // fullscreen=0x1E93A0, scaling=0x1E93B0, priority=0x1E93F8 (u32),
    // loading_bar=0x1E93FC (u32). All fields now round-trip.
    parse_kv(txt, [&](auto& k, auto& v) {
        if (k == "fullscreen") write_glob_bool(ADDR_SETTING_FULLSCREEN, v=="1");
        else if (k == "interpolate_pixels") write_glob_bool(ADDR_SETTING_INTERPOLATE, v=="1");
        else if (k == "dont_draw_border") write_glob_bool(ADDR_SETTING_DONT_DRAW_BORDER, v=="1");
        else if (k == "display_cursor") write_glob_bool(ADDR_SETTING_DISPLAY_CURSOR, v=="1");
        else if (k == "color_depth") write_glob_u32(ADDR_SETTING_COLOR_DEPTH, (uint32_t)std::stoul(v));
        else if (k == "resolution") write_glob_u32(ADDR_SETTING_RESOLUTION, (uint32_t)std::stoul(v));
        else if (k == "frequency") write_glob_u32(ADDR_SETTING_FREQUENCY, (uint32_t)std::stoul(v));
        else if (k == "scaling") write_glob_i32(ADDR_SETTING_SCALING, (int32_t)std::stoul(v)); // signed; stoi throws on u32-encoded -1
        else if (k == "clear_color") write_glob_u32(ADDR_SETTING_CLEAR_COLOR, (uint32_t)std::stoul(v));
        else if (k == "dont_show_buttons") write_glob_u8(ADDR_SETTING_DONT_SHOW_BUTTONS, (uint8_t)std::stoul(v));
        else if (k == "vsync") write_glob_u8(ADDR_SETTING_VSYNC, (uint8_t)std::stoul(v));
        else if (k == "disable_screensaver") write_glob_u8(ADDR_SETTING_DISABLE_SCREENSAVER, (uint8_t)std::stoul(v));
        else if (k == "f4_fullscreen_toggle") write_glob_u8(ADDR_SETTING_F4_FULLSCREEN, (uint8_t)std::stoul(v));
        else if (k == "f1_help_menu") write_glob_u8(ADDR_SETTING_F1_HELP, (uint8_t)std::stoul(v));
        else if (k == "esc_close_game") write_glob_u8(ADDR_SETTING_ESC_CLOSE, (uint8_t)std::stoul(v));
        else if (k == "f5_save_f6_load") write_glob_u8(ADDR_SETTING_F5_SAVE_F6_LOAD, (uint8_t)std::stoul(v));
        else if (k == "f9_screenshot") write_glob_u8(ADDR_SETTING_F9_SCREENSHOT, (uint8_t)std::stoul(v));
        else if (k == "treat_close_as_esc") write_glob_u8(ADDR_SETTING_TREAT_CLOSE_AS_ESC, (uint8_t)std::stoul(v));
        else if (k == "priority") write_glob_u32(ADDR_SETTING_PRIORITY, (uint32_t)std::stoul(v));
        else if (k == "freeze_on_lose_focus") write_glob_bool(ADDR_SETTING_FREEZE_ON_LOSE_FOCUS, v=="1");
        else if (k == "allow_resize") write_glob_bool(ADDR_SETTING_ALLOW_RESIZE, v=="1");
        else if (k == "window_on_top") write_glob_bool(ADDR_SETTING_WINDOW_ON_TOP, v=="1");
        else if (k == "set_resolution") write_glob_bool(ADDR_SETTING_SET_RESOLUTION, v=="1");
        // gm82save writes the loading-bar type as "custom_bar"; accept the old
        // "loading_bar" key too for files saved by earlier versions of this plugin.
        else if (k == "custom_bar" || k == "loading_bar")
            write_glob_u32(ADDR_SETTING_LOADING_BAR, (uint32_t)std::stoul(v));
        else if (k == "show_error_messages") write_glob_u8(0x1E9420, (uint8_t)std::stoul(v));// byte_5E9420
        else if (k == "log_errors") write_glob_u8(0x1E9424, (uint8_t)std::stoul(v));         // byte_5E9424
        else if (k == "always_abort") write_glob_u8(0x1E9428, (uint8_t)std::stoul(v));       // byte_5E9428
        else if (k == "zero_uninitialized_vars") write_glob_u8(0x1E942C, (uint8_t)std::stoul(v)); // byte_5E942C
        // Loading-bar look (GM 8.0 globals verified from sub_59DD5C):
        else if (k == "custom_loader") write_glob_u8(0x1E9400, (uint8_t)std::stoul(v));          // byte_5E9400
        else if (k == "transparent") write_glob_u8(0x1E9410, (uint8_t)std::stoul(v));            // byte_5E9410
        else if (k == "translucency") write_glob_u32(0x1E9414, (uint32_t)std::stoul(v));         // dword_5E9414
        else if (k == "scale_progress_bar") write_glob_u8(0x1E9418, (uint8_t)std::stoul(v));     // byte_5E9418
        // Version number quad (dword_5E943C/40/44/48 — .gmk save writes 4×u32)
        else if (k == "exe_version") {
            // metadata only; the GM globals are written by load_settings caller
        }
    });

    // Loading-bar bitmaps: settings/back.bmp → dword_5E940C, front.bmp →
    // dword_5E9408, loader.bmp → dword_5E9404 (GM 8.0 TBitmap objects;
    // verified from sub_59DD5C which uses sub_59DCD0 = stream → TBitmap via
    // GM80_TBitmap_Create + LoadFromStream at vtable+0x54).
    // Class references are VMT metadata-block addresses: TBitmap = 0x42D15C
    // (off_42D110 holds it), TIcon = 0x42D248. NOT the first virtual method
    // (0x41CE44 / 0x435F50) which is what dereferencing would yield.
    gm80l_log("Load: settings parse done, loading bar bitmaps...");
    // Class ref [0x42D110] = GM's loading-bar bitmap class (sub_4EAC48).
    // Was 0x42D15C (= sub_59DCD0's general bitmap class) → wrong class → AV.
    load_image_file_safe(root, "back.bmp", 0x1E940C, 0x42D110);
    load_image_file_safe(root, "front.bmp", 0x1E9408, 0x42D110);
    load_image_file_safe(root, "loader.bmp", 0x1E9404, 0x42D110);
    gm80l_log("Load: bar bitmaps done, loading icon...");
    load_icon_file_safe(root, "icon.ico", 0x1E941C);
    gm80l_log("Load: icon done");

    // Version number globals from the root metadata (dword_5E943C..48)
    {
        fs::path metaFile;
        for (auto& entry : fs::directory_iterator(root)) {
            auto ext = entry.path().extension().string();
            if (ext == ".gm80" || entry.path().filename().string().find(".gm80") != std::string::npos) {
                metaFile = entry.path();
                break;
            }
        }
        if (!metaFile.empty()) {
            std::string meta = read_file(metaFile);
            parse_kv(meta, [&](auto& k, auto& v) {
                if (k == "exe_version") {
                    int parts[4] = {0, 0, 0, 0};
                    int idx = 0;
                    std::string cur;
                    for (char c : v) {
                        if (c == '.') { if (idx < 4) parts[idx++] = atoi(cur.c_str()); cur.clear(); }
                        else cur += c;
                    }
                    if (idx < 4) parts[idx] = atoi(cur.c_str());
                    write_glob_u32(0x1E943C, (uint32_t)parts[0]);
                    write_glob_u32(0x1E9440, (uint32_t)parts[1]);
                    write_glob_u32(0x1E9444, (uint32_t)parts[2]);
                    write_glob_u32(0x1E9448, (uint32_t)parts[3]);
                }
            });
        }
    }

    // Load constants
    fs::path constPath = root / "settings" / "constants.txt";
    std::string constants = read_file(constPath);
    if (!constants.empty()) {
        std::vector<std::string> names, values;
        std::istringstream css(constants);
        std::string line;
        while (std::getline(css, line)) {
            if (line.empty()) continue;
            auto eq = line.find('=');
            if (eq != std::string::npos) {
                names.push_back(line.substr(0, eq));
                values.push_back(line.substr(eq + 1));
            }
        }
        uint32_t cnt = (uint32_t)names.size();
        if (cnt > 0) {
            // GM 8.0 constant lists (verified GM80_LoadConstants 0x573514):
            //   names array 0x1F1C90, values array 0x1F1C94 (Delphi dynamic
            //   arrays via @DynArraySetLength), count 0x1E932C (GM80_Count_Constants),
            //   timestamp 0x1F1CA0. Type infos off_57346C (UStr name) / 573494.
            // The previous 0x1E91C8/0x1E91CC/0x1E91D8 had NO xrefs — wrong.
            uint8_t* b = (uint8_t*)g_load_base;
            uint32_t fn = (uint32_t)b + 0x6A38; // @DynArraySetLength (ADDR_DYN_ARRAY_SETLENGTH, defined later)
            for (int which = 0; which < 2; which++) {
                uint32_t arrAddr = (uint32_t)b + (which ? 0x1F1C94 : 0x1F1C90);
                uint32_t ti = *(uint32_t*)(b + (which ? 0x173494 : 0x17346C));
                uint32_t* cur = *(uint32_t**)arrAddr;
                if (cur == (uint32_t*)-1) *(uint32_t**)arrAddr = nullptr;
                __asm {
                    mov eax, arrAddr
                    mov edx, ti
                    mov ecx, 1
                    push cnt
                    call fn
                    add esp, 4
                }
            }
            write_glob_u32(0x1E932C, cnt); // GM80_Count_Constants
            uint32_t* nameArr = *(uint32_t**)(b + 0x1F1C90);
            uint32_t* valArr  = *(uint32_t**)(b + 0x1F1C94);
            for (uint32_t i = 0; i < cnt; i++) {
                if (nameArr) nameArr[i] = (uint32_t)(uintptr_t)make_delphi_str(names[i]);
                if (valArr)  valArr[i]  = (uint32_t)(uintptr_t)make_delphi_str(values[i]);
            }
        }
    }
}

// Load Game Information (settings/gameinfo.txt → 0x1E936C text + byte flags).
// Mirrors GM80_SaveGameInfo 0x5991A0 fields: off_5E936C = the F1 help text,
// byte_5E9368 / byte_5E9380/84/88/8C = window flags.
static void* make_memory_stream(const std::string& data);

// Restore the F1 help text into the GameInfo RichEdit control.
// Chain: [0x5EAEE8] → [p] → +0x360 → +0x298 → vtable+0x6C (LoadFromStream).
// __try lives here in a POD-only frame (no C++ object unwinding).
static void restore_richtext(uint8_t* b, const uint8_t* data, uint32_t len) {
    __try {
        uint32_t p = *(uint32_t*)(b + 0x1EAEE8);
        uint32_t obj = p ? *(uint32_t*)p : 0;
        uint32_t sub = obj ? *(uint32_t*)(obj + 0x360) : 0;
        uint32_t re = sub ? *(uint32_t*)(sub + 0x298) : 0;
        if (!(re && re >= 0x10000) || !data || len == 0) return;
        uint32_t streamCls = *(uint32_t*)(b + 0xEA854);
        if (streamCls < 0x400000) streamCls = *(uint32_t*)(b + 0xEA8A0);
        void* stream = nullptr;
        __asm {
            mov dl, 1
            mov eax, streamCls
            mov ecx, 0x404560
            call ecx
            mov stream, eax
        }
        if (!stream) return;
        char* bufPtr = (char*)data;
        uint32_t bufLen = len;
        __asm {
            mov eax, stream
            mov edx, bufPtr
            mov ecx, bufLen
            mov ebx, 0x41F8E8
            call ebx
        }
        *(uint32_t*)((uint8_t*)stream + 12) = 0; // FPosition
        __asm {
            mov eax, re
            mov edx, stream
            mov ecx, [eax]
            call dword ptr [ecx+0x6C]   // RichEdit.LoadFromStream
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Apply the game info background colour via sub_460D00 (SetColor: writes
// [editor+0x70], clears [editor+0x5A], redraws). __try in a POD-only frame.
static void restore_gameinfo_color(uint8_t* b, uint32_t color) {
    __try {
        uint32_t p = *(uint32_t*)(b + 0x1EAEE8);
        uint32_t obj = p ? *(uint32_t*)p : 0;
        uint32_t ed = obj ? *(uint32_t*)(obj + 0x360) : 0;
        if (!(ed && ed >= 0x10000)) return;
        uint32_t fn = (uint32_t)b + 0x60D00; // sub_460D00 = TControl.SetColor
        __asm {
            mov eax, ed
            mov edx, color
            mov ebx, fn
            call ebx
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void load_gameinfo(const fs::path& root) {
    uint8_t* b = (uint8_t*)g_load_base;
    std::string txt = read_file(root / "settings" / "gameinfo.txt");
    if (!txt.empty()) {
        parse_kv(txt, [&](auto& k, auto& v) {
            if (k == "color") restore_gameinfo_color(b, (uint32_t)std::stoul(v));
            else if (k == "caption" || k == "text") write_glob_str(0x1E936C, decode_delimit(v));
            else if (k == "byte_9368") *(uint8_t*)(b + 0x1E9368) = (uint8_t)std::stoul(v);
            else if (k == "left") *(uint32_t*)(b + 0x1E9370) = (uint32_t)std::stoul(v);
            else if (k == "top") *(uint32_t*)(b + 0x1E9374) = (uint32_t)std::stoul(v);
            else if (k == "width") *(uint32_t*)(b + 0x1E9378) = (uint32_t)std::stoul(v);
            else if (k == "height") *(uint32_t*)(b + 0x1E937C) = (uint32_t)std::stoul(v);
            else if (k == "byte_9380") *(uint8_t*)(b + 0x1E9380) = (uint8_t)std::stoul(v);
            else if (k == "byte_9384") *(uint8_t*)(b + 0x1E9384) = (uint8_t)std::stoul(v);
            else if (k == "byte_9388") *(uint8_t*)(b + 0x1E9388) = (uint8_t)std::stoul(v);
            else if (k == "byte_938C") *(uint8_t*)(b + 0x1E938C) = (uint8_t)std::stoul(v);
        });
    }
    // F1 help text (RichEdit content) from settings/gameinfo.rtf.
    std::string rtf = read_file(root / "settings" / "gameinfo.rtf");
    if (!rtf.empty())
        restore_richtext(b, (const uint8_t*)rtf.data(), (uint32_t)rtf.size());
}

// Create a TMemoryStream filled with data (FPosition=0). Same class chain as
// the icon/loading-bar load (off_4EA854 → 0x4EA8A0).
static void* make_memory_stream(const std::string& data) {
    if (data.empty()) return nullptr;
    uint8_t* base = (uint8_t*)g_load_base;
    uint32_t streamCls = *(uint32_t*)(base + 0xEA854);
    if (streamCls < 0x400000) streamCls = *(uint32_t*)(base + 0xEA8A0);
    void* stream = nullptr;
    __asm {
        mov dl, 1
        mov eax, streamCls
        mov ecx, 0x404560
        call ecx
        mov stream, eax
    }
    if (!stream) return nullptr;
    char* bufPtr = (char*)data.data();
    uint32_t bufLen = (uint32_t)data.size();
    __asm {
        mov eax, stream
        mov edx, bufPtr
        mov ecx, bufLen
        mov ebx, 0x41F8E8
        call ebx
    }
    *(uint32_t*)((uint8_t*)stream + 12) = 0; // FPosition
    return stream;
}

// Load included files (datafiles/) — gm82save format.
// GM 8.0 (verified GM80_LoadIncludedFiles 0x59ADA4): count 0x1E9398, object
// array 0x1E9390 (SetLength via off_59AC58 type info), timestamps 0x1E9394
// (off_59AC80). Object ctor GM80_IncludedFile_Create (0x5997B8), class ref
// [0x599714]=0x5993E0. Fields: +4 name, +8 source_path, +12 data_exists,
// +16 source_length, +20 stored_in_gmk, +24 data TMemoryStream*,
// +28 export_setting, +32 export_folder, +36 overwrite, +37 free, +38 remove.
static void load_included_files(const fs::path& root) {
    std::string idx = read_file(root / "datafiles" / "index.yyd");
    if (idx.empty()) return;
    std::vector<std::string> names;
    std::istringstream ss(idx);
    std::string line;
    while (std::getline(ss, line)) if (!line.empty()) names.push_back(line);
    uint32_t cnt = (uint32_t)names.size();
    if (cnt == 0 || cnt > 10000) return;
    uint8_t* b = (uint8_t*)g_load_base;
    // SetLength object + timestamp arrays
    uint32_t fn = (uint32_t)b + 0x6A38; // @DynArraySetLength
    for (int which = 0; which < 2; which++) {
        uint32_t arrAddr = (uint32_t)b + (which ? 0x1E9394 : 0x1E9390);
        uint32_t ti = *(uint32_t*)(b + (which ? 0x19AC80 : 0x19AC58));
        uint32_t* cur = *(uint32_t**)arrAddr;
        if (cur == (uint32_t*)-1) *(uint32_t**)arrAddr = nullptr;
        __asm {
            mov eax, arrAddr
            mov edx, ti
            mov ecx, 1
            push cnt
            call fn
            add esp, 4
        }
    }
    write_glob_u32(0x1E9398, cnt);
    uint32_t* objArr = *(uint32_t**)(b + 0x1E9390);
    uint32_t cls = *(uint32_t*)(b + 0x199714); // [0x599714] = IncludedFile class ref
    for (uint32_t i = 0; i < cnt; i++) {
        void* f = nullptr;
        __asm {
            mov eax, cls
            mov dl, 1
            xor ecx, ecx
            mov ebx, 0x5997B8          // GM80_IncludedFile_Create
            call ebx
            mov f, eax
        }
        if (!f || f == (void*)cls) continue;
        std::string meta = read_file(root / "datafiles" / (names[i] + ".txt"));
        bool stored = false, overwrite = false, freeMem = false, removeAtEnd = false;
        uint32_t exportSetting = 0;
        std::string exportFolder;
        parse_kv(meta, [&](auto& k, auto& v) {
            if (k == "store") stored = (v == "1");
            else if (k == "overwrite") overwrite = (v == "1");
            else if (k == "free") freeMem = (v == "1");
            else if (k == "remove") removeAtEnd = (v == "1");
            else if (k == "export") exportSetting = (uint32_t)std::stoul(v);
            else if (k == "export_folder") exportFolder = v;
        });
        set_obj_str(f, 4, names[i]);
        set_obj_str(f, 8, (root / "datafiles" / "include" / names[i]).string());
        set_obj_u32(f, 28, exportSetting);
        if (!exportFolder.empty()) set_obj_str(f, 32, exportFolder);
        *(uint8_t*)((uint8_t*)f + 36) = overwrite ? 1 : 0;
        *(uint8_t*)((uint8_t*)f + 37) = freeMem ? 1 : 0;
        *(uint8_t*)((uint8_t*)f + 38) = removeAtEnd ? 1 : 0;
        std::string content = read_file(root / "datafiles" / "include" / names[i]);
        if (stored && !content.empty()) {
            *(uint8_t*)((uint8_t*)f + 12) = 1;   // data_exists
            set_obj_u32(f, 16, (uint32_t)content.size()); // source_length
            *(uint8_t*)((uint8_t*)f + 20) = 1;   // stored_in_gmk
            set_obj_ptr(f, 24, make_memory_stream(content));
        } else {
            *(uint8_t*)((uint8_t*)f + 20) = stored ? 1 : 0;
        }
        if (objArr) objArr[i] = (uint32_t)(uintptr_t)f;
    }
    *(uint8_t*)(b + 0x1F6210) = 0; // clear updated flag
}

// ==== Load extensions (settings/extensions.txt → loaded flags) ====
// GM 8.0 (verified sub_5A80A8 name lookup + sub_5A7FF0 loaded check +
// sub_5A7910 init: SetLength(&0x6000BC, n) → dword_6000BC is a Delphi
// dynamic array VARIABLE holding the element pointer):
//   0x1E9460 = extension object array (dynamic array), 0x1E9464 = count,
//   0x2000BC = loaded flags (dynamic array of bytes)
// Extension object: +4 = name (AnsiString). Same semantics as gm82save
// load_extensions: match name → set loaded → GM shows it in the tree.
static void load_extensions(const fs::path& root) {
    std::string txt = read_file(root / "settings" / "extensions.txt");
    if (txt.empty()) return;
    uint8_t* b = (uint8_t*)g_load_base;
    uint32_t cnt = *(uint32_t*)(b + 0x1E9464);
    uint32_t* arr = *(uint32_t**)(b + 0x1E9460);
    uint8_t* flags = *(uint8_t**)(b + 0x2000BC); // deref the dynamic array var!
    if (!arr || !flags || cnt == 0 || cnt > 1000) return;
    std::istringstream ss(txt);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty()) continue;
        for (uint32_t i = 0; i < cnt; i++) {
            uint32_t obj = arr[i];
            if (!obj) continue;
            char* namePtr = *(char**)((uint8_t*)(uintptr_t)obj + 4);
            if (!namePtr) continue;
            uint32_t len = *(uint32_t*)(namePtr - 4);
            if (len > 500) continue;
            if (std::string(namePtr, len) == line) {
                flags[i] = 1; // loaded flag
                break;
            }
        }
    }
}

// ==== Load trigger ====
static void* load_trigger(const std::string& name, const fs::path& trigDir) {
    fs::path txtPath = trigDir / (name + ".txt");
    fs::path gmlPath = trigDir / (name + ".gml");
    std::string txt = read_file(txtPath);
    std::string gml = read_file(gmlPath);

    const ResInfo* ri = find_res("triggers");
    if (!ri) return nullptr;

    uint32_t trig_vmt = 0x55C304;
    void* trig = delphi_ctor(trig_vmt, 0x55C358);
    if (trig == (void*)trig_vmt) trig = nullptr;
    if (!trig) return nullptr;

    // Trigger fields: +4=name, +8=condition, +12=constant_name, +16=kind
    set_obj_str(trig, 4, name);
    set_obj_str(trig, 8, load_gml(gml));

    std::string cnst, kind;
    parse_kv(txt, [&](auto& k, auto& v) {
        if (k == "constant") cnst = v;
        else if (k == "kind") kind = v;
    });
    set_obj_str(trig, 12, cnst);
    set_obj_u32(trig, 16, kind.empty() ? 0 : (uint32_t)std::stoul(kind));

    return trig;
}

// ==== Load script ====
static void* load_script(const std::string& name, const fs::path& scriptDir) {
    fs::path gmlPath = scriptDir / (name + ".gml");
    std::string gml = read_file(gmlPath);

    const ResInfo* ri = find_res("scripts");
    if (!ri) return nullptr;

    void* sc = make_obj_with_arr(ri->arrObjOff, ri->vmtRva, ri->ctorRva);
    if (!sc) return nullptr;

    // Script: +4=source (AnsiString, verified: save side reads RS(obj,4)).
    // Name lives in the parallel name array (load_assets_simple), not the object.
    set_obj_str(sc, 4, load_gml(gml));

    return sc;
}

// ==== Load font ====
static void* load_font(const std::string& name, const fs::path& fontDir) {
    fs::path txtPath = fontDir / (name + ".txt");
    std::string txt = read_file(txtPath);

    const ResInfo* ri = find_res("fonts");
    if (!ri) return nullptr;

    void* font = make_obj_with_arr(ri->arrObjOff, ri->vmtRva, ri->ctorRva);
    if (!font) return nullptr;

    // +4 = sys_name (font FAMILY name, e.g. "Arial"), NOT the resource name.
    // The resource name goes to the parallel names array (load_assets_simple);
    // overwriting +4 here with the resource name made the font unrenderable.
    // Verified: GM's font load (sub_557B2C) stores the stream string at [font+4];
    // gm82save Font { vmt, sys_name: UStr, size, bold, italic, ... }.
    parse_kv(txt, [&](auto& k, auto& v) {
        // GM 8.0 has no charset/aa_level fields (save side hardcodes 0)
        if (k == "name") set_obj_str(font, 4, v);
        else if (k == "size") set_obj_u32(font, 8, (uint32_t)std::stoul(v));
        else if (k == "bold") set_obj_bool(font, 12, v == "1");
        else if (k == "italic") set_obj_bool(font, 13, v == "1");
        else if (k == "range_start") set_obj_u32(font, 16, (uint32_t)std::stoul(v));
        else if (k == "range_end") set_obj_u32(font, 20, (uint32_t)std::stoul(v));
    });

    return font;
}

// ==== Load sound ====
// GM 8.0 layout (verified via IDA GM80_Sound_Create 0x5447A0 +
// SaveSound_Individual 0x544B8C + LoadSound_Individual 0x5449C8, 2026-08-02):
//   +4 kind, +8 name (AnsiString), +12 effects (i32), +16 filename/source,
//   +24 volume (double, ctor=1.0), +32 pan (double, ctor=0.0),
//   +40 preload (byte), +44 data (TMemoryStream*), +48 internal (ctor -1)
// (Note: effects/volume/pan were previously at +48/+32/+24 — wrong.)
static void* load_sound(const std::string& name, const fs::path& sndDir) {
    fs::path txtPath = sndDir / (name + ".txt");
    std::string txt = read_file(txtPath);

    const ResInfo* ri = find_res("sounds");
    if (!ri) return nullptr;

    void* snd = make_obj_with_arr(ri->arrObjOff, ri->vmtRva, ri->ctorRva);
    if (!snd) return nullptr;

    std::string ext, src;
    bool exists = false;
    parse_kv(txt, [&](auto& k, auto& v) {
        if (k == "extension") ext = v;
        else if (k == "source") src = v;
        else if (k == "exists") exists = (v == "1");
        else if (k == "kind") set_obj_u32(snd, 4, (uint32_t)std::stoul(v));
        else if (k == "effects") set_obj_i32(snd, 12, std::stoi(v));
        else if (k == "volume") set_obj_f64(snd, 24, std::stod(v));
        else if (k == "pan") set_obj_f64(snd, 32, std::stod(v));
        else if (k == "preload") set_obj_bool(snd, 40, v == "1");
    });
    set_obj_str(snd, 8, name);   // name lives both in object +8 and parallel array
    if (!src.empty()) set_obj_str(snd, 16, utf8_to_ansi(src)); // file is UTF-8, GM stores AnsiString

    // Load audio binary data into a TMemoryStream at +44
    if (exists && !ext.empty()) {
        std::string extClean = ext;
        if (extClean[0] == '.') extClean = extClean.substr(1);
        fs::path audioPath = sndDir / (name + "." + extClean);
        if (file_exists(audioPath)) {
            std::string audioData = read_file(audioPath);
            if (!audioData.empty()) {
                void* ms = make_delphi_stream(audioData.data(), (uint32_t)audioData.size());
                if (ms) set_obj_ptr(snd, 44, ms);
            }
        }
    }

    return snd;
}

// ==== Load frame (PNG → BGRA pixel data) ====
struct DelphiFrame {
    uint32_t vmt;
    uint32_t width;
    uint32_t height;
    uint8_t* data;
};

// Load PNG → BGRA8 pixel data using stb_image (matches save_png's WIC BGRA output)
static bool load_frame_png(const fs::path& pngPath, uint32_t& width, uint32_t& height, std::vector<uint8_t>& out) {
    std::string bytes = read_file(pngPath);
    if (bytes.empty()) return false;

    int w = 0, h = 0, comp = 0;
    stbi_uc* rgba = stbi_load_from_memory((const stbi_uc*)bytes.data(), (int)bytes.size(),
                                          &w, &h, &comp, 4);
    if (!rgba || w <= 0 || h <= 0) return false;

    width = (uint32_t)w; height = (uint32_t)h;
    out.resize((size_t)w * h * 4);
    // RGBA → BGRA (GM frame data layout, same as save_png output)
    for (size_t i = 0; i < (size_t)w * h; i++) {
        out[i*4+0] = rgba[i*4+2];
        out[i*4+1] = rgba[i*4+1];
        out[i*4+2] = rgba[i*4+0];
        out[i*4+3] = rgba[i*4+3];
    }
    stbi_image_free(rgba);
    return true;
}

// ==== Load sprite ====
// GM 8.0 layout (verified via IDA GM80_SaveSprite_Individual + GM80_Sprite_Create):
//   +4 frame_count, +16 origin_x, +20 origin_y, +24 per_frame_colliders(byte),
//   +28 bbox_left, +32 bbox_top, +36 bbox_type, +40 bbox_right, +44 bbox_bottom,
//   +48 frames (Frame** raw array, NOT TList)
// Name lives in the parallel name array (load_assets_simple), NOT at +4.
// Frame: +4 width, +8 height, +12 pixel data (BGRA8, top-down — same as save_png).
static void* load_sprite_obj(const std::string& name, const fs::path& spriteDir) {
    const ResInfo* ri = find_res("sprites");
    if (!ri) return nullptr;

    fs::path subDir = spriteDir / name;
    fs::path txtPath = subDir / "sprite.txt";
    std::string txt = read_file(txtPath);

    uint32_t sp_vmt = get_real_vmt(ri->arrObjOff, ri->vmtRva);
    void* sp = delphi_ctor(sp_vmt, (uint32_t)glob_base() + ri->ctorRva);
    if (!sp || sp == (void*)sp_vmt) { gm80l_log("Sprite %s: ctor FAILED", name.c_str()); return nullptr; }

    uint32_t frameCount = 0;
    // GM 8.0 layout (verified from sub_4F8E40 .gmk loader order + GM 8.1
    // equivalent): +8 origin_x, +12 origin_y, +16 collision_shape,
    // +20 alpha_tolerance, +24 per_frame_colliders, +28 bbox_left,
    // +32 bbox_top, +36 bbox_type, +40 bbox_right, +44 bbox_bottom
    parse_kv(txt, [&](auto& k, auto& v) {
        try {
        if (k == "origin_x") set_obj_i32(sp, 8, std::stoi(v));
        else if (k == "origin_y") set_obj_i32(sp, 12, std::stoi(v));
        else if (k == "collision_shape") set_obj_u32(sp, 16, (uint32_t)std::stoul(v));
        else if (k == "alpha_tolerance") set_obj_u32(sp, 20, (uint32_t)std::stoul(v));
        else if (k == "per_frame_colliders") set_obj_bool(sp, 24, v == "1");
        else if (k == "bbox_left") set_obj_i32(sp, 28, std::stoi(v));
        else if (k == "bbox_top") set_obj_i32(sp, 32, std::stoi(v));
        else if (k == "bbox_type") set_obj_u32(sp, 36, (uint32_t)std::stoul(v));
        else if (k == "bbox_right") set_obj_i32(sp, 40, std::stoi(v));
        else if (k == "bbox_bottom") set_obj_i32(sp, 44, std::stoi(v));
        else if (k == "frames") frameCount = (uint32_t)std::stoul(v);
        } catch(...) { gm80l_log("  WARN: sprite field parse error for %s key=%s", name.c_str(), k.c_str()); }
    });

    // Load frames (PNG) into a raw Frame** array at +48
    if (frameCount > 0 && frameCount < 10000) {
        void** frames = (void**)delphi_alloc(frameCount * sizeof(void*));
        uint32_t loaded = 0;
        for (uint32_t i = 0; i < frameCount; i++) {
            fs::path pngPath = subDir / (std::to_string(i) + ".png");
            if (!file_exists(pngPath)) continue;

            uint32_t fw = 0, fh = 0;
            std::vector<uint8_t> pixels;
            if (!load_frame_png(pngPath, fw, fh, pixels)) {
                gm80l_log("  WARN: cannot decode %ls", pngPath.c_str());
                continue;
            }

            // Pixel data via Delphi GetMem
            uint8_t* data = (uint8_t*)delphi_alloc((uint32_t)pixels.size());
            if (!data) continue;
            memcpy(data, pixels.data(), pixels.size());

            // Frame object: VMT from off_4F29D4 (verified: GM80_Background_Create
            // uses mov eax, ds:off_4F29D4 → 0x4F2A20, static data), ctor GM80_Frame_Create
            void* frame = make_obj_with_arr(0, 0xF29D4, 0xF2AA0);
            if (!frame) { delphi_free(data); continue; }
            set_obj_u32(frame, 4, fw);
            set_obj_u32(frame, 8, fh);
            set_obj_ptr(frame, 12, data);
            frames[loaded++] = frame;
        }
        if (loaded > 0) {
            set_obj_ptr(sp, 48, frames);
            set_obj_u32(sp, 4, loaded);
        } else {
            delphi_free(frames);
        }
    }

    return sp;
}

// ==== Load background ====
// GM 8.0 layout (verified via IDA GM80_Background_Create + save_background):
//   +4 Frame* (created by ctor GM80_Background_Create → GM80_Frame_Create),
//   +8 tileset(byte), +12 tile_width, +16 tile_height, +20 tile_hoffset,
//   +24 tile_voffset, +28 tile_hsep, +32 tile_vsep
// Name lives in the parallel name array (load_assets_simple), NOT at +4.
// Frame: +4 width, +8 height, +12 pixel data.
static void* load_bg_obj(const std::string& name, const fs::path& bgDir) {
    const ResInfo* ri = find_res("backgrounds");
    if (!ri) return nullptr;

    fs::path txtPath = bgDir / (name + ".txt");
    std::string txt = read_file(txtPath);

    uint32_t bg_vmt = get_real_vmt(ri->arrObjOff, ri->vmtRva);
    void* bg = delphi_ctor(bg_vmt, (uint32_t)g_load_base + ri->ctorRva);
    if (bg == (void*)bg_vmt) bg = nullptr;
    if (!bg) return nullptr;

    bool exists = false;
    parse_kv(txt, [&](auto& k, auto& v) {
        if (k == "exists") exists = (v == "1");
        else if (k == "tileset") set_obj_bool(bg, 8, v == "1");
        else if (k == "tile_width") set_obj_u32(bg, 12, (uint32_t)std::stoul(v));
        else if (k == "tile_height") set_obj_u32(bg, 16, (uint32_t)std::stoul(v));
        else if (k == "tile_hoffset") set_obj_u32(bg, 20, (uint32_t)std::stoul(v));
        else if (k == "tile_voffset") set_obj_u32(bg, 24, (uint32_t)std::stoul(v));
        else if (k == "tile_hsep") set_obj_u32(bg, 28, (uint32_t)std::stoul(v));
        else if (k == "tile_vsep") set_obj_u32(bg, 32, (uint32_t)std::stoul(v));
    });

    if (exists) {
        fs::path pngPath = bgDir / (name + ".png");
        if (file_exists(pngPath)) {
            uint32_t fw = 0, fh = 0;
            std::vector<uint8_t> pixels;
            if (load_frame_png(pngPath, fw, fh, pixels)) {
                uint8_t* data = (uint8_t*)delphi_alloc((uint32_t)pixels.size());
                if (data) {
                    memcpy(data, pixels.data(), pixels.size());
                    // Frame object was created by the background ctor at +4
                    void* frame = *(void**)((uint8_t*)bg + 4);
                    if (frame) {
                        set_obj_u32(frame, 4, fw);
                        set_obj_u32(frame, 8, fh);
                        set_obj_ptr(frame, 12, data);
                    } else {
                        delphi_free(data);
                    }
                }
            }
        }
    }

    return bg;
}

// ==== Load path ====
// GM 8.0 layout (verified from sub_5470CC editor copy — identical to GM 8.1):
//   +4 points (DelphiList dynamic array, 24 bytes/point: x/y/speed doubles),
//   +8 point_count, +12 connection(u32), +16 closed(byte), +20 precision,
//   +40 room_bg (i32, -1), +44 snap_x, +48 snap_y
// Name lives in the parallel name array (load_assets_simple).
static void* load_path_obj(const std::string& name, const fs::path& pathDir) {
    const ResInfo* ri = find_res("paths");
    if (!ri) return nullptr;

    fs::path subDir = pathDir / name;
    fs::path txtPath = subDir / "path.txt";
    fs::path ptsPath = subDir / "points.txt";
    std::string txt = read_file(txtPath);

    void* pp = make_obj_with_arr(ri->arrObjOff, ri->vmtRva, ri->ctorRva);
    if (!pp) return nullptr;

    // +12 connection (sub_5470CC: *(a1+12)=*(a2+12)), +16 closed (byte),
    // +20 precision (ctor=4)
    parse_kv(txt, [&](auto& k, auto& v) {
        if (k == "connection") set_obj_u32(pp, 12, (uint32_t)std::stoul(v));
        else if (k == "closed") set_obj_bool(pp, 16, v == "1");
        else if (k == "precision") set_obj_u32(pp, 20, (uint32_t)std::stoul(v));
        else if (k == "background") set_obj_i32(pp, 40, v.empty() ? -1 : std::stoi(v));
        else if (k == "snap_x") set_obj_u32(pp, 44, (uint32_t)std::stoul(v));
        else if (k == "snap_y") set_obj_u32(pp, 48, (uint32_t)std::stoul(v));
    });

    // Load points into a Delphi dynamic array at +4
    // (header [refcount][length] then 24-byte points: x,y,speed as doubles)
    std::string pts = read_file(ptsPath);
    if (!pts.empty()) {
        uint32_t ptCount = 0;
        double coords[768]; // up to 256 points × 3
        std::istringstream pss(pts);
        std::string line;
        while (std::getline(pss, line) && ptCount < 256) {
            if (line.empty()) continue;
            auto c1 = line.find(',');
            auto c2 = line.find(',', c1 + 1);
            if (c1 == std::string::npos) continue;
            coords[ptCount*3+0] = std::stod(line.substr(0, c1));
            coords[ptCount*3+1] = (c2 != std::string::npos)
                ? std::stod(line.substr(c1 + 1, c2 - c1 - 1))
                : std::stod(line.substr(c1 + 1));
            coords[ptCount*3+2] = (c2 != std::string::npos) ? std::stod(line.substr(c2 + 1)) : 100.0;
            ptCount++;
        }
        if (ptCount > 0) {
            void* mem = delphi_alloc(8 + ptCount * 24);
            if (mem) {
                *(uint32_t*)mem = 1;              // refcount
                *(uint32_t*)((uint8_t*)mem + 4) = ptCount; // length
                double* dst = (double*)((uint8_t*)mem + 8);
                for (uint32_t i = 0; i < ptCount; i++)
                    for (int j = 0; j < 3; j++)
                        dst[i*3+j] = coords[i*3+j];
                set_obj_ptr(pp, 4, dst);          // +4 = element pointer
                set_obj_u32(pp, 8, ptCount);      // +8 = count
            }
        }
    }

    // Regenerate the spline table (+24 spline array / +28 count / +32 length):
    // GM 8.0 loads .gmk paths then calls sub_547030 (RVA 0x147030), which
    // builds Catmull-Rom (connection=0) or linear (connection=1) spline data
    // from the points array. Without it the path editor draws no connecting
    // line (v52 = +32/4 == 0 in sub_555324) and the interpolator sub_547528
    // always returns the first point. Same call is made by the editor copy
    // function sub_5470CC, so this must run on the loaded object too.
    {
        uint8_t* b = glob_base();
        uint32_t fn = (uint32_t)b + 0x147030;
        __asm {
            mov eax, pp
            call fn
        }
    }

    return pp;
}

static std::vector<std::string> load_names(const fs::path& idxPath); // defined below

// ==== Object events (object.gml → Event/Action Delphi objects) ====
// GM 8.0 (verified from sub_4F1A18/sub_59713C/GM80_Event_AddAction):
//   Event: +4 actions (DelphiList), +8 action_count
//   Event ctor: sub_4F1A18(off_4F1978 value, 1, &tmp)
//   AddAction: GM80_Event_AddAction(event, 0, 0) — handles SetLength + ctor
// GM 8.0 Action: +4 lib_id, +8 id, +12 kind, +16 can_be_relative(byte),
//   +17 is_condition, +18 applies_to_something, +20 execution_type,
//   +24 fn_name(str), +28 fn_code(str), +32 param_count,
//   +36..+68 param_types[8], +68 applies_to, +72 is_relative(byte),
//   +76..+108 param_strings[8], +108 invert_condition(byte)
static void* make_event() {
    uint8_t* b = glob_base();
    uint32_t cls = *(uint32_t*)(b + 0xF1978); // off_4F1978 = Event class ref
    uint32_t fn = (uint32_t)b + 0xF1A18;      // sub_4F1A18
    uint32_t tmp = 0;
    void* ev = nullptr;
    __asm {
        mov eax, cls
        mov edx, 1
        lea ecx, tmp
        call fn
        mov ev, eax
    }
    if (!ev || ev == (void*)cls) gm80l_log("make_event FAILED cls=0x%X", cls);
    return ev;
}

static void* event_add_action(void* ev) {
    uint8_t* b = glob_base();
    uint32_t fn = (uint32_t)b + 0xF1BA4;      // GM80_Event_AddAction
    void* act = nullptr;
    __asm {
        mov eax, ev
        xor edx, edx
        xor ecx, ecx
        call fn
        mov act, eax
    }
    return act;
}

// YYD ACTION token that separates action blocks (same as save side)
static const char* const ACTION_TOKEN = "/*\"/*'/**//* YYD ACTION";

// Manual equivalent of GM80_Action_FillIn (0x5A6620): copy the action-library
// template's defaults into the action. GM's own FillIn is unusable during
// our load — it raises STATUS_PRIVILEGED_INSTRUCTION (0xC0000096) inside the
// library search, swallowed by SEH — so replicate its field copies in pure
// C++. Layouts verified from FillIn's asm: library array at base+0x209D08
// (array body, count at base+0x1E9468), library object +8 id / +0x2C action
// count / +0x30 action array, template +8 id / +0x28 kind / +0x32
// can_be_relative / +0x30 is_condition / +0x31 applies_to_something /
// +0xB8 execution_type / +0x34 param_count / +0x58+4i param_types.
// Mirrors gm82save's Action::fill_in — the template's action_kind is
// authoritative: Execute Code is kind 7 even with empty code.
static bool gm80_action_fill_in(void* act, uint32_t libId, uint32_t actId) {
    uint8_t* b = (uint8_t*)g_load_base;
    if (!b || !act) return false;
    uint32_t libCnt = *(uint32_t*)(b + 0x1E9468);
    uint32_t* libs = (uint32_t*)(b + 0x209D08);
    if (libCnt == 0 || libCnt > 64) return false;
    for (uint32_t li = 0; li < libCnt; li++) {
        uint32_t lpv = libs[li];
        if (!lpv || IsBadReadPtr((void*)lpv, 0x100)) continue;
        uint8_t* lib = (uint8_t*)(uintptr_t)lpv;
        if (*(uint32_t*)(lib + 8) != libId) continue;
        uint32_t acnt = *(uint32_t*)(lib + 44);
        if (acnt == 0 || acnt > 4096) continue;
        uint32_t* acts = *(uint32_t**)(lib + 48);
        if (!acts || IsBadReadPtr(acts, acnt * 4)) continue;
        for (uint32_t ai = 0; ai < acnt; ai++) {
            uint8_t* tpl = (uint8_t*)(uintptr_t)acts[ai];
            if (!tpl || IsBadReadPtr(tpl, 0xC8)) continue;
            if (*(uint32_t*)(tpl + 8) != actId) continue;
            // Found — copy the fields FillIn would copy:
            set_obj_u32(act, 12, *(uint32_t*)(tpl + 40));      // action_kind
            set_obj_bool(act, 16, *(uint8_t*)(tpl + 50) != 0); // can_be_relative
            set_obj_bool(act, 17, *(uint8_t*)(tpl + 48) != 0); // is_condition
            set_obj_bool(act, 18, *(uint8_t*)(tpl + 49) != 0); // applies_to_something
            set_obj_u32(act, 20, *(uint32_t*)(tpl + 184));     // execution_type
            set_obj_u32(act, 32, *(uint32_t*)(tpl + 52));      // param_count
            for (int i = 0; i < 8; i++)
                set_obj_u32(act, 36 + i * 4, *(uint32_t*)(tpl + 88 + i * 4)); // param_types
            return true;
        }
    }
    return false;
}

// Advance GM's progress bar (sub_5996B8) to an ABSOLUTE position 0..100 —
// the position is passed in EAX (sub_5996B8 forwards it to PBM_SETPOS via
// sub_49C530; GM's own callers do `mov eax, N; call sub_5996B8`). The
// progress form is shown by GM80_LoadRecentProject before our hook runs.
void gm80_progress_step(int pos) {
    if (pos < 0) pos = 0;
    if (pos > 100) pos = 100;
    uint8_t* b = (uint8_t*)g_load_base;
    if (!b) b = (uint8_t*)GetModuleHandle(NULL);
    if (!b) return;
    uint32_t fn = (uint32_t)b + 0x1996B8;
    __asm {
        mov eax, pos
        call fn
    }
}

// SEH wrapper for FillIn — must be its own function: __try cannot coexist
// with C++ objects needing unwinding. The library-template search AVs when
// GM hasn't built the library array yet; catch it here so GM's SEH never
// sees it (it would swallow the whole load as "corrupt file").
static bool fill_in_safe(void* act, uint32_t libId, uint32_t actId) {
    __try {
        return gm80_action_fill_in(act, libId, actId);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        gm80l_log("fill_in_safe: AV code=0x%X lib=%u id=%u act=0x%X",
                  GetExceptionCode(), libId, actId, (uint32_t)act);
        return false;
    }
}


// Resource name → index maps for action parameters (gm82save parity: a
// resource-typed action param stores the INDEX in param_strings, converted
// from the name in the file. The save side reverses it via stoi → name).
struct AssetNameMaps {
    std::vector<std::string> sprites, sounds, bgs, paths, scripts,
                             objects, rooms, fonts, timelines;
    static int find(const std::vector<std::string>& v, const std::string& name) {
        for (size_t i = 0; i < v.size(); i++) if (v[i] == name) return (int)i;
        return -1;
    }
};
// Populated once per load in gm80_load_project before objects/timelines load.
static AssetNameMaps g_action_names;

// Parse YYD ACTION blocks from a body string into an Event (shared by
// objects and timelines). Matches gm82save's load_event + save side format.
static void parse_actions_into_event(void* ev, const std::string& body,
                                     const std::vector<std::string>& objectNames) {
    std::string b = body;
    size_t pos = 0;
    while ((pos = b.find(ACTION_TOKEN, pos)) != std::string::npos) {
        pos += strlen(ACTION_TOKEN);
        size_t end = b.find("*/\n", pos);
        std::string block = b.substr(pos, (end == std::string::npos) ? std::string::npos : end - pos);
        pos = (end == std::string::npos) ? b.size() : end + 3;
        std::string codeAfter;
        if (end != std::string::npos) {
            size_t nl = b.find_first_not_of("\r\n", end + 3);
            if (nl != std::string::npos) {
                size_t nextTok = b.find(ACTION_TOKEN, nl);
                codeAfter = b.substr(nl, (nextTok == std::string::npos) ? std::string::npos : nextTok - nl);
            }
        }
        void* act = event_add_action(ev);
        if (!act) continue;

        // Phase 1: lib_id/action_id first, then fill in the action-library
        // template (gm82save: action.fill_in after action_id is parsed).
        uint32_t libId = 0, actionId = 0;
        parse_kv(block, [&](auto& k, auto& v) {
            if (k == "lib_id") libId = (uint32_t)std::stoul(v);
            else if (k == "action_id") actionId = (uint32_t)std::stoul(v);
        });
        bool templFound = false;
        if (libId != 0 || actionId != 0) {
            set_obj_u32(act, 4, libId);
            set_obj_u32(act, 8, actionId);
            templFound = fill_in_safe(act, libId, actionId);
        }
        // Do NOT run the post-init template param copy (0x5A6714): the
        // library template's param_strings for unused slots can be garbage,
        // and GM's action validator (sub_5A6B60, run by the post-load object
        // refresh) reads every param up to param_count — a copied garbage
        // pointer crashes it. Match the native .gmk loader instead: write
        // every slot explicitly, empty when absent. (The raw-constructor init
        // already set +68=applies_to:self, +72/+108=0 and "0"-default params;
        // the +72/+108/+68 keys below overwrite their fields as needed.)
        for (int j = 0; j < 8; j++) set_obj_str(act, 76 + j * 4, "");

        // Phase 2: remaining keys override the template defaults, in file
        // order. can_be_relative / applies_to_something come from the
        // template (gm82save parity); the keys only touch their own fields.
        bool hasRepeats = false, hasVar = false;
        bool pset[8] = { false };
        std::string pstrs[8];
        int pcount = 0;
        parse_kv(block, [&](auto& k, auto& v) {
            if (k == "lib_id" || k == "action_id") return;
            if (k == "relative") {
                set_obj_bool(act, 72, v == "1");
                if (!templFound) set_obj_bool(act, 16, true);
            } else if (k == "applies_to") {
                if (!templFound) set_obj_bool(act, 18, true);
                if (v == "other") set_obj_i32(act, 68, -2);
                else if (v == "self") set_obj_i32(act, 68, -1);
                else if (v.empty()) set_obj_i32(act, 68, -4);
                else set_obj_i32(act, 68, name_to_index(objectNames, v));
            } else if (k == "invert") set_obj_bool(act, 108, v == "1");
            else if (k == "repeats") { hasRepeats = true; pset[0] = true; pstrs[0] = v; if (pcount < 1) pcount = 1; }
            else if (k == "var_name") { hasVar = true; pset[0] = true; pstrs[0] = v; if (pcount < 1) pcount = 1; }
            else if (k == "var_value") { pset[1] = true; pstrs[1] = v; if (pcount < 2) pcount = 2; }
            else if (k.size() >= 3 && k[0] == 'a' && k[1] == 'r' && k[2] == 'g') {
                int j = std::atoi(k.c_str() + 3);
                if (j >= 0 && j < 8) { pset[j] = true; pstrs[j] = v; if (j + 1 > pcount) pcount = j + 1; }
            }
        });
        // Write params that appeared in the block — empty values included: an
        // explicit `arg0=` must override the template default; a missing arg
        // keeps the template's default (gm82save parity).
        // Resource-typed params (param_types[j] in 5..14, except 13) store the
        // resource INDEX in param_strings (gm82save load.rs does the same
        // name→index conversion). The file has the name ("arg0=fMain"); convert
        // it here so the save side's stoi round-trips instead of throwing
        // "invalid stoi argument" on a non-numeric name.
        for (int j = 0; j < 8; j++) {
            if (!pset[j]) continue;
            std::string pv = decode_delimit(pstrs[j]);
            uint32_t ptype = *(uint32_t*)((uint8_t*)act + 36 + j * 4); // param_types[j]
            if (ptype >= 5 && ptype <= 14 && ptype != 13) {
                int idx = -1;
                if (!pv.empty()) {
                    switch (ptype) {
                        case 5:  idx = AssetNameMaps::find(g_action_names.sprites, pv); break;
                        case 6:  idx = AssetNameMaps::find(g_action_names.sounds, pv); break;
                        case 7:  idx = AssetNameMaps::find(g_action_names.bgs, pv); break;
                        case 8:  idx = AssetNameMaps::find(g_action_names.paths, pv); break;
                        case 9:  idx = AssetNameMaps::find(g_action_names.scripts, pv); break;
                        case 10: idx = AssetNameMaps::find(g_action_names.objects, pv); break;
                        case 11: idx = AssetNameMaps::find(g_action_names.rooms, pv); break;
                        case 12: idx = AssetNameMaps::find(g_action_names.fonts, pv); break;
                        case 14: idx = AssetNameMaps::find(g_action_names.timelines, pv); break;
                    }
                }
                pv = std::to_string(idx);
            }
            set_obj_str(act, 76 + j * 4, pv);
        }

        // action_kind: the template's value when the action is known (never
        // inferred); structural inference only for unknown actions.
        uint32_t kind;
        if (templFound) {
            kind = *(uint32_t*)((uint8_t*)act + 12);
        } else {
            kind = hasRepeats ? 5 : hasVar ? 6 : 0;
            if (kind == 0 && !codeAfter.empty() &&
                codeAfter.find_first_not_of(" \r\n\t") != std::string::npos)
                kind = 7;
            set_obj_u32(act, 12, kind);
            set_obj_u32(act, 32, (uint32_t)pcount);
        }
        // Code actions: the text after `*/` is the code. Always stored, even
        // when empty — the library default "0" (copied in by the init when no
        // template matches, and sitting in the template's own code slot
        // otherwise) would otherwise be compiled as code and fail with
        // "Variable name expected".
        if (kind == 7) set_obj_str(act, 76, load_gml(codeAfter));
    }
}

// Parse "#define EventName_N" → (eventType 0..11, index)
static int parse_event_header(const std::string& line, int& evIndex) {
    static const char* evNames[] = {"Create","Destroy","Alarm","Step","Collision",
        "Keyboard","Mouse","Other","Draw","KeyPress","KeyRelease","Trigger"};
    std::string hdr = line;
    size_t p = hdr.find("#define ");
    if (p == std::string::npos) return -1;
    std::string evName = hdr.substr(p + 8);
    // trim \r
    while (!evName.empty() && (evName.back() == '\r' || evName.back() == ' ')) evName.pop_back();
    size_t us = evName.find_last_of('_');
    std::string base = (us == std::string::npos) ? evName : evName.substr(0, us);
    std::string num  = (us == std::string::npos) ? "" : evName.substr(us + 1);
    for (int i = 0; i < 12; i++) {
        if (base == evNames[i]) {
            evIndex = num.empty() ? 0 : std::atoi(num.c_str());
            return i;
        }
    }
    return -1;
}

// Append an Event to the object's event dynamic array at +28 + evType*4.
// Every slot gets a real Event (GM's own loader fills all slots with
// sub_4F1A18 — null slots crash the editor's event copy, sub_4F1A98).
static void obj_add_event(void* obj, int evType, int evIndex, void* ev) {
    uint32_t off = 28 + evType * 4;
    void*** arrPtr = (void***)((uint8_t*)obj + off);
    void** arr = *arrPtr;
    uint32_t len = arr ? *(uint32_t*)((uint8_t*)arr - 4) : 0;
    uint32_t need = (uint32_t)(evIndex + 1);
    uint32_t newLen = (need > len) ? need : len;
    void* mem = delphi_alloc(8 + newLen * 4);
    if (!mem) return;
    *(uint32_t*)mem = 1;
    *(uint32_t*)((uint8_t*)mem + 4) = newLen;
    void** dst = (void**)((uint8_t*)mem + 8);
    for (uint32_t i = 0; i < len; i++) dst[i] = arr[i];
    for (uint32_t i = len; i < newLen; i++) dst[i] = (i == (uint32_t)evIndex) ? ev : make_event();
    set_obj_ptr(obj, off, dst);
}

// ==== Load object ====
// GM 8.0 layout (verified via save_object + sub_596F90):
//   +4 sprite_idx, +8 solid(byte), +9 visible(byte), +12 depth,
//   +16 persistent(byte), +20 parent_idx, +24 mask_idx,
//   +28..+72: 12 event dynamic arrays (one per event type, 4 bytes each)
// Name lives in the parallel name array (load_assets_simple), NOT at +4.
static void* load_object(const std::string& name, const fs::path& objDir,
    const std::vector<std::string>& objectNames,
    const std::vector<std::string>& spriteNames)
{
    const ResInfo* ri = find_res("objects");
    if (!ri) return nullptr;

    fs::path subDir = objDir / name;
    fs::path txtPath = objDir / (name + ".txt");  // flat layout (gm82save: set_extension("txt"))
    std::string txt = read_file(txtPath);

    void* obj = make_obj_with_arr(ri->arrObjOff, ri->vmtRva, ri->ctorRva);
    if (!obj) return nullptr;

    parse_kv(txt, [&](auto& k, auto& v) {
        if (k == "sprite") set_obj_i32(obj, 4, name_to_index(spriteNames, v));
        else if (k == "visible") set_obj_bool(obj, 9, v == "1");
        else if (k == "solid") set_obj_bool(obj, 8, v == "1");
        else if (k == "depth") set_obj_i32(obj, 12, std::stoi(v));
        else if (k == "persistent") set_obj_bool(obj, 16, v == "1");
        else if (k == "parent") set_obj_i32(obj, 20, name_to_index(objectNames, v));
        else if (k == "mask") set_obj_i32(obj, 24, name_to_index(spriteNames, v));
    });

    // Events from <name>.gml (save side writes flat objects/<name>.gml)
    fs::path gmlPath = objDir / (name + ".gml");
    std::string gml = read_file(gmlPath);
    if (gml.empty()) return obj;

    // Split into #define sections
    std::istringstream gss(gml);
    std::string line, curName;
    std::vector<std::pair<std::string, std::string>> sections; // (event name, body)
    std::string curBody;
    auto flushSection = [&]() {
        if (!curName.empty()) sections.emplace_back(curName, curBody);
        curBody.clear();
    };
    while (std::getline(gss, line)) {
        if (line.find("#define ") == 0) {
            flushSection();
            curName = line;
        } else {
            curBody += line + "\n";
        }
    }
    flushSection();

    for (auto& sec : sections) {
        int evIndex = 0;
        int evType = parse_event_header(sec.first, evIndex);
        if (evType < 0) continue;
        // For Collision (4) and Trigger (11), the index is an object/trigger
        // name in save format — resolve to index
        if (evType == 4) {
            std::string num = sec.first.substr(sec.first.find("Collision_") + 10);
            while (!num.empty() && (num.back() == '\r' || num.back() == ' ')) num.pop_back();
            evIndex = name_to_index(objectNames, num);
            if (evIndex < 0) evIndex = std::atoi(num.c_str());
        } else if (evType == 11) {
            auto trigNames = load_names(objDir.parent_path() / "triggers" / "index.yyd");
            std::string num = sec.first.substr(sec.first.find("Trigger_") + 8);
            while (!num.empty() && (num.back() == '\r' || num.back() == ' ')) num.pop_back();
            evIndex = name_to_index(trigNames, num);
            if (evIndex < 0) evIndex = std::atoi(num.c_str());
        }

        void* ev = make_event();
        if (!ev) continue;

        // Parse YYD ACTION blocks within the section
        parse_actions_into_event(ev, sec.second, objectNames);

        // Place event at its index in the type's sparse array
        obj_add_event(obj, evType, evIndex, ev);
    }

    return obj;
}

// ==== Load timeline ====
// GM 8.0 layout (verified from sub_562468 + save side):
//   +4 moment_events (DelphiList<Event*>), +8 moment_times (DelphiList<u32>),
//   +12 moment_count. VMT off_559298, ctor sub_5593D4.
static void* load_timeline(const std::string& name, const fs::path& tlDir) {
    const ResInfo* ri = find_res("timelines");
    if (!ri) return nullptr;

    fs::path gmlPath = tlDir / (name + ".gml");
    std::string gml = read_file(gmlPath);

    void* tl = make_obj_with_arr(ri->arrObjOff, ri->vmtRva, ri->ctorRva);
    if (!tl) return nullptr;

    // Parse "#define <time>" sections (each = one moment with actions)
    std::vector<uint32_t> times;
    std::vector<void*> events;
    std::istringstream ss(gml);
    std::string line, curBody;
    uint32_t curTime = 0;
    bool haveTime = false;
    auto flushMoment = [&]() {
        if (!haveTime) return;
        void* ev = make_event();
        if (ev) {
            auto objNames = load_names(tlDir.parent_path() / "objects" / "index.yyd");
            parse_actions_into_event(ev, curBody, objNames);
            times.push_back(curTime);
            events.push_back(ev);
        }
        curBody.clear();
        haveTime = false;
    };
    while (std::getline(ss, line)) {
        if (line.find("#define ") == 0) {
            flushMoment();
            curTime = (uint32_t)std::stoul(line.substr(8));
            haveTime = true;
        } else {
            curBody += line + "\n";
        }
    }
    flushMoment();

    if (!times.empty()) {
        // moments at +8 (DelphiList<u32> with manual header)
        void* mem = delphi_alloc(8 + times.size() * 4);
        if (mem) {
            *(uint32_t*)mem = 1;
            *(uint32_t*)((uint8_t*)mem + 4) = (uint32_t)times.size();
            uint32_t* dst = (uint32_t*)((uint8_t*)mem + 8);
            for (size_t i = 0; i < times.size(); i++) dst[i] = times[i];
            set_obj_ptr(tl, 8, dst);
        }
        // events at +4 (DelphiList<Event*> with manual header)
        mem = delphi_alloc(8 + events.size() * 4);
        if (mem) {
            *(uint32_t*)mem = 1;
            *(uint32_t*)((uint8_t*)mem + 4) = (uint32_t)events.size();
            void** dst = (void**)((uint8_t*)mem + 8);
            for (size_t i = 0; i < events.size(); i++) dst[i] = events[i];
            set_obj_ptr(tl, 4, dst);
        }
        set_obj_u32(tl, 12, (uint32_t)times.size());
    }

    return tl;
}

// Fill room instances/tiles after the room object exists
// (defined before load_room_obj; see below for layout notes)
static void load_room_instances(void* rm, const fs::path& subDir,
    const std::vector<std::string>& objectNames,
    const std::vector<std::string>& bgNames);

// ==== Load room ====
// GM 8.0 layout (verified via sub_548360, save_room, sub_5480A4):
//   +4 caption/name (AnsiString), +8 roomspeed, +12 width, +16 height,
//   +20/+24 snap, +28 isometric(byte), +29 persistent(byte), +32 bg_color,
//   +36 clear_screen(byte), +37 clear_view(byte),
//   +40..+296: 8×32 RoomBackground, +296 views_enabled(byte),
//   +300..+748: 8×56 View, +752 instance_count, +756 instances array,
//   +760 tile_count, +764 tiles array, +768 remember(byte),
//   +772 editor_width, +776 editor_height
static void* load_room_obj(const std::string& name, const fs::path& roomDir,
    const std::vector<std::string>& objectNames,
    const std::vector<std::string>& bgNames)
{
    const ResInfo* ri = find_res("rooms");
    if (!ri) return nullptr;

    fs::path subDir = roomDir / name;
    fs::path txtPath = subDir / "room.txt";
    std::string txt = read_file(txtPath);

    void* rm = make_obj_with_arr(ri->arrObjOff, ri->vmtRva, ri->ctorRva);
    if (!rm) return nullptr;

    // GM 8.0 layout (verified from sub_548360 loader + GM80_SaveRoom_Individual):
    // +4 caption, +8 speed, +12 width, +16 height, +20/+24 snap, +28 isometric,
    // +29 persistent, +32 bg_color, +36 clear_screen, +37 clear_view
    parse_kv(txt, [&](auto& k, auto& v) {
        if (k == "caption") set_obj_str(rm, 4, v);
        else if (k == "roomspeed") set_obj_u32(rm, 8, (uint32_t)std::stoul(v));
        else if (k == "width") set_obj_u32(rm, 12, (uint32_t)std::stoul(v));
        else if (k == "height") set_obj_u32(rm, 16, (uint32_t)std::stoul(v));
        else if (k == "snap_x") set_obj_u32(rm, 20, (uint32_t)std::stoul(v));
        else if (k == "snap_y") set_obj_u32(rm, 24, (uint32_t)std::stoul(v));
        else if (k == "isometric") set_obj_bool(rm, 28, v == "1");
        else if (k == "roompersistent") set_obj_bool(rm, 29, v == "1");
        else if (k == "bg_color") set_obj_u32(rm, 32, (uint32_t)std::stoul(v));
        else if (k == "clear_screen") set_obj_bool(rm, 36, v == "1");
        else if (k == "clear_view") set_obj_bool(rm, 37, v == "1");
    });

    // 8 room backgrounds at +40, 32 bytes each (see save_room for layout)
    for (int i = 0; i < 8; i++) {
        int bo = 40 + i * 32;
        std::string p0 = "bg_visible" + std::to_string(i);
        std::string p1 = "bg_is_foreground" + std::to_string(i);
        std::string p2 = "bg_source" + std::to_string(i);
        std::string p3 = "bg_xoffset" + std::to_string(i);
        std::string p4 = "bg_yoffset" + std::to_string(i);
        std::string p5 = "bg_tile_h" + std::to_string(i);
        std::string p6 = "bg_tile_v" + std::to_string(i);
        std::string p7 = "bg_hspeed" + std::to_string(i);
        std::string p8 = "bg_vspeed" + std::to_string(i);
        std::string p9 = "bg_stretch" + std::to_string(i);
        parse_kv(txt, [&](auto& k, auto& v) {
            if (k == p0) set_obj_bool(rm, bo, v == "1");
            else if (k == p1) set_obj_bool(rm, bo + 1, v == "1");
            else if (k == p2) set_obj_i32(rm, bo + 4, name_to_index(bgNames, v));
            else if (k == p3) set_obj_i32(rm, bo + 8, std::stoi(v));
            else if (k == p4) set_obj_i32(rm, bo + 12, std::stoi(v));
            else if (k == p5) set_obj_bool(rm, bo + 16, v == "1");
            else if (k == p6) set_obj_bool(rm, bo + 17, v == "1");
            else if (k == p7) set_obj_i32(rm, bo + 20, std::stoi(v));
            else if (k == p8) set_obj_i32(rm, bo + 24, std::stoi(v));
            else if (k == p9) set_obj_bool(rm, bo + 28, v == "1");
        });
    }

    // 8 views at +300, 56 bytes each; views_enabled at +296
    parse_kv(txt, [&](auto& k, auto& v) {
        if (k == "views_enabled") set_obj_bool(rm, 296, v == "1");
    });
    for (int i = 0; i < 8; i++) {
        int vo = 300 + i * 56;
        std::string p0 = "view_visible" + std::to_string(i);
        std::string p1 = "view_xview" + std::to_string(i);
        std::string p2 = "view_yview" + std::to_string(i);
        std::string p3 = "view_wview" + std::to_string(i);
        std::string p4 = "view_hview" + std::to_string(i);
        std::string p5 = "view_xport" + std::to_string(i);
        std::string p6 = "view_yport" + std::to_string(i);
        std::string p7 = "view_wport" + std::to_string(i);
        std::string p8 = "view_hport" + std::to_string(i);
        std::string p9 = "view_fol_hbord" + std::to_string(i);
        std::string p10 = "view_fol_vbord" + std::to_string(i);
        std::string p11 = "view_fol_hspeed" + std::to_string(i);
        std::string p12 = "view_fol_vspeed" + std::to_string(i);
        std::string p13 = "view_fol_target" + std::to_string(i);
        parse_kv(txt, [&](auto& k, auto& v) {
            if (k == p0) set_obj_bool(rm, vo, v == "1");
            else if (k == p1) set_obj_i32(rm, vo + 4, std::stoi(v));
            else if (k == p2) set_obj_i32(rm, vo + 8, std::stoi(v));
            else if (k == p3) set_obj_u32(rm, vo + 12, (uint32_t)std::stoul(v));
            else if (k == p4) set_obj_u32(rm, vo + 16, (uint32_t)std::stoul(v));
            else if (k == p5) set_obj_i32(rm, vo + 20, std::stoi(v));
            else if (k == p6) set_obj_i32(rm, vo + 24, std::stoi(v));
            else if (k == p7) set_obj_u32(rm, vo + 28, (uint32_t)std::stoul(v));
            else if (k == p8) set_obj_u32(rm, vo + 32, (uint32_t)std::stoul(v));
            else if (k == p9) set_obj_i32(rm, vo + 36, std::stoi(v));
            else if (k == p10) set_obj_i32(rm, vo + 40, std::stoi(v));
            else if (k == p11) set_obj_i32(rm, vo + 44, std::stoi(v));
            else if (k == p12) set_obj_i32(rm, vo + 48, std::stoi(v));
            else if (k == p13) set_obj_i32(rm, vo + 52, name_to_index(objectNames, v));
        });
    }

    // Instances + tiles (instances.txt / layers.txt) — see load_room_instances
    load_room_instances(rm, subDir, objectNames, bgNames);

    // Creation code (code.gml, saved by save_room from +748; matches gm82save
    // Room.creation_code which sits after the 8 views at 300+8*56=748).
    {
        fs::path codePath = subDir / "code.gml";
        std::string code = read_file(codePath);
        if (!code.empty()) set_obj_str(rm, 748, load_gml(code));
    }

    return rm;
}

// Fill room instances/tiles after the room object exists
// (kept separate to keep load_room_obj readable)
static void load_room_instances(void* rm, const fs::path& subDir,
    const std::vector<std::string>& objectNames,
    const std::vector<std::string>& bgNames)
{
    // ==== Instances (instances.txt) ====
    {
        fs::path instPath = subDir / "instances.txt";
        std::string instTxt = read_file(instPath);
        if (!instTxt.empty()) {
            struct InstRow { int32_t obj; int32_t x; int32_t y; std::string hash;
                             bool locked; int32_t xscale, yscale, blend, angle; bool hasCode; };
            std::vector<InstRow> rows;
            std::istringstream iss(instTxt);
            std::string line;
            while (std::getline(iss, line)) {
                if (line.empty()) continue;
                std::vector<std::string> cols;
                size_t s = 0, e;
                while ((e = line.find(',', s)) != std::string::npos) {
                    cols.push_back(line.substr(s, e - s));
                    s = e + 1;
                }
                cols.push_back(line.substr(s));
                if (cols.size() < 5) continue;
                InstRow r;
                r.obj = name_to_index(objectNames, cols[0]);
                r.x = std::stoi(cols[1]);
                r.y = std::stoi(cols[2]);
                r.hash = cols[3];
                r.locked = (cols[4] == "1");
                r.xscale = cols.size() > 5 ? std::stoi(cols[5]) : 1;
                r.yscale = cols.size() > 6 ? std::stoi(cols[6]) : 1;
                r.blend = cols.size() > 7 ? (int32_t)std::stoul(cols[7]) : 0xFFFFFFFF;
                r.angle = cols.size() > 8 ? std::stoi(cols[8]) : 0;
                r.hasCode = cols.size() > 9 ? (cols[9] == "1") : !r.hash.empty();
                rows.push_back(r);
            }
            if (!rows.empty()) {
                void* mem = delphi_alloc(8 + rows.size() * 24);
                if (mem) {
                    *(uint32_t*)mem = 1;
                    *(uint32_t*)((uint8_t*)mem + 4) = (uint32_t)rows.size();
                    uint8_t* dst = (uint8_t*)mem + 8;
                    for (size_t i = 0; i < rows.size(); i++) {
                        uint8_t* inst = dst + i * 24;
                        // GM 8.0 Instance layout (GM80_SaveRoom_Individual
                        // 0x548BB7-0x548C1D + save_room): +0 x, +4 y, +8 object,
                        // +12 id, +16 creation_code (AnsiString), +20 locked
                        *(int32_t*)(inst + 0) = rows[i].x;
                        *(int32_t*)(inst + 4) = rows[i].y;
                        *(int32_t*)(inst + 8) = rows[i].obj;
                        *(int32_t*)(inst + 12) = rows[i].hash.empty()
                            ? 0 : (int32_t)std::stoul(rows[i].hash, nullptr, 16);
                        *(inst + 20) = rows[i].locked ? 1 : 0;
                        if (rows[i].hasCode && !rows[i].hash.empty()) {
                            fs::path codePath = subDir / (rows[i].hash + ".gml");
                            std::string code = read_file(codePath);
                            if (!code.empty())
                                *(char**)(inst + 16) = make_delphi_str(load_gml(code));
                        }
                    }
                    set_obj_u32(rm, 752, (uint32_t)rows.size());
                    set_obj_ptr(rm, 756, dst);
                }
            }
        }
    }

    // ==== Tiles (layers.txt + %depth%.txt → +760 count / +764 array, 40 bytes) ====
    // GM 8.0 Tile: +0 x, +4 y, +8 source_bg, +12 u, +16 v, +20 width,
    // +24 height, +28 depth, +32 id, +36 locked(byte)
    {
        fs::path layersPath = subDir / "layers.txt";
        std::string layersTxt = read_file(layersPath);
        if (!layersTxt.empty()) {
            std::vector<std::array<int32_t, 10>> tiles; // x,y,bg,u,v,w,h,depth,id,locked
            std::istringstream lss(layersTxt);
            std::string depthLine;
            while (std::getline(lss, depthLine)) {
                if (depthLine.empty()) continue;
                fs::path layerFile = subDir / (depthLine + ".txt");
                std::string layerTxt = read_file(layerFile);
                std::istringstream tss(layerTxt);
                std::string tline;
                while (std::getline(tss, tline)) {
                    if (tline.empty()) continue;
                    std::vector<std::string> cols;
                    size_t s = 0, e;
                    while ((e = tline.find(',', s)) != std::string::npos) {
                        cols.push_back(tline.substr(s, e - s));
                        s = e + 1;
                    }
                    cols.push_back(tline.substr(s));
                    if (cols.size() < 8) continue;
                    std::array<int32_t, 10> t = {};
                    t[0] = std::stoi(cols[1]);               // x
                    t[1] = std::stoi(cols[2]);               // y
                    t[2] = name_to_index(bgNames, cols[0]);  // source_bg
                    t[3] = std::stoi(cols[3]);               // u
                    t[4] = std::stoi(cols[4]);               // v
                    t[5] = std::stoi(cols[5]);               // width
                    t[6] = std::stoi(cols[6]);               // height
                    t[7] = std::stoi(depthLine);             // depth
                    t[8] = 0;                                // id
                    t[9] = (cols.size() > 7 && cols[7] == "1") ? 1 : 0; // locked
                    tiles.push_back(t);
                }
            }
            if (!tiles.empty()) {
                void* mem = delphi_alloc(8 + tiles.size() * 40);
                if (mem) {
                    *(uint32_t*)mem = 1;
                    *(uint32_t*)((uint8_t*)mem + 4) = (uint32_t)tiles.size();
                    uint8_t* dst = (uint8_t*)mem + 8;
                    for (size_t i = 0; i < tiles.size(); i++) {
                        uint8_t* tl = dst + i * 40;
                        for (int j = 0; j < 9; j++) *(int32_t*)(tl + j * 4) = tiles[i][j];
                        *(tl + 36) = (uint8_t)tiles[i][9];
                    }
                    set_obj_u32(rm, 760, (uint32_t)tiles.size());
                    set_obj_ptr(rm, 764, dst);
                }
            }
        }
    }
}

// ==== Load names from index.yyd ====
static std::vector<std::string> load_names(const fs::path& idxPath) {
    std::vector<std::string> out;
    std::string idx = read_file(idxPath);
    if (idx.empty()) return out;
    std::istringstream ss(idx);
    std::string line;
    while (std::getline(ss, line)) out.push_back(line);
    return out;
}

// ==== Clear updated flags (same 16 flags as sub_59BA38) ====
static void clear_all_updated_flags() {
    uint8_t* base = (uint8_t*)g_load_base;
    static const uint32_t flag_rvas[] = ADDR_DIRTY_FLAGS;
    for (int i = 0; i < 16; i++) {
        *(uint8_t*)(base + flag_rvas[i]) = 0;
    }
}

// ==== Resource array allocation via Delphi @DynArraySetLength ====
// GM manages resource arrays as Delphi dynamic arrays. Verified from the
// .gmk loaders (sub_540108 sprites, sub_546120 sounds, sub_536860 backgrounds,
// sub_556C44 paths, sub_55B9CC scripts, sub_558A84 fonts, sub_562468 timelines,
// sub_5963E0 objects, sub_553C30 rooms, sub_55D220 triggers):
//   mov eax, offset <array global>   ; EAX = address of array pointer global
//   mov ecx, 1                        ; ECX = dimension count
//   mov edx, ds:off_XXXX              ; EDX = type info
//   push count; call sub_406A38       ; stack = element count
// sub_406A38 = @DynArraySetLength wrapper: converts the stack count value to
// &count (the counts array) before calling sub_4068AC. Call it exactly like
// the GM loaders do (eax=&array, edx=typeInfo, ecx=1, push count).
#define ADDR_DYN_ARRAY_SETLENGTH 0x6A38

struct AssetArrays {
    const char* dir;
    uint32_t countRva;   // count global (RVA)
    uint32_t arr[5];     // array globals: assets, forms, names, timestamps, [extra]
    uint32_t ti[5];      // type info data offsets (off_XXXX RVAs)
    int n;               // number of arrays
};

// Array/typeInfo pairs extracted from the loaders above (RVA form).
static const AssetArrays s_assetArrays[] = {
    {"sprites",     0x1E911C, {0x1E9108, 0x1E910C, 0x1E9110, 0x1E9114, 0x1E9118},
                             {0x13FFB8, 0x13FFDC, 0x140000, 0x140024, 0x140048}, 5},
    {"sounds",      0x1E9288, {0x1E9278, 0x1E927C, 0x1E9280, 0x1E9284, 0},
                             {0x146008, 0x14602C, 0x146050, 0x146074, 0}, 4},
    {"backgrounds", 0x1E90A8, {0x1E9094, 0x1E9098, 0x1E909C, 0x1E90A0, 0x1E90A4},
                             {0x1366FC, 0x136724, 0x13674C, 0x136774, 0x13679C}, 5},
    {"paths",       0x1E92BC, {0x1E92AC, 0x1E92B0, 0x1E92B4, 0x1E92B8, 0},
                             {0x156B2C, 0x156B50, 0x156B74, 0x156B98, 0}, 4},
    {"scripts",     0x1E92E4, {0x1E92D4, 0x1E92D8, 0x1E92DC, 0x1E92E0, 0},
                             {0x15B460, 0x15B484, 0x15B4A8, 0x15B4CC, 0}, 4},
    {"fonts",       0x1E92D0, {0x1E92C0, 0x1E92C4, 0x1E92C8, 0x1E92CC, 0},
                             {0x15896C, 0x158990, 0x1589B4, 0x1589D8, 0}, 4},
    {"timelines",   0x1E9310, {0x1E9300, 0x1E9304, 0x1E9308, 0x1E930C, 0},
                             {0x162340, 0x162368, 0x162390, 0x1623B8, 0}, 4},
    {"objects",     0x1E9364, {0x1E9354, 0x1E9358, 0x1E935C, 0x1E9360, 0},
                             {0x1962C8, 0x1962EC, 0x196310, 0x196334, 0}, 4},
    {"rooms",       0x1E92A4, {0x1E9294, 0x1E9298, 0x1E929C, 0x1E92A0, 0},
                             {0x153B00, 0x153B24, 0x153B48, 0x153B6C, 0}, 4},
    {"triggers",    0x1E92EC, {0x1E92E8, 0, 0, 0, 0},
                             {0x15D1A0, 0, 0, 0, 0}, 1},
};

// After alloc_asset_arrays: get the freshly SetLength'd arrays
static void* get_asset_array(uint32_t arrOff) {
    uint8_t* b = (uint8_t*)g_load_base;
    return *(void**)(b + arrOff);
}

// Resize all resource arrays (assets/forms/names/timestamps[/extra]) to count
// using GM's own @DynArraySetLength. Zero-fills new elements (Delphi behavior).
static void alloc_asset_arrays(const char* dir, uint32_t count) {
    for (auto& aa : s_assetArrays) {
        if (strcmp(aa.dir, dir)) continue;
        uint8_t* b = glob_base();
        uint32_t fn = (uint32_t)b + ADDR_DYN_ARRAY_SETLENGTH;
        for (int i = 0; i < aa.n; i++) {
            uint32_t arrAddr = (uint32_t)b + aa.arr[i];
            uint32_t typeInfo = *(uint32_t*)(b + aa.ti[i]);
            // GM uses 0xFFFFFFFF as "uninitialized array" sentinel; @DynArraySetLength
            // would deref ptr-4 on it and crash — normalize to null first
            uint32_t* cur = *(uint32_t**)arrAddr;
            if (cur == (uint32_t*)-1) *(uint32_t**)arrAddr = nullptr;
            __asm {
                mov eax, arrAddr
                mov edx, typeInfo
                mov ecx, 1
                push count
                call fn
                add esp, 4
            }
        }
        write_glob_u32(aa.countRva, count);
        // GM initializes the 5th array (thumbnails/ids) to -1 per element
        if (aa.n == 5 && aa.arr[4]) {
            int32_t* extra = (int32_t*)get_asset_array(aa.arr[4]);
            if (extra) for (uint32_t i = 0; i < count; i++) extra[i] = -1;
        }
        return;
    }
}

// ==== Load generic resource types ====
typedef void* (*LoadFn)(const std::string& name, const fs::path& dir);
typedef void* (*LoadFnCtx)(const std::string& name, const fs::path& dir,
    const std::vector<std::string>&, const std::vector<std::string>&);

static bool load_assets_simple(
    const char* dirName,
    LoadFn loader,
    const ResInfo* ri,
    const fs::path& root)
{
    auto idxPath = root / dirName / "index.yyd";
    auto names = load_names(idxPath);
    gm80l_log("  %s: %zu names from index.yyd", dirName, names.size());
    if (names.empty()) return true;

    uint8_t* base = (uint8_t*)g_load_base;
    uint32_t cnt = (uint32_t)names.size();
    gm80l_log("  %s: allocating %u objects + names...", dirName, cnt);

    // Allocate via GM's @DynArraySetLength (proper Delphi dynamic arrays)
    alloc_asset_arrays(dirName, cnt);
    void** newObjs = (void**)get_asset_array(ri->arrObjOff);
    void** newNames = ri->arrNameOff ? (void**)get_asset_array(ri->arrNameOff) : nullptr;
    gm80l_log("  %s: arrays allocated, loading %u items...", dirName, cnt);

    fs::path resDir = root / dirName;
    bool isSprites = (strcmp(dirName, "sprites") == 0);
    bool isBg = (strcmp(dirName, "backgrounds") == 0);
    for (uint32_t i = 0; i < cnt; i++) {
        if (names[i].empty()) continue;
        void* obj = loader(names[i], resDir);
        if (obj) {
            newObjs[i] = obj;
            if (newNames) newNames[i] = make_delphi_str(names[i]);
            // Register 16×16 thumbnail like GM's loaders:
            //   sprites: sub_4F959C(sprite); bgs: sub_521060(bg)
            //   then sub_4F18D0(TBitmap) → index → 5th array (0x1E9118 / 0x1E90A4)
            uint32_t fnThumb = 0, extraArr = 0;
            if (isSprites) { fnThumb = (uint32_t)base + 0xF959C; extraArr = 0x1E9118; }
            else if (isBg)  { fnThumb = (uint32_t)base + 0x121060; extraArr = 0x1E90A4; }
            if (fnThumb) {
                void* thumb = nullptr;
                __asm {
                    mov eax, obj
                    mov edx, 1
                    call fnThumb
                    mov thumb, eax
                }
                if (thumb) {
                    uint32_t fnReg = (uint32_t)base + 0xF18D0;
                    uint32_t idx = 0;
                    __asm {
                        mov eax, thumb
                        call fnReg
                        mov idx, eax
                    }
                    int32_t* extra = (int32_t*)get_asset_array(extraArr);
                    if (extra) extra[i] = (int32_t)idx;
                    delphi_free(thumb); // GM frees the TBitmap after registering
                }
            }
        }
    }

    return true;
}

// Same as load_assets_simple but for loaders that need name context
// (objects need sprite names; rooms need object+background names)
static bool load_assets_ctx(
    const char* dirName,
    LoadFnCtx loader,
    const ResInfo* ri,
    const fs::path& root,
    const std::vector<std::string>& ctxA,
    const std::vector<std::string>& ctxB)
{
    auto idxPath = root / dirName / "index.yyd";
    auto names = load_names(idxPath);
    if (names.empty()) return true;

    uint8_t* base = (uint8_t*)g_load_base;
    uint32_t cnt = (uint32_t)names.size();

    alloc_asset_arrays(dirName, cnt);
    void** newObjs = (void**)get_asset_array(ri->arrObjOff);
    void** newNames = ri->arrNameOff ? (void**)get_asset_array(ri->arrNameOff) : nullptr;

    fs::path resDir = root / dirName;
    for (uint32_t i = 0; i < cnt; i++) {
        if (names[i].empty()) continue;
        void* obj = loader(names[i], resDir, ctxA, ctxB);
        if (obj) {
            newObjs[i] = obj;
            if (newNames) newNames[i] = make_delphi_str(names[i]);
        }
    }

    return true;
}

// ==== Resource tree roots map ====
static uint32_t rt_kind(int kind) {
    switch (kind) {
        case 1: return RT_OBJECTS;
        case 2: return RT_SPRITES;
        case 3: return RT_SOUNDS;
        case 4: return RT_ROOMS;
        case 6: return RT_BACKGROUNDS;
        case 7: return RT_SCRIPTS;
        case 8: return RT_PATHS;
        case 9: return RT_FONTS;
        case 12: return RT_TIMELINES;
        default: return 0;
    }
}

// ==== Main load entry point ====
bool gm80_load_project(void* gm_base, const std::wstring& wpath) {
    g_load_base = gm_base;
    fs::path root(wpath);
    if (!fs::is_directory(root)) return false;

    // 1. InitializeProject already called by GM80_LoadRecentProject before our hook.
    //    Calling it again would double-reset and corrupt. Skip.
    // init_project();

    // 1b. Cache real VMTs from GM's array objects BEFORE SetLength replaces them
    cache_vmts();

    // 2. Read root .gm80 metadata
    auto stem = root.filename();
    std::string projName = "";
    fs::path metaFile;   // the .gm80 metadata FILE inside the project folder
    // Find the .gm80 metadata file
    for (auto& entry : fs::directory_iterator(root)) {
        auto ext = entry.path().extension().string();
        if (ext == ".gm80" || entry.path().filename().string().find(".gm80") != std::string::npos) {
            metaFile = entry.path();
            std::string meta = read_file(entry.path());
            if (!meta.empty()) {
                parse_kv(meta, [&](auto& k, auto& v) {
                    if (k == "gameid") write_glob_u32(ADDR_GAME_ID, (uint32_t)std::stoul(v));
                    else if (k == "info_author") write_glob_str(ADDR_SETTING_AUTHOR, v);
                    else if (k == "info_version") write_glob_str(ADDR_SETTING_VERSION, v);
                    else if (k == "info_information") write_glob_str(ADDR_SETTING_INFO, decode_delimit(v));
                    else if (k == "exe_company") write_glob_str(ADDR_SETTING_COMPANY, v);
                    else if (k == "exe_copyright") write_glob_str(ADDR_SETTING_COPYRIGHT, v);
                    else if (k == "exe_product") write_glob_str(ADDR_SETTING_PRODUCT, v);
                    else if (k == "exe_description") write_glob_str(ADDR_SETTING_DESCRIPTION, v);
                });
                break;
            }
        }
    }

    gm80l_log("Load: metadata done");
    // 3. Load settings + constants
    load_settings(root);
    gm80l_log("Load: settings done");
    load_gameinfo(root);
    load_extensions(root);
    gm80l_log("Load: extensions done");
    load_included_files(root);
    gm80l_log("Load: included files done");

    // 4. Load triggers (single array, names live inside objects at +4)
    {
        auto names = load_names(root / "triggers" / "index.yyd");
        const ResInfo* ri = find_res("triggers");
        if (ri && !names.empty()) {
            uint32_t cnt = (uint32_t)names.size();
            alloc_asset_arrays("triggers", cnt);
            void** newObjs = (void**)get_asset_array(ri->arrObjOff);

            fs::path trigDir = root / "triggers";
            for (uint32_t i = 0; i < cnt; i++) {
                if (names[i].empty()) continue;
                void* trig = load_trigger(names[i], trigDir);
                if (trig) newObjs[i] = trig;
            }
        }
    }
    gm80l_log("Load: triggers done");

    // 5. Load sounds
    gm80l_log("Loading sounds...");
    load_assets_simple("sounds", load_sound, find_res("sounds"), root);
    gm80l_log("Sounds done.");
    gm80_progress_step(10);

    // 6. Load sprites
    gm80l_log("Loading sprites...");
    load_assets_simple("sprites", load_sprite_obj, find_res("sprites"), root);
    gm80l_log("Sprites done.");
    gm80_progress_step(20);

    // 7. Load backgrounds
    gm80l_log("Loading backgrounds...");
    load_assets_simple("backgrounds", load_bg_obj, find_res("backgrounds"), root);
    gm80l_log("Backgrounds done.");
    gm80_progress_step(30);

    // 8. Load paths
    gm80l_log("Loading paths...");
    load_assets_simple("paths", load_path_obj, find_res("paths"), root);
    gm80l_log("Paths done.");
    gm80_progress_step(40);

    // 9. Load scripts
    gm80l_log("Loading scripts...");
    load_assets_simple("scripts", load_script, find_res("scripts"), root);
    gm80l_log("Scripts done.");
    gm80_progress_step(50);

    // 10. Load fonts
    gm80l_log("Loading fonts...");
    load_assets_simple("fonts", load_font, find_res("fonts"), root);
    gm80l_log("Fonts done.");
    gm80_progress_step(60);

    // 11. Load objects (needs sprite + object name context)
    // NOTE: the action-library array is only built by GM's sub_5A93B4, which
    // runs AFTER our parser returns (unconditionally, success or failure) —
    // calling it from here crashes (wrong environment), so fill_in_safe's
    // SEH degradation covers the first load; from the second load on the
    // library is already built and FillIn works normally.
    // 11b. Action-param name maps (all resource types): action params that
    // reference a resource store the INDEX in memory; the file has the NAME.
    g_action_names.sprites   = load_names(root / "sprites" / "index.yyd");
    g_action_names.sounds    = load_names(root / "sounds" / "index.yyd");
    g_action_names.bgs       = load_names(root / "backgrounds" / "index.yyd");
    g_action_names.paths     = load_names(root / "paths" / "index.yyd");
    g_action_names.scripts   = load_names(root / "scripts" / "index.yyd");
    g_action_names.objects   = load_names(root / "objects" / "index.yyd");
    g_action_names.rooms     = load_names(root / "rooms" / "index.yyd");
    g_action_names.fonts     = load_names(root / "fonts" / "index.yyd");
    g_action_names.timelines = load_names(root / "timelines" / "index.yyd");

    gm80l_log("Loading objects...");
    {
        auto names = load_names(root / "objects" / "index.yyd");
        auto sprites = load_names(root / "sprites" / "index.yyd");
        load_assets_ctx("objects", load_object, find_res("objects"), root, names, sprites);
    }
    gm80l_log("Objects done.");
    gm80_progress_step(70);

    // 12. Load rooms (needs object + background name context)
    gm80l_log("Loading rooms...");
    {
        auto names = load_names(root / "rooms" / "index.yyd");
        auto objs = load_names(root / "objects" / "index.yyd");
        auto bgs = load_names(root / "backgrounds" / "index.yyd");
        load_assets_ctx("rooms", load_room_obj, find_res("rooms"), root, objs, bgs);
    }
    gm80l_log("Rooms done.");
    gm80_progress_step(80);

    // 13. Resource tree (tree.yyd per type) — needed for the IDE to display assets
    gm80l_log("Loading resource trees...");
    {
        const struct { const char* dir; int kind; } treeTypes[] = {
            {"sprites", 2}, {"sounds", 3}, {"backgrounds", 6}, {"paths", 8},
            {"scripts", 7}, {"fonts", 9}, {"timelines", 12},
            {"objects", 1}, {"rooms", 4},
        };
        for (auto& t : treeTypes) {
            auto names = load_names(root / t.dir / "index.yyd");
            load_resource_tree(names, t.kind, t.dir, root);
        }
    }
    gm80l_log("Resource trees done.");
    gm80_progress_step(90);

    // 14. Load timelines (before objects — they share the Event/Action system)
    gm80l_log("Loading timelines...");
    load_assets_simple("timelines", load_timeline, find_res("timelines"), root);
    gm80l_log("Timelines done.");
    gm80_progress_step(100);

    // 15. Clear all updated flags
    clear_all_updated_flags();

    // 16. Update settings timestamp — GM 8.0 keeps the "last modified" as a
    // Delphi TDateTime (double, days since 1899-12-30); writing 0.0 shows
    // 1899/12/30 in the project properties. Use GM's own Now() (0x405CF18)
    // for a correct value.
    {
        uint8_t* b = (uint8_t*)g_load_base;
        uint32_t fn = (uint32_t)b + 0xCF18;   // sub_40CF18 = Now() (GetLocalTime→EncodeDate+EncodeTime)
        double now = 0.0;
        __asm {
            call fn
            fstp qword ptr [now]              // Delphi double return lives in ST(0), NOT EDX:EAX
        }
        write_glob_f64(ADDR_SETTINGS_TIMESTAMP, now);
        gm80l_log("gm80_load_project: timestamp set to %f", now);
    }

    // 17. Working directory: GM launches the compiled game with
    // lpCurrentDirectory=NULL (CreateProcessA at 0x521DF3), so the game
    // process inherits the IDE's current directory. For .gmk projects the
    // cwd ends up at the .gmk file's folder (the open dialog sets it there);
    // the .gm80 project folder sits one level below, so use the PARENT —
    // that is where external_define'd DLLs and data files live.
    {
        fs::path cwd = root.parent_path();
        if (cwd.empty()) cwd = root;
        if (SetCurrentDirectoryW(cwd.c_str())) {
            gm80l_log("gm80_load_project: cwd set to '%ls'", cwd.c_str());
        } else {
            gm80l_log("gm80_load_project: SetCurrentDirectoryW failed err=%u",
                      (uint32_t)GetLastError());
        }
    }

    // 18. GM80_ProjectPath (0x1EA27C): GM's project-path semantics are the
    // FILE path (a .gmk file; for .gm80 the metadata FILE inside the project
    // folder — matching gm82save's PROJECT_PATH = folder\folder.gm82). This
    // is what Recent Projects stores and what the open/load flows use, so
    // set it to the metadata file path, not the folder.
    {
        fs::path projFile = metaFile.empty() ? (root / stem) : metaFile;
        std::wstring wproj = projFile.wstring();
        int alen = WideCharToMultiByte(CP_ACP, 0, wproj.c_str(),
                                       (int)wproj.size(), NULL, 0, NULL, NULL);
        if (alen > 0) {
            std::string aproj(alen, '\0');
            WideCharToMultiByte(CP_ACP, 0, wproj.c_str(), (int)wproj.size(),
                                &aproj[0], alen, NULL, NULL);
            write_glob_str(0x1EA27C, aproj);
            gm80l_log("gm80_load_project: GM80_ProjectPath set to '%s'",
                      aproj.c_str());
        }
    }

    gm80l_log("gm80_load_project: SUCCESS, returning true");
    return true;
}

