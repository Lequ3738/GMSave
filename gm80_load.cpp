// GM80 multi-file load — direct Delphi object creation (matches gm82save approach)
// Creates Delphi objects and inserts them into GM's resource arrays
#include "pch.h"
#include "gm80_load.h"
#include "gm80_addresses.h"
#include "gmk_format.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <functional>
#include <map>
#include <vector>
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
#define ADDR_LSTR_CLR             0x47E8   // @LStrClr: EAX=ptr_to_string (free)

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

// Debug wrapper: logs VMT info then calls delphi_ctor
static void* make_obj_debug(uint32_t vmt_rva, uint32_t ctor_rva, const char* name) {
    uint8_t* b = glob_base();
    uint32_t class_ref = *(uint32_t*)(b + vmt_rva);
    uint32_t instSize = *(uint32_t*)(b + vmt_rva - 40); // VMT[-40] = instance size
    gm80l_log("make_obj %s: vmt_rva=0x%X class_ref=0x%X instSize=%u (0x%X)",
        name, vmt_rva, class_ref, instSize, instSize);
    if (class_ref < 0x400000) { gm80l_log("  -> class_ref<0x400000, returning NULL"); return nullptr; }
    void* obj = delphi_ctor(class_ref, (uint32_t)b + ctor_rva);
    gm80l_log("  -> ctor returned 0x%p (class_ref=0x%X)", obj, class_ref);
    if (obj == (void*)class_ref) { gm80l_log("  -> obj==class_ref, allocation failed, returning NULL"); return nullptr; }
    return obj;
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
#define ADDR_TSTREAM_VMT_DATA 0x4EA854
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
    // kind=3: sounds    arr=0x1E92FC name=0x1E932C cnt=0x1E9288 off_544660
    {0x1E92FC, 0x1E932C, 0x1E9288, 0x144660, 0x144768, "sounds", 3, 0},
    // kind=6: backgrounds arr=0x1E9094 name=0x1E909C cnt=0x1E90A8 off_5207B4
    {0x1E9094, 0x1E909C, 0x1E90A8, 0x1207B4, 0x12084C, "backgrounds", 6, 0},
    // kind=8: paths     arr=0x1E92AC name=0x1E92B4 cnt=0x1E92BC off_54695C
    {0x1E92AC, 0x1E92B4, 0x1E92BC, 0x14695C, 0x147054, "paths", 8, 0},
    // kind=7: scripts   arr=0x1E92D4 name=0x1E92DC cnt=0x1E92E4 off_559B9C
    {0x1E92D4, 0x1E92DC, 0x1E92E4, 0x159B9C, 0x159C2C, "scripts", 7, 0},
    // kind=9: fonts     arr=0x1E92C0 name=0x1E92C8 cnt=0x1E92D0 off_55742C
    {0x1E92C0, 0x1E92C8, 0x1E92D0, 0x15742C, 0x157A78, "fonts", 9, 0},
    // kind=12: timelines arr=0x1E9300 name=0x1E9308 cnt=0x1E9310 (VMT/ctor TBD)
    {0x1E9300, 0x1E9308, 0x1E9310, 0x159B9C, 0x159C2C, "timelines", 12, 0},
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
static void load_settings(const fs::path& root) {
    fs::path settPath = root / "settings" / "settings.txt";
    std::string txt = read_file(settPath);
    if (txt.empty()) return;

    parse_kv(txt, [&](auto& k, auto& v) {
        if (k == "fullscreen") write_glob_bool(ADDR_SETTING_FULLSCREEN, v=="1");
        else if (k == "interpolate_pixels") write_glob_bool(ADDR_SETTING_INTERPOLATE, v=="1");
        else if (k == "color_depth") write_glob_u32(ADDR_SETTING_COLOR_DEPTH, (uint32_t)std::stoul(v));
        else if (k == "resolution") write_glob_u32(ADDR_SETTING_RESOLUTION, (uint32_t)std::stoul(v));
        else if (k == "frequency") write_glob_u32(ADDR_SETTING_FREQUENCY, (uint32_t)std::stoul(v));
        else if (k == "scaling") write_glob_i32(ADDR_SETTING_SCALING, std::stoi(v));
        else if (k == "clear_color") write_glob_u8(ADDR_SETTING_CLEAR_COLOR, (uint8_t)std::stoul(v));
        else if (k == "priority") write_glob_u8(ADDR_SETTING_PRIORITY, (uint8_t)std::stoul(v));
        else if (k == "loading_bar") write_glob_u8(ADDR_SETTING_LOADING_BAR, (uint8_t)std::stoul(v));
    });

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
            // Resize constant arrays (same pattern as DelphiList)
            write_glob_u32(0x1E91D8, cnt); // count
            uint32_t* nameArr = *(uint32_t**)((uint8_t*)g_load_base + 0x1E91C8);
            uint32_t* valArr  = *(uint32_t**)((uint8_t*)g_load_base + 0x1E91CC);
            for (uint32_t i = 0; i < cnt; i++) {
                if (nameArr) nameArr[i] = (uint32_t)(uintptr_t)make_delphi_str(names[i]);
                if (valArr)  valArr[i]  = (uint32_t)(uintptr_t)make_delphi_str(values[i]);
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
    uint32_t trig_inst = *(uint32_t*)((uint8_t*)trig_vmt - 40);
    gm80l_log("Trigger: class_ref=0x%X instSize=%u", trig_vmt, trig_inst);
    void* trig = delphi_ctor(trig_vmt, 0x55C358);
    gm80l_log("Trigger ctor returned 0x%p", trig);
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

    set_obj_str(font, 4, name);
    parse_kv(txt, [&](auto& k, auto& v) {
        // GM 8.0 has no charset/aa_level fields (save side hardcodes 0)
        if (k == "size") set_obj_u32(font, 8, (uint32_t)std::stoul(v));
        else if (k == "bold") set_obj_bool(font, 12, v == "1");
        else if (k == "italic") set_obj_bool(font, 13, v == "1");
        else if (k == "range_start") set_obj_u32(font, 16, (uint32_t)std::stoul(v));
        else if (k == "range_end") set_obj_u32(font, 20, (uint32_t)std::stoul(v));
    });

    return font;
}

// ==== Load sound ====
// GM 8.0 layout (verified via IDA GM80_Sound_Create/sub_5447A0 + save_sound):
//   +4 kind, +8 name (AnsiString), +16 filename/source (AnsiString),
//   +24 pan (double, ctor=1.0), +32 volume (double), +40 preload (byte),
//   +44 data (TMemoryStream*), +48 effects (i32, ctor=-1)
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
        else if (k == "effects") set_obj_i32(snd, 48, std::stoi(v));
        else if (k == "volume") set_obj_f64(snd, 32, std::stod(v));
        else if (k == "pan") set_obj_f64(snd, 24, std::stod(v));
        else if (k == "preload") set_obj_bool(snd, 40, v == "1");
    });
    set_obj_str(snd, 8, name);   // name lives both in object +8 and parallel array
    if (!src.empty()) set_obj_str(snd, 16, src);

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
            gm80l_log("Sprite %s: %u/%u frames loaded", name.c_str(), loaded, frameCount);
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
// GM 8.0 layout (verified from sub_5470CC editor copy + GM80_Path_Create):
//   +4 points (DelphiList dynamic array, 24 bytes/point: x/y/speed doubles),
//   +8 point_count, +12 ?, +16 connection(byte), +20 precision,
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

    parse_kv(txt, [&](auto& k, auto& v) {
        if (k == "connection") set_obj_u32(pp, 16, (uint32_t)std::stoul(v));
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

    return pp;
}

// ==== Load object ====
// GM 8.0 layout (verified via save_object):
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
    fs::path txtPath = subDir / "object.txt";
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

    // Events (object.gml → Event/Action Delphi objects) — TODO next step:
    // each event type is a Delphi dynamic array at +28 + evType*4
    // (ptr to Event*[n], length at ptr-4); Event: +4 Action*[], +8 count.

    return obj;
}

// ==== Load room ====
// GM 8.0 layout (verified via save_room, sub_5480A4):
//   +4 caption/name (AnsiString), +8 roomspeed, +12 width, +16 height,
//   +20 snap_x, +24 snap_y, +28 clear_screen(byte), +29 clear_view(byte),
//   +32 bg_color, +40..+296: 8×32 RoomBackground, +296 views_enabled(byte),
//   +300..+748: 8×56 View, +772 remember(byte), +776 editor_width, +780 editor_height
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

    set_obj_str(rm, 4, name); // room name == caption
    parse_kv(txt, [&](auto& k, auto& v) {
        if (k == "roomspeed") set_obj_u32(rm, 8, (uint32_t)std::stoul(v));
        else if (k == "width") set_obj_u32(rm, 12, (uint32_t)std::stoul(v));
        else if (k == "height") set_obj_u32(rm, 16, (uint32_t)std::stoul(v));
        else if (k == "snap_x") set_obj_u32(rm, 20, (uint32_t)std::stoul(v));
        else if (k == "snap_y") set_obj_u32(rm, 24, (uint32_t)std::stoul(v));
        else if (k == "clear_screen") set_obj_bool(rm, 28, v == "1");
        else if (k == "clear_view") set_obj_bool(rm, 29, v == "1");
        else if (k == "bg_color") set_obj_u32(rm, 32, (uint32_t)std::stoul(v));
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

    // Instances/tiles (instances.txt, layers.txt) — TODO next step

    return rm;
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
    for (uint32_t i = 0; i < cnt; i++) {
        if (names[i].empty()) continue;
        void* obj = loader(names[i], resDir);
        if (obj) {
            newObjs[i] = obj;
            if (newNames) newNames[i] = make_delphi_str(names[i]);
            // Register 16×16 thumbnail like GM's sprite loader (sub_540108):
            //   sub_4F959C(sprite) → TBitmap; sub_4F18D0(TBitmap) → index
            // index stored in the 5th sprite array (0x1E9118)
            if (isSprites) {
                uint32_t fnThumb = (uint32_t)base + 0xF959C;
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
                    int32_t* extra = (int32_t*)get_asset_array(0x1E9118);
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
    // Find the .gm80 metadata file
    for (auto& entry : fs::directory_iterator(root)) {
        auto ext = entry.path().extension().string();
        if (ext == ".gm80" || entry.path().filename().string().find(".gm80") != std::string::npos) {
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

    // 3. Load settings + constants
    load_settings(root);

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

    // 5. Load sounds
    gm80l_log("Loading sounds...");
    load_assets_simple("sounds", load_sound, find_res("sounds"), root);
    gm80l_log("Sounds done.");

    // 6. Load sprites
    gm80l_log("Loading sprites...");
    load_assets_simple("sprites", load_sprite_obj, find_res("sprites"), root);
    gm80l_log("Sprites done.");

    // 7. Load backgrounds
    gm80l_log("Loading backgrounds...");
    load_assets_simple("backgrounds", load_bg_obj, find_res("backgrounds"), root);
    gm80l_log("Backgrounds done.");

    // 8. Load paths
    gm80l_log("Loading paths...");
    load_assets_simple("paths", load_path_obj, find_res("paths"), root);
    gm80l_log("Paths done.");

    // 9. Load scripts
    gm80l_log("Loading scripts...");
    load_assets_simple("scripts", load_script, find_res("scripts"), root);
    gm80l_log("Scripts done.");

    // 10. Load fonts
    gm80l_log("Loading fonts...");
    load_assets_simple("fonts", load_font, find_res("fonts"), root);
    gm80l_log("Fonts done.");

    // 11. Load objects (needs sprite + object name context)
    gm80l_log("Loading objects...");
    {
        auto names = load_names(root / "objects" / "index.yyd");
        auto sprites = load_names(root / "sprites" / "index.yyd");
        load_assets_ctx("objects", load_object, find_res("objects"), root, names, sprites);
    }
    gm80l_log("Objects done.");

    // 12. Load rooms (needs object + background name context)
    gm80l_log("Loading rooms...");
    {
        auto names = load_names(root / "rooms" / "index.yyd");
        auto objs = load_names(root / "objects" / "index.yyd");
        auto bgs = load_names(root / "backgrounds" / "index.yyd");
        load_assets_ctx("rooms", load_room_obj, find_res("rooms"), root, objs, bgs);
    }
    gm80l_log("Rooms done.");

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

    // 14. Timelines — SKIPPED for now (VMT/ctor pending)

    // 15. Clear all updated flags
    clear_all_updated_flags();

    // 16. Update settings timestamp
    write_glob_f64(ADDR_SETTINGS_TIMESTAMP, 0.0);

    gm80l_log("gm80_load_project: SUCCESS, returning true");
    return true;
}

// ==== Fallback: .gm80 → GMKProject → .gmk → GM loader ====
// Kept for backward compatibility
bool gm80_load_from_path(GMKProject& proj, const std::wstring& wpath) {
    fs::path root(wpath);
    if (!fs::is_directory(root)) return false;

    // Read root .gm80 metadata
    for (auto& entry : fs::directory_iterator(root)) {
        auto ext = entry.path().extension().string();
        if (ext == ".gm80" || entry.path().filename().string().find(".gm80") != std::string::npos) {
            std::string meta = read_file(entry.path());
            if (!meta.empty()) {
                parse_kv(meta, [&](auto& k, auto& v) {
                    if (k == "gameid") proj.game_id = (uint32_t)std::stoul(v);
                    else if (k == "info_author") proj.settings.author = v;
                    else if (k == "info_version") proj.settings.version_str = v;
                    else if (k == "info_information") proj.settings.info = decode_delimit(v);
                    else if (k == "exe_company") proj.settings.company = v;
                    else if (k == "exe_copyright") proj.settings.copyright = v;
                    else if (k == "exe_product") proj.settings.product = v;
                    else if (k == "exe_description") proj.settings.description = v;
                });
                break;
            }
        }
    }

    // Read settings
    std::string settxt = read_file(root / "settings" / "settings.txt");
    parse_kv(settxt, [&](auto& k, auto& v) {
        if (k == "fullscreen") proj.settings.fullscreen = (v == "1");
        else if (k == "interpolate_pixels") proj.settings.interpolate_pixels = (v == "1");
        else if (k == "scaling") proj.settings.scaling = std::stoi(v);
        else if (k == "clear_color") proj.settings.clear_color = (uint32_t)std::stoul(v);
        else if (k == "color_depth") proj.settings.color_depth = (uint32_t)std::stoul(v);
        else if (k == "resolution") proj.settings.resolution = (uint32_t)std::stoul(v);
        else if (k == "frequency") proj.settings.frequency = (uint32_t)std::stoul(v);
    });

    // Read resource names
    auto load_n = [&](const char* dir, std::vector<std::string>& out) {
        out = load_names(root / dir / "index.yyd");
    };
    load_n("scripts", proj.script_names);
    load_n("sprites", proj.sprite_names);
    load_n("backgrounds", proj.bg_names);
    load_n("paths", proj.path_names);
    load_n("objects", proj.object_names);
    load_n("rooms", proj.room_names);
    load_n("fonts", proj.font_names);
    load_n("triggers", proj.trigger_names);

    // Read script sources
    for (auto& name : proj.script_names) {
        if (name.empty()) { proj.script_sources.push_back(""); continue; }
        std::string src = read_file(root / "scripts" / (name + ".gml"));
        proj.script_sources.push_back(load_gml(src));
    }

    // Read trigger conditions
    for (auto& name : proj.trigger_names) {
        if (name.empty()) {
            proj.trigger_conditions.push_back("");
            proj.trigger_constants.push_back("");
            continue;
        }
        std::string txt = read_file(root / "triggers" / (name + ".txt"));
        std::string cnst;
        parse_kv(txt, [&](auto& k, auto& v) {
            if (k == "constant") cnst = v;
        });
        std::string gml = read_file(root / "triggers" / (name + ".gml"));
        proj.trigger_conditions.push_back(load_gml(gml));
        proj.trigger_constants.push_back(cnst);
    }

    proj.sprite_count  = (uint32_t)proj.sprite_names.size();
    proj.script_count  = (uint32_t)proj.script_names.size();
    proj.bg_count      = (uint32_t)proj.bg_names.size();
    proj.path_count    = (uint32_t)proj.path_names.size();
    proj.object_count  = (uint32_t)proj.object_names.size();
    proj.room_count    = (uint32_t)proj.room_names.size();
    proj.font_count    = (uint32_t)proj.font_names.size();
    proj.trigger_count = (uint32_t)proj.trigger_names.size();

    return true;
}
