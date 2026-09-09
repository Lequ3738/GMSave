// GM80 multi-file project save — complete rewrite with full resource data
// Reads directly from Delphi objects and writes .gm80 format
#include "pch.h"
#include "gm80_save.h"
#include "gm80_load.h"
#include "gm80_addresses.h"
#include "gm_log.h"
#include "gm80_diag.h"
#include <cstdio>
#include <cstdlib>
#include <set>
#include <sstream>
#include <map>
#include <cctype>
#include <cstring>

// ==== Delphi object field reading ====
// These use the offsets verified by IDA analysis of GM 8.0 serializers

static void* g_save_base = nullptr;

// Any file write failed during this save. When set, gm80_save_to_path does NOT
// advance the smart-save baseline (LAST_SAVE + name hashes), so the next save
// is a full save that retries everything instead of silently skipping a file
// that failed to write.
static bool g_save_io_error = false;

// Reason gm80_save_to_path returned false (resource-name validation error).
// Read by the caller (ide_hooks) AFTER it closes the progress form, so the
// error dialog is never buried under the "Saving…" progress window.
static std::string g_save_error;

const std::string& gm80_save_last_error()
{
    return g_save_error;
}

// ==== Smart save state ====
// A resource is re-written on save only when its Delphi timestamp is newer than
// the last save (LAST_SAVE). Type name/index structure changes (add/delete/
// rename/reorder) are detected via an FNV-1a hash of the index.yyd names and
// force a full re-save of the affected type(s). Type indices match the order in
// gm80_save_to_path's per-type blocks:
//   0 sprites, 1 sounds, 2 backgrounds, 3 paths, 4 scripts, 5 fonts,
//   6 timelines, 7 objects, 8 rooms, 9 triggers
static double g_last_save = 0.0;
static uint64_t g_last_names_hash[10] = {0};
static bool g_has_last_names[10] = {false};
// Included files have their own name-space (index.yyd); track it separately.
static uint64_t g_last_data_hash = 0;
static bool g_has_last_data = false;

// Delphi Now() → TDateTime in ST(0) (sub_40CF18). Same clock GM uses for the
// per-resource timestamps, so ts[i] and LAST_SAVE are directly comparable.
static double now_t()
{
    double r = 0.0;
    uint32_t fn = (uint32_t)g_save_base + 0xCF18;
    __asm {
        call fn
        fstp qword ptr [r]
    }
    return r;
}

// FNV-1a 64 over the index.yyd names (incl. empty slots → structure-sensitive).
static uint64_t names_hash(const std::vector<std::string>& names)
{
    uint64_t h = 14695981039346656037ULL;
    for (auto& n : names)
    {
        for (unsigned char c : n)
        {
            h ^= c;
            h *= 1099511628211ULL;
        }
        h ^= 0xFF;
        h *= 1099511628211ULL; // separator
    }
    return h;
}

// Delphi timestamp array (double*) for a resource type. Returns nullptr when the
// array is absent (null or the 0xFFFFFFFF "uninitialized dynamic array" sentinel).
static double* ts_ptr(uint32_t tsOff)
{
    void* p = *(void**)((uint8_t*)g_save_base + tsOff);
    if (!p || (uintptr_t)p == 0xFFFFFFFF) return nullptr;
    return (double*)p;
}

// xorshift32 — full 32-bit pseudo-random. (rand() has only 15 useful bits and a
// permanently-zero bit 15, which would halve the hash space; the used-set retry
// below makes collisions impossible regardless, but a full-range source retries
// less.)
static uint32_t xrng_state = 0;

static uint32_t xrng()
{
    if (!xrng_state) xrng_state = (uint32_t)GetTickCount64() ^ 0x9E3779B9u;
    xrng_state ^= xrng_state << 13;
    xrng_state ^= xrng_state >> 17;
    xrng_state ^= xrng_state << 5;
    return xrng_state;
}

// Generate a unique 8-hex code-hash for a NEW instance (one the load didn't
// bring in from the file). gm82save parity: instances.txt's hash column stays
// stable across re-saves; only newly-placed instances get a fresh random name.
static std::string gm80_unique_instance_hash(std::set<std::string>& used)
{
    for (;;)
    {
        uint32_t r = xrng() ^ (uint32_t)GetTickCount64();
        char buf[16];
        snprintf(buf, sizeof(buf), "%08X", r);
        std::string h(buf);
        if (used.insert(h).second) return h;
    }
}

// ==== Resource name validation (gm82save filename_invalid parity) ====
// Windows path-component restrictions: `<>:"/\|?*`, reserved device names
// (CON/PRN/AUX/NUL/COM1-9/LPT1-9), trailing dot, blank/`.`/`..`. Returns a short
// reason, or nullptr if the name is usable as a file/directory component.
static const char* filename_invalid(const std::string& s)
{
    if (s == "." || s == "..") return "reserved \".\"";
    // Windows strips trailing dots AND spaces ("foo " becomes "foo") — either
    // collides with a real "foo" directory, so reject both.
    if (!s.empty() && (s.back() == '.' || s.back() == ' ')) return "trailing dot/space";
    if (s.empty()) return "blank";
    bool blank = true;
    for (char c : s)
        if (!isspace((unsigned char)c))
        {
            blank = false;
            break;
        }
    if (blank) return "blank";
    for (char c : s)
        if (strchr("<>:\"/\\|?*", c)) return "contains an invalid character";
    static const char* const reserved[] = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };
    for (auto* r : reserved)
        if (_stricmp(s.c_str(), r) == 0) return "is a reserved device name";
    return nullptr;
}

// Validate one name list; returns a descriptive error for the first invalid or
// case-insensitively duplicate name, or "" if every name is usable.
static std::string validate_name_list(
    const char* what, const std::vector<std::string>& names)
{
    std::map<std::string, int> seen; // lowercase name → first index
    for (size_t i = 0; i < names.size(); i++)
    {
        const std::string& n = names[i];
        if (n.empty()) continue;
        if (const char* why = filename_invalid(n))
        {
            char buf[512];
            snprintf(buf, sizeof(buf), "%s '%s' %s", what, n.c_str(), why);
            return buf;
        }
        // GM 8.0 resource names must be referenceable in code, which only
        // works for ASCII — reject non-ASCII names instead of silently
        // writing GBK bytes into the UTF-8 project files.
        for (unsigned char c : n)
        {
            if (c >= 0x80)
            {
                char buf[512];
                snprintf(buf, sizeof(buf),
                    "%s '%s' contains non-ASCII characters (resource names "
                    "must be English)",
                    what, n.c_str());
                return buf;
            }
        }
        std::string l = n;
        for (auto& c : l)
            c = (char)tolower((unsigned char)c);
        auto it = seen.find(l);
        if (it != seen.end())
        {
            char buf[512];
            snprintf(buf, sizeof(buf), "%s '%s' duplicates '%s' (case-insensitive)", what,
                n.c_str(), names[it->second].c_str());
            return buf;
        }
        seen[l] = (int)i;
    }
    return "";
}

static uint32_t R4(void* obj, int off)
{
    return *(uint32_t*)((uint8_t*)obj + off);
}
static int32_t R4s(void* obj, int off)
{
    return *(int32_t*)((uint8_t*)obj + off);
}
static bool R1(void* obj, int off)
{
    return *(uint8_t*)((uint8_t*)obj + off) != 0;
}
static double R8(void* obj, int off)
{
    return *(double*)((uint8_t*)obj + off);
}
static void* RP(void* obj, int off)
{
    return *(void**)((uint8_t*)obj + off);
}

// Read Delphi AnsiString from object field
// data pointer may be nil for empty strings (matching gm82save UStr::as_slice)
static std::string RS(void* obj, int off)
{
    char** pp = (char**)((uint8_t*)obj + off);
    char* data = *pp;
    if (!data) return "";
    uint32_t len = (uint32_t)*(int32_t*)(data - 4);
    if (len > 2000000) return std::string(data);
    return std::string(data, len);
}

// ==== Stale-resource cleanup ====
// Renaming or deleting a resource in the GM IDE leaves its old .gm80 files
// behind (GMSave — like gm82save — only writes current assets). After a
// successful save, scan each type directory and remove entries whose resource
// name is no longer live. Folder-type resources (sprites/paths/rooms) store one
// directory per resource; file-type resources store one or more files named
// "<name>.<ext>". Only entries matching the type's layout are touched, and
// index.yyd / tree.yyd are always kept. datafiles/ is never scanned (included
// files are real relative paths, handled separately).
static std::string ascii_lower(const std::string& s)
{
    std::string r = s;
    for (auto& c : r)
        if (c >= 'A' && c <= 'Z') c = (char)(c + ('a' - 'A'));
    return r;
}

static bool remove_dir_recursive(const std::wstring& path)
{
    WIN32_FIND_DATAW fd;
    std::wstring pattern = path + L"\\*";
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE)
    {
        do
        {
            std::wstring e = fd.cFileName;
            if (e == L"." || e == L"..") continue;
            std::wstring full = path + L"\\" + e;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                remove_dir_recursive(full);
            else
                DeleteFileW(full.c_str());
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return RemoveDirectoryW(path.c_str()) != 0;
}

// Scan one type directory under `root`; delete entries whose resource name
// isn't in `names`. `folder_type` = the resource name is a directory
// (sprites/paths/rooms); otherwise the name is the file stem (last extension
// stripped). Returns the number of entries removed.
static int cleanup_type_dir(const std::wstring& root, const wchar_t* dir,
    const std::vector<std::string>& names, bool folder_type)
{
    std::wstring dirPath = root + L"\\" + dir;
    if (GetFileAttributesW(dirPath.c_str()) == INVALID_FILE_ATTRIBUTES) return 0;

    std::set<std::string> live;
    for (auto& n : names)
        if (!n.empty()) live.insert(ascii_lower(n));

    WIN32_FIND_DATAW fd;
    std::wstring pattern = dirPath + L"\\*";
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    int removed = 0;
    do
    {
        std::wstring entry = fd.cFileName;
        if (entry == L"." || entry == L"..") continue;
        if (entry == L"index.yyd" || entry == L"tree.yyd") continue;
        bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (isDir != folder_type) continue; // only scan the type's own layout

        std::string name;
        if (folder_type)
        {
            // directory name is the resource name (wchar→char 1:1, matching the
            // save-side widening of the byte names)
            for (wchar_t w : entry)
                name.push_back((char)w);
        }
        else
        {
            auto dot = entry.find_last_of(L'.');
            if (dot == std::wstring::npos) continue; // extensionless file → not ours
            for (wchar_t w : entry.substr(0, dot))
                name.push_back((char)w);
        }
        if (live.count(ascii_lower(name))) continue; // still live → keep

        std::wstring full = dirPath + L"\\" + entry;
        bool ok = isDir ? remove_dir_recursive(full) : (DeleteFileW(full.c_str()) != 0);
        if (ok)
        {
            removed++;
            gm_log("cleanup: removed stale %S", full.c_str());
        }
        else
        {
            gm_log("cleanup: could not remove %S", full.c_str());
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return removed;
}

// Read global u32/u8
static uint32_t GU32(uint32_t off)
{
    return *(uint32_t*)((uint8_t*)g_save_base + off);
}
static uint8_t GU8(uint32_t off)
{
    return *(uint8_t*)((uint8_t*)g_save_base + off);
}

// Read Delphi AnsiString from global
// data pointer may be nil or sentinel for uninitialized strings
static std::string GS(uint32_t off)
{
    char** pp = (char**)((uint8_t*)g_save_base + off);
    char* data = *pp;
    if (!data || (uintptr_t)data < 0x10000) return "";
    uint32_t len = (uint32_t)*(int32_t*)(data - 4);
    if (len > 200000) return "";
    return std::string(data, len);
}

// Read names from a DelphiList of Delphi string pointers.
// Returns false when the array looks invalid (null / GM's 0xFFFFFFFF
// "uninitialized dynamic array" sentinel / absurd count). Callers MUST treat
// false as "read failed", not as "zero resources" — cleanup_type_dir with an
// empty live set would DELETE every file of that type, and dereferencing the
// sentinel pointer is an instant read-AV (2026-09-09).
static bool read_names_global(
    uint32_t name_off, uint32_t cnt_off, std::vector<std::string>& out)
{
    uint32_t* names = *(uint32_t**)((uint8_t*)g_save_base + name_off);
    uint32_t cnt = *(uint32_t*)((uint8_t*)g_save_base + cnt_off);
    if (!names || names == (uint32_t*)0xFFFFFFFF || cnt > 50000) return false;
    out.reserve(cnt);
    for (uint32_t i = 0; i < cnt; i++)
    {
        char* p = (char*)(uintptr_t)names[i];
        if (!p)
        {
            out.push_back("");
            continue;
        }
        uint32_t len = (uint32_t)*(int32_t*)(p - 4);
        if (len > 200000)
        {
            out.push_back(std::string(p));
            continue;
        } // garbage length: C-string fallback

        // A resource name is the bytes up to the first NUL. GM may leave
        // trailing bytes after the terminator (stale folder path / a previous
        // longer name). Those must never reach validation or filenames — this
        // is why renaming a script to "g" still failed "contains an invalid
        // character": the declared length covered junk past the NUL while
        // %s rendered only up to it.
        const char* nul = (const char*)memchr(p, '\0', len);
        size_t nlen = nul ? (size_t)(nul - p) : (size_t)len;
        if (nul)
        {
            std::string hex;
            for (uint32_t k = 0; k < len && k < 48; k++)
            {
                char h[4];
                snprintf(h, sizeof(h), "%02X ", (unsigned char)p[k]);
                hex += h;
            }
            gm_log("save: name has embedded NUL (declared %u, real %zu) — bytes: %s", len,
                nlen, hex.c_str());
        }
        out.push_back(std::string(p, nlen));
    }
    return true;
}

// Read a DelphiList header from object field and return items array + count
struct ListInfo
{
    void** items;
    uint32_t count;
};
static ListInfo read_list(void* obj, int off)
{
    ListInfo li = {nullptr, 0};
    if (!obj) return li;
    void* listPtr = RP(obj, off);
    if (!listPtr)
    {
        // Maybe it's an inline list
        uint32_t* itemsPtr = (uint32_t*)((uint8_t*)obj + off);
        li.items = *(void***)((uint8_t*)obj + off);
        li.count = *(uint32_t*)((uint8_t*)obj + off + 8);
        return li;
    }
    // It's a pointer to a TList
    li.items = *(void***)((uint8_t*)listPtr + 4);
    li.count = *(uint32_t*)((uint8_t*)listPtr + 8);
    return li;
}

static std::string to_str(bool v)
{
    return v ? "1" : "0";
}
static std::string to_str(int v)
{
    return std::to_string(v);
}
static std::string to_str(unsigned v)
{
    return std::to_string(v);
}
static std::string to_str(double v)
{
    char b[64];
    snprintf(b, 64, "%.17g", v);
    return b;
}

// ==== File output via Win32 ====
// Read a whole file (ANSI path) as bytes — for included-file source copies
static std::string read_file_ansi(const std::string& path)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return "";
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::string r;
    if (sz > 0 && sz < 64 * 1024 * 1024)
    {
        r.resize((size_t)sz);
        fread(&r[0], 1, (size_t)sz, f);
    }
    fclose(f);
    return r;
}

static bool wf(const std::wstring& fp, const std::string& content)
{
    auto lp = fp.find_last_of(L"\\/");
    if (lp != std::wstring::npos)
    {
        std::wstring parent = fp.substr(0, lp);
        for (size_t i = 0; i < parent.size(); i++)
        {
            if (parent[i] == L'\\' || parent[i] == L'/')
            {
                std::wstring partial = parent.substr(0, i);
                if (!partial.empty() && partial.back() != L':')
                    CreateDirectoryW(partial.c_str(), NULL);
            }
        }
        CreateDirectoryW(parent.c_str(), NULL);
    }
    HANDLE h = CreateFileW(
        fp.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        g_save_io_error = true;
        return false;
    }
    DWORD written;
    if (!WriteFile(h, content.c_str(), (DWORD)content.size(), &written, NULL) ||
        written != content.size())
        g_save_io_error = true; // partial/failed write
    CloseHandle(h);
    return true;
}

// Serialize a Delphi TBitmap/TIcon object (dword_5E940C/5E9408/5E9404/
// 5E941C) to a file via SaveToStream (vtable+0x58 — 8.0: LoadFromStream is
// vtable+0x54 per sub_59DCD0, SaveToStream follows it) into a TMemoryStream
// whose memory (FMemory=+4, FSize=+8) we dump to file.
// Free a Delphi OBJECT via GM's own TObject.Free (sub_404590: `if Self<>nil
// then call vmt[-4]` = virtual Destroy — verified in IDA 2026-09-09). Used for
// scratch TMemoryStreams; raw FreeMem would skip the destructor.
static void free_delphi_obj(void* obj)
{
    if (!obj) return;
    uint32_t fn = (uint32_t)g_save_base + 0x4590; // TObject.Free
    __asm {
        mov eax, obj
        mov ecx, fn
        call ecx
    }
}

static void save_bitmap_to_file(uint32_t bmpPtr, const wchar_t* fname)
{
    if (!bmpPtr) return;
    // Create TMemoryStream the same way GM's Outer does (off_4EA854 chain).
    uint32_t streamCls = *(uint32_t*)((uint8_t*)g_save_base + 0xEA854);
    if (streamCls < 0x400000) streamCls = *(uint32_t*)((uint8_t*)g_save_base + 0xEA8A0);
    void* stream = nullptr;
    __asm {
        mov dl, 1
        mov eax, streamCls
        mov ecx, 0x404560 // @ClassCreate
        call ecx
        mov stream, eax
    }
    if (!stream) return;
    // TBitmap.SaveToStream(stream) — vtable+0x58
    __asm {
        mov eax, bmpPtr
        mov edx, stream
        mov ecx, [eax]
        call dword ptr [ecx+0x58]
    }
    uint8_t* mem = *(uint8_t**)((uint8_t*)stream + 4); // FMemory
    uint32_t size = *(uint32_t*)((uint8_t*)stream + 8); // FSize
    if (mem && size > 0 && size < 64 * 1024 * 1024)
    {
        wf(fname, std::string((char*)mem, size));
    }
    free_delphi_obj(stream); // scratch stream (leak fix — 4 per save otherwise)
}

static bool wb(const std::wstring& fp, const void* data, size_t len)
{
    auto lp = fp.find_last_of(L"\\/");
    if (lp != std::wstring::npos) CreateDirectoryW(fp.substr(0, lp).c_str(), NULL);
    HANDLE h = CreateFileW(
        fp.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        g_save_io_error = true;
        return false;
    }
    DWORD written;
    if (!WriteFile(h, data, (DWORD)len, &written, NULL) || written != len)
        g_save_io_error = true;
    CloseHandle(h);
    return true;
}

// Convert ANSI (CP_ACP / GBK) → UTF-8 for GML output (matching gm82save)
static std::string ansi_to_utf8(const std::string& ansi)
{
    if (ansi.empty()) return ansi;
    int wlen = MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), (int)ansi.size(), NULL, 0);
    if (wlen <= 0) return ansi;
    std::wstring wide(wlen, 0);
    MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), (int)ansi.size(), &wide[0], wlen);
    int u8len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), wlen, NULL, 0, NULL, NULL);
    if (u8len <= 0) return ansi;
    std::string u8(u8len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), wlen, &u8[0], u8len, NULL, NULL);
    return u8;
}

static std::string encode_gml(const std::string& gml)
{
    std::string out;
    std::istringstream ss(gml);
    std::string line;
    while (std::getline(ss, line))
    {
        // Strip only CR (from CRLF). Keep trailing spaces: they may be part of a
        // string literal (e.g. a multi-line string ending in a space) or the
        // indentation a blank line carries for the editor's auto-indent — both
        // would be corrupted by trimming.
        if (!line.empty() && line.back() == '\r') line.pop_back();
        out += ansi_to_utf8(line) + "\r\n";
    }
    return out;
}

static std::string encode_delimit(const std::string& s)
{
    std::string r;
    for (char c : s)
    {
        if (c == '\\') r += "\\\\";
        else if (c == '\r')
            r += "\\r";
        else if (c == '\n')
            r += "\\n";
        else
            r += c;
    }
    // Replace */ with *\/
    size_t pos = 0;
    while ((pos = r.find("*/", pos)) != std::string::npos)
    {
        r.replace(pos, 2, "*\\/");
        pos += 3;
    }
    return r;
}

// ==== PNG writer for frame data (BGRA → RGBA PNG via WIC) ====
#include <wincodec.h>
#include <shlwapi.h>
#pragma comment(lib, "windowscodecs.lib")

static bool save_png(const std::wstring& fp, const uint8_t* bgra, uint32_t w, uint32_t h)
{
    if (!bgra || w == 0 || h == 0) return false;

    // COM init (once)
    static bool comInit = false;
    if (!comInit)
    {
        (void)CoInitializeEx(NULL, COINIT_MULTITHREADED);
        comInit = true;
    }

    IWICImagingFactory* factory = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory));
    if (FAILED(hr) || !factory) return false;

    IWICBitmapEncoder* encoder = nullptr;
    hr = factory->CreateEncoder(GUID_ContainerFormatPng, NULL, &encoder);
    if (FAILED(hr))
    {
        factory->Release();
        return false;
    }

    IWICStream* stream = nullptr;
    hr = factory->CreateStream(&stream);
    if (FAILED(hr))
    {
        encoder->Release();
        factory->Release();
        return false;
    }

    hr = stream->InitializeFromFilename(fp.c_str(), GENERIC_WRITE);
    if (FAILED(hr))
    {
        stream->Release();
        encoder->Release();
        factory->Release();
        return false;
    }

    hr = encoder->Initialize(stream, WICBitmapEncoderNoCache);
    if (FAILED(hr))
    {
        stream->Release();
        encoder->Release();
        factory->Release();
        return false;
    }

    IWICBitmapFrameEncode* frame = nullptr;
    IPropertyBag2* props = nullptr;
    hr = encoder->CreateNewFrame(&frame, &props);
    if (FAILED(hr))
    {
        stream->Release();
        encoder->Release();
        factory->Release();
        return false;
    }

    hr = frame->Initialize(props);
    if (props) props->Release();
    if (FAILED(hr))
    {
        frame->Release();
        stream->Release();
        encoder->Release();
        factory->Release();
        return false;
    }

    hr = frame->SetSize(w, h);
    if (FAILED(hr))
    {
        frame->Release();
        stream->Release();
        encoder->Release();
        factory->Release();
        return false;
    }

    WICPixelFormatGUID format = GUID_WICPixelFormat32bppBGRA;
    hr = frame->SetPixelFormat(&format);
    if (FAILED(hr))
    {
        frame->Release();
        stream->Release();
        encoder->Release();
        factory->Release();
        return false;
    }

    // BGRA data already in correct format — write directly
    UINT stride = w * 4;
    UINT dataSize = stride * h;
    hr = frame->WritePixels(h, stride, dataSize, (BYTE*)bgra);
    if (FAILED(hr))
    {
        frame->Release();
        stream->Release();
        encoder->Release();
        factory->Release();
        return false;
    }

    hr = frame->Commit();
    frame->Release();
    if (FAILED(hr))
    {
        stream->Release();
        encoder->Release();
        factory->Release();
        return false;
    }

    hr = encoder->Commit();
    encoder->Release();
    stream->Release();
    factory->Release();
    return SUCCEEDED(hr);
}

// ==== Save individual resource types ====

// -- Font --
static void save_font(void* obj, const std::wstring& outPath)
{
    std::string t;
    auto L = [&](const char* k, const std::string& v)
        {
            t += k;
            t += "=";
            t += v;
            t += "\n";
        };
    L("name", ansi_to_utf8(RS(obj, 4)));
    L("size", to_str(R4(obj, 8)));
    L("bold", to_str(R1(obj, 12)));
    L("italic", to_str(R1(obj, 13)));
    L("charset", "0"); // GM80 doesn't have charset byte
    L("aa_level", "0"); // GM80 doesn't have aa_level
    L("range_start", to_str(R4(obj, 16)));
    L("range_end", to_str(R4(obj, 20)));
    wf(outPath + L".txt", t);
}

// -- Path --
static void save_path(void* obj, const std::wstring& outPath)
{
    CreateDirectoryW(outPath.c_str(), NULL);
    // path.txt
    std::string t;
    auto L = [&](const char* k, const std::string& v)
        {
            t += k;
            t += "=";
            t += v;
            t += "\n";
        };
    L("connection", to_str(R4(obj, 12))); // +12 connection (sub_5470CC editor copy)
    L("closed", to_str((uint32_t)*(uint8_t*)((uint8_t*)obj + 16))); // +16 closed (byte)
    L("precision", to_str(R4(obj, 20))); // +20 precision (ctor=4)
    // Room background index
    int roomBg = R4s(obj, 40);
    L("background", roomBg < 0 ? "" : to_str(roomBg));
    L("snap_x", to_str(R4(obj, 44)));
    L("snap_y", to_str(R4(obj, 48)));
    wf(outPath + L"\\path.txt", t);

    // points.txt — read from +4 DelphiList (24 bytes/point: x,y,speed doubles)
    int ptCount = R4s(obj, 8);
    if (ptCount > 256) ptCount = 256;
    std::string pts;
    if (ptCount > 0)
    {
        uint8_t* ptsPtr = (uint8_t*)RP(obj, 4);
        if (ptsPtr)
        {
            for (int i = 0; i < ptCount; i++)
            {
                double x = *(double*)(ptsPtr + 24 * i);
                double y = *(double*)(ptsPtr + 24 * i + 8);
                double spd = *(double*)(ptsPtr + 24 * i + 16);
                pts += to_str((int)x) + "," + to_str((int)y) + "," + to_str((int)spd) +
                    "\n";
            }
        }
    }
    wf(outPath + L"\\points.txt", pts);
}

// -- Sound --
static void save_sound(void* obj, const std::wstring& outPath)
{
    // GM80 sound object layout (verified from GM80_Sound_Create 0x5447A0 +
    // SaveSound_Individual 0x544B8C + LoadSound_Individual 0x5449C8, 2026-08-02):
    //   +4 kind, +8 name, +12 effects, +16 filename/source,
    //   +24 volume (f64, ctor 1.0), +32 pan (f64, ctor 0.0),
    //   +40 preload (byte), +44 data (TMemoryStream*), +48 internal (ctor -1)
    std::string t;
    auto L = [&](const char* k, const std::string& v)
        {
            t += k;
            t += "=";
            t += v;
            t += "\n";
        };
    std::string sndExt = RS(obj, 16); // filename/extension
    // Extract extension from filename
    auto dotPos = sndExt.find_last_of('.');
    std::string cleanExt = (dotPos != std::string::npos) ? sndExt.substr(dotPos + 1)
                                                         : sndExt;
    L("extension", cleanExt);
    L("source",
        ansi_to_utf8(RS(obj, 16))); // UTF-8 (was raw ANSI — mojibake for non-ASCII names)
    L("kind", to_str(R4(obj, 4))); // kind
    L("effects", to_str(R4(obj, 12))); // effects (was wrongly +48)
    L("volume", to_str(R8(obj, 24))); // volume as double (was wrongly +32)
    L("pan", to_str(R8(obj, 32))); // pan as double (was wrongly +24)
    L("preload", to_str(R1(obj, 40))); // preload flag
    // Check for binary audio data
    void* dataObj = RP(obj, 44);
    bool exists = (dataObj != nullptr);
    L("exists", to_str(exists));
    wf(outPath + L".txt", t);

    // Write audio data if present
    if (exists)
    {
        // Delphi TMemoryStream layout: [vtable:4][memory:4][size:4][position:4][capacity:4]
        void* mem = *(void**)((uint8_t*)dataObj + 4);
        uint32_t sz = *(uint32_t*)((uint8_t*)dataObj + 8);
        if (mem && sz > 0 && sz < 100 * 1024 * 1024)
        {
            wb(outPath + L"." + std::wstring(cleanExt.begin(), cleanExt.end()), mem, sz);
        }
    }
}

// -- Sprite --
static void save_sprite(void* obj, const std::wstring& outPath)
{
    CreateDirectoryW(outPath.c_str(), NULL);

    // sprite.txt
    std::string t;
    auto L = [&](const char* k, const std::string& v)
        {
            t += k;
            t += "=";
            t += v;
            t += "\n";
        };
    int frameCount = R4s(obj, 4);
    L("frames", to_str(frameCount));
    // GM 8.0 layout (verified from sub_4F8E40 .gmk loader order):
    // +8 origin_x, +12 origin_y, +16 collision_shape, +20 alpha_tolerance
    L("origin_x", to_str(R4s(obj, 8)));
    L("origin_y", to_str(R4s(obj, 12)));
    L("collision_shape", to_str(R4(obj, 16)));
    L("alpha_tolerance", to_str(R4(obj, 20)));
    L("per_frame_colliders", to_str(R1(obj, 24)));
    L("bbox_type", to_str(R4(obj, 36)));
    L("bbox_left", to_str(R4s(obj, 28)));
    L("bbox_top", to_str(R4s(obj, 32)));
    L("bbox_right", to_str(R4s(obj, 40)));
    L("bbox_bottom", to_str(R4s(obj, 44)));
    wf(outPath + L"\\sprite.txt", t);

    // Frames: raw Frame** array at +48 (NOT TList), count from +4
    void** framePtrs = (void**)RP(obj, 48);
    if (framePtrs && frameCount > 0 && frameCount < 10000)
    {
        for (int i = 0; i < frameCount; i++)
        {
            void* frame = framePtrs[i];
            if (!frame) continue;
            uint32_t fw = R4(frame, 4);
            uint32_t fh = R4(frame, 8);
            uint8_t* pix = (uint8_t*)RP(frame, 12);
            if (pix && fw > 0 && fh > 0 && fw < 16384 && fh < 16384)
            {
                wchar_t fname[32];
                swprintf(fname, 32, L"\\%u.png", i);
                if (!save_png(outPath + fname, pix, fw, fh)) g_save_io_error = true;
            }
        }
    }
}

// -- Background --
static void save_background(void* obj, const std::wstring& outPath)
{
    void* frame = RP(obj, 4); // Frame object at +4
    bool exists = false;
    uint32_t fw = 0, fh = 0;
    uint8_t* pix = nullptr;
    if (frame)
    {
        fw = R4(frame, 4);
        fh = R4(frame, 8);
        pix = (uint8_t*)RP(frame, 12);
        exists = (pix && fw > 0 && fh > 0);
    }

    // Save image
    if (exists)
    {
        if (!save_png(outPath + L".png", pix, fw, fh)) g_save_io_error = true;
    }

    // bg.txt
    std::string t;
    auto L = [&](const char* k, const std::string& v)
        {
            t += k;
            t += "=";
            t += v;
            t += "\n";
        };
    L("exists", to_str(exists));
    // GM 8.0 does have tileset at +8 (verified sub_5208C4 bg editor copy)
    L("tileset", to_str((uint32_t)*(uint8_t*)((uint8_t*)obj + 8)));
    L("tile_width", to_str(R4(obj, 12)));
    L("tile_height", to_str(R4(obj, 16)));
    L("tile_hoffset", to_str(R4(obj, 20)));
    L("tile_voffset", to_str(R4(obj, 24)));
    L("tile_hsep", to_str(R4(obj, 28)));
    L("tile_vsep", to_str(R4(obj, 32)));
    wf(outPath + L".txt", t);
}

// -- Script --
static void save_script(void* obj, const std::string& source, const std::wstring& outPath)
{
    wf(outPath + L".gml", encode_gml(source));
}

// -- Trigger --
static void save_trigger(void* obj, const std::wstring& outPath)
{
    std::string t;
    t += "constant=" + ansi_to_utf8(RS(obj, 12)) + "\n"; // constant_name
    t += "kind=" + to_str(R4(obj, 16)) + "\n"; // kind
    wf(outPath + L".txt", t);
    wf(outPath + L".gml", encode_gml(RS(obj, 8))); // condition
}

// -- Timeline --
static void save_timeline(
    void* obj, const std::vector<std::string>& objectNames, const std::wstring& outPath)
{
    int momentCount = R4s(obj, 12);
    if (momentCount <= 0 || momentCount > 10000) return;

    void** actionLists = *(void***)((uint8_t*)obj + 4); // Array of action list pointers
    int* moments = *(int**)((uint8_t*)obj + 8); // Array of moment times

    if (!actionLists || !moments) return;

    std::string gml;
    for (int i = 0; i < momentCount; i++)
    {
        int step = moments[i];
        void* evList = actionLists[i]; // List of action pointers
        if (!evList) continue;
        uint32_t actCount = *(uint32_t*)((uint8_t*)evList + 8);
        void** actions = *(void***)((uint8_t*)evList + 4);
        if (!actions || actCount == 0 || actCount > 10000) continue;

        gml += "#define " + to_str(step) + "\r\n";
        for (uint32_t a = 0; a < actCount; a++)
        {
            void* act = actions[a];
            if (!act) continue;
            gml += "/*\"/*'/**//* YYD ACTION\r\n";
            gml += "lib_id=" + to_str(R4(act, 4)) + "\r\n"; // +4 = lib_id
            gml += "action_id=" + to_str(R4(act, 8)) + "\r\n"; // +8 = action_id
            uint32_t kind = R4(act, 12); // +12 = action_kind
            if (R1(act, 16)) // +16 = can_be_relative
                gml += "relative=" + to_str(R1(act, 72)) + "\r\n"; // +72 = is_relative
            if (R1(act, 18))
            { // +18 = applies_to_something
                int32_t at = R4s(act, 68); // +68 = applies_to
                if (at == -2) gml += "applies_to=other\r\n";
                else if (at == -1)
                    gml += "applies_to=self\r\n";
                else if (at >= 0)
                {
                    if (at < (int)objectNames.size())
                        gml += "applies_to=" + objectNames[at] + "\r\n";
                    else
                    {
                        gml += "applies_to=" + to_str(at) + "\r\n"; // tolerant fallback
                        gm80_diag_add("a timeline action applies_to references a deleted "
                            "object (index %d)",
                            at);
                    }
                }
            }
            int argCount = R4s(act, 32); // +32 = param_count
            switch (kind)
            {
            case 0:     // normal — use param_strings (matching gm82save)
                gml += "invert=" + to_str(R1(act, 108)) +
                    "\r\n";     // +108 = invert_condition
                for (int j = 0; j < argCount && j < 8; j++)
                {
                    std::string pval = RS(act, 76 + j * 4);     // +76 = param_strings[j]
                    gml += "arg" + to_str(j) + "=" +
                        encode_delimit(ansi_to_utf8(pval)) + "\r\n";
                }
                break;
            case 5:     // repeat
                gml += "repeats=" + ansi_to_utf8(RS(act, 76)) + "\r\n"; // param_strings[0]
                break;
            case 6:     // variable
                gml += "var_name=" + ansi_to_utf8(RS(act, 76)) + "\r\n";
                gml += "var_value=" + ansi_to_utf8(RS(act, 80)) + "\r\n"; // param_strings[1]
                break;
                // case 7: code — write nothing before */
            }
            gml += "*/\r\n";
            if (kind == 7)
            { // code action
                std::string code = RS(act, 76); // param_strings[0]
                if (!code.empty()) gml += encode_gml(code);
            }
        }
    }
    wf(outPath + L".gml", gml);
}

// -- Object --
static void save_object(void* obj, const std::vector<std::string>& spriteNames,
    const std::vector<std::string>& soundNames, const std::vector<std::string>& bgNames,
    const std::vector<std::string>& pathNames,
    const std::vector<std::string>& scriptNames,
    const std::vector<std::string>& fontNames, const std::vector<std::string>& tlNames,
    const std::vector<std::string>& objectNames,
    const std::vector<std::string>& roomNames,
    const std::vector<std::string>& triggerNames, const std::wstring& outPath)
{

    // .txt
    std::string t;
    auto L = [&](const char* k, const std::string& v)
        {
            t += k;
            t += "=";
            t += v;
            t += "\n";
        };
    int sprIdx = R4s(obj, 4);
    int parentIdx = R4s(obj, 20);
    int maskIdx = R4s(obj, 24);
    L("sprite",
        (sprIdx >= 0 && sprIdx < (int)spriteNames.size()) ? spriteNames[sprIdx] : "");
    L("visible", to_str(R1(obj, 9)));
    L("solid", to_str(R1(obj, 8)));
    L("persistent", to_str(R1(obj, 16)));
    L("depth", to_str(R4s(obj, 12)));
    L("parent",
        (parentIdx >= 0 && parentIdx < (int)objectNames.size()) ? objectNames[parentIdx]
                                                                : "");
    L("mask",
        (maskIdx >= 0 && maskIdx < (int)spriteNames.size()) ? spriteNames[maskIdx] : "");
    wf(outPath + L".txt", t);

    // object.gml — events (Delphi dynamic arrays, NOT TList)
    std::string gml;
    const char* evNames[] = {"Create", "Destroy", "Alarm", "Step", "Collision",
                             "Keyboard", "Mouse", "Other", "Draw", "KeyPress", "KeyRelease", "Trigger"};
    for (int evType = 0; evType < 12; evType++)
    {
        int listOff = 28 + evType * 4;
        // Dynamic array: pointer to first element, length at pointer-4
        void* evArray = RP(obj, listOff);
        if (!evArray) continue;
        uint32_t evCount = *(uint32_t*)((uint8_t*)evArray - 4);
        void** events = (void**)evArray;
        // Event numbers are small (keyboard/mouse codes ≤ 255); a garbage
        // count would make the loop below scan far past the array (read-AV).
        if (evCount == 0 || evCount > 4096) continue;

        for (uint32_t ei = 0; ei < evCount; ei++)
        {
            void* ev = events[ei];
            if (!ev) continue;
            // Event: +4=Action*[] raw array, +8=action_count
            uint32_t actCount = *(uint32_t*)((uint8_t*)ev + 8);
            void** actions = (void**)*(void**)((uint8_t*)ev + 4);
            if (!actions || actCount == 0 || actCount > 10000) continue;

            // Event name
            std::string evName = evNames[evType];
            if (evType == 4)
            { // Collision — use object name for event number
                evName += "_" +
                    ((ei < objectNames.size()) ? objectNames[ei] : to_str((int)ei));
            }
            else if (evType == 11)
            { // Trigger — use trigger name
                evName += "_" +
                    ((ei < triggerNames.size()) ? triggerNames[ei] : to_str((int)ei));
            }
            else
            {
                evName += "_" + to_str((int)ei);
            }
            gml += "#define " + evName + "\r\n";

            // Write actions (matching gm82save save_event exactly)
            for (uint32_t a = 0; a < actCount; a++)
            {
                void* act = actions[a];
                if (!act) continue;
                gml += "/*\"/*'/**//* YYD ACTION\r\n";
                gml += "lib_id=" + to_str(R4(act, 4)) + "\r\n"; // +4 = lib_id
                gml += "action_id=" + to_str(R4(act, 8)) + "\r\n"; // +8 = action_id
                uint32_t kind = R4(act, 12); // +12 = action_kind
                if (R1(act, 16)) // +16 = can_be_relative
                    gml += "relative=" + to_str(R1(act, 72)) +
                        "\r\n"; // +72 = is_relative
                if (R1(act, 18))
                { // +18 = applies_to_something
                    int32_t at = R4s(act, 68); // +68 = applies_to
                    if (at == -2) gml += "applies_to=other\r\n";
                    else if (at == -1)
                        gml += "applies_to=self\r\n";
                    else if (at >= 0)
                    {
                        if (at < (int)objectNames.size())
                            gml += "applies_to=" + objectNames[at] + "\r\n";
                        else
                        {
                            // Deleted object: keep the save tolerant (write the
                            // index) but flag it so the broken action is found.
                            gml += "applies_to=" + to_str(at) + "\r\n";
                            gm80_diag_add("an action applies_to references a deleted "
                                "object (index %d)",
                                at);
                        }
                    }
                }
                int argCount = R4s(act, 32); // +32 = param_count
                switch (kind)
                {
                case 0:     // normal — resolve param_types to resource names
                    gml += "invert=" + to_str(R1(act, 108)) +
                        "\r\n";     // +108 = invert_condition
                    for (int j = 0; j < argCount && j < 8; j++)
                    {
                        uint32_t ptype = R4(act, 36 + j * 4);     // +36 = param_types[j]
                        std::string pval = RS(
                            act, 76 + j * 4);     // +76 = param_strings[j]
                        if (ptype >= 5 && ptype <= 14)
                        {
                            // Non-throwing numeric parse (std::stoi throws on a
                            // corrupted param string and aborts the whole save).
                            // Garbage → -1 → written as "no reference".
                            int idx = -1;
                            if (!pval.empty())
                            {
                                char* end = nullptr;
                                long v = strtol(pval.c_str(), &end, 10);
                                if (end && *end == '\0' && v >= 0 && v < 1000000)
                                    idx = (int)v;
                            }
                            if (ptype == 5)
                                pval = (idx >= 0 && idx < (int)spriteNames.size())
                                        ? spriteNames[idx]
                                        : "";
                            else if (ptype == 6)
                                pval = (idx >= 0 && idx < (int)soundNames.size())
                                        ? soundNames[idx]
                                        : "";
                            else if (ptype == 7)
                                pval = (idx >= 0 && idx < (int)bgNames.size())
                                        ? bgNames[idx]
                                        : "";
                            else if (ptype == 8)
                                pval = (idx >= 0 && idx < (int)pathNames.size())
                                        ? pathNames[idx]
                                        : "";
                            else if (ptype == 9)
                                pval = (idx >= 0 && idx < (int)scriptNames.size())
                                        ? scriptNames[idx]
                                        : "";
                            else if (ptype == 10)
                                pval = (idx >= 0 && idx < (int)objectNames.size())
                                        ? objectNames[idx]
                                        : "";
                            else if (ptype == 11)
                                pval = (idx >= 0 && idx < (int)roomNames.size())
                                        ? roomNames[idx]
                                        : "";
                            else if (ptype == 12)
                                pval = (idx >= 0 && idx < (int)fontNames.size())
                                        ? fontNames[idx]
                                        : "";
                            else if (ptype == 14)
                                pval = (idx >= 0 && idx < (int)tlNames.size())
                                        ? tlNames[idx]
                                        : "";
                        }
                        gml += "arg" + to_str(j) + "=" +
                            encode_delimit(ansi_to_utf8(pval)) + "\r\n";
                    }
                    break;
                case 5:     // repeat
                    gml += "repeats=" + ansi_to_utf8(RS(act, 76)) + "\r\n";
                    break;
                case 6:     // variable
                    gml += "var_name=" + ansi_to_utf8(RS(act, 76)) + "\r\n";
                    gml += "var_value=" + ansi_to_utf8(RS(act, 80)) + "\r\n";
                    break;
                }
                gml += "*/\r\n";
                if (kind == 7)
                { // code action
                    std::string code = RS(act, 76); // param_strings[0]
                    if (!code.empty()) gml += encode_gml(code);
                }
            }
        }
    }
    wf(outPath + L".gml", gml);
}

// Clean unused assets before serializing a room: GM's own room save
// (GM80_SaveRoom_Individual 0x54898C) calls GM80_Room_CleanUnused (0x547F80)
// first — it removes instances/tiles that reference deleted objects/backgrounds
// (compacting the arrays) so a stale reference is never serialized. We mirror
// that. (Verified: 8.1 GM81_Room_CleanUnused 0x6576FC ↔ 8.0 0x547F80,
// similarity 1.0.)
static void clean_room_unused(void* room)
{
    if (!room || (uintptr_t)room < 0x10000) return;
    uint32_t fn = (uint32_t)g_save_base + 0x147F80; // GM80_Room_CleanUnused
    __asm {
        mov eax, room
        call fn
    }
}

// -- Room --
static void save_room(void* obj, const std::vector<std::string>& bgNames,
    const std::vector<std::string>& objectNames,
    const std::vector<std::string>& roomNames, const std::wstring& outPath)
{
    CreateDirectoryW(outPath.c_str(), NULL);
    clean_room_unused(obj);

    // room.txt
    std::string t;
    auto L = [&](const std::string& k, const std::string& v)
        {
            t += k;
            t += "=";
            t += v;
            t += "\n";
        };

    L("caption", ansi_to_utf8(RS(obj, 4)));
    L("width", to_str(R4(obj, 12)));
    L("height", to_str(R4(obj, 16)));
    // snap at +20/+24, clear at +28/+29 — verified from sub_5480A4 room init
    L("snap_x", to_str(R4(obj, 20)));
    L("snap_y", to_str(R4(obj, 24)));
    L("isometric", to_str(R1(obj, 28))); // +28 (verified sub_548360)
    L("roomspeed", to_str(R4(obj, 8)));
    L("roompersistent", to_str(R1(obj, 29))); // +29
    L("bg_color", to_str(R4(obj, 32)));
    L("clear_screen", to_str(R1(obj, 36))); // +36
    L("clear_view", to_str(R1(obj, 37))); // +37

    // 8 backgrounds
    t += "\n";
    for (int i = 0; i < 8; i++)
    {
        int bgOff = 40 + i * 32;
        std::string si = to_str(i);
        L("bg_visible" + si, to_str(R1(obj, bgOff)));
        L("bg_is_foreground" + si, to_str(R1(obj, bgOff + 1)));
        int bgSrc = R4s(obj, bgOff + 4);
        std::string bgName = (bgSrc >= 0 && bgSrc < (int)bgNames.size()) ? bgNames[bgSrc]
                                                                         : "";
        L("bg_source" + si, bgName);
        L("bg_xoffset" + si, to_str(R4s(obj, bgOff + 8)));
        L("bg_yoffset" + si, to_str(R4s(obj, bgOff + 12)));
        L("bg_tile_h" + si, to_str(R1(obj, bgOff + 16)));
        L("bg_tile_v" + si, to_str(R1(obj, bgOff + 17)));
        L("bg_hspeed" + si, to_str(R4s(obj, bgOff + 20)));
        L("bg_vspeed" + si, to_str(R4s(obj, bgOff + 24)));
        L("bg_stretch" + si, to_str(R1(obj, bgOff + 28)));
    }

    // views_enabled at +296, 8 views at +300 (56 bytes each) — verified from sub_5480A4
    t += "\n";
    L("views_enabled", to_str(R1(obj, 296)));
    for (int i = 0; i < 8; i++)
    {
        int vwOff = 300 + i * 56;
        std::string si = to_str(i);
        L("view_visible" + si, to_str(R1(obj, vwOff)));
        L("view_xview" + si, to_str(R4s(obj, vwOff + 4)));
        L("view_yview" + si, to_str(R4s(obj, vwOff + 8)));
        L("view_wview" + si, to_str(R4(obj, vwOff + 12)));
        L("view_hview" + si, to_str(R4(obj, vwOff + 16)));
        L("view_xport" + si, to_str(R4s(obj, vwOff + 20)));
        L("view_yport" + si, to_str(R4s(obj, vwOff + 24)));
        L("view_wport" + si, to_str(R4(obj, vwOff + 28)));
        L("view_hport" + si, to_str(R4(obj, vwOff + 32)));
        L("view_fol_hbord" + si, to_str(R4s(obj, vwOff + 36)));
        L("view_fol_vbord" + si, to_str(R4s(obj, vwOff + 40)));
        L("view_fol_hspeed" + si, to_str(R4s(obj, vwOff + 44)));
        L("view_fol_vspeed" + si, to_str(R4s(obj, vwOff + 48)));
        int folTgt = R4s(obj, vwOff + 52);
        std::string objName = (folTgt >= 0 && folTgt < (int)objectNames.size())
            ? objectNames[folTgt]
            : "";
        L("view_fol_target" + si, objName);
    }

    // Editor state (verified GM80_SaveRoom_Individual 0x54898c 2026-08-02):
    //   +768 remember(byte), +772 editor_width, +776 editor_height,
    //   +780..787 show_grid/show_objects/show_tiles/show_backgrounds/
    //   show_foregrounds/show_views/delete_underlying_objects/
    //   delete_underlying_tiles (bytes), +788 tab, +792 editor_x, +796 editor_y.
    // (Was +4-shifted: remember read +772, editor_x read +788, show_*/tab
    //  hardcoded 0 — wrong values written to the file.)
    t += "\n";
    L("remember", to_str(R1(obj, 768)));
    L("editor_width", to_str(R4(obj, 772)));
    L("editor_height", to_str(R4(obj, 776)));
    L("show_grid", to_str(R1(obj, 780)));
    L("show_objects", to_str(R1(obj, 781)));
    L("show_tiles", to_str(R1(obj, 782)));
    L("show_backgrounds", to_str(R1(obj, 783)));
    L("show_foregrounds", to_str(R1(obj, 784)));
    L("show_views", to_str(R1(obj, 785)));
    L("delete_underlying_objects", to_str(R1(obj, 786)));
    L("delete_underlying_tiles", to_str(R1(obj, 787)));
    L("tab", to_str(R4(obj, 788)));
    L("editor_x", to_str(R4s(obj, 792)));
    L("editor_y", to_str(R4s(obj, 796)));

    wf(outPath + L"\\room.txt", t);

    // code.gml — always write (matching gm82save)
    wf(outPath + L"\\code.gml", encode_gml(RS(obj, 748)));

    // instances.txt — +752=count, +756=Instance[] inline array (24 bytes each)
    // Serializer: mov edx, [eax+ebp*8+off] where ebp=esi*3 → 24-byte stride
    int instCount = R4s(obj, 752);
    uint8_t* instData = *(uint8_t**)((uint8_t*)obj + 756);
    if (instData && instCount > 0 && instCount < 100000)
    {
        std::string ilines;
        std::set<std::string> usedHashes;
        gm80_instance_hashes_collect(usedHashes);
        // Orphaned code files (left behind when an instance was deleted) must not
        // be overwritten by a newly generated hash. ("code.gml" is the room's own
        // creation code, not an instance.)
        {
            std::error_code ec;
            for (auto& e : fs::directory_iterator(outPath, ec))
            {
                if (e.path().extension() != L".gml") continue;
                std::string stem = e.path().stem().string();
                if (stem == "code") continue;
                usedHashes.insert(stem);
            }
        }
        for (int i = 0; i < instCount; i++)
        {
            uint8_t* inst = instData + i * 24;
            int ox = *(int32_t*)(inst + 0);
            int oy = *(int32_t*)(inst + 4);
            int oid = *(int32_t*)(inst + 8);
            int iid = *(int32_t*)(inst + 12);
            char* ccodePtr = *(char**)(inst + 16);
            std::string ccode;
            if (ccodePtr)
            {
                uint32_t len = (uint32_t)*(int32_t*)(ccodePtr - 4);
                if (len < 2000000) ccode.assign(ccodePtr, len);
                else
                    ccode = ccodePtr;
            }
            bool locked = *(uint8_t*)(inst + 20) != 0;
            std::string oname = (oid >= 0 && oid < (int)objectNames.size())
                ? objectNames[oid]
                : to_str(oid);
            // Stable code-hash from the load, or a fresh random one for new
            // instances — NOT derived from the id, so the hash column doesn't
            // change on re-save (git-friendly, gm82save model).
            std::string hash;
            if (const std::string* h = gm80_instance_hash_get(iid))
                if (gm80_valid_code_hash(*h)) hash = *h;
            if (hash.empty())
            {
                hash = gm80_unique_instance_hash(usedHashes);
                gm80_instance_hash_set(iid, hash);
            }
            ilines += oname + "," + to_str(ox) + "," + to_str(oy) + ",";
            ilines += hash;
            ilines += "," + to_str(locked);
            ilines += ",1,1,4294967295,0";
            ilines += "," + to_str(!ccode.empty());
            ilines += "\n";
            if (!ccode.empty())
            {
                wf(outPath + L"\\" + std::wstring(hash.begin(), hash.end()) + L".gml",
                    encode_gml(ccode));
            }
        }
        wf(outPath + L"\\instances.txt", ilines);
    }

    // Tiles — +760=count, +764=Tile[] inline array (40 bytes each)
    // GM 8.0 Tile layout (GM80_SaveRoom_Individual 0x548C50, 9×u32 + locked byte):
    //   +0 x, +4 y, +8 source_bg, +12 u, +16 v, +20 width, +24 height,
    //   +28 depth, +32 id, +36 locked(byte)
    // Output matches gm82save save_tiles: one <depth>.txt per layer with CSV lines
    // "bg,x,y,u,v,w,h,locked,1,1,4294967295" + layers.txt (one depth per line).
    int tileCount = R4s(obj, 760);
    uint8_t* tileData = *(uint8_t**)((uint8_t*)obj + 764);
    if (tileData && tileCount > 0 && tileCount < 100000)
    {
        std::map<int32_t, std::string> layers; // depth → csv lines
        for (int i = 0; i < tileCount; i++)
        {
            uint8_t* tile = tileData + i * 40;
            int tx = *(int32_t*)(tile + 0);
            int ty = *(int32_t*)(tile + 4);
            int bgId = *(int32_t*)(tile + 8);
            int tu = *(int32_t*)(tile + 12);
            int tv = *(int32_t*)(tile + 16);
            int tw = *(int32_t*)(tile + 20);
            int th = *(int32_t*)(tile + 24);
            int depth = *(int32_t*)(tile + 28);
            bool locked = *(uint8_t*)(tile + 36) != 0;
            std::string bgName = (bgId >= 0 && bgId < (int)bgNames.size()) ? bgNames[bgId]
                                                                           : to_str(bgId);
            char buf[160];
            snprintf(buf, sizeof(buf), "%s,%d,%d,%d,%d,%d,%d,%d,1,1,4294967295\n",
                bgName.c_str(), tx, ty, tu, tv, tw, th, locked ? 1 : 0);
            layers[depth] += buf;
        }
        std::string layerNames;
        for (auto& kv : layers)
        {
            layerNames += to_str(kv.first) + "\n";
            wf(outPath + L"\\" + std::to_wstring(kv.first) + L".txt", kv.second);
        }
        wf(outPath + L"\\layers.txt", layerNames);
    }
}

// ==== TTreeNode VCL helpers (standalone, for hierarchical tree.yyd) ====
// TTreeNode: [vtable:4][f1:4][f2:4][name:4][data:4]
// TreeNodeData: [unknown:4][rtype:4][kind:4][index:4]  rtype:2=folder, 3=leaf

// GM 8.0 tree functions — IDA verified from sub_59EB64/sub_59EC84
// sub_497254 (RVA 0x97254): GetCount(node) → child count
// sub_497178 (RVA 0x97178): GetItem(node, index) → child node
static uint32_t __fastcall tree_get_count(void* node)
{
    if (!node || (uintptr_t)node < 0x10000) return 0;
    uint32_t func = (uint32_t)g_save_base + 0x97254;
    uint32_t out;
    __asm {
        mov eax, node
        call func
        mov out, eax
    }
    return out;
}
static void* __fastcall tree_get_item(void* node, uint32_t idx)
{
    uint32_t func = (uint32_t)g_save_base + 0x97178;
    uint32_t out;
    __asm {
        mov eax, node
        mov edx, idx
        call func
        mov out, eax
    }
    return (void*)out;
}

// Read TTreeNode fields (no asm needed)
// Delphi 7 TTreeNode: +4=FOwner, +8=name(AnsiString), +12=data(ptr)
static std::string tree_read_name(void* node)
{
    if (!node) return "";
    char** pp = (char**)((uint8_t*)node + 8);
    char* data = *pp;
    if (!data) return "";
    uint32_t len = (uint32_t)*(int32_t*)(data - 4);
    if (len > 2000) return "";
    return std::string(data, len);
}
static uint32_t* tree_get_data(void* node)
{
    if (!node) return nullptr;
    return *(uint32_t**)((uint8_t*)node + 12);
}

static uint32_t tree_read_rtype(void* node)
{
    uint32_t* td = tree_get_data(node);
    return td ? td[1] : 0;
}

static uint32_t tree_read_index(void* node)
{
    uint32_t* td = tree_get_data(node);
    return td ? td[3] : 0;
}

static uint32_t tree_read_kind(void* node)
{
    uint32_t* td = tree_get_data(node);
    return td ? td[2] : 0;
}

static void tree_write_recurse(void* parent, const std::vector<std::string>& names,
    std::string& tabs, std::string& out)
{
    uint32_t cnt = tree_get_count(parent);
    for (uint32_t i = 0; i < cnt; i++)
    {
        void* child = tree_get_item(parent, i);
        if (!child) continue;
        std::string name = tree_read_name(child);
        uint32_t rtype = tree_read_rtype(child);
        uint32_t index = tree_read_index(child);
        if (rtype == 2)
        {
            // Group (folder) names are free text — GM 8.0 allows Chinese folder
            // names in the resource tree (not referenceable in code, not used
            // as file names), so convert ANSI → UTF-8 like other text fields.
            out += tabs + "+" + ansi_to_utf8(name) + "\n";
            tabs += "\t";
            tree_write_recurse(child, names, tabs, out);
            tabs.pop_back();
        }
        else if (rtype == 3)
        {
            std::string leafName = (index < names.size()) ? names[index] : name;
            out += tabs + "|" + leafName + "\n";
        }
    }
}

// Find TTreeNodes from TTreeView (tries Delphi 7 VCL offsets)
// RT_* TTreeNode root pointers — verified from IDA sub_59EC84 switch table
static uint32_t rt_kind_globals[] = {
    0x1F6258, // kind 1 = Objects
    0x1F625C, // kind 2 = Sprites
    0x1F6260, // kind 3 = Sounds
    0x1F6264, // kind 4 = Rooms
    0x1F6268, // kind 6 = Backgrounds
    0x1F6270, // kind 7 = Scripts
    0x1F626C, // kind 8 = Paths
    0x1F6274, // kind 9 = Fonts
    0x1F6278, // kind 12 = Timelines
};
static uint32_t rt_kinds[] = {1, 2, 3, 4, 6, 7, 8, 9, 12};

// Get the root TTreeNode for a resource type kind
static void* tree_get_root(void* base, uint32_t kind)
{
    for (int i = 0; i < 9; i++)
    {
        if (rt_kinds[i] == kind)
        {
            void** ppNode = (void**)((uint8_t*)base + rt_kind_globals[i]);
            void* node = *ppNode;
            if (node && (uintptr_t)node > 0x10000 && (uintptr_t)node < 0x7FF00000)
                return node;
        }
    }
    return nullptr;
}

// ==== Resource-tree expansion state (tree_state.yyd) ====
// GM 8.0 persists NOTHING about the tree's expanded folders (.gmk tree section
// = structure only, verified sub_59F094), so every load/reload collapses the
// tree. We persist the expanded folders ourselves.
// Control plumbing verified from GM's own expand/collapse (sub_496BC8):
//   hWnd  = [treeView + 0x1B4]   (treeView = [base + 0x1F6288])
//   hItem = [node + 0x10]
//   read  : SendMessage(hWnd, TVM_GETITEMSTATE(0x1127), hItem, TVIS_EXPANDED(0x20))
//   set   : SendMessage(hWnd, TVM_EXPAND(0x1102), TVE_EXPAND(2), hItem)

static HWND tree_view_hwnd(uint8_t* base)
{
    void* tv = *(void**)(base + 0x1F6288);
    if (!tv || (uintptr_t)tv < 0x10000) return NULL;
    HWND h = *(HWND*)((uint8_t*)tv + 0x1B4);
    return (h && (uintptr_t)h >= 0x10000) ? h : NULL;
}

static bool tree_node_expanded(uint8_t* base, void* node)
{
    HWND h = tree_view_hwnd(base);
    if (!h || !node) return false;
    uint32_t hItem = *(uint32_t*)((uint8_t*)node + 0x10);
    if (!hItem) return false;
    LRESULT st = SendMessageW(h, 0x1127 /*TVM_GETITEMSTATE*/, hItem, 0x20 /*TVIS_EXPANDED*/);
    return (st & 0x20) != 0;
}

static void tree_collect_expanded(uint8_t* base, void* parent, std::string& tabs,
    std::set<std::string>& out)
{
    uint32_t cnt = tree_get_count(parent);
    for (uint32_t i = 0; i < cnt; i++)
    {
        void* child = tree_get_item(parent, i);
        if (!child) continue;
        if (tree_read_rtype(child) == 2)
        {
            // Line format matches load_resource_tree's matching: tab*level + name
            // (name as stored in tree.yyd = UTF-8).
            if (tree_node_expanded(base, child))
                out.insert(tabs + ansi_to_utf8(tree_read_name(child)));
            tabs += "\t";
            tree_collect_expanded(base, child, tabs, out);
            tabs.pop_back();
        }
    }
}

// Capture the expanded-folder state of all 9 resource trees and write it to
// <projDir>\cache\tree_state.yyd. Called at the end of every save and just
// before a watcher-triggered reload, so the tree survives reloads and project
// reopen. The cache/ folder holds generated IDE state only — safe to ignore
// in git.
bool gm80_capture_tree_state(void* gm_base, const std::wstring& projDir)
{
    uint8_t* base = (uint8_t*)gm_base;
    if (!base || projDir.empty()) return false;
    if (!tree_view_hwnd(base)) return false; // tree view not ready — nothing to capture

    std::string s;
    for (int i = 0; i < 9; i++)
    {
        void* root = tree_get_root(base, rt_kinds[i]);
        if (!root) continue;
        std::set<std::string> lines;
        // The type root itself (e.g. the "Scripts" root folder) can be
        // expanded/collapsed too — record it with a dedicated marker line.
        if (tree_node_expanded(base, root))
            lines.insert("root_expanded");
        std::string tabs;
        tree_collect_expanded(base, root, tabs, lines);
        if (!lines.empty())
        {
            s += "kind=" + to_str(rt_kinds[i]) + "\n";
            for (auto& line : lines)
                s += line + "\n";
        }
    }

    std::wstring statePath = projDir + L"\\cache\\tree_state.yyd";
    if (s.empty())
    {
        // Nothing expanded — remove any stale state file, or the next load
        // would restore folders the user has since collapsed.
        DeleteFileW(statePath.c_str());
        return true;
    }
    CreateDirectoryW((projDir + L"\\cache").c_str(), NULL);
    wf(statePath, s);
    gm_log("TreeState: wrote %s (%zu bytes)", "cache\\tree_state.yyd", s.size());
    return true;
}

// Extract the F1 help text from the GameInfo RichEdit control.
// Chain: [0x5EAEE8] → [p] → +0x360 → +0x298 → vtable+0x78 (SaveToStream).
// __try lives here in a POD-only frame (no C++ object unwinding).
static bool extract_richtext(uint8_t* b, std::string* out)
{
    out->clear();
    __try
    {
        uint32_t p = *(uint32_t*)(b + 0x1EAEE8);
        uint32_t obj = p ? *(uint32_t*)p : 0;
        uint32_t sub = obj ? *(uint32_t*)(obj + 0x360) : 0;
        uint32_t re = sub ? *(uint32_t*)(sub + 0x298) : 0;
        if (!(re && re >= 0x10000)) return false;
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
        if (!stream) return false;
        __asm {
            mov eax, re
            mov edx, stream
            mov ecx, [eax]
            call dword ptr [ecx+0x78] // RichEdit.SaveToStream
        }
        uint8_t* mem = *(uint8_t**)((uint8_t*)stream + 4);
        uint32_t size = *(uint32_t*)((uint8_t*)stream + 8);
        bool ok = mem && size > 0 && size < 64 * 1024 * 1024;
        if (ok) out->assign((char*)mem, size);
        free_delphi_obj(stream); // scratch stream (leak fix)
        return ok;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return false;
}

// ==== Main save function ====
bool gm80_save_to_path(void* gm_base, const std::wstring& path)
{
    g_save_base = gm_base;
    g_save_io_error = false;
    gm80_diag_reset();
    uint8_t* base = (uint8_t*)gm_base;

    CreateDirectoryW(path.c_str(), NULL);
    auto sub = [&](const wchar_t* s) {
            return path + L"\\" + s;
        };

    // Read resource counts
    uint32_t spriteCnt = GU32(0x1E911C);
    uint32_t soundCnt = GU32(0x1E9288);
    uint32_t bgCnt = GU32(0x1E90A8);
    uint32_t pathCnt = GU32(0x1E92BC);
    uint32_t scriptCnt = GU32(0x1E92E4);
    uint32_t fontCnt = GU32(0x1E92D0);
    uint32_t tlCnt = GU32(0x1E9310);
    uint32_t objectCnt = GU32(0x1E9364);
    uint32_t roomCnt = GU32(0x1E92A4);
    uint32_t triggerCnt = GU32(0x1E92EC);

    // Read resource names (ok=false → array unreadable: skip the type AND its
    // stale-file cleanup — see read_names_global)
    std::vector<std::string> spriteNames, soundNames, bgNames, pathNames;
    std::vector<std::string> scriptNames, fontNames, tlNames, objectNames, roomNames,
        triggerNames;
    bool spriteNamesOk = read_names_global(0x1E9110, 0x1E911C, spriteNames);
    bool bgNamesOk = read_names_global(0x1E909C, 0x1E90A8, bgNames);
    bool pathNamesOk = read_names_global(0x1E92B4, 0x1E92BC, pathNames);
    bool scriptNamesOk = read_names_global(0x1E92DC, 0x1E92E4, scriptNames);
    bool fontNamesOk = read_names_global(0x1E92C8, 0x1E92D0, fontNames);
    bool tlNamesOk = read_names_global(0x1E9308, 0x1E9310, tlNames);
    bool objectNamesOk = read_names_global(0x1E935C, 0x1E9364, objectNames);
    bool roomNamesOk = read_names_global(0x1E929C, 0x1E92A4, roomNames);
    bool soundNamesOk = read_names_global(0x1E9280, 0x1E9288, soundNames); // 0x1E9280 names / 0x1E9288 count

    // Triggers: names inside object at +4
    {
        uint32_t* tarr = *(uint32_t**)(base + 0x1E92E8);
        uint32_t tcnt = *(uint32_t*)(base + 0x1E92EC);
        if (tarr && tcnt && tcnt < 500)
        {
            for (uint32_t i = 0; i < tcnt; i++)
            {
                void* tObj = (void*)(uintptr_t)tarr[i];
                if (!tObj)
                {
                    triggerNames.push_back("");
                    continue;
                }
                triggerNames.push_back(RS(tObj, 4));
            }
        }
    }

    // ==== Resource name validation (abort before any write) ====
    // A name Windows can't use as a path component would silently fail
    // CreateFileW (resource missing on reload) or collide case-insensitively
    // (one file overwrites another → two resources point at the same file).
    // Validate everything up front so an abort leaves the on-disk project
    // exactly as the last good save.
    {
        std::string nerr = validate_name_list("sprite", spriteNames);
        if (nerr.empty()) nerr = validate_name_list("sound", soundNames);
        if (nerr.empty()) nerr = validate_name_list("background", bgNames);
        if (nerr.empty()) nerr = validate_name_list("path", pathNames);
        if (nerr.empty()) nerr = validate_name_list("script", scriptNames);
        if (nerr.empty()) nerr = validate_name_list("font", fontNames);
        if (nerr.empty()) nerr = validate_name_list("timeline", tlNames);
        if (nerr.empty()) nerr = validate_name_list("object", objectNames);
        if (nerr.empty()) nerr = validate_name_list("room", roomNames);
        if (nerr.empty()) nerr = validate_name_list("trigger", triggerNames);
        if (nerr.empty())
        {
            uint32_t dCnt = *(uint32_t*)(base + 0x1E9398);
            uint32_t* dArr = *(uint32_t**)(base + 0x1E9390);
            std::vector<std::string> dNames;
            if (dCnt > 0 && dCnt < 10000 && dArr)
            {
                dNames.reserve(dCnt);
                for (uint32_t i = 0; i < dCnt; i++)
                {
                    void* f = (void*)(uintptr_t)dArr[i];
                    dNames.push_back(f ? RS(f, 4) : std::string());
                }
            }
            nerr = validate_name_list("included file", dNames);
        }
        if (!nerr.empty())
        {
            g_save_error = nerr;
            gm_log("Save: ABORTED — %s", nerr.c_str());
            return false; // caller shows the error after closing the progress form
        }
    }

    // ==== Smart save decision ====
    // changed[t] = type t needs a FULL re-save (its name/index structure changed,
    // or it depends on a type whose structure changed). Otherwise per-resource
    // timestamps decide what is rewritten.
    enum
    {
        T_SPR = 0,
        T_SND,
        T_BG,
        T_PAT,
        T_SCR,
        T_FNT,
        T_TLN,
        T_OBJ,
        T_ROM,
        T_TRG
    };
    const uint64_t curHash[10] = {
        names_hash(spriteNames),
        names_hash(soundNames),
        names_hash(bgNames),
        names_hash(pathNames),
        names_hash(scriptNames),
        names_hash(fontNames),
        names_hash(tlNames),
        names_hash(objectNames),
        names_hash(roomNames),
        names_hash(triggerNames),
    };
    bool changed[10];
    bool anyChanged = false;
    for (int t = 0; t < 10; t++)
    {
        changed[t] = !g_has_last_names[t] || g_last_names_hash[t] != curHash[t];
        if (changed[t]) anyChanged = true;
    }
    // Clock went backwards → timestamps untrustworthy → full save everything.
    if (now_t() < g_last_save)
    {
        for (int t = 0; t < 10; t++)
            changed[t] = true;
        anyChanged = true;
    }
    // Dependency closure (matches gm82save's dependency checks, more conservative):
    // objects & timelines reference every type via action parameters; rooms
    // reference objects+backgrounds; paths reference rooms. A structure change
    // anywhere forces these dependents to be re-saved so index→name references
    // stay correct.
    if (anyChanged)
    {
        changed[T_OBJ] = true;
        changed[T_TLN] = true;
    }
    if (changed[T_OBJ] || changed[T_BG]) changed[T_ROM] = true;
    if (changed[T_ROM]) changed[T_PAT] = true;
    bool smart = (g_last_save != 0.0); // we have saved at least once before
    gm_log("SmartSave: anyChanged=%d full=[%d%d%d%d%d%d%d%d%d%d] smart=%d", anyChanged,
        changed[0], changed[1], changed[2], changed[3], changed[4], changed[5],
        changed[6], changed[7], changed[8], changed[9], smart);

    // ==== Root .gm80 metadata ====
    {
        std::string m;
        m += "gm80_version=" + to_str(GM80_VERSION) + "\n";
        m += "gameid=" + to_str(GU32(0x1F6218)) + "\n\n";
        m += "info_author=" + ansi_to_utf8(GS(0x1E9430)) + "\n";
        m += "info_version=" + ansi_to_utf8(GS(0x1E9434)) + "\n";
        m += "info_information=" +
            encode_delimit(ansi_to_utf8(GS(0x1E9438))) + "\n\n";
        m += "exe_company=" + ansi_to_utf8(GS(0x1E944C)) + "\n";
        m += "exe_product=" + ansi_to_utf8(GS(0x1E9450)) + "\n";
        m += "exe_copyright=" + ansi_to_utf8(GS(0x1E9454)) + "\n";
        m += "exe_description=" + ansi_to_utf8(GS(0x1E9458)) + "\n";
        // Version number quad from GM 8.0 globals dword_5E943C/40/44/48
        // (verified from sub_59E648 .gmk save: 4×u32 after the strings).
        m += "exe_version=" + to_str(GU32(0x1E943C)) + "." + to_str(GU32(0x1E9440)) +
            "." + to_str(GU32(0x1E9444)) + "." + to_str(GU32(0x1E9448)) + "\n\n";
        m += "has_backgrounds=" + to_str(!bgNames.empty()) + "\n";
        m += "has_datafiles=" +
            to_str(*(uint32_t*)((uint8_t*)g_save_base + 0x1E9398) > 0) + "\n";
        m += "has_fonts=" + to_str(!fontNames.empty()) + "\n";
        m += "has_objects=" + to_str(!objectNames.empty()) + "\n";
        m += "has_paths=" + to_str(!pathNames.empty()) + "\n";
        m += "has_scripts=" + to_str(!scriptNames.empty()) + "\n";
        m += "has_sounds=" + to_str(soundCnt > 0) + "\n";
        m += "has_sprites=" + to_str(!spriteNames.empty()) + "\n";
        m += "has_timelines=" + to_str(!tlNames.empty()) + "\n";
        m += "has_triggers=" + to_str(!triggerNames.empty()) + "\n";
        auto basename = path.substr(path.find_last_of(L"\\/") + 1);
        wf(path + L"\\" + basename, m);
    }

    // ==== Settings ====
    // Field offsets corrected 2026-08-02 from GM80_SaveSettings (0x59E648)
    // disasm: fullscreen=0x1E93A0 … scaling=0x1E93B0 … priority=0x1E93F8,
    // loading_bar=0x1E93FC (u32). Previously every field was shifted by one.
    {
        std::string s;
        auto L = [&](const char* k, const std::string& v)
            {
                s += std::string(k) + "=" + v + "\n";
            };
        L("fullscreen", to_str(GU8(ADDR_SETTING_FULLSCREEN) != 0));
        L("interpolate_pixels", to_str(GU8(ADDR_SETTING_INTERPOLATE) != 0));
        L("dont_draw_border", to_str((unsigned)GU8(ADDR_SETTING_DONT_DRAW_BORDER)));
        L("display_cursor", to_str((unsigned)GU8(ADDR_SETTING_DISPLAY_CURSOR)));
        L("scaling",
            to_str((int32_t)GU32(
                ADDR_SETTING_SCALING))); // signed (-1=keep aspect); stoi on u32 form crashes
        L("allow_resize", to_str(GU8(ADDR_SETTING_ALLOW_RESIZE) != 0));
        L("window_on_top", to_str(GU8(ADDR_SETTING_WINDOW_ON_TOP) != 0));
        L("clear_color", to_str(GU32(ADDR_SETTING_CLEAR_COLOR))); // u32 RGBA
        L("set_resolution", to_str(GU8(ADDR_SETTING_SET_RESOLUTION) != 0));
        L("color_depth", to_str(GU32(ADDR_SETTING_COLOR_DEPTH)));
        L("resolution", to_str(GU32(ADDR_SETTING_RESOLUTION)));
        L("frequency", to_str(GU32(ADDR_SETTING_FREQUENCY)));
        L("dont_show_buttons", to_str((unsigned)GU8(ADDR_SETTING_DONT_SHOW_BUTTONS)));
        L("vsync", to_str((unsigned)GU8(ADDR_SETTING_VSYNC)));
        L("swap_creation_events", "0"); // no GM80 global
        L("disable_screensaver", to_str((unsigned)GU8(ADDR_SETTING_DISABLE_SCREENSAVER)));
        L("f4_fullscreen_toggle", to_str((unsigned)GU8(ADDR_SETTING_F4_FULLSCREEN)));
        L("f1_help_menu", to_str((unsigned)GU8(ADDR_SETTING_F1_HELP)));
        L("esc_close_game", to_str((unsigned)GU8(ADDR_SETTING_ESC_CLOSE)));
        L("f5_save_f6_load", to_str((unsigned)GU8(ADDR_SETTING_F5_SAVE_F6_LOAD)));
        L("f9_screenshot", to_str((unsigned)GU8(ADDR_SETTING_F9_SCREENSHOT)));
        L("treat_close_as_esc", to_str((unsigned)GU8(ADDR_SETTING_TREAT_CLOSE_AS_ESC)));
        L("priority", to_str(GU32(ADDR_SETTING_PRIORITY))); // u32 0/1/2
        L("freeze_on_lose_focus", to_str(GU8(ADDR_SETTING_FREEZE_ON_LOSE_FOCUS) != 0));
        // Loading-bar state: value at 0x1E93FC (u32 0 none / 1 default / 2 custom);
        // custom bitmaps at dword_5E940C/5E9408 (back/front) and dword_5E9404
        // (loader image), flagged by byte_5E9400.
        L("custom_loader", to_str((unsigned)GU8(ADDR_SETTING_CUSTOM_LOADER)));
        L("custom_bar", to_str(GU32(ADDR_SETTING_LOADING_BAR)));
        L("bar_has_bg",
            to_str(*(uint32_t*)((uint8_t*)g_save_base + ADDR_SETTING_BAR_BACK) != 0));
        L("bar_has_fg",
            to_str(*(uint32_t*)((uint8_t*)g_save_base + ADDR_SETTING_BAR_FRONT) != 0));
        L("transparent", to_str((unsigned)GU8(ADDR_SETTING_BAR_TRANSPARENT)));
        L("translucency", to_str(GU32(ADDR_SETTING_BAR_TRANSLUCENCY)));
        L("scale_progress_bar", to_str((unsigned)GU8(ADDR_SETTING_BAR_SCALE)));
        L("show_error_messages", to_str((unsigned)GU8(0x1E9420)));
        L("log_errors", to_str((unsigned)GU8(0x1E9424)));
        L("always_abort", to_str((unsigned)GU8(0x1E9428)));
        L("zero_uninitialized_vars", to_str((unsigned)GU8(0x1E942C)));
        L("error_on_uninitialized_args", "0"); // no GM80 global
        wf(sub(L"settings\\settings.txt"), s);

        // Constants — settings/constants.txt (gm82save parity; was never saved).
        // GM 8.0 lists (verified GM80_SaveConstants 0x573618): names 0x1F1C90,
        // values 0x1F1C94 (arrays of AnsiString data ptrs), count 0x1E932C.
        {
            uint8_t* b = (uint8_t*)g_save_base;
            uint32_t cnt = *(uint32_t*)(b + 0x1E932C); // GM80_Count_Constants
            if (cnt > 0 && cnt < 10000)
            {
                uint32_t* nameArr = *(uint32_t**)(b + 0x1F1C90);
                uint32_t* valArr = *(uint32_t**)(b + 0x1F1C94);
                if (nameArr && valArr)
                {
                    std::string c;
                    for (uint32_t i = 0; i < cnt; i++)
                    {
                        const char* n = nameArr[i] ? (const char*)(uintptr_t)nameArr[i]
                                                   : "";
                        const char* v = valArr[i] ? (const char*)(uintptr_t)valArr[i]
                                                  : "";
                        c += ansi_to_utf8(std::string(n)) + "=" + ansi_to_utf8(std::string(v)) +
                            "\n";
                    }
                    wf(sub(L"settings\\constants.txt"), c);
                }
            }
        }

        // Game Information — GM80_SaveGameInfo 0x5991A0. Fields:
        //   caption 0x1E936C (off_5E936C), window pos/size dwords 0x1E9370/74/78/7C,
        //   flags byte_5E9368 + byte_5E9380/84/88/8C.
        // The F1 help TEXT lives in a RichEdit control, reached via
        //   [0x5EAEE8] → [p] → +0x360 → +0x298 → vtable+0x78 (SaveToStream).
        {
            uint8_t* b = (uint8_t*)g_save_base;
            std::string g;
            auto GL = [&](const char* k, const std::string& v)
                {
                    g += std::string(k) + "=" + v + "\n";
                };
            // Background colour: editor = [[0x5EAEE8]+0x360]. GM80_SaveGameInfo
            // reads [editor+0x70] (verified 0xFF = user-set red, not the
            // [obj+0x47C] field). Load restores it via sub_460D00 (SetColor).
            {
                uint32_t p = *(uint32_t*)(b + 0x1EAEE8);
                uint32_t obj = p ? *(uint32_t*)p : 0;
                uint32_t ed = obj ? *(uint32_t*)(obj + 0x360) : 0;
                GL("color", to_str(ed && ed >= 0x10000 ? *(uint32_t*)(ed + 0x70) : 0));
            }
            GL("caption", encode_delimit(ansi_to_utf8(GS(0x1E936C))));
            // 5 flag bytes (verified 2026-08-03 via GM80_SaveGameInfo 0x5991A0 /
            // GM80_LoadGameInfo 0x599024 read order — matches GM 8.1's layout):
            //   +9368 new_window, +9380 border, +9384 resizable,
            //   +9388 window_on_top, +938C freeze_game
            GL("new_window", to_str((unsigned)*(uint8_t*)(b + 0x1E9368)));
            GL("left", to_str(*(uint32_t*)(b + 0x1E9370)));
            GL("top", to_str(*(uint32_t*)(b + 0x1E9374)));
            GL("width", to_str(*(uint32_t*)(b + 0x1E9378)));
            GL("height", to_str(*(uint32_t*)(b + 0x1E937C)));
            GL("border", to_str((unsigned)*(uint8_t*)(b + 0x1E9380)));
            GL("resizable", to_str((unsigned)*(uint8_t*)(b + 0x1E9384)));
            GL("window_on_top", to_str((unsigned)*(uint8_t*)(b + 0x1E9388)));
            GL("freeze_game", to_str((unsigned)*(uint8_t*)(b + 0x1E938C)));
            wf(sub(L"settings\\gameinfo.txt"), g);

            // F1 help text (RichEdit content) → gameinfo.rtf
            std::string rtf;
            if (extract_richtext(b, &rtf) && !rtf.empty())
                wf(sub(L"settings\\gameinfo.rtf"), rtf);
        }

        // NOTE: absolute paths via sub() — relative paths would land in the
        // process cwd (outside the .gm80 project folder).
        save_bitmap_to_file(*(uint32_t*)((uint8_t*)g_save_base + 0x1E940C),
            sub(L"settings\\back.bmp").c_str());
        save_bitmap_to_file(*(uint32_t*)((uint8_t*)g_save_base + 0x1E9408),
            sub(L"settings\\front.bmp").c_str());
        save_bitmap_to_file(*(uint32_t*)((uint8_t*)g_save_base + 0x1E9404),
            sub(L"settings\\loader.bmp").c_str());
        // Game icon: TIcon at dword_5E941C (verified sub_59DAC4) → icon.ico
        save_bitmap_to_file(*(uint32_t*)((uint8_t*)g_save_base + 0x1E941C),
            sub(L"settings\\icon.ico").c_str());

        // Extensions — settings/extensions.txt (matches gm82save)
        // GM 8.0 (verified sub_5A80A8/sub_5A7FF0/sub_5A7910):
        //   0x1E9460 = extension object array (dynamic array), 0x1E9464 = count,
        //   0x2000BC = loaded flags (dynamic array of bytes — deref the var!);
        //   extension object +4 = name
        uint32_t extCnt = *(uint32_t*)((uint8_t*)g_save_base + 0x1E9464);
        uint32_t* extArr = *(uint32_t**)((uint8_t*)g_save_base + 0x1E9460);
        uint8_t* extLoaded = *(uint8_t**)((uint8_t*)g_save_base + 0x2000BC);
        if (extArr && extLoaded && extCnt > 0 && extCnt < 1000)
        {
            std::string exts;
            for (uint32_t i = 0; i < extCnt; i++)
            {
                if (extLoaded[i] && extArr[i])
                {
                    char* namePtr = *(char**)((uint8_t*)(uintptr_t)extArr[i] + 4);
                    if (namePtr)
                    {
                        uint32_t len = *(uint32_t*)(namePtr - 4);
                        if (len < 500) exts += std::string(namePtr, len) + "\n";
                    }
                }
            }
            if (!exts.empty()) wf(sub(L"settings\\extensions.txt"), exts);
        }
    }

    // ==== Included files (datafiles/) — gm82save format ====
    // GM 8.0 (verified GM80_SaveIncludedFiles 0x59AE20): count 0x1E9398,
    // object array 0x1E9390, timestamps 0x1E9394. IncludedFile object:
    // +4 file_name, +8 source_path, +12 data_exists, +16 source_length,
    // +20 stored_in_gmk, +24 data (TMemoryStream*), +28 export_setting,
    // +32 export_custom_folder, +36 overwrite, +37 free, +38 remove_at_end.
    uint64_t dataHash = 0;
    {
        uint8_t* b = (uint8_t*)g_save_base;
        uint32_t ifCnt = *(uint32_t*)(b + 0x1E9398);
        uint32_t* ifArr = *(uint32_t**)(b + 0x1E9390);
        double* ifTs = *(double**)(b + 0x1E9394);
        // Included-file name-space hash → add/remove/rename forces a full re-write.
        std::vector<std::string> dataNames;
        if (ifCnt > 0 && ifCnt < 10000 && ifArr)
        {
            dataNames.reserve(ifCnt);
            for (uint32_t i = 0; i < ifCnt; i++)
            {
                void* f = (void*)(uintptr_t)ifArr[i];
                dataNames.push_back(f ? RS(f, 4) : std::string());
            }
        }
        dataHash = names_hash(dataNames);
        bool dataFull = !g_has_last_data || g_last_data_hash != dataHash;
        gm_log("SmartSave: included files dataFull=%d (count=%u)", dataFull, ifCnt);
        if (ifCnt > 0 && ifCnt < 10000 && ifArr)
        {
            CreateDirectoryW(sub(L"datafiles").c_str(), NULL);
            CreateDirectoryW(sub(L"datafiles\\include").c_str(), NULL);
            std::string index;
            for (uint32_t i = 0; i < ifCnt; i++)
            {
                void* f = (void*)(uintptr_t)ifArr[i];
                if (!f) continue;
                std::string name = RS(f, 4);
                if (name.empty()) continue;
                std::wstring wname(name.begin(), name.end());
                index += name + "\n";
                if (!dataFull && smart && ifTs && ifTs[i] <= g_last_save)
                    continue; // smart skip

                bool dataExists = *(uint8_t*)((uint8_t*)f + 12) != 0;
                bool storedInGmk = *(uint8_t*)((uint8_t*)f + 20) != 0;
                if (dataExists)
                {
                    std::string content;
                    if (storedInGmk)
                    {
                        uint8_t* stream = *(uint8_t**)((uint8_t*)f + 24);
                        if (stream)
                        {
                            uint8_t* mem = *(uint8_t**)(stream + 4);
                            uint32_t size = *(uint32_t*)(stream + 8);
                            if (mem && size > 0 && size < 64 * 1024 * 1024)
                                content.assign((char*)mem, size);
                        }
                    }
                    else
                    {
                        std::string src = RS(f, 8);
                        if (!src.empty()) content = read_file_ansi(src);
                    }
                    if (!content.empty())
                        wf(sub((L"datafiles\\include\\" + wname).c_str()), content);
                }
                std::string meta;
                auto ML = [&](const char* k, const std::string& v)
                    {
                        meta += std::string(k) + "=" + v + "\n";
                    };
                ML("store", to_str(storedInGmk ? 1 : 0));
                ML("free", to_str((unsigned)*(uint8_t*)((uint8_t*)f + 37)));
                ML("overwrite", to_str((unsigned)*(uint8_t*)((uint8_t*)f + 36)));
                ML("remove", to_str((unsigned)*(uint8_t*)((uint8_t*)f + 38)));
                uint32_t exportSetting = R4(f, 28);
                ML("export", to_str(exportSetting));
                if (exportSetting == 3) ML("export_folder", ansi_to_utf8(RS(f, 32)));
                wf(sub((L"datafiles\\" + wname + L".txt").c_str()), meta);
            }
            wf(sub(L"datafiles\\index.yyd"), index);
        }
    }

    // ==== Resource index.yyd + data ====
    auto save_index = [&](const wchar_t* dir, const std::vector<std::string>& names)
        {
            std::string idx;
            for (auto& n : names)
                idx += n + "\n";
            wf(sub((std::wstring(dir) + L"\\index.yyd").c_str()), idx);
        };
    // ==== Hierarchical tree.yyd — matches gm82save's write_tree_children exactly ====
    auto save_tree =
        [&](const wchar_t* dir, const std::vector<std::string>& names, uint32_t kind)
        {
            std::string tree;
            void* rootNode = tree_get_root(base, kind);
            if (rootNode)
            {
                std::string tabs;
                tree_write_recurse(rootNode, names, tabs, tree);
            }
            if (tree.empty())
            {
                for (auto& n : names)
                    tree += "|" + n + "\n";
            }
            wf(sub((std::wstring(dir) + L"\\tree.yyd").c_str()), tree);
        };

    // Scripts
    if (!scriptNames.empty())
    {
        save_index(L"scripts", scriptNames);
        save_tree(L"scripts", scriptNames, 7);
        uint32_t* scripts = *(uint32_t**)(base + 0x1E92D4);
        uint32_t scCnt = *(uint32_t*)(base + 0x1E92E4);
        double* scrTs = ts_ptr(0x1E92E0);
        if (scripts && scCnt < 50000)
        {
            for (uint32_t i = 0; i < scCnt && i < (uint32_t)scriptNames.size(); i++)
            {
                if (scriptNames[i].empty()) continue;
                if (!changed[T_SCR] && scrTs && scrTs[i] <= g_last_save)
                    continue; // smart skip
                void* scObj = (void*)(uintptr_t)scripts[i];
                if (!scObj) continue;
                std::string src = scObj ? RS(scObj, 4) : "";
                std::wstring wname(scriptNames[i].begin(), scriptNames[i].end());
                save_script(scObj, src, sub((L"scripts\\" + wname).c_str()));
            }
        }
    }

    // Fonts
    if (!fontNames.empty())
    {
        save_index(L"fonts", fontNames);
        save_tree(L"fonts", fontNames, 9);
        uint32_t* fObjArr = *(uint32_t**)(base + 0x1E92C0); // font object array
        uint32_t fCnt = *(uint32_t*)(base + 0x1E92D0);
        double* fntTs = ts_ptr(0x1E92CC);
        if (fObjArr && fCnt < 10000)
        {
            for (uint32_t i = 0; i < fCnt && i < (uint32_t)fontNames.size(); i++)
            {
                if (fontNames[i].empty()) continue;
                if (!changed[T_FNT] && fntTs && fntTs[i] <= g_last_save)
                    continue; // smart skip
                void* fObj = (void*)(uintptr_t)fObjArr[i];
                if (!fObj) continue;
                std::wstring wname(fontNames[i].begin(), fontNames[i].end());
                save_font(fObj, sub((L"fonts\\" + wname).c_str()));
            }
        }
    }

    // Paths
    if (!pathNames.empty())
    {
        save_index(L"paths", pathNames);
        save_tree(L"paths", pathNames, 8);
        uint32_t* pObjArr = *(uint32_t**)(base + 0x1E92AC);
        double* patTs = ts_ptr(0x1E92B8);
        if (pObjArr)
        {
            for (uint32_t i = 0; i < pathCnt && i < (uint32_t)pathNames.size(); i++)
            {
                if (pathNames[i].empty()) continue;
                if (!changed[T_PAT] && patTs && patTs[i] <= g_last_save)
                    continue; // smart skip
                void* pObj = (void*)(uintptr_t)pObjArr[i];
                if (!pObj) continue;
                std::wstring wname(pathNames[i].begin(), pathNames[i].end());
                save_path(pObj, sub((L"paths\\" + wname).c_str()));
            }
        }
    }

    // Sounds
    if (soundCnt > 0)
    {
        // Names come from soundNames (filled at the top from 0x1E9280 — the
        // correct name array, verified 2026-08-02; 0x1E932C is the CONSTANTS
        // count and must never be used here. Object array is 0x1E9278.)
        save_index(L"sounds", soundNames);
        save_tree(L"sounds", soundNames, 3); // was missing → no tree.yyd → empty IDE tree
        uint32_t* sndArr = *(uint32_t**)(base + 0x1E9278);
        double* sndTs = ts_ptr(0x1E9284);
        if (sndArr)
        {
            for (uint32_t i = 0; i < soundCnt && i < (uint32_t)soundNames.size(); i++)
            {
                if (soundNames[i].empty()) continue;
                if (!changed[T_SND] && sndTs && sndTs[i] <= g_last_save)
                    continue; // smart skip
                void* sObj = (void*)(uintptr_t)sndArr[i];
                if (!sObj) continue;
                std::wstring wname(soundNames[i].begin(), soundNames[i].end());
                save_sound(sObj, sub((L"sounds\\" + wname).c_str()));
            }
        }
    }

    // Sprites
    if (!spriteNames.empty())
    {
        save_index(L"sprites", spriteNames);
        save_tree(L"sprites", spriteNames, 2);
        uint32_t* spArr = *(uint32_t**)(base + 0x1E9108); // sprite array
        double* sprTs = ts_ptr(0x1E9114);
        if (spArr && spriteCnt < 50000)
        {
            for (uint32_t i = 0; i < spriteCnt && i < (uint32_t)spriteNames.size(); i++)
            {
                if (spriteNames[i].empty()) continue;
                if (!changed[T_SPR] && sprTs && sprTs[i] <= g_last_save)
                    continue; // smart skip
                void* spObj = (void*)(uintptr_t)spArr[i];
                if (!spObj) continue;
                std::wstring wname(spriteNames[i].begin(), spriteNames[i].end());
                save_sprite(spObj, sub((L"sprites\\" + wname).c_str()));
            }
        }
    }

    // Backgrounds
    if (!bgNames.empty())
    {
        save_index(L"backgrounds", bgNames);
        save_tree(L"backgrounds", bgNames, 6);
        uint32_t* bgArr = *(
            uint32_t**)(base + 0x1E9094); // verified: dword_5E9094 from serializer
        double* bgTs = ts_ptr(0x1E90A0);
        if (bgArr && bgCnt < 10000)
        {
            for (uint32_t i = 0; i < bgCnt && i < (uint32_t)bgNames.size(); i++)
            {
                if (bgNames[i].empty()) continue;
                if (!changed[T_BG] && bgTs && bgTs[i] <= g_last_save)
                    continue; // smart skip
                void* bgObj = (void*)(uintptr_t)bgArr[i];
                if (!bgObj) continue;
                std::wstring wname(bgNames[i].begin(), bgNames[i].end());
                save_background(bgObj, sub((L"backgrounds\\" + wname).c_str()));
            }
        }
    }

    // Timelines
    if (!tlNames.empty())
    {
        save_index(L"timelines", tlNames);
        save_tree(L"timelines", tlNames, 12);
        uint32_t* tlArr = *(uint32_t**)(base + 0x1E9300);
        double* tlTs = ts_ptr(0x1E930C);
        if (tlArr && tlCnt < 10000)
        {
            for (uint32_t i = 0; i < tlCnt && i < (uint32_t)tlNames.size(); i++)
            {
                if (tlNames[i].empty()) continue;
                if (!changed[T_TLN] && tlTs && tlTs[i] <= g_last_save)
                    continue; // smart skip
                void* tlObj = (void*)(uintptr_t)tlArr[i];
                if (!tlObj) continue;
                std::wstring wname(tlNames[i].begin(), tlNames[i].end());
                // save_timeline appends ".gml" itself (like scripts/conditions).
                // Was "...+wname+L".gml"" → double ".gml.gml" filename.
                save_timeline(tlObj, objectNames, sub((L"timelines\\" + wname).c_str()));
            }
        }
    }

    // Triggers
    if (!triggerNames.empty())
    {
        save_index(L"triggers", triggerNames);
        uint32_t* tArr = *(uint32_t**)(base + 0x1E92E8);
        if (tArr && triggerCnt < 500)
        {
            for (uint32_t i = 0; i < triggerCnt && i < (uint32_t)triggerNames.size(); i++)
            {
                if (triggerNames[i].empty()) continue;
                void* tObj = (void*)(uintptr_t)tArr[i];
                if (!tObj) continue;
                std::wstring wname(triggerNames[i].begin(), triggerNames[i].end());
                save_trigger(tObj, sub((L"triggers\\" + wname).c_str()));
            }
        }
    }

    // Objects
    if (!objectNames.empty())
    {
        save_index(L"objects", objectNames);
        save_tree(L"objects", objectNames, 1);
        uint32_t* oArr = *(uint32_t**)(base + 0x1E9354);
        double* objTs = ts_ptr(0x1E9360);
        if (oArr && objectCnt < 50000)
        {
            for (uint32_t i = 0; i < objectCnt && i < (uint32_t)objectNames.size(); i++)
            {
                if (objectNames[i].empty()) continue;
                if (!changed[T_OBJ] && objTs && objTs[i] <= g_last_save)
                    continue; // smart skip
                void* oObj = (void*)(uintptr_t)oArr[i];
                if (!oObj) continue;
                std::wstring wname(objectNames[i].begin(), objectNames[i].end());
                save_object(oObj, spriteNames, soundNames, bgNames, pathNames,
                    scriptNames, fontNames, tlNames, objectNames, roomNames, triggerNames,
                    sub((L"objects\\" + wname).c_str()));
            }
        }
    }

    // Rooms
    if (!roomNames.empty())
    {
        save_index(L"rooms", roomNames);
        save_tree(L"rooms", roomNames, 4);
        uint32_t* rArr = *(uint32_t**)(base + 0x1E9294);
        double* romTs = ts_ptr(0x1E92A0);
        if (rArr && roomCnt < 10000)
        {
            for (uint32_t i = 0; i < roomCnt && i < (uint32_t)roomNames.size(); i++)
            {
                if (roomNames[i].empty()) continue;
                if (!changed[T_ROM] && romTs && romTs[i] <= g_last_save)
                    continue; // smart skip
                void* rObj = (void*)(uintptr_t)rArr[i];
                if (!rObj) continue;
                std::wstring wname(roomNames[i].begin(), roomNames[i].end());
                save_room(rObj, bgNames, objectNames, roomNames,
                    sub((L"rooms\\" + wname).c_str()));
            }
        }
    }

    // ==== Update smart-save baseline ====
    // (Names arrays are re-hashed after the save; stored hash == what we just wrote,
    // so a subsequent unchanged save skips everything.)
    if (g_save_io_error)
    {
        // A file write failed — do NOT advance the baseline, so the next save is
        // a full save that retries the failed file(s) instead of silently
        // skipping them (which would lose the change).
        gm_log(
            "SmartSave: I/O error during save — baseline NOT updated (next save full)");
        return true;
    }

    // ==== Resource-tree expansion state ====
    // Persist expanded folders so the tree survives project reopen. Written
    // AFTER the baseline update point above — a failed save skips it too.
    gm80_capture_tree_state(gm_base, path);
    g_last_save = now_t();
    for (int t = 0; t < 10; t++)
    {
        g_last_names_hash[t] = curHash[t];
        g_has_last_names[t] = true;
    }
    g_last_data_hash = dataHash;
    g_has_last_data = true;
    gm_log("SmartSave: LAST_SAVE=%f", g_last_save);

    // ==== Stale-resource cleanup (only after a fully successful save) ====
    // Renames and deletions in the IDE leave old .gm80 files; remove them now
    // so a rename doesn't accumulate stale files and git stays clean. Runs on
    // every save; when nothing changed it's a cheap no-op scan.
    // A type whose name array could NOT be read is skipped entirely: its live
    // set would be empty and cleanup would delete the type's whole directory
    // (2026-09-09).
    int removed = 0;
    if (spriteNamesOk) removed += cleanup_type_dir(path, L"sprites", spriteNames, true);
    if (bgNamesOk) removed += cleanup_type_dir(path, L"backgrounds", bgNames, false);
    if (pathNamesOk) removed += cleanup_type_dir(path, L"paths", pathNames, true);
    if (scriptNamesOk) removed += cleanup_type_dir(path, L"scripts", scriptNames, false);
    if (fontNamesOk) removed += cleanup_type_dir(path, L"fonts", fontNames, false);
    if (tlNamesOk) removed += cleanup_type_dir(path, L"timelines", tlNames, false);
    if (objectNamesOk) removed += cleanup_type_dir(path, L"objects", objectNames, false);
    if (roomNamesOk) removed += cleanup_type_dir(path, L"rooms", roomNames, true);
    if (soundNamesOk) removed += cleanup_type_dir(path, L"sounds", soundNames, false);
    gm_log("SmartSave: cleanup removed %d stale entries", removed);

    return true;
}
