// Three-way merge flow for external .gm80 changes. See merge_flow.h.
//
// Layout conventions:
//   snapshot : <projDir>\cache\gmsave-base\root\<rel>   (text file copies)
//              <projDir>\cache\gmsave-base\manifest.json (all files hashed)
//   session  : %TEMP%\gmsave-merge-<pid>\{local,base,remote,decisions,backup}
//              + manifest.json (written by us) / decisions.json + decisions\
//              (written by GMSaveMerge)
#include "pch.h"
#include "merge_flow.h"
#include "gm80_addresses.h"
#include "gm80_save.h"
#include "diff3.h"
#include "project_watcher.h"
#include "gm_log.h"
#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include "../Librarys/json.hpp" // nlohmann::json — manifest + decisions protocol
namespace fs = std::filesystem;

// ==== Small utilities ====

static std::string read_bytes(const fs::path& p)
{
    std::ifstream f(p, std::ios::binary);
    if (!f) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static bool write_bytes(const fs::path& p, const std::string& data)
{
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    FILE* f = _wfopen(p.c_str(), L"wb");
    if (!f) return false;
    size_t w = fwrite(data.data(), 1, data.size(), f);
    fclose(f);
    return w == data.size();
}

static uint64_t fnv1a(const std::string& d)
{
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : d)
    {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h;
}

static std::string hex64(uint64_t v)
{
    char b[17];
    snprintf(b, sizeof(b), "%016llx", (unsigned long long)v);
    return b;
}

// Wide ↔ UTF-8 (JSON carries UTF-8; paths on disk are wide).
static std::string wide_to_utf8(const std::wstring& w)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0,
        nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr,
        nullptr);
    return s;
}

static std::wstring utf8_to_wide(const std::string& s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// ==== File-kind classification ====

static bool is_binary_rel(const std::wstring& rel)
{
    static const wchar_t* kBinExt[] = {L".png", L".gif", L".jpg", L".jpeg",
        L".bmp", L".ico", L".cur", L".wav", L".mp3", L".mid", L".midi", L".ogg",
        L".bin", L".dat", L".rtf", nullptr};
    // Included-file payloads are arbitrary user data.
    if (rel.rfind(L"datafiles\\include\\", 0) == 0) return true;
    size_t dot = rel.find_last_of(L'.');
    if (dot == std::wstring::npos) return false;
    std::wstring ext = rel.substr(dot);
    for (int i = 0; kBinExt[i]; i++)
        if (_wcsicmp(ext.c_str(), kBinExt[i]) == 0) return true;
    return false;
}

enum TextMode { TM_LINES, TM_KEYED_CSV4, TM_KEYED_LINE };

// Encoding detection for the tool: strict-UTF-8 → "utf-8", high bytes →
// "gbk", else plain ASCII ("utf-8" is fine).
static std::string detect_encoding(const std::string& d)
{
    bool high = false;
    for (unsigned char c : d)
        if (c >= 0x80) { high = true; break; }
    if (!high) return "utf-8";
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, d.c_str(),
        (int)d.size(), nullptr, 0);
    return wlen > 0 ? "utf-8" : "gbk";
}

static TextMode text_mode_for(const std::wstring& rel)
{
    size_t slash = rel.find_last_of(L'\\');
    std::wstring name = (slash == std::wstring::npos) ? rel : rel.substr(slash + 1);
    if (name == L"index.yyd" || name == L"tree.yyd") return TM_KEYED_LINE;
    if (name == L"instances.txt") return TM_KEYED_CSV4;
    if (name == L"layers.txt") return TM_KEYED_LINE;
    // rooms/<name>/<depth>.txt tile layer files: numeric stem under rooms/
    if (rel.rfind(L"rooms\\", 0) == 0 && name.size() > 4 &&
        _wcsicmp(name.c_str() + name.size() - 4, L".txt") == 0)
    {
        bool allDigit = true;
        for (size_t i = 0; i + 4 < name.size(); i++)
            if (!iswdigit(name[i])) { allDigit = false; break; }
        if (allDigit) return TM_KEYED_LINE;
    }
    return TM_LINES;
}

// ==== Snapshot ====

struct SnapEntry
{
    std::wstring rel;
    uint64_t hash = 0;
    unsigned long long size = 0;
    long long mtime = 0;
    bool text = false;
};

static fs::path snapshot_dir_of(const std::wstring& projDir)
{
    return fs::path(projDir) / L"cache" / L"gmsave-base";
}

static void enumerate_tree(const fs::path& root, const std::wstring& skipTop,
    std::vector<std::wstring>& out)
{
    std::error_code ec;
    if (!fs::exists(root, ec)) return;
    for (auto it = fs::recursive_directory_iterator(root, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec))
    {
        if (ec) break;
        if (!it->is_regular_file(ec)) continue;
        std::wstring rel = it->path().lexically_relative(root).wstring();
        if (!skipTop.empty() &&
            (rel == skipTop || rel.rfind(skipTop + L"\\", 0) == 0))
        {
            it.disable_recursion_pending();
            continue;
        }
        out.push_back(rel);
    }
}

static void write_snapshot_manifest(const fs::path& manifest,
    const std::vector<SnapEntry>& entries)
{
    // Explicit object()/array() construction throughout — nested brace
    // init-lists are an nlohmann deduction trap (crashed once in tests).
    nlohmann::json j = nlohmann::json::object();
    j["version"] = 1;
    j["files"] = nlohmann::json::array();
    for (auto& e : entries)
    {
        nlohmann::json f = nlohmann::json::object();
        f["path"] = wide_to_utf8(e.rel);
        f["hash"] = hex64(e.hash);
        f["size"] = e.size;
        f["mtime"] = e.mtime;
        f["text"] = e.text;
        j["files"].push_back(std::move(f));
    }
    write_bytes(manifest, j.dump());
}

static bool read_snapshot_manifest(const fs::path& manifest,
    std::vector<SnapEntry>& out)
{
    std::string j = read_bytes(manifest);
    if (j.empty()) return false;
    try
    {
        nlohmann::json v = nlohmann::json::parse(j);
        auto files = v.find("files");
        if (files == v.end() || !files->is_array()) return false;
        for (auto& f : *files)
        {
            SnapEntry e;
            auto p = f.find("path");
            if (p == f.end() || !p->is_string()) continue;
            // rel came in as UTF-8 from our own manifest; decoding it per-byte
            // would corrupt every non-ASCII (Chinese) path.
            e.rel = utf8_to_wide(p->get<std::string>());
            if (auto h = f.find("hash"); h != f.end() && h->is_string())
                e.hash = (uint64_t)_strtoui64(h->get<std::string>().c_str(),
                    nullptr, 16);
            if (auto s = f.find("size"); s != f.end() && s->is_number())
                e.size = s->get<unsigned long long>();
            if (auto m = f.find("mtime"); m != f.end() && m->is_number())
                e.mtime = m->get<long long>();
            if (auto t = f.find("text"); t != f.end() && t->is_boolean())
                e.text = t->get<bool>();
            if (!e.rel.empty()) out.push_back(std::move(e));
        }
    }
    catch (const std::exception&)
    {
        return false; // malformed manifest = missing snapshot
    }
    return !out.empty();
}

void merge_flow_snapshot_refresh(const std::wstring& projDir)
{
    fs::path snap = snapshot_dir_of(projDir);
    std::error_code ec;
    fs::remove_all(snap, ec);
    fs::path root = snap / L"root";
    fs::create_directories(root, ec);

    std::vector<std::wstring> rels;
    enumerate_tree(fs::path(projDir), L"cache", rels);
    std::vector<SnapEntry> entries;
    for (auto& rel : rels)
    {
        fs::path src = fs::path(projDir) / rel;
        SnapEntry e;
        e.rel = rel;
        e.text = !is_binary_rel(rel);
        if (e.text)
        {
            std::string data = read_bytes(src);
            e.hash = fnv1a(data);
            e.size = data.size();
            write_bytes(root / rel, data);
        }
        else
        {
            std::string data = read_bytes(src);
            e.hash = fnv1a(data);
            e.size = data.size();
        }
        if (auto t = fs::last_write_time(src, ec); !ec)
        {
            auto sys = t - fs::file_time_type::clock::now() +
                std::chrono::system_clock::now();
            e.mtime = std::chrono::duration_cast<std::chrono::seconds>(
                          sys.time_since_epoch())
                          .count();
        }
        entries.push_back(e);
    }
    write_snapshot_manifest(snap / L"manifest.json", entries);
    gm_log("MergeFlow: snapshot refreshed (%zu files)", entries.size());
}

static bool file_meta(const fs::path& p, unsigned long long& size, long long& mtime)
{
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &d)) return false;
    size = ((unsigned long long)d.nFileSizeHigh << 32) | d.nFileSizeLow;
    ULARGE_INTEGER u;
    u.LowPart = d.ftLastWriteTime.dwLowDateTime;
    u.HighPart = d.ftLastWriteTime.dwHighDateTime;
    mtime = (long long)(u.QuadPart / 10000000ULL - 11644473600ULL);
    return true;
}

bool merge_flow_disk_differs(const std::wstring& projDir)
{
    std::vector<SnapEntry> snap;
    if (!read_snapshot_manifest(snapshot_dir_of(projDir) / L"manifest.json", snap))
        return false; // no snapshot (e.g. pre-upgrade project): no foreign state known
    std::map<std::wstring, SnapEntry> byRel;
    for (auto& e : snap) byRel[e.rel] = e;

    std::vector<std::wstring> rels;
    enumerate_tree(fs::path(projDir), L"cache", rels);
    std::set<std::wstring> disk;
    for (auto& rel : rels)
    {
        disk.insert(rel);
        auto it = byRel.find(rel);
        if (it == byRel.end()) return true; // new foreign file
        unsigned long long size = 0;
        long long mtime = 0;
        if (!file_meta(fs::path(projDir) / rel, size, mtime)) return true;
        if (size != it->second.size) return true;
        if (mtime == it->second.mtime) continue; // fast path
        std::string data = read_bytes(fs::path(projDir) / rel);
        if (fnv1a(data) != it->second.hash) return true;
    }
    for (auto& e : snap)
        if (!disk.count(e.rel)) return true; // deleted on disk
    return false;
}

// ==== Editor-window helpers ====

static const struct
{
    uint32_t arr, cnt;
} kFormsArrays[] = {
    {0x1E910C, 0x1E911C}, // sprites
    {0x1E927C, 0x1E9288}, // sounds
    {0x1E9098, 0x1E90A8}, // backgrounds
    {0x1E92B0, 0x1E92BC}, // paths
    {0x1E92D8, 0x1E92E4}, // scripts
    {0x1E92C4, 0x1E92D0}, // fonts
    {0x1E9304, 0x1E9310}, // timelines
    {0x1E9358, 0x1E9364}, // objects
    {0x1E9298, 0x1E92A4}, // rooms
};

static bool valid_form_slot(uint32_t* arr, uint32_t cnt, uint32_t i)
{
    uint32_t form = arr[i];
    if (!form || form < 0x10000 || form == 0xFFFFFFFF) return false;
    return !IsBadReadPtr((void*)form, 0x360);
}

int merge_flow_count_editor_windows()
{
    uint8_t* b = (uint8_t*)GetModuleHandle(NULL);
    if (!b) return 0;
    int n = 0;
    for (auto& f : kFormsArrays)
    {
        uint32_t cnt = *(uint32_t*)(b + f.cnt);
        uint32_t* arr = *(uint32_t**)(b + f.arr);
        if (!arr || (uintptr_t)arr == 0xFFFFFFFF || cnt == 0 || cnt > 50000) continue;
        for (uint32_t i = 0; i < cnt; i++)
            if (valid_form_slot(arr, cnt, i)) n++;
    }
    return n;
}

bool merge_flow_non_editor_modal_open()
{
    uint8_t* b = (uint8_t*)GetModuleHandle(NULL);
    if (!b) return false;
    void* screen = *(void**)(b + ADDR_SCREEN);
    if (!screen || IsBadReadPtr(screen, 0x90)) return false;
    // Decide by the MODAL STACK (FSaveFocusedList, TList — ShowModal inserts
    // itself at index 0), NOT by FFocusedForm: the main form itself occupies
    // FFocusedForm whenever no editor is open, which made every tick defer and
    // silently killed the no-editor reload path (2026-09-15). The modal stack
    // only ever contains forms that are actually inside ShowModal.
    uint32_t list = *(uint32_t*)((uint8_t*)screen + OFF_SCREEN_FSAVEFOCUSEDLIST);
    if (!list || list < 0x10000 || IsBadReadPtr((void*)list, 0x10)) return false;
    uint32_t count = *(uint32_t*)((uint8_t*)list + OFF_TLIST_FCOUNT);
    if (count == 0 || count > 256) return false;
    uint32_t items = *(uint32_t*)(list + 4); // TList.FItems (pointer array)
    if (!items || items < 0x10000 ||
        IsBadReadPtr((void*)items, count * sizeof(uint32_t)))
        return false;
    // Proceed only when EVERY open modal is a resource editor (present in the
    // forms arrays — those get closed via the prompt flow). Anything else
    // (Global Game Settings, a message box, a file dialog) defers the tick.
    for (uint32_t k = 0; k < count; k++)
    {
        uint32_t form = ((uint32_t*)items)[k];
        if (!form || form < 0x10000 || form == 0xFFFFFFFF) return true;
        bool isEditor = false;
        for (auto& f : kFormsArrays)
        {
            uint32_t cnt = *(uint32_t*)(b + f.cnt);
            uint32_t* arr = *(uint32_t**)(b + f.arr);
            if (!arr || (uintptr_t)arr == 0xFFFFFFFF || cnt == 0 || cnt > 50000)
                continue;
            for (uint32_t i = 0; i < cnt; i++)
                if (arr[i] == form) { isEditor = true; break; }
            if (isEditor) break;
        }
        if (!isEditor) return true;
    }
    return false;
}

// Free a Delphi object through GM's TObject.Free (sub_404590: virtual
// vmt[-4] Destroy — same call ide_hooks uses).
static void free_delphi_obj(void* obj)
{
    if (!obj) return;
    uint8_t* base = (uint8_t*)GetModuleHandle(NULL);
    if (!base) return;
    uint32_t fn = (uint32_t)base + 0x4590;
    __asm {
        mov eax, obj
        mov ecx, fn
        call ecx
    }
}

int merge_flow_close_editors(int modalResult)
{
    uint8_t* b = (uint8_t*)GetModuleHandle(NULL);
    if (!b) return 0;
    int freed = 0;
    for (auto& f : kFormsArrays)
    {
        uint32_t cnt = *(uint32_t*)(b + f.cnt);
        uint32_t* arr = *(uint32_t**)(b + f.arr);
        if (!arr || (uintptr_t)arr == 0xFFFFFFFF || cnt == 0 || cnt > 50000) continue;
        for (uint32_t i = 0; i < cnt; i++)
        {
            if (!valid_form_slot(arr, cnt, i)) continue;
            uint8_t* form = (uint8_t*)arr[i];
            uint8_t fstate = *(uint8_t*)(form + OFF_FORM_FORMSTATE);
            if (fstate & FS_MODAL_FLAG)
            {
                // Inside ShowModal: end the loop like a button click would.
                // The dialog's own epilogue (apply/discard, slot cleanup, Free)
                // runs when its message loop unwinds.
                *(uint32_t*)(form + OFF_FORM_MODALRESULT) = modalResult;
            }
            else
            {
                // Modeless (script/room editors): the treatment InitializeProject
                // itself applies — free the form. Script editors apply their
                // content on destroy (verified sub_55A750).
                free_delphi_obj(form);
                arr[i] = 0;
                freed++;
            }
        }
    }
    return freed;
}

// ==== Staging save ====

// SEH guard around the Delphi interop save (same policy as ide_hooks).
static bool stage_save_seh(void* base, const std::wstring& path)
{
    __try
    {
        return gm80_save_to_path(base, path);
    }
    __except (GetExceptionCode() == 0xE06D7363 ? EXCEPTION_CONTINUE_SEARCH
                                               : EXCEPTION_EXECUTE_HANDLER)
    {
        gm_log("MergeFlow: staging save SEH exception 0x%X", GetExceptionCode());
        return false;
    }
}

static bool stage_save(const std::wstring& stagingDir)
{
    void* base = GetModuleHandle(NULL);
    // Force-full: write every type regardless of the smart-skip baseline and
    // freeze that baseline. (Zeroing LAST_SAVE — the previous trick — stopped
    // working after a reload: per-resource timestamps come back as 0 while
    // the name-hash baseline survives, so every type was skipped and the
    // staging tree shipped as a stub whose missing files then read as
    // IDE-side deletions — 2026-09-15, nearly deleted 7 real files.)
    gm80_save_set_force_full(true);
    bool ok = stage_save_seh(base, stagingDir);
    gm80_save_set_force_full(false);
    if (!ok) gm_log("MergeFlow: staging save FAILED (%s)", gm80_save_last_error().c_str());
    return ok;
}

// ==== Classification + merge ====

enum FileStatus
{
    FS_UNCHANGED,   // all three equal → skip
    FS_REMOTE,      // only remote changed / remote-only → keep disk (auto)
    FS_LOCAL,       // only local changed / local-only → write local (auto)
    FS_AUTO,        // text three-way clean merge → write result (auto)
    FS_CONFLICT,    // needs the merge tool
    FS_DELETED,     // gone on BOTH the disk side we track and staging — the
                    // file is already absent where it matters, nothing to do
    FS_DELETE_LOCAL // staging (IDE memory) dropped it and disk is untouched →
                    // the disk copy must be removed on apply
};

struct MergeFile
{
    std::wstring rel;
    bool binary = false;
    bool hasBase = false, hasLocal = false, hasRemote = false;
    uint64_t hashBase = 0, hashLocal = 0, hashRemote = 0;
    std::string baseB, localB, remoteB; // text only
    std::string enc = "utf-8";
    FileStatus status = FS_UNCHANGED;
    diff3::Result dres; // text three-way details
    std::string resultB;
};

static bool load_text_or_hash(MergeFile& mf, const fs::path& base,
    const fs::path& localRoot, const fs::path& remoteRoot,
    const SnapEntry* snapE)
{
    // local (staging)
    fs::path lp = localRoot / mf.rel;
    std::error_code ec;
    if (fs::is_regular_file(lp, ec))
    {
        mf.hasLocal = true;
        std::string d = read_bytes(lp);
        mf.hashLocal = fnv1a(d);
        if (!mf.binary) mf.localB = std::move(d);
    }
    fs::path rp = remoteRoot / mf.rel;
    if (fs::is_regular_file(rp, ec))
    {
        mf.hasRemote = true;
        std::string d = read_bytes(rp);
        mf.hashRemote = fnv1a(d);
        if (!mf.binary) mf.remoteB = std::move(d);
    }
    if (snapE)
    {
        mf.hasBase = true;
        mf.hashBase = snapE->hash;
        if (!mf.binary) mf.baseB = read_bytes(base / mf.rel);
    }
    // One encoding verdict per file, used by the tool for every side it
    // shows. Must NOT live in the clean-merge branch only: early-returning
    // classifications otherwise keep the "utf-8" default and the tool then
    // renders our GBK-on-disk text as mojibake (2026-09-15 gameinfo.txt).
    if (!mf.binary)
        mf.enc = detect_encoding(!mf.remoteB.empty() ? mf.remoteB : mf.localB);
    return true;
}

static void classify_and_merge(MergeFile& mf)
{
    if (mf.binary)
    {
        if (!mf.hasLocal && !mf.hasRemote) { mf.status = FS_DELETED; return; }
        if (!mf.hasBase)
        {
            // New file on one or both sides.
            if (!mf.hasLocal) { mf.status = FS_REMOTE; return; }
            if (!mf.hasRemote) { mf.status = FS_LOCAL; return; }
            mf.status = (mf.hashLocal != mf.hashRemote) ? FS_CONFLICT : FS_UNCHANGED;
            return;
        }
        bool lCh = mf.hasLocal && mf.hashLocal != mf.hashBase;
        bool rCh = mf.hasRemote && mf.hashRemote != mf.hashBase;
        if (!mf.hasRemote && lCh) { mf.status = FS_CONFLICT; return; } // del-vs-change
        if (!mf.hasRemote) { mf.status = FS_DELETED; return; } // remote-gone, local==base
        if (!mf.hasLocal && rCh) { mf.status = FS_CONFLICT; return; } // change-vs-del
        // IDE memory dropped the file while disk is untouched — the disk copy
        // is a stale orphan (e.g. Trigger0.* left behind by an older save) and
        // must be removed, not kept. 2026-09-15: this used to be FS_REMOTE.
        if (!mf.hasLocal) { mf.status = FS_DELETE_LOCAL; return; }
        if (lCh && rCh && mf.hashLocal != mf.hashRemote)
            mf.status = FS_CONFLICT;
        else if (lCh)
            mf.status = FS_LOCAL;
        else if (rCh)
            mf.status = FS_REMOTE;
        else
            mf.status = FS_UNCHANGED;
        return;
    }

    // ---- text ----
    if (mf.hasLocal && mf.hasRemote && mf.hasBase &&
        mf.localB == mf.baseB && mf.remoteB == mf.baseB)
    {
        mf.status = FS_UNCHANGED;
        return;
    }
    if (!mf.hasRemote && mf.hasLocal)
    {
        if (!mf.hasBase) { mf.status = FS_LOCAL; return; } // brand-new in IDE
        mf.status = (mf.localB != mf.baseB) ? FS_CONFLICT : FS_DELETED;
        return;
    }
    if (!mf.hasLocal && mf.hasRemote)
    {
        if (!mf.hasBase) { mf.status = FS_REMOTE; return; } // brand-new on disk
        if (mf.remoteB != mf.baseB) { mf.status = FS_CONFLICT; return; }
        mf.status = FS_DELETE_LOCAL; // IDE dropped it, disk untouched → orphan
        return;
    }
    if (!mf.hasLocal && !mf.hasRemote)
    {
        mf.status = FS_DELETED;
        return;
    }
    // all present (base may be absent = both new)
    if (mf.localB == mf.remoteB) { mf.status = FS_UNCHANGED; return; }
    if (mf.hasBase && mf.localB == mf.baseB) { mf.status = FS_REMOTE; return; }
    if (mf.hasBase && mf.remoteB == mf.baseB) { mf.status = FS_LOCAL; return; }

    TextMode tm = text_mode_for(mf.rel);
    std::vector<std::string> b = diff3::split_lines(mf.baseB);
    std::vector<std::string> l = diff3::split_lines(mf.localB);
    std::vector<std::string> r = diff3::split_lines(mf.remoteB);
    switch (tm)
    {
    case TM_KEYED_CSV4:
        mf.dres = diff3::merge_keyed(b, l, r, diff3::key_instances_csv4);
        break;
    case TM_KEYED_LINE:
        mf.dres = diff3::merge_keyed(b, l, r, diff3::key_whole_line);
        break;
    default:
        mf.dres = diff3::merge_lines(b, l, r);
        break;
    }
    if (mf.dres.clean())
    {
        mf.status = FS_AUTO;
        mf.resultB = diff3::join_lines(mf.dres.lines, "\r\n");
    }
    else
    {
        mf.status = FS_CONFLICT;
        mf.resultB = diff3::join_lines(mf.dres.lines, "\r\n"); // preview with markers
    }
}

// ==== Session + tool ====

static std::wstring session_dir()
{
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring s(tmp);
    if (!s.empty() && s.back() == L'\\') s.pop_back();
    return s + L"\\gmsave-merge-" + std::to_wstring(GetCurrentProcessId());
}

static bool find_merge_tool(std::wstring& out)
{
    // GMSaveMerge.exe is the deployed name (deploy-gm8.ps1 copies the Cargo
    // artifact gmsave-merge.exe under this name). The lowercase artifact name
    // stays as a fallback so a tree laid out by hand still works.
    const wchar_t* names[] = {L"GMSaveMerge.exe", L"gmsave-merge.exe", nullptr};
    wchar_t exeDir[MAX_PATH], dllDir[MAX_PATH];
    GetModuleFileNameW(NULL, exeDir, MAX_PATH);
    wchar_t* s = wcsrchr(exeDir, L'\\');
    if (s) *(s + 1) = 0;
    HMODULE self;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)&find_merge_tool, &self);
    GetModuleFileNameW(self, dllDir, MAX_PATH);
    s = wcsrchr(dllDir, L'\\');
    if (s) *(s + 1) = 0;
    for (int i = 0; names[i]; i++)
    {
        std::wstring c1 = std::wstring(exeDir) + names[i];
        std::wstring c2 = std::wstring(dllDir) + names[i];
        if (GetFileAttributesW(c1.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            out = c1;
            return true;
        }
        if (GetFileAttributesW(c2.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            out = c2;
            return true;
        }
    }
    return false;
}

// Wait for the tool while keeping GM painted (it is disabled meanwhile).
static DWORD wait_tool_with_pump(HANDLE proc)
{
    for (;;)
    {
        DWORD w = WaitForSingleObject(proc, 120);
        if (w == WAIT_OBJECT_0) break;
        MSG msg;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    DWORD code = (DWORD)-1;
    GetExitCodeProcess(proc, &code);
    return code;
}

// ==== Apply ====

static bool apply_decisions(const std::wstring& projDir, const fs::path& session,
    const fs::path& staging, std::vector<MergeFile>& files,
    const std::map<std::wstring, std::string>& decisions,
    const std::set<std::wstring>& edited)
{
    // Stop the watcher BEFORE touching disk so our own writes never read as
    // foreign changes; the reload re-arms it after the load.
    project_watcher_stop();

    fs::path backup = session / L"backup";
    bool ok = true;
    for (auto& mf : files)
    {
        fs::path disk = fs::path(projDir) / mf.rel;
        auto dit = decisions.find(mf.rel);
        std::string action = (dit != decisions.end()) ? dit->second : "auto";
        // A conflict REQUIRES an explicit decision; missing one (tool bug)
        // degrades to keeping the local side rather than aborting mid-apply.
        if (mf.status == FS_CONFLICT && dit == decisions.end()) action = "local";

        // Resolve the effect: {srcFile | resultBytes | delete | nothing}.
        fs::path src;
        bool useResult = false, wantDelete = false, skip = false;
        if (action == "remote")
        {
            if (!mf.hasRemote) wantDelete = true; // remote side deleted it
            else skip = true;                     // disk already holds remote
        }
        else if (action == "edited")
        {
            src = session / L"decisions" / mf.rel;
            std::error_code ec;
            if (!fs::is_regular_file(src, ec) || !edited.count(mf.rel))
            {
                gm_log("MergeFlow: missing edited content for '%S'",
                    mf.rel.c_str());
                ok = false;
                skip = true;
            }
        }
        else if (action == "local")
        {
            if (!mf.hasLocal) wantDelete = true; // local side deleted it
            else src = staging / mf.rel;
        }
        else // auto
        {
            switch (mf.status)
            {
            case FS_UNCHANGED:
            case FS_REMOTE:
            case FS_DELETED: skip = true; break;
            case FS_LOCAL: src = staging / mf.rel; break;
            case FS_AUTO: useResult = true; break;
            case FS_DELETE_LOCAL: wantDelete = true; break;
            case FS_CONFLICT: action = "local";
                if (mf.hasLocal) src = staging / mf.rel;
                else wantDelete = true;
                break;
            }
        }

        std::error_code ec;
        auto backupDisk = [&]()
        {
            if (fs::is_regular_file(disk, ec))
                fs::copy_file(disk, backup / mf.rel,
                    fs::copy_options::overwrite_existing, ec);
        };

        if (skip) continue;
        if (wantDelete)
        {
            backupDisk();
            if (fs::is_regular_file(disk, ec) && !fs::remove(disk, ec)) ok = false;
        }
        else if (!src.empty())
        {
            backupDisk();
            fs::create_directories(disk.parent_path(), ec);
            fs::copy_file(src, disk, fs::copy_options::overwrite_existing, ec);
            if (ec) ok = false;
        }
        else if (useResult)
        {
            backupDisk();
            if (!write_bytes(disk, mf.resultB)) ok = false;
        }
    }
    return ok;
}

// ==== The flow ====

bool merge_flow_run(const std::wstring& projDir)
{
    fs::path session(session_dir());
    std::error_code ec;
    fs::remove_all(session, ec);
    // The .gm80 convention names the metadata file after the project FOLDER
    // (gm80_save writes <target>\<leaf(target)>). A staging dir called
    // "local" made the save emit its metadata as a file named "local", which
    // then looked like a phantom conflict. Stage under the project's own leaf
    // name so the layout matches the real tree byte for byte.
    fs::path projLeaf = fs::path(projDir).filename();
    if (projLeaf.empty()) projLeaf = L"local";
    fs::path staging = session / projLeaf;
    fs::create_directories(staging, ec);

    gm_log("MergeFlow: run (session '%S')", session.c_str());

    // 0. The base snapshot must exist — without it the three-way comparison is
    //    meaningless (every file would look like an all-sides rewrite with an
    //    empty base). Missing snapshot = first run after an upgrade or a failed
    //    snapshot write: re-baseline from the current disk and skip this round;
    //    the next external change merges correctly.
    {
        std::vector<SnapEntry> probe;
        if (!read_snapshot_manifest(
                snapshot_dir_of(projDir) / L"manifest.json", probe))
        {
            gm_log("MergeFlow: no base snapshot — re-baselining from disk, "
                   "skipping this round");
            merge_flow_snapshot_refresh(projDir);
            MessageBoxW(gm80_prompt_owner(),
                L"No merge baseline was found for this project (first run "
                L"after an upgrade), so this external change was not applied.\r\n"
                L"The baseline has been created — make the external change "
                L"again to merge it.",
                L"Game Maker 8.0", MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
            return false;
        }
    }

    // 1. staging save (full tree of current IDE memory)
    if (!stage_save(staging.wstring()))
    {
        MessageBoxW(gm80_prompt_owner(),
            L"Cannot stage the current project state for merging.\r\n"
            L"The project was NOT reloaded.",
            L"Game Maker 8.0", MB_OK | MB_ICONERROR);
        return false;
    }

    // 2. gather the three trees
    std::vector<SnapEntry> snap;
    read_snapshot_manifest(snapshot_dir_of(projDir) / L"manifest.json", snap);
    std::map<std::wstring, const SnapEntry*> snapBy;
    for (auto& e : snap) snapBy[e.rel] = &e;

    std::vector<std::wstring> localRels, remoteRels;
    enumerate_tree(staging, L"cache", localRels);
    enumerate_tree(fs::path(projDir), L"cache", remoteRels);

    // Guard: a staging tree far smaller than the snapshot means the staging
    // save skipped types anyway (a future smart-skip regression) — applying
    // that would read every missing file as an IDE-side deletion. Abort
    // instead; nothing has been written to the project yet.
    if (snap.size() > 8 && localRels.size() * 2 < snap.size())
    {
        gm_log("MergeFlow: staging tree suspiciously small (%zu files vs %zu "
               "snapshotted) — aborting, nothing applied",
            localRels.size(), snap.size());
        MessageBoxW(gm80_prompt_owner(),
            L"The plugin's internal snapshot of the project state came out "
            L"incomplete (plugin bug).\r\n"
            L"The merge was cancelled and NOTHING was changed.\r\n"
            L"Saving the project once and retrying the external change "
            L"usually clears this.",
            L"Game Maker 8.0", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        return false;
    }

    std::set<std::wstring> all;
    for (auto& r : localRels) all.insert(r);
    for (auto& r : remoteRels) all.insert(r);
    for (auto& e : snap) all.insert(e.rel);

    std::vector<MergeFile> files;
    bool anyLocal = false, anyRemote = false, anyConflict = false;
    for (auto& rel : all)
    {
        MergeFile mf;
        mf.rel = rel;
        mf.binary = is_binary_rel(rel);
        load_text_or_hash(mf, snapshot_dir_of(projDir) / L"root", staging,
            fs::path(projDir), snapBy.count(rel) ? snapBy[rel] : nullptr);
        classify_and_merge(mf);
        if (mf.status == FS_UNCHANGED) continue;
        if (mf.status == FS_DELETED)
        {
            // Disk deletion with local untouched — nothing to write, but the
            // IDE memory still holds the resource, so a reload IS required.
            // 2026-09-15: skipping these entirely left a pure external delete
            // with nothing to do (flag-wise), and the flow silently returned.
            anyRemote = true;
            continue;
        }
        if (mf.status == FS_DELETE_LOCAL)
        {
            // IDE memory dropped the file (stale disk orphan) — keep it in
            // the list so apply removes the disk copy.
            anyRemote = true;
        }
        if (mf.status == FS_LOCAL || mf.status == FS_AUTO) anyLocal = true;
        if (mf.status == FS_REMOTE) anyRemote = true;
        if (mf.status == FS_CONFLICT) anyConflict = true;
        files.push_back(std::move(mf));
    }
    gm_log("MergeFlow: %zu changed files (conflicts=%d local=%d remote=%d)",
        files.size(), (int)anyConflict, (int)anyLocal, (int)anyRemote);

    if (files.empty() && !anyRemote)
    {
        // Nothing foreign after all (e.g. only mtimes moved): nothing to apply
        // and no reason to reload — the user's editor state stays put.
        // NOTE: FS_AUTO (clean three-way merge) lands IN files, so a
        // non-touching local+external edit pair applies and reloads here —
        // gating on anyRemote alone used to skip it entirely (2026-09-15).
        gm_log("MergeFlow: no external difference found — nothing to do");
        return false;
    }

    // 3. conflicts → session + tool
    std::map<std::wstring, std::string> decisions;
    std::set<std::wstring> edited;
    if (anyConflict)
    {
        // Materialize the three sides for every listed file.
        for (auto& mf : files)
        {
            auto cp = [&](const wchar_t* side, const std::string* bytes,
                          const fs::path* srcFile)
            {
                if (bytes && !bytes->empty())
                    write_bytes(session / side / mf.rel, *bytes);
                else if (srcFile)
                {
                    fs::create_directories((session / side / mf.rel).parent_path(), ec);
                    fs::copy_file(*srcFile, session / side / mf.rel,
                        fs::copy_options::overwrite_existing, ec);
                }
            };
            if (mf.hasBase)
                cp(L"base", mf.binary ? nullptr : &mf.baseB,
                    mf.binary ? nullptr : nullptr);
            if (mf.hasLocal)
            {
                fs::path lp = staging / mf.rel;
                if (mf.binary) cp(L"local", nullptr, &lp);
                else cp(L"local", &mf.localB, nullptr);
            }
            if (mf.hasRemote)
            {
                fs::path rp = fs::path(projDir) / mf.rel;
                if (mf.binary) cp(L"remote", nullptr, &rp);
                else cp(L"remote", &mf.remoteB, nullptr);
            }
        }

        // manifest.json for the tool
        {
            nlohmann::json j = nlohmann::json::object();
            j["version"] = 1;
            j["files"] = nlohmann::json::array();
            for (auto& mf : files)
            {
                nlohmann::json e = nlohmann::json::object();
                e["path"] = wide_to_utf8(mf.rel);
                e["kind"] = mf.binary ? "binary" : "text";
                // FS_DELETE_LOCAL advertises as "local": following the IDE
                // side means the file is gone, so apply removes it from disk.
                e["status"] = mf.status == FS_CONFLICT ? "conflict"
                    : mf.status == FS_AUTO             ? "auto"
                    : mf.status == FS_LOCAL            ? "local"
                    : mf.status == FS_DELETE_LOCAL     ? "local"
                                                       : "remote";
                e["encoding"] = mf.enc;
                if (!mf.binary && !mf.dres.conflicts.empty())
                {
                    nlohmann::json cs = nlohmann::json::array();
                    for (auto& c : mf.dres.conflicts)
                    {
                        nlohmann::json cc = nlohmann::json::object();
                        cc["b"] = nlohmann::json::array({c.baseStart, c.baseLen});
                        cc["l"] = nlohmann::json::array({c.localStart, c.localLen});
                        cc["r"] = nlohmann::json::array({c.remoteStart, c.remoteLen});
                        cs.push_back(std::move(cc));
                    }
                    e["conflicts"] = std::move(cs);
                }
                j["files"].push_back(std::move(e));
            }
            write_bytes(session / L"manifest.json", j.dump());
        }

        std::wstring tool;
        if (!find_merge_tool(tool))
        {
            // Fallback: list conflicts, keep local or cancel.
            std::wstring list;
            int n = 0;
            for (auto& mf : files)
                if (mf.status == FS_CONFLICT && n++ < 12)
                    list += L"\n  " + mf.rel;
            int r = MessageBoxW(gm80_prompt_owner(),
                (L"GMSaveMerge.exe was not found. Conflicting files:" + list +
                 L"\n\nYes = keep MY version and reload (external changes to "
                 L"these files are discarded)\n"
                 L"No = keep editing (no reload)\n"
                 L"(Backup of your files is NOT made in this mode.)")
                    .c_str(),
                L"Game Maker 8.0", MB_YESNO | MB_ICONWARNING | MB_SETFOREGROUND);
            if (r != IDYES) return false;
            for (auto& mf : files)
                if (mf.status == FS_CONFLICT) decisions[mf.rel] = "local";
        }
        else
        {
            HWND main = FindWindowW(L"TMainForm", NULL);
            STARTUPINFOW si = {sizeof(si)};
            PROCESS_INFORMATION pi = {};
            std::wstring cmd = L"\"" + tool + L"\" --manifest \"" +
                               (session / L"manifest.json").wstring() + L"\"";
            if (main) EnableWindow(main, FALSE);
            BOOL launched = CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, 0, NULL,
                NULL, &si, &pi);
            if (!launched)
            {
                if (main) EnableWindow(main, TRUE);
                gm_log("MergeFlow: CreateProcess failed err=%u", GetLastError());
                MessageBoxW(gm80_prompt_owner(), L"Could not start the merge tool.",
                    L"Game Maker 8.0", MB_OK | MB_ICONERROR);
                return false;
            }
            DWORD code = wait_tool_with_pump(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            if (main) EnableWindow(main, TRUE);

            std::string dj = read_bytes(session / L"decisions.json");
            bool applied = false;
            if (!dj.empty())
            {
                try
                {
                    nlohmann::json v = nlohmann::json::parse(dj);
                    if (auto res = v.find("result");
                        res != v.end() && res->is_string() &&
                        res->get<std::string>() == "apply")
                        applied = true;
                    if (applied)
                        if (auto fl = v.find("files");
                            fl != v.end() && fl->is_array())
                            for (auto& f : *fl)
                            {
                                auto p = f.find("path");
                                auto a = f.find("action");
                                if (p == f.end() || !p->is_string()) continue;
                                std::wstring w = utf8_to_wide(
                                    p->get<std::string>());
                                if (a != f.end() && a->is_string())
                                {
                                    decisions[w] = a->get<std::string>();
                                    if (decisions[w] == "edited") edited.insert(w);
                                }
                            }
                }
                catch (const std::exception&)
                {
                    gm_log("MergeFlow: decisions.json parse failed");
                    applied = false;
                }
            }
            gm_log("MergeFlow: tool exit=%u applied=%d decisions=%zu (code %u)",
                code, (int)applied, decisions.size(), code);
            if (!applied)
            {
                gm_log("MergeFlow: user cancelled the merge — keeping IDE state");
                return false;
            }
        }
    }

    // 4. apply + reload
    bool appliedOk = apply_decisions(projDir, session, staging, files, decisions,
        edited);
    if (!appliedOk)
        gm_log("MergeFlow: apply had errors — reloading anyway (backups in session\\backup)");
    else
        gm_log("MergeFlow: applied — reloading project");

    project_watcher_reload_project();
    return true;
}
