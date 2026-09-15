// One-shot check of the JSON protocol's encoding chain, mirroring
// merge_flow.cpp: wide path -> UTF-8 -> nlohmann dump -> parse -> wide.
#include <windows.h>
#include <string>
#include <cstdio>
#include "../../Librarys/json.hpp"

using nlohmann::json;

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

static int fails = 0;
static FILE* out = nullptr;
static void check(bool ok, const char* what)
{
    fprintf(out, "%s %s\n", ok ? "PASS" : "FAIL", what);
    fflush(out); // survive a later crash: last line shows where it died
    if (!ok) fails++;
}

int main()
{
    out = fopen("json_test_result.txt", "w");
    if (!out) return 2;
    fprintf(out, "start\n");
    fflush(out);
    // Snapshot-manifest shape, with Chinese paths and a decisions-like object.
    std::wstring rel1 = L"sprites/主角.png"; // forward slashes: tool-side form
    std::wstring rel2 = L"scripts/攻击逻辑.gml";
    std::wstring rel3 = L"rooms/房间1/instances.txt";

    json j = json::object();
    j["version"] = 1;
    j["files"] = json::array();
    for (auto* rel : {&rel1, &rel2, &rel3})
    {
        json f = json::object();
        f["path"] = wide_to_utf8(*rel);
        f["hash"] = "0123456789abcdef";
        f["size"] = 123;
        f["mtime"] = 1700000000LL;
        f["text"] = true;
        j["files"].push_back(std::move(f));
    }
    std::string dumped = j.dump();

    // Raw bytes must carry the UTF-8 of 主角 (E4 B8 BB E8 A7 92) unescaped.
    check(dumped.find("\xE4\xB8\xBB\xE8\xA7\x92") != std::string::npos,
        "dump keeps raw UTF-8 for Chinese paths");

    // Round-trip back to wide.
    json v = json::parse(dumped);
    bool all = v["files"].size() == 3;
    const std::wstring* outs[] = {&rel1, &rel2, &rel3};
    for (int i = 0; i < 3; i++)
    {
        std::wstring back = utf8_to_wide(v["files"][i]["path"].get<std::string>());
        all = all && back == *outs[i];
    }
    check(all, "all three Chinese paths round-trip losslessly");

    // Decisions shape (explicit construction — nested brace init-lists are
    // an nlohmann deduction trap that crashed this test once already).
    json d = json::object();
    d["result"] = "apply";
    json f0 = json::object();
    f0["path"] = wide_to_utf8(rel2);
    f0["action"] = "edited";
    d["files"] = json::array({f0});
    std::string dj = d.dump();
    json dv = json::parse(dj);
    check(dv["result"] == "apply" &&
              utf8_to_wide(dv["files"][0]["path"].get<std::string>()) == rel2 &&
              dv["files"][0]["action"] == "edited",
        "decisions.json shape round-trips");

    // Malformed input must throw (callers catch) rather than mis-parse.
    bool threw = false;
    try
    {
        json::parse("{\"result\": oops}");
    }
    catch (const std::exception&)
    {
        threw = true;
    }
    check(threw, "malformed JSON throws (caught by caller)");

    fprintf(out, fails ? "JSON round-trip tests FAILED\n"
                       : "all JSON round-trip tests passed\n");
    fclose(out);
    return fails ? 1 : 0;
}
