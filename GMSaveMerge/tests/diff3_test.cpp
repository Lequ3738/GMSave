// Standalone unit test for diff3.cpp (no GM dependencies).
// Build: cl /nologo /EHsc /std:c++20 /I.. diff3_test.cpp ..\GMSave\diff3.cpp
// (diff3.cpp includes pch.h — provide a stub via this guard.)
#include <cstdio>
#include <string>
#include <vector>

// pch.h stub for standalone build
#define NOMINMAX
#include <cstdint>
#include <cstring>

#include "diff3.h"

using namespace diff3;

static int g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do                                                                         \
    {                                                                          \
        if (!(cond))                                                           \
        {                                                                      \
            printf("FAIL: %s (line %d)\n", msg, __LINE__);                     \
            g_fail++;                                                          \
        }                                                                      \
    } while (0)

static std::vector<std::string> V(std::initializer_list<const char*> l)
{
    std::vector<std::string> v;
    for (auto* s : l) v.push_back(s);
    return v;
}

static void test_split_join()
{
    auto l = split_lines("a\r\nb\nc");
    CHECK(l.size() == 3, "split 3 lines");
    CHECK(l[0] == "a" && l[1] == "b" && l[2] == "c", "cr stripped");
    auto l2 = split_lines("x\n");
    CHECK(l2.size() == 1, "trailing empty dropped");
    auto l3 = split_lines("");
    CHECK(l3.empty(), "empty text");
    CHECK(join_lines(V({"a", "b"}), "\r\n") == "a\r\nb\r\n", "join crlf");
    CHECK(join_lines(V({}), "\r\n").empty(), "join empty");
}

static void test_merge_clean()
{
    // local changes line 2, remote changes line 4 — different regions
    auto b = V({"// hdr", "hp = 100;", "speed = 4;", "lives = 3;"});
    auto l = V({"// hdr", "hp = 999;", "speed = 4;", "lives = 3;"});
    auto r = V({"// hdr", "hp = 100;", "speed = 4;", "lives = 5;"});
    auto res = merge_lines(b, l, r);
    CHECK(res.clean(), "clean merge");
    CHECK(res.lines == V({"// hdr", "hp = 999;", "speed = 4;", "lives = 5;"}),
        "both sides taken");
}

static void test_merge_conflict()
{
    auto b = V({"// hdr", "hp = 100;"});
    auto l = V({"// hdr", "hp = 999;"});
    auto r = V({"// hdr", "hp = 555;"});
    auto res = merge_lines(b, l, r);
    CHECK(!res.clean(), "conflict detected");
    CHECK(res.conflicts.size() == 1, "one conflict");
    auto& c = res.conflicts[0];
    CHECK(c.baseStart == 1 && c.baseLen == 1, "base range");
    CHECK(c.localStart == 1 && c.localLen == 1, "local range");
    CHECK(c.remoteStart == 1 && c.remoteLen == 1, "remote range");
}

static void test_merge_one_side()
{
    auto b = V({"a", "b", "c"});
    auto r = V({"a", "b", "c", "d"});
    auto res = merge_lines(b, b, r); // local == base
    CHECK(res.clean(), "remote-only clean");
    CHECK(res.lines == r, "remote taken");
    res = merge_lines(b, r, b); // remote == base
    CHECK(res.clean() && res.lines == r, "local taken");
}

static void test_merge_insert_both()
{
    // both insert at different anchors
    auto b = V({"top", "bottom"});
    auto l = V({"top", "local-add", "bottom"});
    auto r = V({"top", "remote-add", "bottom"});
    auto res = merge_lines(b, l, r);
    // "local-add"/"remote-add" are unique in both sides of their diffs, but
    // they collide in the same region → conflict is acceptable; the stricter
    // expectation is that top/bottom are preserved around whatever block.
    bool hasTop = false, hasBottom = false;
    for (auto& s : res.lines)
    {
        if (s == "top") hasTop = true;
        if (s == "bottom") hasBottom = true;
    }
    CHECK(hasTop && hasBottom, "anchors preserved");
}

static void test_keyed_instances()
{
    // room instance reorder (local) + external edit of one instance:
    // keyed by col 3 (hash) — reorder alone must NOT conflict.
    auto b = V({"objA,0,0,aaaa1111,0", "objB,10,20,bbbb2222,0", "objC,5,5,cccc3333,0"});
    auto l = V({"objC,5,5,cccc3333,0", "objA,0,0,aaaa1111,0", "objB,10,20,bbbb2222,0"}); // reordered
    auto r = V({"objA,0,0,aaaa1111,0", "objB,99,99,bbbb2222,0", "objC,5,5,cccc3333,0"}); // moved objB
    auto res = merge_keyed(b, l, r, key_instances_csv4);
    CHECK(res.clean(), "reorder + external edit no conflict");
    bool foundMoved = false;
    for (auto& s : res.lines)
        if (s == "objB,99,99,bbbb2222,0") foundMoved = true;
    CHECK(foundMoved, "external edit applied");
    CHECK(res.lines.size() == 3, "all 3 instances kept");
}

static void test_keyed_same_instance_conflict()
{
    auto b = V({"objA,0,0,aaaa1111,0"});
    auto l = V({"objA,1,2,aaaa1111,0"});
    auto r = V({"objA,3,4,aaaa1111,0"});
    auto res = merge_keyed(b, l, r, key_instances_csv4);
    CHECK(!res.clean(), "same-instance both-changed conflicts");
}

static void test_keyed_add_delete()
{
    auto b = V({"a,0,0,k1,0", "b,0,0,k2,0"});
    auto l = V({"a,0,0,k1,0", "b,0,0,k2,0", "c,0,0,k3,0"}); // local adds c
    auto r = V({"a,0,0,k1,0"});                               // remote deletes b
    auto res = merge_keyed(b, l, r, key_instances_csv4);
    printf("  add/del result clean=%d lines:", (int)res.clean());
    for (auto& s : res.lines) printf(" [%s]", s.c_str());
    printf("\n");
    CHECK(res.clean(), "add+delete disjoint keys");
    CHECK(res.lines == V({"a,0,0,k1,0", "c,0,0,k3,0"}), "add kept, delete applied");
}

static void test_keyed_delete_vs_change()
{
    auto b = V({"a,0,0,k1,0"});
    auto l = V({});            // local deleted
    auto r = V({"a,9,9,k1,0"}); // remote changed
    auto res = merge_keyed(b, l, r, key_instances_csv4);
    CHECK(!res.clean(), "delete vs change conflicts");
}

static void test_keyed_tile_lines()
{
    // tile layer lines: whole-line keys — "modify" is delete+add.
    // local deletes tile X; remote "locks" X (= X deleted, X' added).
    // Set semantics: X deleted both sides; X' is a remote-only addition and
    // survives (external's new entity shouldn't vanish because local removed
    // the old one).
    auto b = V({"bg,0,0,0,0,16,16,0", "bg,32,0,0,0,16,16,0"});
    auto l = V({"bg,32,0,0,0,16,16,0"});                        // deleted first tile
    auto r = V({"bg,0,0,0,0,16,16,1", "bg,32,0,0,0,16,16,0"}); // locked first tile
    auto res = merge_keyed(b, l, r, key_whole_line);
    CHECK(res.clean(), "tile set semantics no conflict");
    CHECK(res.lines == V({"bg,0,0,0,0,16,16,1", "bg,32,0,0,0,16,16,0"}),
        "locked variant survives, other tile kept");
}

static void test_keyed_index_rename()
{
    // index.yyd: resource renamed locally + another added remotely
    auto b = V({"script_old", "other"});
    auto l = V({"script_new", "other"});      // rename = del+add
    auto r = V({"script_old", "other", "ext"}); // external adds
    auto res = merge_keyed(b, l, r, key_whole_line);
    CHECK(res.clean(), "rename+add clean");
    // remote order: script_old(gone), other, ext; local-only script_new appended
    CHECK(res.lines == V({"other", "ext", "script_new"}), "rename + add combined");
}

static void test_keyed_gbk_key()
{
    // key extraction on an ANSI/GBK-content line: pure byte slicing
    std::string line = "obj\xc4\xfa\xba\xc3,1,2,abcd1234,0"; // GBK obj name
    CHECK(key_instances_csv4(line) == "abcd1234", "csv4 key on gbk line");
}

static void test_xmerge_adjacent_insert_vs_change()
{
    // git case A (verified with `git merge-file`): local appends after line 1,
    // remote changes line 1. The hunks' base ranges touch → ONE conflict, not
    // a clean merge and not a whole-file rewrite.
    auto b = V({"// test test test ss"});
    auto l = V({"// test test test ss", "// ddd"});
    auto r = V({"// test test test ssssttt"});
    auto res = merge_lines(b, l, r);
    CHECK(!res.clean(), "adjacent insert vs change conflicts (git case A)");
    CHECK(res.conflicts.size() == 1, "single conflict block");
    CHECK(res.conflicts[0].baseLen == 1, "base range is the one line");
    CHECK(res.conflicts[0].localLen == 2, "local projection keeps both rows");
    CHECK(res.conflicts[0].remoteLen == 1, "remote projection one row");
}

static void test_xmerge_disjoint_far_apart()
{
    // git case B: changes far apart merge clean, both taken.
    auto b = V({"1", "2", "3", "4", "5", "6", "7", "8", "9"});
    auto l = V({"1x", "2", "3", "4", "5", "6", "7", "8", "9"});
    auto r = V({"1", "2", "3", "4", "5", "6", "7", "8", "9x"});
    auto res = merge_lines(b, l, r);
    CHECK(res.clean(), "far-apart edits clean (git case B)");
    CHECK(res.lines.front() == "1x" && res.lines.back() == "9x", "both taken");
}

static void test_xmerge_refine_common_rows()
{
    // git case G: both append "same" + a distinct row; refine lifts "same"
    // out of the conflict so only the distinct rows block.
    auto b = V({"x"});
    auto l = V({"x", "same", "ours"});
    auto r = V({"x", "same", "theirs"});
    auto res = merge_lines(b, l, r);
    CHECK(!res.clean(), "conflict present (git case G)");
    CHECK(res.conflicts.size() == 1, "one refined block");
    CHECK(res.conflicts[0].localLen == 1 && res.conflicts[0].remoteLen == 1,
        "block shrunk to the distinct rows");
    // "same" appears exactly once, outside markers.
    int same = 0;
    for (auto& s : res.lines)
        if (s == "same") same++;
    CHECK(same == 1, "shared row emitted once as merged text");
}

static void test_xmerge_delete_vs_change()
{
    // git case F: local deletes line 2, remote changes line 2 → conflict with
    // an empty local block.
    auto b = V({"1", "2", "3"});
    auto l = V({"1", "3"});
    auto r = V({"1", "2x", "3"});
    auto res = merge_lines(b, l, r);
    CHECK(!res.clean(), "delete vs change conflicts (git case F)");
    CHECK(res.conflicts.size() == 1 && res.conflicts[0].localLen == 0,
        "deleted side projects empty");
    CHECK(res.conflicts[0].remoteLen == 1, "changed side one row");
}

static void test_xmerge_both_same_change()
{
    // Both sides make the identical change → clean, no conflict.
    auto b = V({"a", "b", "c"});
    auto l = V({"a", "B2", "c"});
    auto r = V({"a", "B2", "c"});
    auto res = merge_lines(b, l, r);
    CHECK(res.clean(), "identical changes merge clean");
    CHECK(res.lines == l, "changed line once");
}

int main()
{
    test_split_join();
    test_merge_clean();
    test_merge_conflict();
    test_merge_one_side();
    test_merge_insert_both();
    test_xmerge_adjacent_insert_vs_change();
    test_xmerge_disjoint_far_apart();
    test_xmerge_refine_common_rows();
    test_xmerge_delete_vs_change();
    test_xmerge_both_same_change();
    test_keyed_instances();
    test_keyed_same_instance_conflict();
    test_keyed_add_delete();
    test_keyed_delete_vs_change();
    test_keyed_tile_lines();
    test_keyed_index_rename();
    test_keyed_gbk_key();
    if (g_fail)
    {
        printf("%d FAILURES\n", g_fail);
        return 1;
    }
    printf("all diff3 tests passed\n");
    return 0;
}
