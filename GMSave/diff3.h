// Line-level and keyed three-way merge (git-style) for the .gm80 conflict flow.
// Pure standard C++ — no Windows dependencies, unit-testable standalone.
#pragma once
#include <functional>
#include <string>
#include <vector>

namespace diff3 {

// A conflict region: line ranges in each of the three inputs (half-open).
struct Conflict {
    size_t baseStart = 0, baseLen = 0;
    size_t localStart = 0, localLen = 0;
    size_t remoteStart = 0, remoteLen = 0;
};

struct Result {
    // Merged lines. Conflict regions are emitted with <<<<<<< / ======= / >>>>>>>
    // markers (local block first, remote block second) so the text stays
    // previewable; the merge TOOL does not consume markers — it renders each
    // Conflict from the original three inputs.
    std::vector<std::string> lines;
    std::vector<Conflict> conflicts;
    bool clean() const { return conflicts.empty(); }
};

// Classic line-level three-way merge. Diff quality is patience-style (anchored
// on lines unique in both sides), which suits GML code well and has no
// O(N*M) blowup on large files.
Result merge_lines(const std::vector<std::string>& base,
    const std::vector<std::string>& local, const std::vector<std::string>& remote);

// Record-keyed three-way merge for order-sensitive record files
// (instances.txt / index.yyd / tree.yyd / tile layers). keyOf maps a line to
// its stable identity; records with equal keys are matched across versions
// regardless of position. Output order: remote order first, local-only
// additions appended at the end (instance order has no runtime meaning —
// ids are reassigned on load — only git readability, which this preserves
// well enough for the common add-in-the-middle case only partially).
Result merge_keyed(const std::vector<std::string>& base,
    const std::vector<std::string>& local, const std::vector<std::string>& remote,
    const std::function<std::string(const std::string& line)>& keyOf);

// Convenience key: the whole line (tile layers, index.yyd, tree.yyd —
// "modify" degenerates to delete+add, which is exactly the set semantics
// those files want).
std::string key_whole_line(const std::string& line);

// Key for instances.txt: the 4th CSV column (stable 8-hex code hash that
// names the instance's creation-code file — independent of the runtime id).
std::string key_instances_csv4(const std::string& line);

// Split text into lines: strips a trailing \r per line (CRLF-agnostic), keeps
// a final unterminated line, drops one trailing empty line (git-like).
std::vector<std::string> split_lines(const std::string& text);
// Join lines with the given newline ("\r\n" matches what save writes).
std::string join_lines(const std::vector<std::string>& lines, const char* nl);

} // namespace diff3
