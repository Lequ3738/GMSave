#include "pch.h"
#include "diff3.h"
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace diff3 {

// ==== Line splitting ====

std::vector<std::string> split_lines(const std::string& text)
{
    std::vector<std::string> lines;
    size_t start = 0;
    while (start <= text.size())
    {
        size_t nl = text.find('\n', start);
        if (nl == std::string::npos)
        {
            if (start < text.size()) lines.push_back(text.substr(start));
            break;
        }
        size_t end = nl;
        if (end > start && text[end - 1] == '\r') end--;
        lines.push_back(text.substr(start, end - start));
        start = nl + 1;
    }
    // Drop one trailing empty line so files that do / don't end with a newline
    // compare equal (git-style).
    if (!lines.empty() && lines.back().empty()) lines.pop_back();
    return lines;
}

std::string join_lines(const std::vector<std::string>& lines, const char* nl)
{
    std::string out;
    for (const auto& l : lines)
    {
        out += l;
        out += nl;
    }
    return out;
}

// ==== Patience anchors: match lines unique on both sides, in order ====

// Returns pairs (baseIdx, sideIdx) of matched equal lines, increasing in both.
static std::vector<std::pair<size_t, size_t>> patience_anchors(
    const std::vector<std::string>& base, const std::vector<std::string>& side)
{
    std::unordered_map<std::string, size_t> baseCount, sideCount;
    baseCount.reserve(base.size() * 2);
    sideCount.reserve(side.size() * 2);
    for (auto& l : base) baseCount[l]++;
    for (auto& l : side) sideCount[l]++;

    // Candidate anchors in base order: (baseIdx, sideIdx) for lines occurring
    // exactly once in both.
    struct Cand { size_t b, s; };
    std::vector<Cand> cands;
    std::unordered_map<std::string, size_t> sideFirst;
    for (size_t i = 0; i < side.size(); i++)
        if (sideCount[side[i]] == 1 && baseCount[side[i]] == 1)
            sideFirst[side[i]] = i; // only for unique-on-both lines
    for (size_t i = 0; i < base.size(); i++)
    {
        auto it = sideFirst.find(base[i]);
        if (it != sideFirst.end()) cands.push_back({i, it->second});
    }

    // Longest strictly-increasing subsequence over sideIdx (cands are already
    // in base order) — O(n log n) tails array.
    std::vector<size_t> tailsIdx; // index into cands of best tail per length
    std::vector<size_t> prev(cands.size(), SIZE_MAX);
    for (size_t i = 0; i < cands.size(); i++)
    {
        size_t s = cands[i].s;
        // lower_bound: first tail with sideIdx >= s (strictly increasing)
        size_t lo = 0, hi = tailsIdx.size();
        while (lo < hi)
        {
            size_t mid = (lo + hi) / 2;
            if (cands[tailsIdx[mid]].s < s) lo = mid + 1;
            else hi = mid;
        }
        if (lo > 0) prev[i] = tailsIdx[lo - 1];
        if (lo == tailsIdx.size()) tailsIdx.push_back(i);
        else tailsIdx[lo] = i;
    }
    std::vector<std::pair<size_t, size_t>> out;
    for (size_t i = tailsIdx.empty() ? SIZE_MAX : tailsIdx.back(); i != SIZE_MAX;
         i = prev[i])
        out.push_back({cands[i].b, cands[i].s});
    std::reverse(out.begin(), out.end());
    return out;
}

// ==== Line-level three-way merge ====

static bool seg_eq(const std::vector<std::string>& a, size_t a0, size_t a1,
    const std::vector<std::string>& b, size_t b0, size_t b1)
{
    if (a1 - a0 != b1 - b0) return false;
    for (size_t i = 0; i < a1 - a0; i++)
        if (a[a0 + i] != b[b0 + i]) return false;
    return true;
}

Result merge_lines(const std::vector<std::string>& base,
    const std::vector<std::string>& local, const std::vector<std::string>& remote)
{
    auto al = patience_anchors(base, local);
    auto ar = patience_anchors(base, remote);

    // base index -> side index when anchored (line matched) on that side
    std::unordered_map<size_t, size_t> ml, mr;
    for (auto& p : al) ml[p.first] = p.second;
    for (auto& p : ar) mr[p.first] = p.second;

    Result res;
    size_t bi = 0, li = 0, ri = 0;
    size_t nB = base.size(), nL = local.size(), nR = remote.size();

    auto emitConflict = [&](size_t b0, size_t b1, size_t l0, size_t l1, size_t r0,
                            size_t r1)
    {
        res.conflicts.push_back({b0, b1 - b0, l0, l1 - l0, r0, r1 - r0});
        res.lines.push_back("<<<<<<< local");
        for (size_t i = l0; i < l1; i++) res.lines.push_back(local[i]);
        res.lines.push_back("=======");
        for (size_t i = r0; i < r1; i++) res.lines.push_back(remote[i]);
        res.lines.push_back(">>>>>>> remote");
    };

    // Walk stable lines: base positions anchored in BOTH sides.
    while (bi < nB || li < nL || ri < nR)
    {
        // Advance to the next base line stable in both sides.
        size_t sbi = bi, sli = li, sri = ri;
        bool found = false;
        while (sbi < nB)
        {
            auto fl = ml.find(sbi);
            auto fr = mr.find(sbi);
            if (fl != ml.end() && fr != mr.end())
            {
                sli = fl->second;
                sri = fr->second;
                found = true;
                break;
            }
            sbi++;
        }
        size_t nextB = found ? sbi : nB;
        size_t nextL = found ? sli : nL;
        size_t nextR = found ? sri : nR;

        // Region [cur, next) differs somewhere.
        if (bi < nextB || li < nextL || ri < nextR)
        {
            bool lEqB = seg_eq(local, li, nextL, base, bi, nextB);
            bool rEqB = seg_eq(remote, ri, nextR, base, bi, nextB);
            bool lEqR = seg_eq(local, li, nextL, remote, ri, nextR);
            if (lEqR)
                for (size_t i = li; i < nextL; i++) res.lines.push_back(local[i]);
            else if (rEqB)
                for (size_t i = li; i < nextL; i++) res.lines.push_back(local[i]);
            else if (lEqB)
                for (size_t i = ri; i < nextR; i++) res.lines.push_back(remote[i]);
            else
                emitConflict(bi, nextB, li, nextL, ri, nextR);
        }

        if (!found) break;
        // Emit the stable line itself.
        res.lines.push_back(base[nextB]);
        bi = nextB + 1;
        li = nextL + 1;
        ri = nextR + 1;
    }
    return res;
}

// ==== Keyed record merge ====

static bool line_list_eq(const std::vector<std::string>& a,
    const std::vector<std::string>& b)
{
    return a == b;
}

Result merge_keyed(const std::vector<std::string>& base,
    const std::vector<std::string>& local, const std::vector<std::string>& remote,
    const std::function<std::string(const std::string& line)>& keyOf)
{
    auto index = [&](const std::vector<std::string>& lines,
                     std::vector<std::vector<size_t>>& byKey,
                     std::vector<std::string>& order)
    {
        std::unordered_map<std::string, size_t> slot;
        for (size_t i = 0; i < lines.size(); i++)
        {
            std::string k = keyOf(lines[i]);
            auto it = slot.find(k);
            if (it == slot.end())
            {
                slot[k] = byKey.size();
                byKey.push_back({});
                order.push_back(k);
            }
            byKey[slot[k]].push_back(i);
        }
    };

    std::vector<std::vector<size_t>> bKey, lKey, rKey;
    std::vector<std::string> bOrder, lOrder, rOrder;
    index(base, bKey, bOrder);
    index(local, lKey, lOrder);
    index(remote, rKey, rOrder);

    std::unordered_map<std::string, size_t> bSlot;
    for (size_t i = 0; i < bOrder.size(); i++) bSlot[bOrder[i]] = i;

    auto lines_at = [&](const std::vector<std::string>& src,
                        const std::vector<size_t>& idxs)
    {
        std::vector<std::string> out;
        out.reserve(idxs.size());
        for (size_t i : idxs) out.push_back(src[i]);
        return out;
    };

    // Resolve one key → lines to emit (or conflict). Index lists are empty for
    // absent records.
    Result res;
    auto resolve = [&](const std::string& key, const std::vector<size_t>& bIdx,
                       const std::vector<size_t>& lIdx, const std::vector<size_t>& rIdx)
    {
        (void)key;
        std::vector<std::string> bL = lines_at(base, bIdx);
        std::vector<std::string> lL = lines_at(local, lIdx);
        std::vector<std::string> rL = lines_at(remote, rIdx);

        bool lDel = lIdx.empty() && !bIdx.empty();
        bool rDel = rIdx.empty() && !bIdx.empty();
        bool lChanged = !lIdx.empty() && !line_list_eq(lL, bL);
        bool rChanged = !rIdx.empty() && !line_list_eq(rL, bL);

        auto firstOr0 = [](const std::vector<size_t>& v)
        { return v.empty() ? 0 : v.front(); };

        if (bIdx.empty())
        {
            // Added on one/both sides.
            if (lIdx.empty()) // remote-only add
                for (auto& s : rL) res.lines.push_back(s);
            else if (rIdx.empty()) // local-only add
                for (auto& s : lL) res.lines.push_back(s);
            else if (line_list_eq(lL, rL))
                for (auto& s : lL) res.lines.push_back(s);
            else
            {
                res.conflicts.push_back({0, 0, firstOr0(lIdx), lL.size(),
                    firstOr0(rIdx), rL.size()});
                for (auto& s : lL) res.lines.push_back(s);
                for (auto& s : rL) res.lines.push_back(s); // both appended; tool decides
            }
            return;
        }
        if (lDel && rDel) return; // deleted both sides
        if (lDel && !rChanged) return; // deleted locally, untouched remotely
        if (rDel && !lChanged) return; // deleted remotely, untouched locally
        if (lDel && rChanged || rDel && lChanged)
        {
            res.conflicts.push_back({firstOr0(bIdx), bL.size(), firstOr0(lIdx),
                lL.size(), firstOr0(rIdx), rL.size()});
            // delete-vs-change: emit the surviving changed side for preview
            for (auto& s : (lDel ? rL : lL)) res.lines.push_back(s);
            return;
        }
        if (!lChanged && !rChanged)
            for (auto& s : bL) res.lines.push_back(s);
        else if (lChanged && !rChanged)
            for (auto& s : lL) res.lines.push_back(s);
        else if (!lChanged && rChanged)
            for (auto& s : rL) res.lines.push_back(s);
        else if (line_list_eq(lL, rL))
            for (auto& s : lL) res.lines.push_back(s);
        else
        {
            res.conflicts.push_back({firstOr0(bIdx), bL.size(), firstOr0(lIdx),
                lL.size(), firstOr0(rIdx), rL.size()});
            for (auto& s : lL) res.lines.push_back(s);
            for (auto& s : rL) res.lines.push_back(s);
        }
    };

    // Rebuild per-key index lists by walking the three order vectors through
    // the shared key space.
    std::unordered_map<std::string, size_t> lSlot, rSlot;
    for (size_t i = 0; i < lOrder.size(); i++) lSlot[lOrder[i]] = i;
    for (size_t i = 0; i < rOrder.size(); i++) rSlot[rOrder[i]] = i;

    // Pass 1: remote order.
    for (auto& k : rOrder)
    {
        auto bit = bSlot.find(k);
        auto lit = lSlot.find(k);
        resolve(k, bit == bSlot.end() ? std::vector<size_t>{} : bKey[bit->second],
            lit == lSlot.end() ? std::vector<size_t>{} : lKey[lit->second],
            rKey[rSlot[k]]);
    }
    // Pass 2: local-only keys (not in remote), in local order, appended.
    for (auto& k : lOrder)
    {
        if (rSlot.count(k)) continue;
        auto bit = bSlot.find(k);
        resolve(k, bit == bSlot.end() ? std::vector<size_t>{} : bKey[bit->second],
            lKey[lSlot[k]], std::vector<size_t>{});
    }
    return res;
}

std::string key_whole_line(const std::string& line) { return line; }

std::string key_instances_csv4(const std::string& line)
{
    // cols: obj,x,y,hash,locked,... — key = col[4] (index 3), i.e. the text
    // between the 3rd and the 4th comma.
    int seen = 0;
    size_t start = 0, end = line.size();
    for (size_t i = 0; i < line.size(); i++)
    {
        if (line[i] != ',') continue;
        seen++;
        if (seen == 3) start = i + 1;
        else if (seen == 4)
        {
            end = i;
            break;
        }
    }
    return line.substr(start, end - start);
}

} // namespace diff3
