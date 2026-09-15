#include "pch.h"
#include "diff3.h"
#include <algorithm>
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

// ==== Line-level three-way merge (xdiff/xmerge model) ====
//
// Mirrors git: diff base→local and base→remote independently (two-way
// patience diff), then merge the two hunk lists over base coordinates.
// Hunks whose base ranges touch or overlap form one conflict group; disjoint
// hunks apply cleanly. Each conflict group is refined by re-diffing the two
// side projections so shared lines leave the conflict block (git's
// xdl_refine_conflicts / zdiff3 behaviour).

struct Hunk
{
    size_t b0, b1; // base range [b0,b1) being replaced
    size_t s0, s1; // side range [s0,s1) replacing it
};

struct SideDiff
{
    std::vector<Hunk> hunks;                        // sorted by b0, disjoint
    std::vector<std::pair<size_t, size_t>> anchors; // (baseIdx, sideIdx) matches
};

static SideDiff diff_side(const std::vector<std::string>& base,
    const std::vector<std::string>& side)
{
    SideDiff d;
    d.anchors = patience_anchors(base, side);
    size_t bPrev = 0, sPrev = 0;
    auto flush = [&](size_t bEnd, size_t sEnd)
    {
        // Peel equal prefix/suffix rows so matched lines never join a hunk.
        size_t b0 = bPrev, s0 = sPrev;
        while (b0 < bEnd && s0 < sEnd && base[b0] == side[s0])
        {
            b0++;
            s0++;
        }
        size_t b1 = bEnd, s1 = sEnd;
        while (b1 > b0 && s1 > s0 && base[b1 - 1] == side[s1 - 1])
        {
            b1--;
            s1--;
        }
        if (b1 > b0 || s1 > s0) d.hunks.push_back({b0, b1, s0, s1});
    };
    for (auto& a : d.anchors)
    {
        flush(a.first, a.second);
        bPrev = a.first + 1;
        sPrev = a.second + 1;
    }
    flush(base.size(), side.size());
    return d;
}

// Position of base line b in the side, walking the un-hunked alignment
// (nearest anchor at or before b, plus the offset).
static size_t align_pos(const SideDiff& d, size_t b)
{
    size_t lo = 0, hi = d.anchors.size();
    while (lo < hi)
    {
        size_t mid = (lo + hi) / 2;
        if (d.anchors[mid].first <= b) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return b; // before the first anchor the head is 1:1
    auto& a = d.anchors[lo - 1];
    return a.second + (b - a.first);
}

// Apply one side's hunks to base range [g0,g1). Returns the projected rows
// and their index range inside that side.
static void project_side(const std::vector<std::string>& base,
    const std::vector<std::string>& side, const SideDiff& d,
    const std::vector<Hunk>& group, size_t g0, size_t g1,
    std::vector<std::string>& out, size_t& sStart, size_t& sLen)
{
    size_t s = align_pos(d, g0);
    sStart = s;
    size_t cur = g0;
    for (auto& h : group)
    {
        while (cur < h.b0)
        {
            out.push_back(base[cur]);
            cur++;
            s++;
        }
        for (size_t k = h.s0; k < h.s1; k++) out.push_back(side[k]);
        s = h.s1;
        cur = h.b1;
    }
    while (cur < g1)
    {
        out.push_back(base[cur]);
        cur++;
        s++;
    }
    sLen = s - sStart;
}

Result merge_lines(const std::vector<std::string>& base,
    const std::vector<std::string>& local, const std::vector<std::string>& remote)
{
    SideDiff dl = diff_side(base, local);
    SideDiff dr = diff_side(base, remote);
    Result res;

    size_t i = 0, j = 0, bPos = 0;
    while (i < dl.hunks.size() || j < dr.hunks.size())
    {
        // Start a group with whichever hunk comes first in base order.
        bool takeL = (j >= dr.hunks.size()) ||
            (i < dl.hunks.size() && dl.hunks[i].b0 <= dr.hunks[j].b0);
        size_t g0, g1;
        std::vector<Hunk> gl, gr;
        if (takeL)
        {
            g0 = dl.hunks[i].b0;
            g1 = dl.hunks[i].b1;
            gl.push_back(dl.hunks[i]);
            i++;
        }
        else
        {
            g0 = dr.hunks[j].b0;
            g1 = dr.hunks[j].b1;
            gr.push_back(dr.hunks[j]);
            j++;
        }
        // Absorb every hunk whose base range touches the group (xmerge uses
        // strict inequality: touching ranges are ONE conflict, not two clean
        // edits — verified against `git merge-file`).
        for (;;)
        {
            bool grew = false;
            while (i < dl.hunks.size() && dl.hunks[i].b0 <= g1)
            {
                g1 = std::max(g1, dl.hunks[i].b1);
                gl.push_back(dl.hunks[i]);
                i++;
                grew = true;
            }
            while (j < dr.hunks.size() && dr.hunks[j].b0 <= g1)
            {
                g1 = std::max(g1, dr.hunks[j].b1);
                gr.push_back(dr.hunks[j]);
                j++;
                grew = true;
            }
            if (!grew) break;
        }

        // Stable rows before the group.
        for (size_t b = bPos; b < g0; b++) res.lines.push_back(base[b]);

        if (gr.empty() || gl.empty())
        {
            // Only one side touched this region → clean, apply that side.
            bool useLocal = gr.empty();
            size_t s0, sl;
            project_side(base, useLocal ? local : remote,
                useLocal ? dl : dr, useLocal ? gl : gr, g0, g1, res.lines, s0,
                sl);
        }
        else
        {
            // Both sides touched the region → conflict group.
            std::vector<std::string> oursP, theirsP;
            size_t l0, ll, r0, rl;
            project_side(base, local, dl, gl, g0, g1, oursP, l0, ll);
            project_side(base, remote, dr, gr, g0, g1, theirsP, r0, rl);
            // Refine: re-diff the projections; shared rows leave the conflict
            // block(s). Sub-block records share the group's base range (the
            // tool renders the exact local/remote ranges per block).
            auto ranchors = patience_anchors(oursP, theirsP);
            size_t p = 0, q = 0;
            auto flushSub = [&](size_t pEnd, size_t qEnd)
            {
                if (pEnd == p && qEnd == q) return;
                res.conflicts.push_back(
                    {g0, g1 - g0, l0 + p, pEnd - p, r0 + q, qEnd - q});
                res.lines.push_back("<<<<<<< local");
                for (size_t k = p; k < pEnd; k++) res.lines.push_back(oursP[k]);
                res.lines.push_back("=======");
                for (size_t k = q; k < qEnd; k++) res.lines.push_back(theirsP[k]);
                res.lines.push_back(">>>>>>> remote");
            };
            for (auto& a : ranchors)
            {
                flushSub(a.first, a.second);
                res.lines.push_back(oursP[a.first]); // == theirsP[a.second]
                p = a.first + 1;
                q = a.second + 1;
            }
            flushSub(oursP.size(), theirsP.size());
        }
        bPos = g1;
    }
    for (size_t b = bPos; b < base.size(); b++) res.lines.push_back(base[b]);
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
