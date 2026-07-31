// GMK binary format serializer — converts GMKProject to .gmk binary
#include "pch.h"
#include "gmk_format.h"
#include <compressapi.h>

#pragma comment(lib, "cabinet.lib")

// Deflate using Windows built-in Compress API
static std::vector<uint8_t> gmk_deflate(const uint8_t* data, size_t len) {
    if (len == 0) return {};
    COMPRESSOR_HANDLE h;
    if (!CreateCompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &h)) return {};
    SIZE_T destLen = 0;
    Compress(h, data, len, NULL, 0, &destLen);
    std::vector<uint8_t> out(destLen);
    if (!Compress(h, data, len, out.data(), destLen, &destLen)) { CloseCompressor(h); return {}; }
    CloseCompressor(h);
    out.resize(destLen);
    return out;
}

// Write helpers for building GMK binary
struct GMKWriter {
    std::vector<uint8_t> buf;
    void u32(uint32_t v) { buf.insert(buf.end(), (uint8_t*)&v, (uint8_t*)&v + 4); }
    void i32(int32_t v)  { buf.insert(buf.end(), (uint8_t*)&v, (uint8_t*)&v + 4); }
    void u64(uint64_t v) { buf.insert(buf.end(), (uint8_t*)&v, (uint8_t*)&v + 8); }
    void f64(double v)   { buf.insert(buf.end(), (uint8_t*)&v, (uint8_t*)&v + 8); }
    void les(const std::string& s) { u32((uint32_t)s.size()); buf.insert(buf.end(), s.begin(), s.end()); }
    void raw(const void* d, size_t n) { buf.insert(buf.end(), (uint8_t*)d, (uint8_t*)d + n); }
    void raw(const std::vector<uint8_t>& v) { buf.insert(buf.end(), v.begin(), v.end()); }

    // Write zlib-compressed block with length prefix
    void zlib_block(const std::vector<uint8_t>& data) {
        auto compressed = gmk_deflate(data.data(), data.size());
        u32((uint32_t)compressed.size());
        raw(compressed);
    }
};

// Serialize a GMKProject to binary .gmk format
std::vector<uint8_t> gmk_serialize(const GMKProject& proj) {
    GMKWriter w;

    // Header
    w.u32(1234321);       // magic
    w.u32(800);           // GM80 version
    w.u32(proj.game_id);
    w.raw(proj.guid, 16); // 16-byte GUID

    // Settings (simplified — write zlib compressed settings block)
    {
        GMKWriter sw;
        sw.u32(proj.settings.fullscreen ? 1 : 0);
        sw.u32(proj.settings.interpolate_pixels ? 1 : 0);
        sw.i32(proj.settings.scaling);
        sw.u32(proj.settings.clear_color);
        sw.les(proj.settings.author);
        sw.les(proj.settings.version_str);
        sw.u64(proj.settings.timestamp);
        sw.les(proj.settings.info);
        sw.u32(proj.settings.ver_major);
        sw.u32(proj.settings.ver_minor);
        sw.u32(proj.settings.ver_release);
        sw.u32(proj.settings.ver_build);
        sw.les(proj.settings.company);
        sw.les(proj.settings.product);
        sw.les(proj.settings.copyright);
        sw.les(proj.settings.description);
        sw.u64(proj.settings.exe_timestamp);

        w.u32(800); // settings tag
        w.zlib_block(sw.buf);
    }

    // Triggers
    {
        w.u32(800);
        w.u32((uint32_t)proj.trigger_names.size());
        for (size_t i = 0; i < proj.trigger_names.size(); i++) {
            GMKWriter tw;
            tw.u32(1); // have trigger
            tw.u32(800);
            tw.les(proj.trigger_names[i]);
            tw.les(i < proj.trigger_conditions.size() ? proj.trigger_conditions[i] : "");
            tw.u32(0); // event moment
            tw.les(i < proj.trigger_constants.size() ? proj.trigger_constants[i] : "");
            w.zlib_block(tw.buf);
        }
        w.u64(0); // timestamp
    }

    // Constants
    {
        w.u32(800);
        w.u32((uint32_t)proj.constants.size());
        for (auto& [name, expr] : proj.constants) {
            w.les(name);
            w.les(expr);
        }
        w.u64(0);
    }

    // Sounds
    {
        w.u32(800);
        w.u32((uint32_t)proj.sounds.size());
        for (auto& snd : proj.sounds) {
            GMKWriter sw;
            sw.u32(1); // have sound
            sw.les(snd.name);
            sw.u64(snd.timestamp);
            sw.u32(800);
            sw.u32(snd.kind);
            sw.les(snd.extension);
            sw.les(snd.file_name);
            sw.u32(!snd.data.empty());
            if (!snd.data.empty()) { sw.u32((uint32_t)snd.data.size()); sw.raw(snd.data); }
            sw.u32(snd.effects);
            sw.f64(snd.volume);
            sw.f64(snd.pan);
            sw.u32(snd.preload ? 1 : 0);
            w.zlib_block(sw.buf);
        }
    }

    // Sprites
    {
        w.u32(800);
        w.u32((uint32_t)proj.sprites.size());
        for (auto& sp : proj.sprites) {
            GMKWriter sw;
            sw.u32(1);
            sw.les(sp.name);
            sw.u64(sp.timestamp);
            sw.u32(800);
            sw.i32(sp.origin_x);
            sw.i32(sp.origin_y);
            sw.u32((uint32_t)sp.frames.size());
            for (auto& frm : sp.frames) {
                sw.u32(800);
                sw.u32(frm.width);
                sw.u32(frm.height);
                sw.u32((uint32_t)frm.data.size());
                sw.raw(frm.data);
            }
            sw.u32(sp.shape);
            sw.u32(sp.alpha_tolerance);
            sw.u32(sp.per_frame_colliders ? 1 : 0);
            sw.u32(sp.bbox_type);
            sw.u32(sp.bbox_left);
            sw.u32(sp.bbox_right);
            sw.u32(sp.bbox_bottom);
            sw.u32(sp.bbox_top);
            w.zlib_block(sw.buf);
        }
    }

    // Backgrounds
    {
        w.u32(800);
        w.u32((uint32_t)proj.backgrounds.size());
        for (auto& bg : proj.backgrounds) {
            GMKWriter sw;
            sw.u32(1); sw.les(bg.name); sw.u64(bg.timestamp); sw.u32(710);
            sw.u32(bg.is_tileset ? 1 : 0);
            sw.u32(bg.tile_width); sw.u32(bg.tile_height);
            sw.u32(bg.h_offset); sw.u32(bg.v_offset);
            sw.u32(bg.h_sep); sw.u32(bg.v_sep);
            sw.u32(800);
            sw.u32(bg.width); sw.u32(bg.height);
            sw.u32((uint32_t)bg.data.size());
            if (!bg.data.empty()) sw.raw(bg.data);
            w.zlib_block(sw.buf);
        }
    }

    // Paths
    {
        w.u32(800);
        w.u32((uint32_t)proj.paths.size());
        for (auto& pth : proj.paths) {
            GMKWriter sw;
            sw.u32(1); sw.les(pth.name); sw.u64(pth.timestamp); sw.u32(530);
            sw.u32(pth.kind_of_interpolation ? 1 : 0);
            sw.u32(pth.closed ? 1 : 0);
            sw.u32(pth.precision);
            sw.i32(pth.room_bg);
            sw.u32(pth.snap_x); sw.u32(pth.snap_y);
            sw.u32((uint32_t)pth.points.size());
            for (auto& pt : pth.points) { sw.f64(pt.x); sw.f64(pt.y); sw.f64(pt.speed); }
            w.zlib_block(sw.buf);
        }
    }

    // Scripts
    {
        w.u32(800);
        w.u32((uint32_t)proj.scripts.size());
        for (auto& sc : proj.scripts) {
            GMKWriter sw;
            sw.u32(1); sw.les(sc.name); sw.u64(sc.timestamp); sw.u32(800);
            sw.les(sc.source);
            w.zlib_block(sw.buf);
        }
    }

    // Fonts
    {
        w.u32(800);
        w.u32((uint32_t)proj.fonts.size());
        for (auto& f : proj.fonts) {
            GMKWriter sw;
            sw.u32(1); sw.les(f.name); sw.u64(f.timestamp); sw.u32(800);
            sw.les(f.sys_font_name); sw.u32(f.size);
            sw.u32(f.bold ? 1 : 0); sw.u32(f.italic ? 1 : 0);
            sw.u32(f.range_start); sw.u32(f.range_end);
            w.zlib_block(sw.buf);
        }
    }

    // Timelines — simplified stub
    w.u32(800); w.u32((uint32_t)proj.timelines.size());
    for (size_t i = 0; i < proj.timelines.size(); i++) {
        GMKWriter sw; sw.u32(1); w.zlib_block(sw.buf);
    }

    // Objects — simplified stub
    w.u32(800); w.u32((uint32_t)proj.objects.size());
    for (size_t i = 0; i < proj.objects.size(); i++) {
        GMKWriter sw; sw.u32(1); w.zlib_block(sw.buf);
    }

    // Rooms — simplified stub
    w.u32(800); w.u32((uint32_t)proj.rooms.size());
    for (size_t i = 0; i < proj.rooms.size(); i++) {
        GMKWriter sw; sw.u32(1); w.zlib_block(sw.buf);
    }

    // Room order
    w.u32(700); w.u32((uint32_t)proj.room_order.size());
    for (auto id : proj.room_order) w.i32(id);

    // Resource tree
    w.u32(500); w.u32(12); // 12 root nodes
    const char* roots[] = {"Sprites","Sounds","Backgrounds","Paths","Scripts",
        "Fonts","Time Lines","Objects","Rooms","Game Information",
        "Global Game Settings","Extension Packages"};
    for (int i = 0; i < 12; i++) w.les(roots[i]);

    return w.buf;
}
