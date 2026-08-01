// GMK/GM81/GM80 binary format definitions.
// Based on reverse-engineered .gmk/.gm81 file structure.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Format version identifiers
#define GMK_VERSION_GM80 800
#define GMK_VERSION_GM81 810
#define GM80_SAVE_VERSION 5   // Our .gm80 format version

// GMK magic number
#define GMK_MAGIC 1234321

// ---- GMK Binary Reader ----
struct GMKReader {
    const uint8_t* data;
    size_t         pos;
    size_t         size;

    GMKReader(const uint8_t* d, size_t s) : data(d), pos(0), size(s) {}

    template<typename T> T read() {
        T val;
        memcpy(&val, data + pos, sizeof(T));
        pos += sizeof(T);
        return val;
    }
    uint32_t read_u32() { return read<uint32_t>(); }
    int32_t  read_i32() { return read<int32_t>(); }
    uint64_t read_u64() { return read<uint64_t>(); }
    double   read_f64() { return read<double>(); }
    bool     read_bool() { return read_u32() != 0; }

    // Read length-prefixed string (LES: u32 length + data)
    std::string read_les() {
        uint32_t len = read_u32();
        std::string s((const char*)(data + pos), len);
        pos += len;
        return s;
    }

    // Read zlib-compressed block
    std::vector<uint8_t> read_zlib_block() {
        return read_zlib_block_inline(data, pos, size);
    }

    // Read and decompress a GMK zlib block at current position
    static std::vector<uint8_t> read_zlib_block_inline(const uint8_t* d, size_t& p, size_t sz);
};

// ---- GMK structures ----
struct GMKSettings {
    bool     fullscreen = false;
    bool     interpolate_pixels = false;
    bool     dont_draw_border = false;
    bool     display_cursor = true;
    int32_t  scaling = -1;       // -1=keep aspect, 0=full, >0=fixed%
    bool     allow_resize = false;
    bool     window_on_top = false;
    uint32_t clear_color = 0;
    bool     set_resolution = false;
    uint32_t color_depth = 0;    // 0=NoChange, 1=16bit, 2=32bit
    uint32_t resolution = 0;
    uint32_t frequency = 0;
    bool     dont_show_buttons = false;
    uint32_t vsync_flags = 0;    // bit0=vsync, bit7=force cpu render(GM81 only)
    bool     disable_screensaver = false;
    bool     f4_fullscreen = false;
    bool     f1_help = false;
    bool     esc_close = true;
    bool     f5_save_f6_load = false;
    bool     f9_screenshot = false;
    bool     treat_close_as_esc = false;
    uint32_t priority = 0;       // 0=Normal, 1=High, 2=Highest
    bool     freeze_on_lose_focus = false;
    uint32_t loading_bar = 0;    // 0=None, 1=Default, 2=Custom
    std::vector<uint8_t> loading_background;
    std::vector<uint8_t> loading_foreground;
    bool     loading_transparent = false;
    uint32_t loading_translucency = 0;
    bool     scale_progress_bar = false;
    std::vector<uint8_t> loading_image;
    std::vector<uint8_t> icon_data;
    bool     show_error_messages = true;
    bool     log_errors = false;
    bool     always_abort = false;
    uint32_t zero_uninit = 0;    // GM80: bool; GM81: bit0=zero vars, bit1=error on uninit args
    std::string author;
    std::string version_str;
    uint64_t timestamp = 0;
    std::string info;
    uint32_t ver_major = 1, ver_minor = 0, ver_release = 0, ver_build = 0;
    std::string company, product, copyright, description;
    uint64_t exe_timestamp = 0;
};

struct GMKSpriteFrame {
    uint32_t width = 0, height = 0;
    std::vector<uint8_t> data; // BGRA raw pixels
};

struct GMKSprite {
    std::string name;
    uint64_t timestamp = 0;
    int32_t  origin_x = 0, origin_y = 0;
    uint32_t shape = 0;           // collision shape
    uint32_t alpha_tolerance = 0;
    bool     per_frame_colliders = false;
    uint32_t bbox_type = 0;
    int32_t  bbox_left = 0, bbox_right = 0, bbox_bottom = 0, bbox_top = 0;
    std::vector<GMKSpriteFrame> frames;
};

struct GMKSound {
    std::string name;
    uint64_t timestamp = 0;
    uint32_t kind = 0;           // 0=normal, 1=background, 2=3D, 3=multimedia
    std::string extension;
    std::string file_name;
    std::vector<uint8_t> data;
    uint32_t effects = 0;
    double   volume = 1.0;
    double   pan = 0.0;
    bool     preload = false;
};

struct GMKBackground {
    std::string name;
    uint64_t timestamp = 0;
    bool     is_tileset = false;
    uint32_t tile_width = 0, tile_height = 0;
    uint32_t h_offset = 0, v_offset = 0;
    uint32_t h_sep = 0, v_sep = 0;
    uint32_t width = 0, height = 0;
    std::vector<uint8_t> data;
};

struct GMKPathPoint {
    double x, y, speed;
};

struct GMKPath {
    std::string name;
    uint64_t timestamp = 0;
    bool     kind_of_interpolation = false;
    bool     closed = true;
    uint32_t precision = 0;
    int32_t  room_bg = -1;
    uint32_t snap_x = 0, snap_y = 0;
    std::vector<GMKPathPoint> points;
};

struct GMKScript {
    std::string name;
    uint64_t timestamp = 0;
    std::string source; // GML code
};

struct GMKFont {
    std::string name;
    uint64_t timestamp = 0;
    std::string sys_font_name;
    uint32_t size = 12;
    bool     bold = false;
    bool     italic = false;
    uint32_t range_start = 32; // GM80: just range_start
    uint32_t range_end = 127;
    // GM81 extended: charset << 16 | aa_level << 24 in range_start
    uint32_t charset = 0;
    uint32_t aa_level = 0;
};

struct GMKAction {
    uint32_t lib_id = 0;
    uint32_t dnd_id = 0;
    uint32_t action_kind = 0;
    bool     is_relative = false;
    bool     is_condition = false;
    bool     applies_to_something = false;
    uint32_t execution_type = 0;
    std::string func_name;
    std::string func_code;
    std::vector<uint32_t> param_types;
    int32_t  applies_to = -1;
    std::vector<std::string> param_strings;
    bool     invert_condition = false;
};

struct GMKEvent {
    std::vector<GMKAction> actions;
};

struct GMKTimeline {
    std::string name;
    uint64_t timestamp = 0;
    std::vector<uint32_t> moments;
    std::vector<GMKEvent> events;
};

struct GMKObject {
    std::string name;
    uint64_t timestamp = 0;
    int32_t  sprite_index = -1;
    bool     solid = false;
    bool     visible = true;
    int32_t  depth = 0;
    bool     persistent = false;
    int32_t  parent_index = -1;
    int32_t  mask_index = -1;
    // Events: [event_type][event_number]
    std::vector<std::vector<GMKEvent>> events;
};

struct GMKView {
    bool     visible = false;
    int32_t  source_x = 0, source_y = 0;
    uint32_t source_w = 640, source_h = 480;
    int32_t  port_x = 0, port_y = 0;
    uint32_t port_w = 640, port_h = 480;
    int32_t  following_hborder = 32, following_vborder = 32;
    int32_t  following_hspeed = -1, following_vspeed = -1;
    int32_t  following_target = -1;
};

struct GMKBackgroundRef {
    bool     visible_on_start = false;
    bool     is_foreground = false;
    int32_t  source_bg = -1;
    int32_t  xoffset = 0, yoffset = 0;
    bool     tile_horz = false, tile_vert = false;
    int32_t  hspeed = 0, vspeed = 0;
    bool     stretch = false;
};

struct GMKInstance {
    int32_t  x = 0, y = 0;
    int32_t  object = -1;
    int32_t  id = 0;
    std::string creation_code;
    bool     locked = false;
};

struct GMKTile {
    int32_t  x = 0, y = 0;
    int32_t  source_bg = -1;
    int32_t  tile_x = 0, tile_y = 0;
    uint32_t tile_w = 16, tile_h = 16;
    int32_t  depth = 0;
    int32_t  id = 0;
    bool     locked = false;
};

struct GMKRoom {
    std::string name;
    uint64_t timestamp = 0;
    std::string caption;
    uint32_t width = 640, height = 480;
    uint32_t snap_x = 16, snap_y = 16;
    bool     isometric = false;
    uint32_t room_speed = 30;
    bool     persistent = false;
    uint32_t bg_color = 0;
    bool     clear_screen = true;
    std::string creation_code;
    std::vector<GMKBackgroundRef> backgrounds; // always 8
    bool     views_enabled = false;
    std::vector<GMKView> views; // always 8
    std::vector<GMKInstance> instances;
    std::vector<GMKTile> tiles;
    bool     remember_editor = false;
    uint32_t editor_w = 640, editor_h = 480;
    bool     show_grid = true, show_objects = true, show_tiles = true;
    bool     show_backgrounds = true, show_foregrounds = true, show_views = true;
    bool     delete_underlying_objects = false, delete_underlying_tiles = false;
    uint32_t tab = 0;
    uint32_t editor_scroll_x = 0, editor_scroll_y = 0;
};

struct GMKIncludedFile {
    std::string name, source_path;
    std::vector<uint8_t> data;
    uint64_t timestamp = 0;
    bool     data_exists = false, stored_in_gmk = false;
    uint32_t source_length = 0;
    uint32_t export_setting = 0;
    std::string export_folder;
    bool     overwrite = false, free_memory = false, remove_at_end = false;
};

struct GMKTrigger {
    std::string name;
    std::string condition;
    uint32_t event_moment = 0;
    std::string constant_name;
};

struct GMKExtension {
    std::string name;
};

struct GMKProject {
    uint32_t game_id = 0;
    uint8_t  guid[16] = {};
    GMKSettings settings;
    // Resource counts (read from IDE, used for has_* flags)
    uint32_t sprite_count = 0, sound_count = 0, bg_count = 0;
    uint32_t path_count = 0, script_count = 0, font_count = 0;
    uint32_t tl_count = 0, object_count = 0, room_count = 0;
    uint32_t trigger_count = 0;
    // Resource names (read from IDE, used for index.yyd)
    std::vector<std::string> sprite_names, sound_names, bg_names;
    std::vector<std::string> path_names, script_names, font_names;
    std::vector<std::string> tl_names, object_names, room_names;
    std::vector<std::string> trigger_names;
    // Script sources (GML code from IDE)
    std::vector<std::string> script_sources;
    // Trigger fields
    std::vector<std::string> trigger_conditions, trigger_constants;

    std::vector<GMKTrigger> triggers;
    std::vector<std::pair<std::string, std::string>> constants;
    std::vector<GMKSound> sounds;
    std::vector<GMKSprite> sprites;
    std::vector<GMKBackground> backgrounds;
    std::vector<GMKPath> paths;
    std::vector<GMKScript> scripts;
    std::vector<GMKFont> fonts;
    std::vector<GMKTimeline> timelines;
    std::vector<GMKObject> objects;
    std::vector<GMKRoom> rooms;
    std::vector<GMKIncludedFile> included_files;
    std::vector<GMKExtension> extensions;
    // Room editor metadata
    int32_t last_instance_id = 100000;
    int32_t last_tile_id = 100000;
    // Game information
    uint32_t gi_bg_color = 0;
    bool     gi_new_window = false;
    std::string gi_caption;
    int32_t  gi_left = -1, gi_top = -1;
    uint32_t gi_width = 640, gi_height = 480;
    bool     gi_border = true, gi_resizable = true;
    bool     gi_window_on_top = false, gi_freeze = false;
    uint64_t gi_timestamp = 0;
    std::string gi_info;
    // Resource tree
    struct TreeNode { uint32_t status, kind, index; std::string name; std::vector<TreeNode> children; };
    std::vector<TreeNode> resource_tree;
    // Room order
    std::vector<int32_t> room_order;
    // Library init strings
    std::vector<std::string> library_init;
};

// Parse a complete GMK binary file
bool gmk_parse(const std::vector<uint8_t>& data, GMKProject& out);
// Serialize GMKProject to .gmk binary format
std::vector<uint8_t> gmk_serialize(const GMKProject& proj);
