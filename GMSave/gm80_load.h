// GM80 multi-file load — direct Delphi object creation
#pragma once
#include <filesystem>
#include <set>
#include <string>
namespace fs = std::filesystem;

// Direct Delphi object creation (covers scripts, fonts, triggers, settings, etc.)
// gm_base: GetModuleHandle(NULL) of GameMaker.exe
bool gm80_load_project(void* gm_base, const std::wstring& path);

// ==== Instance code-hash map (gm82save model) ====
// instances.txt's 4th column is a stable 8-hex "hash" that names the instance's
// creation-code file. The instance ID itself is GM's counter-based value and is
// NOT serialized. The map (id → hash) is filled on load from the file and
// consulted/extended on save, so the hash column never changes just because the
// project was re-saved (git-friendly).
void gm80_instance_hashes_clear();
const std::string* gm80_instance_hash_get(int32_t id);
void gm80_instance_hash_set(int32_t id, const std::string& hash);
// Collect all current hashes (for uniqueness checks when generating new ones).
void gm80_instance_hashes_collect(std::set<std::string>& out);

// Is a code-hash usable as a file name (safe path chars, sane length)?
// Rejects malformed/foreign hashes so a bad one never reaches CreateFileW.
bool gm80_valid_code_hash(const std::string& h);
