// Delphi FFI layer for interacting with GameMaker 8.0 IDE internals.
// GM 8.0 is a Delphi 7 application. This header provides helpers for
// calling Delphi VCL methods, reading Delphi string types, and
// manipulating Delphi objects from C++.
#pragma once
#include <windows.h>
#include <oleauto.h>

// Delphi UStr (UnicodeString / WideString in Delphi 7)
// In Delphi 7, strings are AnsiString by default. WideString is used
// for Unicode. Layout: [refcount:4][length:4][data:wchar_t[]]
struct DelphiString
{
    uint32_t refcount; // -1 = constant, 0+ = mutable with refcount
    uint32_t length; // character count (not bytes)
    wchar_t data[1]; // null-terminated UTF-16 data
};

// Delphi AnsiString — GM 8.0 uses this primarily
struct DelphiAnsiString
{
    int32_t refcount; // -1 = constant, 0+ = mutable
    uint32_t length; // byte count (not including null)
    char data[1]; // null-terminated data
};

// Delphi TObject base layout
struct DelphiObject
{
    void* vtable;
};

// Delphi TList / array wrapper
// Layout: [vtable:4][items:4][count:4][capacity:4]
struct DelphiList
{
    void* vtable;
    void** items;
    uint32_t count;
    uint32_t capacity;
};

// Delphi TBitmap — used for sprites/backgrounds
struct DelphiBitmap
{
    void* vtable;
    // ... many fields ...
    uint32_t width;
    uint32_t height;
    void* scanline;
    uint32_t pixelFormat;
};

// Delphi TMemoryStream
// Layout: vtable:4, memory:4, size:4, position:4, capacity:4
struct DelphiMemoryStream
{
    void* vtable;
    void* memory;
    uint32_t size;
    uint32_t position;
    uint32_t capacity;
};

// Delphi TTreeNode data
struct DelphiTreeNodeData
{
    uint32_t unknown;
    uint32_t rtype; // 2=folder, 3=leaf
    uint32_t kind; // resource type
    uint32_t index; // resource index
};

struct DelphiTreeNode
{
    void* vtable;
    uint32_t f1, f2; // padding
    char* name; // AnsiString data pointer
    DelphiTreeNodeData* data;
};

struct DelphiTreeNodes
{
    void* vtable;
};

struct DelphiTreeView
{
    uint8_t padding[0x6c];
    uint8_t color[3];
    uint8_t padding2[0x269];
    DelphiTreeNodes* nodes;
};

// ---- Delphi __fastcall helpers ----
// Delphi register calling convention: eax=arg1, edx=arg2, ecx=arg3, stack=rest
// Returns eax as uint32_t
inline uint32_t delphi_fastcall_0(void* func)
{
    uint32_t result;
    __asm {
        call func
        mov result, eax
    }
    return result;
}

inline uint32_t delphi_fastcall_1(void* func, uint32_t a1)
{
    uint32_t result;
    __asm {
        mov eax, a1
        call func
        mov result, eax
    }
    return result;
}

inline uint32_t delphi_fastcall_2(void* func, uint32_t a1, uint32_t a2)
{
    uint32_t result;
    __asm {
        mov eax, a1
        mov edx, a2
        call func
        mov result, eax
    }
    return result;
}

inline uint32_t delphi_fastcall_3(void* func, uint32_t a1, uint32_t a2, uint32_t a3)
{
    uint32_t result;
    __asm {
        mov eax, a1
        mov edx, a2
        mov ecx, a3
        call func
        mov result, eax
    }
    return result;
}

// Construct a Delphi object: calls constructor with (class_ref, 1)
// eax = class_ref (VMT pointer), edx = 1 (allocate flag)
// Returns pointer to new object
inline void* delphi_construct(uint32_t class_ref, void* constructor)
{
    uint32_t result;
    uint32_t ctor_addr = (uint32_t)constructor;
    __asm {
        mov eax, class_ref
        mov edx, 1
        call ctor_addr
        mov result, eax
    }
    return (void*)result;
}

// ---- Delphi TList helper ----

// Resize a Delphi TList-like container to hold `count` items
// Calls list->vtable method for SetCount/Capacity
inline void delphi_list_set_count(void* list, uint32_t count)
{
    if (!list) return;
    DelphiList* dl = (DelphiList*)list;
    uint32_t oldCount = dl->count;
    dl->count = count;
    if (count > dl->capacity)
    {
        // Grow: reallocate items array
        uint32_t newCap = count * 2;
        void** newItems = (void**)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, newCap * sizeof(void*));
        if (dl->items && oldCount > 0)
            memcpy(newItems, dl->items, oldCount * sizeof(void*));
        if (dl->items) HeapFree(GetProcessHeap(), 0, dl->items);
        dl->items = newItems;
        dl->capacity = newCap;
    }
}

// ---- Memory patch helpers ----
inline void patch_bytes(void* addr, const uint8_t* bytes, size_t len)
{
    DWORD old;
    VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old);
    memcpy(addr, bytes, len);
    VirtualProtect(addr, len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
}

inline void patch_call(void* addr, void* target)
{
    uint8_t code[5] = {0xE8}; // CALL rel32
    int32_t rel = (int32_t)((uint8_t*)target - (uint8_t*)addr - 5);
    memcpy(code + 1, &rel, 4);
    patch_bytes(addr, code, 5);
}

inline void patch_jmp(void* addr, void* target)
{
    uint8_t code[5] = {0xE9}; // JMP rel32
    int32_t rel = (int32_t)((uint8_t*)target - (uint8_t*)addr - 5);
    memcpy(code + 1, &rel, 4);
    patch_bytes(addr, code, 5);
}

// ---- Object field reading helpers ----
// These read directly from Delphi object memory at given byte offset

inline uint32_t obj_u32(void* obj, int off)
{
    return *(uint32_t*)((uint8_t*)obj + off);
}
inline int32_t obj_i32(void* obj, int off)
{
    return *(int32_t*)((uint8_t*)obj + off);
}
inline bool obj_bool(void* obj, int off)
{
    return *(uint8_t*)((uint8_t*)obj + off) != 0;
}
inline double obj_f64(void* obj, int off)
{
    return *(double*)((uint8_t*)obj + off);
}
// Read Delphi AnsiString from object field (pointer to string data)
inline std::string obj_str_val(void* obj, int off)
{
    if (!obj || (uintptr_t)obj < 0x10000) return "";
    char** pp = (char**)((uint8_t*)obj + off);
    char* data = *pp;
    if (!data) return "";
    if ((uintptr_t)data < 0x10000) return "";
    uint32_t len = (uint32_t)*(int32_t*)(data - 4);
    if (len == 0) return "";
    if (len > 2000000) return std::string(data);
    return std::string(data, len);
}

// Read raw pointer from object field
inline void* obj_ptr(void* obj, int off)
{
    return *(void**)((uint8_t*)obj + off);
}

// Read DelphiList from object field
inline DelphiList* obj_list(void* obj, int off)
{
    return (DelphiList*)((uint8_t*)obj + off);
}

// ---- Global reading helpers ----
inline uint32_t glob_u32(void* base, uint32_t off)
{
    return *(uint32_t*)((uint8_t*)base + off);
}
inline uint8_t glob_u8(void* base, uint32_t off)
{
    return *(uint8_t*)((uint8_t*)base + off);
}
inline void* glob_ptr(void* base, uint32_t off)
{
    return *(void**)((uint8_t*)base + off);
}
inline DelphiList* glob_list(void* base, uint32_t off)
{
    return *(DelphiList**)((uint8_t*)base + off);
}

// Resource tree nodes (root level)
#define RT_SPRITES 0
#define RT_SOUNDS 1
#define RT_BACKGROUNDS 2
#define RT_PATHS 3
#define RT_SCRIPTS 4
#define RT_FONTS 5
#define RT_TIMELINES 6
#define RT_OBJECTS 7
#define RT_ROOMS 8
#define RT_GAME_INFO 9
#define RT_SETTINGS 10
#define RT_EXTENSIONS 11
