
#pragma once
#include <cstdint>
#include <cstring>

#define PATTERN_LOADBUFFER      "\x2D\xE9\xF0\x4F\xAD\xF5\x00\x00"
#define MASK_LOADBUFFER         "xxxxxxxx"

#define PATTERN_PCALL           "\x10\xB5\x04\x1C\x00\x22"
#define MASK_PCALL              "xxxxxx"

#define PATTERN_HTTPGET         "\xF0\xB5\x04\x1C\x00\x22"
#define MASK_HTTPGET            "xxxxxx"

#define PATTERN_HTTPGETASYNC    "\x2D\xE9\xF0\x4F\xAD\xF5\x00\x00"
#define MASK_HTTPGETASYNC       "xxxxxxxx"

#define LUAU_LOADBUFFER_OFFSET   0x001B9214
#define LUA_PCALL_OFFSET         0x001B84F8
#define LUA_NEWTHREAD_OFFSET     0x001B90D0
#define LUA_RESUME_OFFSET        0x001B875C

#define HTTPGET_OFFSET           0x001A5F90
#define HTTPGETASYNC_OFFSET      0x001A60C0

#define USE_PATTERN_SCAN false

inline uintptr_t pattern_scan(const uint8_t* base, size_t size, const char* pattern, const char* mask) {
    size_t len = strlen(mask);
    for (size_t i = 0; i <= size - len; i++) {
        bool found = true;
        for (size_t j = 0; j < len; j++) {
            if (mask[j] != '?' && pattern[j] != base[i + j]) {
                found = false;
                break;
            }
        }
        if (found)
            return (uintptr_t)(base + i);
    }
    return 0;
}

inline uintptr_t get_luau_loadbuffer(const uint8_t* base = nullptr, size_t size = 0) {
#if USE_PATTERN_SCAN
    return pattern_scan(base, size, PATTERN_LOADBUFFER, MASK_LOADBUFFER);
#else
    return LUAU_LOADBUFFER_OFFSET;
#endif
}

inline uintptr_t get_lua_pcall(const uint8_t* base = nullptr, size_t size = 0) {
#if USE_PATTERN_SCAN
    return pattern_scan(base, size, PATTERN_PCALL, MASK_PCALL);
#else
    return LUA_PCALL_OFFSET;
#endif
}

inline uintptr_t get_httpget(const uint8_t* base = nullptr, size_t size = 0) {
#if USE_PATTERN_SCAN
    return pattern_scan(base, size, PATTERN_HTTPGET, MASK_HTTPGET);
#else
    return HTTPGET_OFFSET;
#endif
}

inline uintptr_t get_httpgetasync(const uint8_t* base = nullptr, size_t size = 0) {
#if USE_PATTERN_SCAN
    return pattern_scan(base, size, PATTERN_HTTPGETASYNC, MASK_HTTPGETASYNC);
#else
    return HTTPGETASYNC_OFFSET;
#endif
}
