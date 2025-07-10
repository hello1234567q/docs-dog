
#include "luau_executor.hpp"

typedef int (*loadbuffer_t)(void*, const char*, size_t, const char*, int);
typedef int (*pcall_t)(void*, int, int, int);

void* L = (void*)0x03500000;

auto loadbuffer = (loadbuffer_t)get_luau_loadbuffer();
auto pcall = (pcall_t)get_lua_pcall();
loadbuffer(L, "print('Hello')", 18, "@autoexec", 0);
pcall(L, 0, 0, 0);
