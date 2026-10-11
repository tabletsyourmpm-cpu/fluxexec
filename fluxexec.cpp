// libfluxexec.so - Full Lua executor
// Hooks lua_pushnumber to capture lua_State*, then executes via luaL_loadbuffer + lua_pcall

#include <jni.h>
#include <dlfcn.h>
#include <android/log.h>
#include <string>
#include <cstdint>
#include <link.h>
#include <cstring>
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#define LOG_TAG "FluxExec"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

struct lua_State;
static lua_State* g_L = nullptr;
static uintptr_t g_roblox_base = 0;
static bool g_hooked = false;

// Pending execution - use atomic flag for synchronization
static char g_pending_code[4096];
static volatile int g_pending = 0; // 0=none, 1=ready (atomic)
static int g_last_result = -999;

// Offsets in libroblox.so (file offsets = vaddr offsets)
#define OFF_LUA_PUSHNUMBER  0x76a254
#define OFF_LUA_L_LOADBUFFER 0x7694b4  // Real one (0x769460 was the modified stub)
#define OFF_LUA_PCALL       0x76a618

// Function pointers (resolved at runtime)
typedef int (*luaL_loadbuffer_fn)(lua_State* L, const char* buff, size_t size, const char* name);
typedef int (*lua_pcall_fn)(lua_State* L, int nargs, int nresults, int errfunc);
static luaL_loadbuffer_fn g_loadbuffer = nullptr;
static lua_pcall_fn g_pcall = nullptr;

static int phdr_cb(struct dl_phdr_info* info, size_t, void*) {
    if (info->dlpi_name && strstr(info->dlpi_name, "libroblox.so")) {
        g_roblox_base = info->dlpi_addr;
        return 1;
    }
    return 0;
}

void hook_lua_pushnumber(lua_State* L, double n) {
    lua_State* saved_L;
    double saved_n;
    __asm__ volatile(
        "mov %0, x0\n"
        "fmov %d1, d0\n"
        : "=r"(saved_L), "=w"(saved_n) : : );
    // Always update g_L (not just first time) - the state changes per game session!
    // Also re-resolve function pointers in case base changed (shouldn't, but safe)
    g_L = saved_L;
    if (g_roblox_base && (!g_loadbuffer || !g_pcall)) {
        g_loadbuffer = (luaL_loadbuffer_fn)(g_roblox_base + OFF_LUA_L_LOADBUFFER);
        g_pcall = (lua_pcall_fn)(g_roblox_base + OFF_LUA_PCALL);
    }
    // If there's pending code, execute it NOW on the game thread
    // Use atomic compare-and-swap to claim it
    if (__sync_bool_compare_and_swap(&g_pending, 1, 0)) {
        // We claimed it. Copy to local stack buffer for safety.
        char local_code[4096];
        size_t len = strlen(g_pending_code);
        if (len < sizeof(local_code)) {
            memcpy(local_code, g_pending_code, len + 1);
            if (g_loadbuffer && g_pcall) {
                int ls = g_loadbuffer(g_L, local_code, len, "fluxexec");
                if (ls != 0) {
                    g_last_result = 1000 + ls;
                } else {
                    int cs = g_pcall(g_L, 0, 0, 0);
                    g_last_result = cs;
                }
            }
        }
    }
    __asm__ volatile(
        "ldr x2, [%0, #0x20]\n"
        "mov w3, #2\n"
        "str %d1, [x2]\n"
        "ldr x1, [%0, #0x20]\n"
        "str w3, [x2, #8]\n"
        "add x1, x1, #0x10\n"
        "str x1, [%0, #0x20]\n"
        :: "r"(saved_L), "w"(saved_n)
        : "x1", "x2", "x3", "memory"
    );
}

static bool install_hook(uintptr_t target) {
    uintptr_t page = target & ~0xFFFUL;
    if (mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE) != 0) return false;
    uint8_t* p = (uint8_t*)target;
    if (p[0] != 0x02 || p[1] != 0x10 || p[2] != 0x40 || p[3] != 0xF9) {
        mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC);
        return false;
    }
    uint32_t* ip = (uint32_t*)target;
    ip[0] = 0x58000070; // ldr x16, #12
    ip[1] = 0xD61F0200; // br x16
    ip[2] = 0xD503201F; // nop
    *(uintptr_t*)(ip + 3) = (uintptr_t)hook_lua_pushnumber;
    mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)target, (char*)(target + 16));
    g_hooked = true;
    LOGI("Hook installed at %p", (void*)target);
    return true;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_better16_executor_OverlayService_nativeExecute(JNIEnv* env, jobject, jstring jcode) {
    const char* code = env->GetStringUTFChars(jcode, nullptr);
    size_t code_len = strlen(code);
    std::string result;

    dl_iterate_phdr(phdr_cb, nullptr);
    if (!g_roblox_base) {
        result = "[fluxexec] libroblox not found";
    } else if (!g_L) {
        if (!g_hooked) {
            if (install_hook(g_roblox_base + OFF_LUA_PUSHNUMBER)) {
                result = "[fluxexec] Hook installed, waiting for lua_State*...";
            } else {
                result = "[fluxexec] Hook install failed";
            }
        } else {
            result = "[fluxexec] Waiting for lua_State*...";
        }
    } else {
        // Have state. Queue code for game-thread execution.
        int pending = __sync_fetch_and_add(&g_pending, 0); // atomic read
        if (pending) {
            result = "[fluxexec] Busy, wait...";
        } else if (g_last_result != -999) {
            if (g_last_result == 0) result = "[fluxexec] Executed OK";
            else if (g_last_result >= 1000) result = "[fluxexec] Load error: " + std::to_string(g_last_result - 1000);
            else result = "[fluxexec] Pcall error: " + std::to_string(g_last_result);
            g_last_result = -999;
        } else if (code_len < sizeof(g_pending_code) - 1) {
            memcpy(g_pending_code, code, code_len);
            g_pending_code[code_len] = '\0';
            __sync_synchronize();
            __sync_lock_test_and_set(&g_pending, 1); // atomic set
            result = "[fluxexec] Queued, press Execute again for result";
        } else {
            result = "[fluxexec] Code too long";
        }
    }

    env->ReleaseStringUTFChars(jcode, code);
    return env->NewStringUTF(result.c_str());
}

__attribute__((constructor)) static void init() {
    LOGI("libfluxexec loaded");
}
