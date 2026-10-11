// libfluxexec.so - Lua state capturer via inline hook
// Hooks lua_pushnumber to capture the lua_State*.

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
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

struct lua_State; // opaque

static lua_State* g_L = nullptr;
static uintptr_t g_roblox_base = 0;

// Original lua_pushnumber bytes (16 bytes = 4 instructions)
static uint8_t g_orig_bytes[16];
static uintptr_t g_hook_addr = 0;
static void* g_trampoline = nullptr;

// Our hook function - called instead of lua_pushnumber
// x0 = L (lua_State*), d0 = number
extern "C" void hook_lua_pushnumber(lua_State* L, double n) {
    if (!g_L) {
        g_L = L;
        LOGI("Captured lua_State* = %p", (void*)L);
    }
    // Call original via trampoline
    if (g_trampoline) {
        typedef void (*orig_fn)(lua_State*, double);
        ((orig_fn)g_trampoline)(L, n);
    }
}

static int phdr_cb(struct dl_phdr_info* info, size_t, void*) {
    if (info->dlpi_name && strstr(info->dlpi_name, "libroblox.so")) {
        g_roblox_base = info->dlpi_addr;
        return 1;
    }
    return 0;
}

// Install inline hook at target_addr
static bool install_hook(uintptr_t target_addr) {
    uintptr_t page = target_addr & ~(0xFFF);
    // W^X: first make writable (no exec), then after writing, make exec (no write)
    if (mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE) != 0) {
        LOGE("mprotect RW failed: %d", errno);
        return false;
    }
    
    // Save original
    memcpy(g_orig_bytes, (void*)target_addr, 16);
    g_hook_addr = target_addr;
    
    // Build trampoline: mmap RW, copy, then mprotect to RX
    g_trampoline = mmap(NULL, 32, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_trampoline == MAP_FAILED) {
        LOGE("mmap failed");
        mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC);
        return false;
    }
    memcpy(g_trampoline, g_orig_bytes, 16);
    uintptr_t tramp_addr = (uintptr_t)g_trampoline;
    int64_t offset = (int64_t)(target_addr + 16) - (int64_t)(tramp_addr + 16);
    uint32_t br_insn = 0x14000000 | ((uint32_t)((offset >> 2) & 0x3FFFFFF));
    ((uint32_t*)g_trampoline)[4] = br_insn;
    // Make trampoline executable (remove write)
    mprotect(g_trampoline, 32, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)g_trampoline, (char*)g_trampoline + 20);
    
    // Write hook: ldr x16, #8; br x16; .quad hook_addr
    uint32_t* p = (uint32_t*)target_addr;
    p[0] = 0x58000050; // ldr x16, #8
    p[1] = 0xD61F0200; // br x16
    *(uintptr_t*)(p + 2) = (uintptr_t)hook_lua_pushnumber;
    
    // Make target executable again (remove write), clear cache
    mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)target_addr, (char*)(target_addr + 16));
    LOGI("Hook installed at %p with trampoline %p", (void*)target_addr, g_trampoline);
    return true;
}

static bool resolve() {
    if (g_L) return true;
    dl_iterate_phdr(phdr_cb, nullptr);
    if (!g_roblox_base) {
        LOGE("libroblox.so not found");
        return false;
    }
    uintptr_t target = g_roblox_base + 0x76a254;
    LOGI("Target lua_pushnumber at %p", (void*)target);
    
    // SAFETY: verify the bytes match expected (ldr x2, [x0, #0x20] = 02 10 40 F9)
    uint8_t* p = (uint8_t*)target;
    if (p[0] != 0x02 || p[1] != 0x10 || p[2] != 0x40 || p[3] != 0xF9) {
        LOGE("Byte verification failed at %p: %02x %02x %02x %02x",
             (void*)target, p[0], p[1], p[2], p[3]);
        return false;
    }
    LOGI("Bytes verified, installing hook...");
    
    return install_hook(target);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_better16_executor_OverlayService_nativeExecute(JNIEnv* env, jobject, jstring jcode) {
    const char* code = env->GetStringUTFChars(jcode, nullptr);
    std::string result;
    
    if (!resolve()) {
        result = "[fluxexec] Hook not installed (see logcat)";
    } else if (!g_L) {
        result = "[fluxexec] Hook active, waiting for lua_State*...";
        LOGI("Hook installed, waiting for game to call lua_pushnumber...");
    } else {
        result = "[fluxexec] Got lua_State*! Need pcall+loadstring.";
        LOGI("Have state %p", (void*)g_L);
    }
    
    env->ReleaseStringUTFChars(jcode, code);
    return env->NewStringUTF(result.c_str());
}

__attribute__((constructor)) static void init() {
    LOGI("libfluxexec loaded (hook on-demand only)");
    // Don't auto-install hook - wait for nativeExecute when libroblox.so is confirmed loaded
}
