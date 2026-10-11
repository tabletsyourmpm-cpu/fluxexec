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

#define LOG_TAG "FluxExec"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

struct lua_State; // opaque

static lua_State* g_L = nullptr;
static uintptr_t g_roblox_base = 0;

// Original lua_pushnumber bytes (16 bytes = 4 instructions)
static uint8_t g_orig_bytes[16];
static uintptr_t g_hook_addr = 0;

// Our hook function - called instead of lua_pushnumber
// x0 = L (lua_State*), d0 = number
extern "C" void hook_lua_pushnumber(lua_State* L, double n) {
    if (!g_L) {
        g_L = L;
        LOGI("Captured lua_State* = %p", (void*)L);
    }
    // Call original: we need to execute the saved instructions
    // For now, just log (TODO: implement trampoline)
    LOGI("lua_pushnumber called with L=%p, n=%f", (void*)L, n);
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
    // ARM64: we need to overwrite with a branch to our hook
    // Simplest: LDR x16, #8; BR x16; <8-byte addr>
    // That's 16 bytes (4 instructions)
    
    uintptr_t page = target_addr & ~(0xFFF);
    if (mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect failed");
        return false;
    }
    
    // Save original
    memcpy(g_orig_bytes, (void*)target_addr, 16);
    g_hook_addr = target_addr;
    
    // Write: ldr x16, #8; br x16; .quad hook_addr
    uint32_t* p = (uint32_t*)target_addr;
    p[0] = 0x58000050; // ldr x16, #8 (PC+8)
    p[1] = 0xD61F0200; // br x16
    *(uintptr_t*)(p + 2) = (uintptr_t)hook_lua_pushnumber;
    
    __builtin___clear_cache((char*)target_addr, (char*)(target_addr + 16));
    LOGI("Hook installed at %p", (void*)target_addr);
    return true;
}

static bool resolve() {
    if (g_L) return true;
    dl_iterate_phdr(phdr_cb, nullptr);
    if (!g_roblox_base) return false;
    
    // lua_pushnumber at file offset 0x76a254
    // At runtime: base + 0x76a254 (if base is 0, else base + offset)
    // Actually, the file offset != vaddr if PIE. Use dladdr to get actual.
    // For now, assume base+offset (libroblox.so is likely non-PIE or we get base from phdr)
    uintptr_t target = g_roblox_base + 0x76a254;
    LOGI("Hooking lua_pushnumber at %p (base %p)", (void*)target, (void*)g_roblox_base);
    
    return install_hook(target);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_better16_executor_OverlayService_nativeExecute(JNIEnv* env, jobject, jstring jcode) {
    const char* code = env->GetStringUTFChars(jcode, nullptr);
    std::string result;
    
    if (!resolve()) {
        result = "[fluxexec] Hook not installed";
    } else if (!g_L) {
        result = "[fluxexec] Waiting for lua_State* (play the game, trigger a push)";
        LOGI("Hook active, waiting for game to call lua_pushnumber...");
    } else {
        result = "[fluxexec] Got lua_State*! Now need luaL_loadstring+lua_pcall addresses.";
        LOGI("Have state %p, need API addresses", (void*)g_L);
    }
    
    env->ReleaseStringUTFChars(jcode, code);
    return env->NewStringUTF(result.c_str());
}

__attribute__((constructor)) static void init() {
    LOGI("libfluxexec hook loaded");
    resolve();
}
