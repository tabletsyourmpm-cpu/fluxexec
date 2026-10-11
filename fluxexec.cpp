// libfluxexec.so - Lua state capturer via naked hook
// Naked assembly hook that captures lua_State* then restores and jumps.

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

struct lua_State;
static lua_State* g_L = nullptr;
static uintptr_t g_roblox_base = 0;
static uintptr_t g_target = 0;
static uint8_t g_orig[16];
static bool g_hooked = false;

static int phdr_cb(struct dl_phdr_info* info, size_t, void*) {
    if (info->dlpi_name && strstr(info->dlpi_name, "libroblox.so")) {
        g_roblox_base = info->dlpi_addr;
        return 1;
    }
    return 0;
}

// Naked hook: x0=L, d0=number
// Saves L to g_L, restores original bytes, jumps to target
__attribute__((naked)) static void naked_hook() {
    __asm__ volatile (
        "stp x16, x17, [sp, #-16]!\n"
        "adrp x16, g_L\n"
        "add x16, x16, :lo12:g_L\n"
        "ldr x17, [x16]\n"
        "cbnz x17, 1f\n"
        "str x0, [x16]\n"
        "1:\n"
        "adrp x16, g_target\n"
        "add x16, x16, :lo12:g_target\n"
        "ldr x16, [x16]\n"
        "adrp x17, g_orig\n"
        "add x17, x17, :lo12:g_orig\n"
        "ldp x2, x3, [x17]\n"
        "stp x2, x3, [x16]\n"
        "ldp x2, x3, [x17, #8]\n"
        "stp x2, x3, [x16, #8]\n"
        // Invalidate instruction cache for the restored region
        "ic ivau, x16\n"
        "dsb ish\n"
        "isb\n"
        // Restore stack and jump to original
        "ldp x16, x17, [sp], #16\n"
        "adrp x16, g_target\n"
        "add x16, x16, :lo12:g_target\n"
        "ldr x16, [x16]\n"
        "br x16\n"
    );
}

static bool install_hook(uintptr_t target) {
    uintptr_t page = target & ~0xFFFUL;
    if (mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE) != 0) return false;
    
    // Verify bytes
    uint8_t* p = (uint8_t*)target;
    if (p[0] != 0x02 || p[1] != 0x10 || p[2] != 0x40 || p[3] != 0xF9) {
        mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC);
        return false;
    }
    
    memcpy(g_orig, (void*)target, 16);
    g_target = target;
    
    // Write hook stub (16 bytes):
    // 0x00: ldr x16, #12  (loads from PC+12 = 0x0C, 8-byte aligned)
    // 0x04: br x16
    // 0x08: nop (padding)
    // 0x0C: .quad naked_hook
    uint32_t* ip = (uint32_t*)target;
    ip[0] = 0x58000060;
    ip[1] = 0xD61F0200;
    ip[2] = 0xD503201F;
    *(uintptr_t*)(ip + 3) = (uintptr_t)naked_hook;
    
    mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)target, (char*)(target + 16));
    g_hooked = true;
    LOGI("Naked hook installed at %p", (void*)target);
    return true;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_better16_executor_OverlayService_nativeExecute(JNIEnv* env, jobject, jstring jcode) {
    const char* code = env->GetStringUTFChars(jcode, nullptr);
    std::string result;
    
    if (g_L) {
        result = "[fluxexec] Have lua_State*!";
    } else {
        dl_iterate_phdr(phdr_cb, nullptr);
        if (!g_roblox_base) {
            result = "[fluxexec] libroblox not found";
        } else if (!g_hooked) {
            uintptr_t target = g_roblox_base + 0x76a254;
            if (install_hook(target)) {
                result = "[fluxexec] Hook installed, waiting for call...";
            } else {
                result = "[fluxexec] Hook failed";
            }
        } else {
            result = "[fluxexec] Hook active, waiting...";
        }
    }
    
    env->ReleaseStringUTFChars(jcode, code);
    return env->NewStringUTF(result.c_str());
}

__attribute__((constructor)) static void init() {
    LOGI("libfluxexec naked hook loaded");
}
