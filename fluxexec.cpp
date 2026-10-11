// libfluxexec.so - Simple C hook, jumps to original after capture
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

// C hook: captures L, restores bytes, jumps to original
void hook_lua_pushnumber(lua_State* L, double n) {
    if (!g_L) {
        g_L = L;
        LOGI("Captured lua_State*=%p", (void*)L);
    }
    // Restore original bytes
    uintptr_t page = g_target & ~0xFFFUL;
    mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE);
    memcpy((void*)g_target, g_orig, 16);
    mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)g_target, (char*)(g_target + 16));
    g_hooked = false;
    LOGI("Hook removed, jumping to original");
    // Jump to original (tail call) - does not return here
    __asm__ volatile("br %0" :: "r"(g_target));
    __builtin_unreachable();
}

static bool install_hook(uintptr_t target) {
    uintptr_t page = target & ~0xFFFUL;
    if (mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE) != 0) return false;
    uint8_t* p = (uint8_t*)target;
    if (p[0] != 0x02 || p[1] != 0x10 || p[2] != 0x40 || p[3] != 0xF9) {
        mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC);
        return false;
    }
    memcpy(g_orig, (void*)target, 16);
    g_target = target;
    uint32_t* ip = (uint32_t*)target;
    ip[0] = 0x58000060; // ldr x16, #12
    ip[1] = 0xD61F0200; // br x16
    ip[2] = 0xD503201F; // nop
    *(uintptr_t*)(ip + 3) = (uintptr_t)hook_lua_pushnumber;
    mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)target, (char*)(target + 16));
    g_hooked = true;
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
            if (install_hook(g_roblox_base + 0x76a254)) {
                result = "[fluxexec] Hook installed";
            } else {
                result = "[fluxexec] Hook failed";
            }
        } else {
            result = "[fluxexec] Waiting...";
        }
    }
    env->ReleaseStringUTFChars(jcode, code);
    return env->NewStringUTF(result.c_str());
}

__attribute__((constructor)) static void init() {
    LOGI("libfluxexec loaded");
}
