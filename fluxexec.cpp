// libfluxexec.so - Hook inlines original instructions, returns normally
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

static int phdr_cb(struct dl_phdr_info* info, size_t, void*) {
    if (info->dlpi_name && strstr(info->dlpi_name, "libroblox.so")) {
        g_roblox_base = info->dlpi_addr;
        return 1;
    }
    return 0;
}

// Hook: capture L, then manually execute the 8 original instructions
// Original at 0x76a254:
//   ldr x2, [x0, #0x20]
//   mov w3, #2
//   str d0, [x2]
//   ldr x1, [x0, #0x20]
//   str w3, [x2, #8]
//   add x1, x1, #0x10
//   str x1, [x0, #0x20]
//   ret
void hook_lua_pushnumber(lua_State* L, double n) {
    if (!g_L) {
        g_L = L;
        LOGI("Captured lua_State*=%p", (void*)L);
    }
    // Manually execute the original 8 instructions using inline asm
    // x0=L (already), d0=n (already)
    // We use x1, x2, x3 as scratch (caller-saved, safe)
    __asm__ volatile(
        "ldr x2, [x0, #0x20]\n"
        "mov w3, #2\n"
        "str d0, [x2]\n"
        "ldr x1, [x0, #0x20]\n"
        "str w3, [x2, #8]\n"
        "add x1, x1, #0x10\n"
        "str x1, [x0, #0x20]\n"
        ::: "x1", "x2", "x3", "memory"
    );
    // Return normally - C epilogue handles stack correctly
    // The hook stays installed; subsequent calls will also be intercepted
    // but that's fine (we already have g_L, just re-execute)
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
    ip[0] = 0x58000060; // ldr x16, #12
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
