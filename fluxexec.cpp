// libfluxexec.so - Flux Executor native bridge for Better16 (2016 Roblox client)
// Built against 2016 source refs (Aya). Does NOT modify libroblox.so.
//
// Execution path (from 2016 source):
//   LogService::executeServerScript (DataModel/LogService.cpp:360)
//     -> ScriptContext::executeInNewThread (Script/ScriptContext.cpp:1346)
//        -> luaL_loadstring + lua_pcall on the ScriptContext's lua_State*
//
// We pattern-scan for ScriptContext::executeInNewThread in libroblox.so
// and call it directly with (GameScript identity, source, "console").
//
// Java side (OverlayService):
//   static { System.loadLibrary("fluxexec"); }
//   private native String nativeExecute(String code);
//
// Build (NDK r25+, ARM64):
//   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang++ \
//     -shared -fPIC -O2 -o libfluxexec.so fluxexec.cpp -ldl -llog

#include <jni.h>
#include <dlfcn.h>
#include <android/log.h>
#include <string>
#include <cstdint>

#define LOG_TAG "FluxExec"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Lua C API types (from 2016 source: lua.h, luaux.h)
// We resolve these at runtime via pattern scanning since libroblox.so
// hides its symbols (no dynamic exports for lua_*).
// ---------------------------------------------------------------------------
struct lua_State; // opaque

typedef int (*luaL_loadstring_fn)(lua_State* L, const char* s);
typedef int (*lua_pcall_fn)(lua_State* L, int nargs, int nresults, int errfunc);
typedef const char* (*lua_tolstring_fn)(lua_State* L, int idx, size_t* len);
typedef void (*lua_settop_fn)(lua_State* L, int idx);

static luaL_loadstring_fn p_luaL_loadstring = nullptr;
static lua_pcall_fn       p_lua_pcall       = nullptr;
static lua_tolstring_fn   p_lua_tolstring   = nullptr;
static lua_settop_fn      p_lua_settop      = nullptr;
static lua_State*         g_L               = nullptr;

// ---------------------------------------------------------------------------
// Pattern scan libroblox.so for the Lua API.
// The 2016 source gives us the function bodies; we match distinctive
// instruction sequences. Patterns are filled in after dumping the
// actual libroblox.so from the Better16 APK.
// ---------------------------------------------------------------------------
static uintptr_t find_pattern(uintptr_t base, size_t size,
                              const uint8_t* pat, const char* mask) {
    size_t plen = 0;
    while (mask[plen]) plen++;
    for (size_t i = 0; i + plen <= size; i++) {
        bool ok = true;
        for (size_t j = 0; j < plen; j++) {
            if (mask[j] == 'x' && ((uint8_t*)(base + i))[j] != pat[j]) { ok = false; break; }
        }
        if (ok) return base + i;
    }
    return 0;
}

// TODO: fill these from the real libroblox.so (Better16 ARM64 build).
// Dump with: llvm-objdump -d libroblox.so | grep -A30 "<luaL_loadstring>:"
// then convert the prologue bytes to a pattern.
static bool resolve_lua_api() {
    if (p_luaL_loadstring) return true; // already resolved

    void* h = dlopen("libroblox.so", RTLD_NOLOAD);
    if (!h) { LOGE("libroblox.so not loaded"); return false; }

    // TODO: implement find_pattern over the .text segment and set:
    //   p_luaL_loadstring, p_lua_pcall, p_lua_tolstring, p_lua_settop
    // TODO: locate the global ScriptContext -> lua_State* (see 2016
    //   source: RBX::ScriptContext::getGlobalState or the DataModel's
    //   script context singleton).

    LOGE("resolve_lua_api: patterns not yet filled in for this build");
    return false;
}

// ---------------------------------------------------------------------------
// JNI entry point called from OverlayService.execute button.
// Returns the script's output or an error string for display.
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_better16_executor_OverlayService_nativeExecute(
        JNIEnv* env, jobject /*thiz*/, jstring jcode) {
    const char* code = env->GetStringUTFChars(jcode, nullptr);
    std::string result;

    if (!resolve_lua_api() || !g_L) {
        result = "[fluxexec] Lua API not resolved yet (patterns pending)";
        LOGE("%s", result.c_str());
    } else {
        // Load the chunk
        int status = p_luaL_loadstring(g_L, code);
        if (status != 0) {
            size_t len = 0;
            const char* err = p_lua_tolstring(g_L, -1, &len);
            result = std::string("[load error] ") + (err ? std::string(err, len) : "?");
            p_lua_settop(g_L, 0);
        } else {
            // Run it
            status = p_lua_pcall(g_L, 0, 0, 0);
            if (status != 0) {
                size_t len = 0;
                const char* err = p_lua_tolstring(g_L, -1, &len);
                result = std::string("[run error] ") + (err ? std::string(err, len) : "?");
                p_lua_settop(g_L, 0);
            } else {
                result = "[executed OK]";
            }
        }
    }

    env->ReleaseStringUTFChars(jcode, code);
    return env->NewStringUTF(result.c_str());
}

// Run on library load: try to resolve early so the first Execute is fast.
__attribute__((constructor)) static void fluxexec_init() {
    LOGI("libfluxexec loaded, resolving Lua API...");
    resolve_lua_api();
}
