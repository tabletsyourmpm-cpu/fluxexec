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

// Offsets in libroblox.so
#define OFF_LUA_PUSHNUMBER  0x76a254
#define OFF_LUA_LOAD        0x76b01c  // Direct lua_load, bypass luaL_loadbuffer
#define OFF_LUA_PCALL       0x76a618

// RC7 bytecode conversion - Roblox custom opcode mapping
// Standard Lua 5.1 opcode -> Roblox opcode
static const unsigned char RBXL_OPNAMES[] = {
    0x06, // MOVE 0
    0x04, // LOADK 1
    0x00, // LOADBOOL 2
    0x07, // LOADNIL 3
    0x02, // GETUPVAL 4
    0x08, // GETGLOBAL 5
    0x01, // GETTABLE 6
    0x03, // SETGLOBAL 7
    0x05, // SETUPVAL 8
    0x0F, // SETTABLE 9
    0x0D, // NEWTABLE 10
    0x09, // SELF 11
    0x10, // ADD 12
    0x0B, // SUB 13
    0x11, // MUL 14
    0x0A, // DIV 15
    0x0C, // MOD 16
    0x0E, // POW 17
    0x18, // UNM 18
    0x16, // NOT 19
    0x12, // LEN 20
    0x19, // CONCAT 21
    0x14, // JMP 22
    0x1A, // EQ 23
    0x13, // LT 24
    0x15, // LE 25
    0x17, // TEST 26
    0x21, // TESTSET 27
    0x1F, // CALL 28
    0x1F, // TAILCALL 29
    0x22, // RETURN 30
    0x1D, // FORLOOP 31
    0x23, // FORPREP 32
    0x1C, // TFORLOOP 33
    0x1E, // SETLIST 34
    0x20, // CLOSE 35
    0x25, // CLOSURE 36
    0x24, // VARARG 37
};

// Opcode modes: 0=ABC, 1=ABx, 2=AsBx
static const unsigned char OP_MODES[] = {
    0,1,0,0,0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,2,2,0,0,0,1,0
};

static unsigned int ConvertOp(unsigned int inst) {
    unsigned int opcode = inst & 0x3F;
    if (opcode >= 38) return 0;
    unsigned int rb_opcode = RBXL_OPNAMES[opcode];
    unsigned int mode = OP_MODES[opcode];
    unsigned int A = (inst >> 6) & 0xFF;
    unsigned int result;
    if (mode == 0) { // ABC
        unsigned int B = (inst >> 23) & 0x1FF;
        unsigned int C = (inst >> 14) & 0x1FF;
        if (opcode == 0) C = 1; // MOVE special case from RC7
        // Roblox: opcode at 26, A at 18, C at 9, B at 0
        result = (rb_opcode << 26) | (A << 18) | (C << 9) | B;
    } else { // ABx/AsBx
        unsigned int Bx = (inst >> 14) & 0x3FFFF;
        // Roblox: opcode at 26, A at 18, Bx at 0
        result = (rb_opcode << 26) | (A << 18) | Bx;
    }
    return result;
}

// Varint encoding (from RC7)
static int encode_varint(unsigned long long value, unsigned char* out) {
    int len = 0;
    while (value >= 0x80) {
        out[len++] = (value & 0x7F) | 0x80;
        value >>= 7;
    }
    out[len++] = value & 0x7F;
    return len;
}

// Build a minimal Roblox bytecode chunk for the WalkSpeed script
// Based on RC7's format: 5 varints header + instructions + constants
// Returns the size, or 0 on failure
static int build_walkspeed_chunk(unsigned char* out, int out_size) {
    // Converted instructions (9 total)
    unsigned int std_instrs[9] = {
        0x00000005, 0x0040400b, 0x00008081, 0x0180801c,
        0x0040c006, 0x00410006, 0x00414006, 0x8341c009, 0x0080001e
    };
    
    // Constants: 7 strings + 1 number (59.0)
    const char* strings[7] = {"game", "GetService", "Players", "LocalPlayer", "Character", "Humanoid", "WalkSpeed"};
    
    int pos = 0;
    unsigned char varint_buf[10];
    int len;
    
    // Header: 5 varints [numparams, numupvals, num_instructions, num_constants, num_protos]
    // For main function: params=0, upvals=0, instructions=9, constants=8, protos=0
    len = encode_varint(0, varint_buf); // numparams
    if (pos + len > out_size) return 0;
    memcpy(out + pos, varint_buf, len); pos += len;
    
    len = encode_varint(0, varint_buf); // numupvals
    if (pos + len > out_size) return 0;
    memcpy(out + pos, varint_buf, len); pos += len;
    
    len = encode_varint(9, varint_buf); // num_instructions
    if (pos + len > out_size) return 0;
    memcpy(out + pos, varint_buf, len); pos += len;
    
    len = encode_varint(8, varint_buf); // num_constants
    if (pos + len > out_size) return 0;
    memcpy(out + pos, varint_buf, len); pos += len;
    
    len = encode_varint(0, varint_buf); // num_protos
    if (pos + len > out_size) return 0;
    memcpy(out + pos, varint_buf, len); pos += len;
    
    // Instructions (converted)
    for (int i = 0; i < 9; i++) {
        unsigned int converted = ConvertOp(std_instrs[i]);
        if (pos + 4 > out_size) return 0;
        // Little-endian
        out[pos++] = converted & 0xFF;
        out[pos++] = (converted >> 8) & 0xFF;
        out[pos++] = (converted >> 16) & 0xFF;
        out[pos++] = (converted >> 24) & 0xFF;
    }
    
    // Constants
    // R_LUA_TSTRING = 4, R_LUA_TNUMBER = 3
    for (int i = 0; i < 7; i++) {
        if (pos + 1 > out_size) return 0;
        out[pos++] = 4; // R_LUA_TSTRING
        int slen = strlen(strings[i]);
        len = encode_varint(slen, varint_buf);
        if (pos + len + slen > out_size) return 0;
        memcpy(out + pos, varint_buf, len); pos += len;
        memcpy(out + pos, strings[i], slen); pos += slen;
    }
    // Number 59.0
    if (pos + 1 + 8 > out_size) return 0;
    out[pos++] = 3; // R_LUA_TNUMBER
    double num = 59.0;
    memcpy(out + pos, &num, 8); pos += 8;
    
    return pos;
}

// Hardcoded WalkSpeed bytecode (standard Lua 5.1, for testing)
// game:GetService("Players").LocalPlayer.Character.Humanoid.WalkSpeed = 59
static const unsigned char walkspeed_luac[] = {
    0x1b, 0x4c, 0x75, 0x61, 0x51, 0x00, 0x01, 0x04, 0x08, 0x04, 0x08, 0x00,
    0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x2f, 0x74, 0x6d,
    0x70, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x6c, 0x75, 0x61, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x09,
    0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x0b, 0x40, 0x40, 0x00, 0x81,
    0x80, 0x00, 0x00, 0x1c, 0x80, 0x80, 0x01, 0x06, 0xc0, 0x40, 0x00, 0x06,
    0x00, 0x41, 0x00, 0x06, 0x40, 0x41, 0x00, 0x09, 0xc0, 0x41, 0x83, 0x1e,
    0x00, 0x80, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x67, 0x61, 0x6d, 0x65, 0x00, 0x04, 0x0b, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x65, 0x74, 0x53, 0x65, 0x72,
    0x76, 0x69, 0x63, 0x65, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x73, 0x00, 0x04, 0x0c,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x6f, 0x63, 0x61, 0x6c,
    0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x43, 0x68, 0x61, 0x72, 0x61, 0x63, 0x74, 0x65,
    0x72, 0x00, 0x04, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48,
    0x75, 0x6d, 0x61, 0x6e, 0x6f, 0x69, 0x64, 0x00, 0x04, 0x0a, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x61, 0x6c, 0x6b, 0x53, 0x70, 0x65,
    0x65, 0x64, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x4d, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};
static const int walkspeed_luac_len = 280;

// Function pointers
typedef int (*lua_load_fn)(lua_State* L, void* reader, void* data, const char* chunkname);
typedef int (*lua_pcall_fn)(lua_State* L, int nargs, int nresults, int errfunc);
static lua_load_fn g_load = nullptr;
static lua_pcall_fn g_pcall = nullptr;

// LoadS struct for the reader
struct LoadS { const char* s; size_t size; };

// Custom reader function (replaces getS)
static const char* my_reader(lua_State* L, void* ud, size_t* size) {
    (void)L;
    struct LoadS* ls = (struct LoadS*)ud;
    if (ls->size == 0) return NULL;
    *size = ls->size;
    ls->size = 0;
    return ls->s;
}

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
    if (g_roblox_base && (!g_load || !g_pcall)) {
        g_load = (lua_load_fn)(g_roblox_base + OFF_LUA_LOAD);
        g_pcall = (lua_pcall_fn)(g_roblox_base + OFF_LUA_PCALL);
    }
    // If there's pending code, execute it NOW on the game thread
    // Use atomic compare-and-swap to claim it
    if (__sync_bool_compare_and_swap(&g_pending, 1, 0)) {
        // Use RC7-format bytecode chunk
        if (g_load && g_pcall) {
            unsigned char chunk[1024];
            int chunk_size = build_walkspeed_chunk(chunk, sizeof(chunk));
            if (chunk_size > 0) {
                struct LoadS ls;
                ls.s = (const char*)chunk;
                ls.size = chunk_size;
                int load_status = g_load(g_L, (void*)my_reader, &ls, "walkspeed");
                if (load_status != 0) {
                    g_last_result = 1000 + load_status;
                } else {
                    int cs = g_pcall(g_L, 0, 0, 0);
                    g_last_result = cs;
                }
            } else {
                g_last_result = 1000 + 99; // Chunk build failed
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
