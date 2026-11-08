#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>

#define LOGFILE "/storage/emulated/0/antipause_log.txt"

static void logf(const char* fmt, ...) {
    FILE* f = fopen(LOGFILE, "a");
    if (!f) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static uintptr_t sym(void* h, const char* name) {
    void* p = dlsym(h, name);
    if (!p) return 0;
    return (uintptr_t)p & ~(uintptr_t)1;
}

static void patch(const char* name, uintptr_t a, const uint8_t* old_b, int n_old,
                  const uint8_t* new_b, int n_new) {
    uint8_t* d = (uint8_t*)a;
    for (int i = 0; i < n_old; i++) {
        if (d[i] != old_b[i]) { logf("[AP] %s mismatch +%d: %02x", name, i, d[i]); return; }
    }
    uintptr_t page = a & ~(uintptr_t)0xFFF;
    mprotect((void*)page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(d, new_b, n_new);
    __builtin___clear_cache((char*)a, (char*)a + n_new);
    logf("[AP] %s ok", name);
}

// ─── EGL fix ──────────────────────────────────────────────
typedef void* EGLDisplay; typedef void* EGLSurface; typedef unsigned int EGLBoolean;
static EGLBoolean (*orig_swap)(EGLDisplay, EGLSurface) = nullptr;
static int   (*p_err)(void) = nullptr;
static void* (*p_cursurf)(int) = nullptr;
static int   (*nv_mc)(void) = nullptr;
static int   g_fixLog = 0;

static EGLBoolean my_swap(EGLDisplay d, EGLSurface s) {
    EGLBoolean r = orig_swap(d, s);
    if (!r && p_err && p_err() == 0x300D) {
        if (g_fixLog < 20) { logf("[AP] swap BAD_SURFACE, rebind"); }
        if (nv_mc) nv_mc();
        void* ns = p_cursurf ? p_cursurf(0x3059) : nullptr;
        r = orig_swap(d, ns ? ns : s);
        if (g_fixLog++ < 20) logf("[AP] retry=%u", r);
    }
    return r;
}

extern "C" {

int antipause_init(void) {
    remove(LOGFILE);
    logf("[AP] init");
    void* h = dlopen("libGTASA.so", RTLD_NOW);
    if (!h) { logf("[AP] ERROR libGTASA"); return 0; }

    uintptr_t pe = sym(h, "_Z13ProcessEventsb");
    uintptr_t am = sym(h, "_Z14NVEventAppMainiPPc");
    if (!pe || !am) { logf("[AP] ERROR sym nil"); return 0; }

    const uint8_t o8[]  = {0x30,0xF7,0xA2,0xEB}, o9[] = {0x30,0xF7,0x92,0xEB};
    const uint8_t nop4[] = {0x00,0xBF,0x00,0xBF};
    const uint8_t ol[]  = {0xF3,0xD1,0x08,0xE0}, nop2[] = {0x00,0xBF};
    const uint8_t og[]  = {0x70,0xB1}, ng[] = {0x0E,0xE0};

    patch("appevent8", pe + 0x1A0, o8, 4, nop4, 4);
    patch("appevent9", pe + 0x1C2, o9, 4, nop4, 4);
    patch("mainloop",  am + 0x13C, ol, 4, nop2, 2);
    patch("gfxthread", pe - 0x269354 + 0x1D2288, og, 2, ng, 2);
    return 1;
}

int antipause_egl_hook(void) {
    logf("[AP] egl hook");
    void* dob = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    void* egl = dlopen("libEGL.so", RTLD_NOW);
    void* gta = dlopen("libGTASA.so", RTLD_NOW);
    if (!dob || !egl) { logf("[AP] ERROR dobby/egl"); return 0; }

    int (*hook)(void*, void*, void**) = (int(*)(void*, void*, void**))dlsym(dob, "DobbyHook");
    p_err     = (int(*)(void))dlsym(egl, "eglGetError");
    p_cursurf = (void*(*)(int))dlsym(egl, "eglGetCurrentSurface");
    nv_mc     = gta ? (int(*)(void))dlsym(gta, "NVEventEGLMakeCurrent") : nullptr;
    void* swp = dlsym(egl, "eglSwapBuffers");
    if (!hook || !swp) { logf("[AP] ERROR hook/swap nil"); return 0; }

    int r = hook(swp, (void*)my_swap, (void**)&orig_swap);
    logf("[AP] hook=%d nv_mc=%p", r, (void*)nv_mc);
    return r == 0;
}

} // extern "C"
