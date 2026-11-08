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
#include <unistd.h>
#include <sys/syscall.h>
typedef void* EGLDisplay; typedef void* EGLSurface; typedef void* EGLContext;
typedef void* EGLConfig; typedef void* EGLWin; typedef unsigned int EGLBoolean;
static EGLBoolean (*orig_swap)(EGLDisplay, EGLSurface) = nullptr;
static EGLBoolean (*orig_mc)(EGLDisplay, EGLSurface, EGLSurface, EGLContext) = nullptr;
static EGLSurface (*orig_cws)(EGLDisplay, EGLConfig, EGLWin, const int*) = nullptr;
static int        (*p_err)(void) = nullptr;
static EGLContext (*p_ctx)(void) = nullptr;
static EGLDisplay (*p_disp)(void) = nullptr;
static EGLDisplay g_d = nullptr; static EGLSurface g_surf = nullptr; static EGLContext g_ctx = nullptr;
static int g_n = 0, g_fix = 0;
#define TID ((int)syscall(SYS_gettid))

static EGLSurface my_cws(EGLDisplay d, EGLConfig c, EGLWin w, const int* a) {
    EGLSurface s = orig_cws(d, c, w, a);
    g_d = d; g_surf = s;
    logf("[AP] cws tid=%d s=%p", TID, s);
    return s;
}
static EGLBoolean my_mc(EGLDisplay d, EGLSurface dr, EGLSurface rd, EGLContext c) {
    EGLBoolean r = orig_mc(d, dr, rd, c);
    if (r && c) { g_ctx = c; g_d = d; }
    if (g_n < 60) { g_n++; logf("[AP] mc tid=%d dr=%p c=%p r=%u", TID, dr, c, r); }
    return r;
}
static EGLBoolean my_swap(EGLDisplay d, EGLSurface s) {
    EGLBoolean r = orig_swap(d, s);
    if (!r && p_err() == 0x300D && g_surf && g_fix < 30) {
        EGLContext c = p_ctx ? p_ctx() : nullptr;
        if (!c) c = g_ctx;
        EGLDisplay dd = d ? d : g_d;
        EGLBoolean m = c ? orig_mc(dd, g_surf, g_surf, c) : 0;
        int e = m ? 0 : p_err();
        if (m) r = orig_swap(dd, g_surf);
        logf("[AP] fix tid=%d surf=%p ctx=%p mc=%u err=%x swap=%u", TID, g_surf, c, m, e, r);
        g_fix++;
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
    const uint8_t o8[]={0x30,0xF7,0xA2,0xEB}, o9[]={0x30,0xF7,0x92,0xEB};
    const uint8_t nop4[]={0x00,0xBF,0x00,0xBF};
    const uint8_t ol[]={0xF3,0xD1,0x08,0xE0}, nop2[]={0x00,0xBF};
    const uint8_t og[]={0x70,0xB1}, ng[]={0x0E,0xE0};
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
    if (!dob || !egl) { logf("[AP] ERROR dobby/egl"); return 0; }
    int (*hook)(void*, void*, void**) = (int(*)(void*, void*, void**))dlsym(dob, "DobbyHook");
    p_err  = (int(*)(void))dlsym(egl, "eglGetError");
    p_ctx  = (EGLContext(*)(void))dlsym(egl, "eglGetCurrentContext");
    p_disp = (EGLDisplay(*)(void))dlsym(egl, "eglGetCurrentDisplay");
    g_ctx = p_ctx ? p_ctx() : nullptr;
    g_d   = p_disp ? p_disp() : nullptr;
    void* sw = dlsym(egl, "eglSwapBuffers");
    void* mc = dlsym(egl, "eglMakeCurrent");
    void* cw = dlsym(egl, "eglCreateWindowSurface");
    if (!hook || !sw || !mc || !cw) { logf("[AP] ERROR hook nil"); return 0; }
    int a = hook(cw, (void*)my_cws,  (void**)&orig_cws);
    int b = hook(mc, (void*)my_mc,   (void**)&orig_mc);
    int c = hook(sw, (void*)my_swap, (void**)&orig_swap);
    logf("[AP] hooks cws=%d mc=%d swap=%d ctx=%p", a, b, c, g_ctx);
    return !(a || b || c);
}

} // extern "C"
