#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define LOGFILE "/storage/emulated/0/antipause_log.txt"
#define TID ((int)syscall(SYS_gettid))

static int g_logn = 0;
static void logf(const char* fmt, ...) {
    if (g_logn++ > 20) return;
    FILE* f = fopen(LOGFILE, "a"); if (!f) return;
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f); fclose(f);
}

static uintptr_t sym(void* h, const char* n) {
    void* p = dlsym(h, n);
    return p ? ((uintptr_t)p & ~(uintptr_t)1) : 0;
}

static bool patch(const char* name, uintptr_t a, const uint8_t* o, int no, const uint8_t* nw, int nn) {
    uint8_t* d = (uint8_t*)a;
    if (memcmp(d, o, no) != 0) { logf("[AP] %s mismatch", name); return false; }
    mprotect((void*)(a & ~(uintptr_t)0xFFF), 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC);
    memcpy(d, nw, nn);
    __builtin___clear_cache((char*)a, (char*)a + nn);
    logf("[AP] %s ok", name);
    return true;
}

typedef void* EGLDisplay; typedef void* EGLSurface; typedef void* EGLContext;
typedef void* EGLConfig; typedef void* EGLWin; typedef unsigned int EGLBoolean;

static EGLBoolean (*orig_swap)(EGLDisplay, EGLSurface) = nullptr;
static EGLBoolean (*orig_mc)(EGLDisplay, EGLSurface, EGLSurface, EGLContext) = nullptr;
static EGLSurface (*orig_cws)(EGLDisplay, EGLConfig, EGLWin, const int*) = nullptr;
static EGLBoolean (*orig_ds)(EGLDisplay, EGLSurface) = nullptr;
static int        (*p_err)(void) = nullptr;
static EGLContext (*p_ctx)(void) = nullptr;
static EGLBoolean (*p_qsurf)(EGLDisplay, EGLSurface, int, int*) = nullptr;

static volatile EGLSurface g_rs = nullptr, g_use = nullptr;
static volatile int g_jcfg = -1, g_rtid = 0;
static int g_fix = 0;
static int (*p_paused)(void) = nullptr;
static volatile int g_bgms = 33;
static unsigned g_bgf = 0;
static int g_lastp = -1;

static EGLSurface my_cws(EGLDisplay d, EGLConfig c, EGLWin w, const int* a) {
    EGLSurface s = orig_cws(d, c, w, a);
    int cid = -1; if (p_qsurf && s) p_qsurf(d, s, 0x3028, &cid);
    if (g_jcfg < 0) g_jcfg = cid;
    else if (cid != g_jcfg && s) { g_rs = s; g_rtid = TID; g_use = nullptr; }
    return s;
}

static EGLBoolean my_ds(EGLDisplay d, EGLSurface s) {
    if (s && s == g_rs && TID != g_rtid) return 1;
    return orig_ds(d, s);
}

static EGLBoolean my_swap(EGLDisplay d, EGLSurface s) {
    if (p_paused && g_bgms > 0) {
        int pz = p_paused() ? 1 : 0;
        if (pz != g_lastp) { g_lastp = pz; logf("[AP] bg=%d", pz); }
        if (pz) { usleep(g_bgms * 1000); if (++g_bgf & 3) return 1; }
    }
    EGLSurface u = g_use;
    EGLBoolean r = orig_swap(d, u ? u : s);
    EGLSurface rs = g_rs;
    if (!r && rs && p_err() == 0x300D) {
        EGLContext c = p_ctx ? p_ctx() : nullptr;
        if (c && orig_mc(d, rs, rs, c)) {
            r = orig_swap(d, rs);
            if (r) g_use = rs;
        }
        if (g_fix++ < 5) logf("[AP] fix tid=%d r=%u", TID, r);
    }
    return r;
}

extern "C" {

int antipause_init(void) {
    remove(LOGFILE);
    logf("[AP] init");
    void* h = dlopen("libGTASA.so", RTLD_NOW);
    if (!h) return 0;
    uintptr_t pe = sym(h, "_Z13ProcessEventsb");
    uintptr_t am = sym(h, "_Z14NVEventAppMainiPPc");
    if (!pe || !am) { logf("[AP] sym nil"); return 0; }

    const uint8_t o8[]={0x30,0xF7,0xA2,0xEB}, o9[]={0x30,0xF7,0x92,0xEB};
    const uint8_t nop4[]={0x00,0xBF,0x00,0xBF};
    const uint8_t ol[]={0xF3,0xD1,0x08,0xE0}, nop2[]={0x00,0xBF};
    const uint8_t og[]={0x70,0xB1}, ng[]={0x0E,0xE0};
    patch("appevent8", pe + 0x1A0, o8, 4, nop4, 4);
    patch("appevent9", pe + 0x1C2, o9, 4, nop4, 4);
    patch("mainloop",  am + 0x13C, ol, 4, nop2, 2);
    patch("gfxthread", pe - 0x269354 + 0x1D2288, og, 2, ng, 2);

    uintptr_t sc = sym(h, "_Z19OS_SystemCheckPausei");
    if (!sc) sc = pe - 0x269354 + 0x26A82C;
    const uint8_t mk[]={0x34,0xF7,0xAC,0xEB}, nb[]={0x00,0x20,0x70,0x47};
    if (memcmp((void*)(sc + 0x56), mk, 4) == 0) patch("syscheck", sc, (const uint8_t*)(sc + 0), 4, nb, 4);
    else logf("[AP] syscheck mismatch");
    return 1;
}

void antipause_set_bg(int ms) { g_bgms = ms < 0 ? 0 : ms; }

int antipause_egl_hook(void) {
    void* dob = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    void* egl = dlopen("libEGL.so", RTLD_NOW);
    if (!dob || !egl) return 0;
    int (*hook)(void*, void*, void**) = (int(*)(void*, void*, void**))dlsym(dob, "DobbyHook");
    p_err   = (int(*)(void))dlsym(egl, "eglGetError");
    p_ctx   = (EGLContext(*)(void))dlsym(egl, "eglGetCurrentContext");
    p_qsurf = (EGLBoolean(*)(EGLDisplay,EGLSurface,int,int*))dlsym(egl, "eglQuerySurface");
    orig_mc = (EGLBoolean(*)(EGLDisplay,EGLSurface,EGLSurface,EGLContext))dlsym(egl, "eglMakeCurrent");
    void* sw = dlsym(egl, "eglSwapBuffers");
    void* cw = dlsym(egl, "eglCreateWindowSurface");
    void* ds = dlsym(egl, "eglDestroySurface");
    void* gta = dlopen("libGTASA.so", RTLD_NOW);
    p_paused = gta ? (int(*)(void))dlsym(gta, "_Z13AndroidPausedv") : nullptr;
    logf("[AP] paused fn=%p", (void*)p_paused);
    if (!hook || !sw || !cw || !ds || !orig_mc || !p_err) return 0;
    int a = hook(cw, (void*)my_cws,  (void**)&orig_cws);
    int b = hook(ds, (void*)my_ds,   (void**)&orig_ds);
    int c = hook(sw, (void*)my_swap, (void**)&orig_swap);
    logf("[AP] hooks %d %d %d", a, b, c);
    return !(a || b || c);
}

}
