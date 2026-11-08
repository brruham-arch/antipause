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

static int g_glTid = 0, g_ok = 0, g_mcn = 0, g_jcfg = -1, g_rtid = 0;
static EGLSurface g_rs = nullptr;
static EGLSurface g_use = nullptr;
static EGLContext (*orig_cc)(EGLDisplay, EGLConfig, EGLContext, const int*) = nullptr;
static EGLBoolean (*orig_ds)(EGLDisplay, EGLSurface) = nullptr;
static EGLBoolean (*p_qctx)(EGLDisplay, EGLContext, int, int*) = nullptr;
static EGLBoolean (*p_qsurf)(EGLDisplay, EGLSurface, int, int*) = nullptr;

// ─── Watchdog ─────────────────────────────────────────────
#include <signal.h>
#include <pthread.h>
#include <dirent.h>
#include <ucontext.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#define WSIG (SIGRTMIN + 6)
static volatile int g_swaps = 0, g_sigdone = 0, g_wdStarted = 0;
static uintptr_t g_pc, g_lr, g_stk[64];

static void sigh(int, siginfo_t*, void* u) {
    ucontext_t* uc = (ucontext_t*)u;
    g_pc = uc->uc_mcontext.arm_pc; g_lr = uc->uc_mcontext.arm_lr;
    uintptr_t* sp = (uintptr_t*)uc->uc_mcontext.arm_sp;
    for (int i = 0; i < 64; i++) g_stk[i] = sp[i];
    g_sigdone = 1;
}
static bool resolve(uintptr_t a, char* out, size_t n, bool needX) {
    FILE* f = fopen("/proc/self/maps", "r"); if (!f) return false;
    char line[512]; bool ok = false;
    while (fgets(line, sizeof line, f)) {
        unsigned long lo, hi, off; char perm[8]; char path[400] = "";
        if (sscanf(line, "%lx-%lx %7s %lx %*s %*s %399[^\n]", &lo, &hi, perm, &off, path) < 4) continue;
        if (a >= lo && a < hi) {
            if (needX && perm[2] != 'x') break;
            const char* b = strrchr(path, '/'); b = b ? b + 1 : path;
            if (needX && !*b) break;
            snprintf(out, n, "%s+0x%lx", *b ? b : "?", (unsigned long)(a - lo + off));
            ok = true; break;
        }
    }
    fclose(f); return ok;
}
static void rd(const char* path, char* o, size_t n) {
    o[0] = 0; FILE* f = fopen(path, "r"); if (!f) return;
    if (fgets(o, n, f)) { size_t l = strlen(o); if (l && o[l-1] == '\n') o[l-1] = 0; }
    fclose(f);
}
static void dumpThreads() {
    int me = (int)syscall(SYS_gettid);
    DIR* d = opendir("/proc/self/task"); if (!d) return;
    struct dirent* e;
    while ((e = readdir(d))) {
        int tid = atoi(e->d_name); if (tid <= 0 || tid == me) continue;
        char p[80], comm[40], st[256], r1[160], r2[160], x[160];
        snprintf(p, sizeof p, "/proc/self/task/%d/comm", tid); rd(p, comm, sizeof comm);
        snprintf(p, sizeof p, "/proc/self/task/%d/stat", tid); rd(p, st, sizeof st);
        char* rp = strrchr(st, ')'); char state = rp ? rp[2] : '?';
        g_sigdone = 0;
        syscall(SYS_tgkill, (int)getpid(), tid, WSIG);
        for (int i = 0; i < 200 && !g_sigdone; i++) usleep(1000);
        if (!g_sigdone) { logf("[WD] tid=%d %s st=%c (no signal)", tid, comm, state); continue; }
        if (!resolve(g_pc, r1, sizeof r1, false)) snprintf(r1, sizeof r1, "%lx", (unsigned long)g_pc);
        if (!resolve(g_lr, r2, sizeof r2, false)) snprintf(r2, sizeof r2, "%lx", (unsigned long)g_lr);
        logf("[WD] tid=%d %s st=%c pc=%s lr=%s", tid, comm, state, r1, r2);
        int shown = 0;
        for (int i = 0; i < 64 && shown < 14; i++)
            if (resolve(g_stk[i], x, sizeof x, true) && !strstr(x, "libc.so")) {
                logf("[WD]    stk[%d]=%s", i, x); shown++;
            }
    }
    closedir(d);
}
static void* wdThread(void*) {
    int last = g_swaps, zero = 0, dumps = 0, n = 0;
    while (1) {
        sleep(1);
        int cur = g_swaps, dl = cur - last; last = cur;
        if (n < 90 && (n++ % 3) == 0) logf("[WD] swaps/s=%d", dl);
        zero = (dl <= 2) ? zero + 1 : 0;
        if (zero == 3 && dumps < 3) { dumps++; logf("[WD] STALL dump #%d", dumps); dumpThreads(); }
        if (access("/storage/emulated/0/ap_dump", F_OK) == 0) {
            remove("/storage/emulated/0/ap_dump");
            logf("[WD] MANUAL dump"); dumpThreads();
        }
    }
    return nullptr;
}
static void startWatch() {
    if (g_wdStarted) return; g_wdStarted = 1;
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sigh; sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(WSIG, &sa, nullptr);
    pthread_t t; pthread_create(&t, nullptr, wdThread, nullptr); pthread_detach(t);
}

static EGLSurface my_cws(EGLDisplay d, EGLConfig c, EGLWin w, const int* a) {
    EGLSurface s = orig_cws(d, c, w, a);
    g_d = d; g_surf = s; g_use = nullptr;
    int cid = -1; if (p_qsurf && s) p_qsurf(d, s, 0x3028, &cid);
    if (g_jcfg < 0) g_jcfg = cid;
    else if (cid != g_jcfg && s) { g_rs = s; g_rtid = TID; g_use = nullptr; }
    logf("[AP] cws tid=%d s=%p cfg=%p cfgid=%d", TID, s, c, cid);
    return s;
}
static EGLContext my_cc(EGLDisplay d, EGLConfig c, EGLContext sh, const int* a) {
    EGLContext r = orig_cc(d, c, sh, a);
    int cid = -1; if (p_qctx && r) p_qctx(d, r, 0x3028, &cid);
    logf("[AP] cc tid=%d ctx=%p cfg=%p cfgid=%d share=%p", TID, r, c, cid, sh);
    return r;
}
static EGLBoolean my_ds(EGLDisplay d, EGLSurface s) {
    if (s && s == g_rs && TID != g_rtid) { logf("[AP] skip ds tid=%d s=%p", TID, s); return 1; }
    logf("[AP] ds tid=%d s=%p", TID, s);
    return orig_ds(d, s);
}
static EGLBoolean my_mc(EGLDisplay d, EGLSurface dr, EGLSurface rd, EGLContext c) {
    EGLBoolean r = orig_mc(d, dr, rd, c);
    if (r && c) { g_ctx = c; g_d = d; }
    if (g_mcn < 40) { g_mcn++; logf("[AP] mc tid=%d dr=%p c=%p r=%u", TID, dr, c, r); }
    return r;
}
static EGLBoolean my_swap(EGLDisplay d, EGLSurface s) {
    g_swaps++;
    EGLBoolean r = orig_swap(d, g_use ? g_use : s);
    if (!r && p_err() == 0x300D && g_rs && g_fix < 12) {
        EGLContext c = p_ctx ? p_ctx() : nullptr;
        EGLDisplay dd = d ? d : g_d;
        EGLBoolean m = c ? orig_mc(dd, g_rs, g_rs, c) : 0;
        int e = m ? 0 : p_err();
        if (m) { r = orig_swap(dd, g_rs); if (r) g_use = g_rs; }
        logf("[AP] fix tid=%d rs=%p ctx=%p mc=%u err=%x swap=%u", TID, g_rs, c, m, e, r);
        g_fix++;
    }
    return r;
}

extern "C" {

int antipause_init(void) {
    remove(LOGFILE);
    logf("[AP] init");
    startWatch();
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
    p_qctx  = (EGLBoolean(*)(EGLDisplay,EGLContext,int,int*))dlsym(egl, "eglQueryContext");
    p_qsurf = (EGLBoolean(*)(EGLDisplay,EGLSurface,int,int*))dlsym(egl, "eglQuerySurface");
    void* ccp = dlsym(egl, "eglCreateContext");
    void* dsp = dlsym(egl, "eglDestroySurface");
    if (ccp) hook(ccp, (void*)my_cc, (void**)&orig_cc);
    if (dsp) hook(dsp, (void*)my_ds, (void**)&orig_ds);
    int a = hook(cw, (void*)my_cws,  (void**)&orig_cws);
    int b = hook(mc, (void*)my_mc,   (void**)&orig_mc);
    int c = hook(sw, (void*)my_swap, (void**)&orig_swap);
    logf("[AP] hooks cws=%d mc=%d swap=%d ctx=%p", a, b, c, g_ctx);
    return !(a || b || c);
}

} // extern "C"
