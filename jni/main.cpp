#include <cstdint>
#include <dlfcn.h>

typedef void (*func_t)();

static void* libGTASA = nullptr;

static void hook_func(void* target, void* replace) {
    // Dobby hook via dlopen libdobby
    typedef int (*DobbyHook_t)(void*, void*, void**);
    static void* dobby = nullptr;
    if (!dobby) dobby = dlopen("libdobby.so", RTLD_NOW);
    if (!dobby) return;
    DobbyHook_t DobbyHook = (DobbyHook_t)dlsym(dobby, "DobbyHook");
    if (DobbyHook) DobbyHook(target, replace, nullptr);
}

static void fake_AndroidPause() {}
static void fake_StartUserPause() {}
static void fake_Suspend() {}

__attribute__((constructor))
static void init() {
    libGTASA = dlopen("libGTASA.so", RTLD_NOW | RTLD_NOLOAD);
    if (!libGTASA) return;

    uintptr_t base = (uintptr_t)dlsym(libGTASA, "_Z12AndroidPausev");
    // Fallback: hitung base dari simbol
    // offset dari nm: 0x269af4
    // base lib = ptr - offset
    uintptr_t lib_base = base - 0x269af4;

    // +1 = Thumb mode
    void* addr_pause   = (void*)((lib_base + 0x269af4) | 1);
    void* addr_userpause = (void*)((lib_base + 0x4210c8) | 1);
    void* addr_suspend = (void*)((lib_base + 0x420f14) | 1);

    hook_func(addr_pause,     (void*)fake_AndroidPause);
    hook_func(addr_userpause, (void*)fake_StartUserPause);
    hook_func(addr_suspend,   (void*)fake_Suspend);
}
