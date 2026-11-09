script_name('AntiPause')
script_version('1.0')
script_author('brruham')

local ffi = require("ffi")

local function copyFile(src, dst)
    local a = io.open(src, "rb")
    if not a then return false end
    local b = io.open(dst, "wb")
    if not b then a:close() return false end
    b:write(a:read("*a"))
    a:close() b:close()
    return true
end

local function getPackageName()
    local parts = {}
    for p in string.gmatch(getWorkingDirectory(), '([^/\\]+)') do parts[#parts+1] = p end
    return parts[#parts-1]
end

local soSrc = getWorkingDirectory() .. "/libantipause.so"
local soDst = "/data/data/" .. getPackageName() .. "/libantipause.so"
copyFile(soSrc, soDst)

ffi.cdef[[
int antipause_init(void);
int antipause_egl_hook(void);
void antipause_set_bg(int ms);
]]

local ok, lib = pcall(ffi.load, soDst)

function main()
    while not isSampAvailable() do wait(100) end
    if not ok then
        sampAddChatMessage("[AP] GAGAL load libantipause.so", 0xFF4444)
        return
    end
    local a = lib.antipause_init()

    lib.antipause_egl_hook()
    sampAddChatMessage("[AP] init=" .. a, 0x00FFCC)
    local bg = 33
    sampRegisterChatCommand("apbg", function(arg)
        local v = tonumber(arg)
        if v then bg = v else bg = (bg > 0) and 0 or 33 end
        lib.antipause_set_bg(bg)
        sampAddChatMessage("[AP] bg delay=" .. bg .. " ms", 0x00FFCC)
    end)
end
