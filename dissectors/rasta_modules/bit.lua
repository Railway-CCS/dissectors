-- Extracted from lua-lockbox: https://github.com/somesocks/lua-lockbox

local my_info = 
{
    version = "1.3.0",
    description = "Wrapper that selects the appropriate 'bit' library for the used Lua version",
    repository = "https://github.com/Railway-CCS/dissectors"
}

set_plugin_info(my_info)

local bit = nil

print(_VERSION)

if _VERSION == "Lua 5.2" then
    print("A")
    local ok, e = pcall(require, "bit32")  -- Try bit32 (Lua 5.2)
    if ok then bit = e end
elseif _VERSION == "Lua 5.1" then
    print("B")
    local ok, e = pcall(require, "bit")  -- Try LuaJIT bit library
    if not ok then
        ok, e = pcall(require, "bit.numberlua")  -- Try numberlua for Lua 5.1
    end
    if ok then bit = e end
else
    print("C")
    -- Lua 5.3+ uses built-in bitwise operators
    bit = {
        band = function(a, b) return a & b end,
        bor = function(a, b) return a | b end,
        bxor = function(a, b) return a ~ b end,
        rshift = function(a, n) return a >> n end,
        lshift = function(a, n) return (a << n) & 0xffffffff end,
        bnot = function(a) return ~a end,
        lrotate = function(a, n) return ((a << n) & 0xffffffff) | (a >> (32 - n)) end,
        rrotate = function(a, n) return (a >> n) | ((a << (32 - n)) & 0xffffffff) end
    }
end

return bit  -- Return the selected bitwise library (or table for Lua 5.3+)