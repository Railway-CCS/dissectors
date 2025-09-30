-- The MIT License (MIT)

-- Copyright (c) 2015 James L.

-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:

-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.

-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
-- 
-- Extracted from lua-lockbox: https://github.com/somesocks/lua-lockbox

local my_info = 
{
    version = "1.4.0",
    description = "Wrapper that selects the appropriate 'bit' library for the used Lua version",
    repository = "https://github.com/Railway-CCS/dissectors"
}

set_plugin_info(my_info)

local bit = nil

if _VERSION == "Lua 5.2" then
    local ok, e = pcall(require, "bit32")  -- Try bit32 (Lua 5.2)
    if ok then bit = e end
elseif _VERSION == "Lua 5.1" then
    local ok, e = pcall(require, "bit")  -- Try LuaJIT bit library
    if not ok then
        ok, e = pcall(require, "bit.numberlua")  -- Try numberlua for Lua 5.1
    end
    if ok then bit = e end
else
    -- Lua 5.3+ uses built-in bitwise operators
    bit = require("bit54")
end

return bit  -- Return the selected bitwise library (or table for Lua 5.3+)