function set_plugin_info(info)
    return
end

local A = 0x67452301;
local B = 0xefcdab89;
local C = 0x98badcfe;
local D = 0x10325476;

local MD4 = require("md4")
local Stream = require("stream")
local bit = require("bit")

print(MD4().update(Stream.fromString("")).finish().asHex()) -- Should be 31d6cfe0d16ae931b73c59d7e0c089c0
print(MD4().update(Stream.fromHex("24004c183fb49600ceca2300564433226655443357010000cb000000")).finish().asHex()) -- Should be 83f0d052406bf492f89f8d1e9b89c98d
print(MD4().finish().asHex())

print("AND:    " .. bit.band(B, C))     -- 2290649224
print("OR:     " .. bit.bor(B, C))      -- 4294967295
print("XOR:    " .. bit.bxor(B, C))     -- 2004318071
print("RSHIFT: " .. bit.rshift(B, 19))  -- 7673
print("LSHIFT: " .. bit.lshift(B, 19))  -- 1548222464
print("NOT:    " .. bit.bnot(B))        -- 271733878
print("LROT:   " .. bit.lrotate(B, 19)) -- 1548713581
print("RROT:   " .. bit.rrotate(B, 19)) -- 3044097529

local F = function(x,y,z) return bit.bor(bit.band(x,y),bit.band(bit.bnot(x),z)); end
local G = function(x,y,z) return bit.bor(bit.band(x,y), bit.bor(bit.band(x,z), bit.band(y,z))); end
local H = function(x,y,z) return bit.bxor(x,bit.bxor(y,z)); end

print("F:      " .. F(B,C,D)) -- 2562383102
print("F:      " .. F(A,B,C)) -- 4294967295
print("G:      " .. G(B,C,D)) -- 2562383102
print("G:      " .. G(A,B,C)) -- 4023233417
print("H:      " .. H(B,C,D)) -- 1732584193

print(A + B + C + D) -- 8589934590
