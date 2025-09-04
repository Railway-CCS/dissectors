local bit = {
    band = function(a, b) return a & b end,
    bor = function(a, b) return a | b end,
    bxor = function(a, b) return a ~ b end,
    rshift = function(a, n) return a >> n end,
    lshift = function(a, n) return (a << n) & 0xffffffff end,
    bnot = function(a) return ~a end,
    lrotate = function(a, n) return ((a << n) & 0xffffffff) | (a >> (32 - n)) & ~(-1 << n) end,
    rrotate = function(a, n) return (a >> n) | ((a << (32 - n)) & 0xffffffff) end
}

return bit