#!/bin/bash

FILES="dissectors/rasta.lua
    dissectors/sci.lua
    dissectors/rasta_modules/bit.lua
    dissectors/rasta_modules/md4.lua
    dissectors/rasta_modules/queue.lua
    dissectors/rasta_modules/rasta_crc.lua
    dissectors/rasta_modules/stream.lua"


for f in $FILES; do
    sed -i "s/version = \"[0-9.]*\"/version = \"$1\"/" $f
    git add $f
done
