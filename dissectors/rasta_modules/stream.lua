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
    description = "Utility functions to chain various conversions together in a fluid API style",
    repository = "https://github.com/Railway-CCS/dissectors"
}

set_plugin_info(my_info)


local Queue = require("queue");
local String = require("string");

local Stream = {};


Stream.fromString = function(string)
	local i=0;
	return function()
		i=i+1;
		if(i <= String.len(string)) then
			return String.byte(string,i);
		else
			return nil;
		end
	end
end


Stream.toString = function(stream)
	local array = {};
	local i=1;

	local byte = stream();
	while byte ~= nil do
		array[i] = String.char(byte);
		i = i+1;
		byte = stream();
	end

	return table.concat(array,"");
end


Stream.fromArray = function(array)
	local queue = Queue();
	local i=1;

	local byte = array[i];
	while byte ~= nil do
		queue.push(byte);
		i=i+1;
		byte = array[i];
	end

	return queue.pop;
end


Stream.toArray = function(stream)
	local array = {};
	local i=1;

	local byte = stream();
	while byte ~= nil do
		array[i] = byte;
		i = i+1;
		byte = stream();
	end

	return array;
end


local fromHexTable = {};
for i=0,255 do
	fromHexTable[String.format("%02X",i)]=i;
	fromHexTable[String.format("%02x",i)]=i;
end

Stream.fromHex = function(hex)
	local queue = Queue();

	for i=1,String.len(hex)/2 do
		local h = String.sub(hex,i*2-1,i*2);
		queue.push(fromHexTable[h]);
	end

	return queue.pop;
end



local toHexTable = {};
for i=0,255 do
	toHexTable[i]=String.format("%02X",i);
end

Stream.toHex = function(stream)
	local hex = {};
	local i = 1;

	local byte = stream();
	while byte ~= nil do
		hex[i] = toHexTable[byte];
		i=i+1;
		byte = stream();
	end

	return table.concat(hex,"");
end

return Stream;
