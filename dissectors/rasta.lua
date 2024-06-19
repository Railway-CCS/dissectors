-- MIT License
--
-- Copyright (c) 2021
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.

local my_info =
{
    version = "1.2.0",
    description = "Dissector to parse the Rail Safe Transport Application (RaSTA) protocol.",
    repository = "https://github.com/Railway-CCS/dissectors"
}

set_plugin_info(my_info)

------------------------
---- RASTA PROTOCOL ----

-- Wireshark path:
--      Mac: Contents/Plugins/wireshark

--
------------------------
local MD4 = require("md4");
local Stream = require("stream");
local CRC = require("rasta_crc");

local CRC_LENGTH = 0
local CRC_OPTION = nil

-- print("#######################")

local p_rasta = Proto("rasta", "RaSTA Protocol")

-- Register preferences --

local ALGO_MD4 = 0
local ALGO_BLAKE2 = 1
local ALGO_SIPHASH = 2

local algo_prefs = {
    {1, "MD4", ALGO_MD4},
    {2, "Blake2b", ALGO_BLAKE2},
    {3, "SIPHASH-2-4", ALGO_SIPHASH},
}

local CRC_NONE = 0
local CRC32_EE5B42FD = 1
local CRC32_1EDC6F41 = 2
local CRC16_1021 = 3
local CRC16_8005 = 4

local crc_type = {
    {1, "None (Option A)", CRC_NONE},
    {1, "CRC32, Poly=EE5B42FD (Option B)", CRC32_EE5B42FD},
    {1, "CRC32, Poly=1EDC6F41 (Option C)", CRC32_1EDC6F41},
    {1, "CRC16, Poly=1021(Option D)", CRC16_1021},
    {1, "CRC16, Poly=8005(Option E)", CRC16_8005},
}

-- safety code parameters
p_rasta.prefs.safety_code_header = Pref.statictext("----- Safety Code -----", "Configuration option for the safety code the send/retransmission layer")
p_rasta.prefs.safety_code_len    = Pref.uint("Length", 8, "Length of the safety code in bytes")
p_rasta.prefs.safety_code_algo   = Pref.enum("Safety Code Algorithm", ALGO_MD4, "Safety Code Algorithm", algo_prefs, false)
p_rasta.prefs.md4_a              = Pref.string("MD4 Initial A (hex)", "67452301", "Initial A value for MD4 safety code calculation as hex string")
p_rasta.prefs.md4_b              = Pref.string("MD4 Initial B (hex)", "efcdab89", "Initial B value for MD4 safety code calculation as hex string")
p_rasta.prefs.md4_c              = Pref.string("MD4 Initial C (hex)", "98badcfe", "Initial C value for MD4 safety code calculation as hex string")
p_rasta.prefs.md4_d              = Pref.string("MD4 Initial D (hex)", "10325476", "Initial D value for MD4 safety code calculation as hex string")
p_rasta.prefs.safety_key         = Pref.uint("Key", 1193046, "Key for the safety code when MD4 is not used")
p_rasta.prefs.packetization      = Pref.bool("Payload Paketization", false, "Paketization for payload data.")
p_rasta.prefs.sci                = Pref.bool("Parse SCI", false, "Try to parse payload as SCI.")

-- CRC parameters
p_rasta.prefs.crc_header         = Pref.statictext("----- CRC -----", "Configuration option for the redundancy layer CRC checksum")
p_rasta.prefs.crc_algo           = Pref.enum("CRC Type", CRC_NONE, "CRC algorithm parameters", crc_type, false)


local vals_message_type = {
    [6200] = "Connection Request",
    [6201] = "Connection Response",
    [6212] = "Retransmission Request",
    [6213] = "Retransmission Response",
    [6216] = "Disconnection Request",
    [6220] = "Heartbeat",
    [6240] = "Data",
    [6241] = "Retransmitted Data"
}

local vals_disconnect_reason = {
    [0] = "user enquiry",
    [1] = "not in use",
    [2] = "received message type not expected for the current state",
    [3] = "error in the sequence number verification during connection establishment",
    [4] = "timeout for incoming messages",
    [5] = "service not allowed in this state",
    [6] = "error in the protocol version",
    [7] = "retransmission failed, requested sequence number not available",
    [8] = "error in the protocol sequence"
}

-- redundancy properties
local redundancy_message_length     = ProtoField.uint16("rasta.redundancy.mlen", "Length")
local redundancy_reserve_bytes      = ProtoField.uint16("rasta.redundancy.reserve", "Reserve")
local redundancy_sequence_number    = ProtoField.uint32("rasta.redundancy.sn", "Sequence number")
local redundancy_check_code         = ProtoField.new("Check code", "rasta.redundancy.check_code", ftypes.BYTES)
local redundancy_check_code_valid   = ProtoField.new("Check code valid", "rasta.redundancy.check_code_valid", ftypes.BOOLEAN)

-- rasta properties
local safety_message_length      = ProtoField.uint16("rasta.safety.mlen", "Message length")
local safety_message_type        = ProtoField.uint16("rasta.safety.type", "Message type", base.DEC, vals_message_type)
local safety_dest_id             = ProtoField.uint32("rasta.safety.dest_id", "Receiver identification")
local safety_src_id              = ProtoField.uint32("rasta.safety.src_id", "Sender identification")
local safety_sequence_number     = ProtoField.uint32("rasta.safety.sn", "Sequence number")
local safety_c_sequence_number   = ProtoField.uint32("rasta.safety.cs", "Confirmed Sequence Number")
local safety_timestamp           = ProtoField.uint32("rasta.safety.ts", "Time stamp")
local safety_c_timestamp         = ProtoField.uint32("rasta.safety.cts", "Confirmed time stamp")
local safety_protocol_version    = ProtoField.string("rasta.safety.protocol_version", "Protocol version")
local safety_n_sendmax           = ProtoField.uint16("rasta.safety.n_sendmax", "N sendmax")
local safety_reserve             = ProtoField.new("Reserve", "rasta.safety.reserve", ftypes.BYTES)
local safety_data                = ProtoField.new("Payload data", "rasta.safety.data", ftypes.BYTES)
local safety_detailed            = ProtoField.new("Detailed information", "rasta.safety.detailed", ftypes.BYTES)
local safety_reason              = ProtoField.uint16("rasta.safety.reason", "Reason", base.DEC, vals_disconnect_reason)
local safety_safety_code         = ProtoField.new("Safety code", "rasta.safety.safety_code", ftypes.BYTES)
local safety_safety_code_valid   = ProtoField.new("Safety code valid", "rasta.safety.safety_code_valid", ftypes.BOOLEAN)


p_rasta.fields = {
-- rasta redundancy packet
    redundancy_message_length,
    redundancy_reserve_bytes,
    redundancy_sequence_number,
    redundancy_check_code,
    redundancy_check_code_valid,
-- rasta packet
    safety_message_length,
    safety_message_type,
    safety_dest_id,
    safety_src_id,
    safety_sequence_number,
    safety_c_sequence_number,
    safety_timestamp,
    safety_c_timestamp,
    safety_data,
    safety_protocol_version,
    safety_n_sendmax,
    safety_reserve,
    safety_detailed,
    safety_reason,
    safety_safety_code,
    safety_safety_code_valid
}

-- redundancy dissector
function p_rasta.dissector(buf, pktinfo, root)
    pktinfo.cols.protocol:set("RaSTA")

    local pktlen = buf:reported_length_remaining()
    local tree = root:add(p_rasta, buf:range(0, pktlen))
    local data_length = buf:range(8,2):le_uint() - 28
    -- print(pktlen)

    -- redundancy layer
    local redundancy = tree:add(p_rasta, buf(), "Redundancy Layer")

    redundancy:add_le(redundancy_message_length,    buf:range(0, 2))
    redundancy:add_le(redundancy_reserve_bytes,     buf:range(2, 2))
    redundancy:add_le(redundancy_sequence_number,   buf:range(4, 4))
    local red_code_itm = redundancy:add_le(redundancy_check_code,        buf:range(data_length + 28 + p_rasta.prefs.safety_code_len,
        pktlen - data_length - 28 - p_rasta.prefs.safety_code_len ))

    -- select crc options from preferences
    if p_rasta.prefs.crc_algo == CRC_NONE then
        CRC_OPTION = nil
        CRC_LENGTH = 0
    elseif p_rasta.prefs.crc_algo == CRC32_EE5B42FD then
        CRC_OPTION = CRC.opt_b()

        CRC_LENGTH = 4
    elseif p_rasta.prefs.crc_algo == CRC32_1EDC6F41 then
        CRC_OPTION = CRC.opt_c()
        CRC_LENGTH = 4
    elseif p_rasta.prefs.crc_algo == CRC16_1021 then
        CRC_OPTION = CRC.opt_d()
        CRC_LENGTH = 2
    elseif p_rasta.prefs.crc_algo == CRC16_8005 then
        CRC_OPTION = CRC.opt_e()
        CRC_LENGTH = 2
    end


    if CRC_LENGTH > 0 then
        print("ENTER")
        -- check redundancy crc code for validity
        local redundancy_packet = buf:raw(0, pktlen - CRC_OPTION.width/8)
        local expected_crc = string.format("%0" .. CRC_OPTION.width/4 .."x", swap_endianness(CRC.calculate(CRC_OPTION, redundancy_packet)))
        local actual_crc = Stream.toHex(Stream.fromString(buf:raw(data_length + 28 + p_rasta.prefs.safety_code_len, CRC_OPTION.width/8))):lower()

        if ( expected_crc == actual_crc ) then
          -- valid CRC
          valid_item = redundancy:add(redundancy_check_code_valid, buf:range(data_length + 28 + p_rasta.prefs.safety_code_len, CRC_OPTION.width/8), true)
          valid_item:set_generated()
          print("VALID CRC")
        else
          -- invalid CRC
          red_code_itm:add_expert_info(PI_CHECKSUM, PI_WARN, "Invalid Checksum, expected " .. expected_crc)

          valid_item = redundancy:add(redundancy_check_code_valid, buf:range(data_length + 28 + p_rasta.prefs.safety_code_len, CRC_OPTION.width/8), false)
          valid_item:set_generated()
        end
    end

    -- safety and retransmission layer
    local msg_type = buf:range(10,2)
    pktinfo.cols.info:append(" " .. get_rasta_type_short(msg_type:le_uint()))

    local safety = tree:add(p_rasta,  buf:range(8, 28 + data_length), "Safety and Retransmission Layer")

    safety:add_le(safety_message_length,      buf:range(8, 2))
    safety:add_le(safety_message_type,        buf:range(10, 2))
    safety:add_le(safety_dest_id,             buf:range(12, 4))
    safety:add_le(safety_src_id,              buf:range(16, 4))
    safety:add_le(safety_sequence_number,     buf:range(20, 4))
    safety:add_le(safety_c_sequence_number,   buf:range(24, 4))
    safety:add_le(safety_timestamp,           buf:range(28, 4))
    safety:add_le(safety_c_timestamp,         buf:range(32, 4))

    if (msg_type:le_uint() == 6200 or msg_type:le_uint() == 6201) then
        -- connection request or connection response
        safety:add(safety_protocol_version, buf:range(36, 4))
        safety:add_le(safety_n_sendmax, buf:range(40, 2))
        safety:add_le(safety_reserve, buf:range(42, 8))
    elseif (msg_type:le_uint() == 6240 or msg_type:le_uint() == 6241) then
        -- data and retransmitted data
        local payload = safety:add_le(safety_data, buf:range(36, data_length - p_rasta.prefs.safety_code_len))
        if p_rasta.prefs.packetization then
            local pos = 36
            local max_pos = 36 + data_length - p_rasta.prefs.safety_code_len
            while  pos < max_pos do
                local msg_length = buf:range(pos,2):le_uint()
                payload:add_le(buf:range(pos+2, msg_length):string())
                pos = pos + 2 + msg_length
            end
        end

        -- call sci-dissector if possible
        if p_rasta.prefs.sci and pcall(function () Dissector.get("sci") end) then
            Dissector.get("sci"):call(buf:range(36, data_length - p_rasta.prefs.safety_code_len):tvb(), pktinfo, root)
        end
    elseif (msg_type:le_uint() == 6216) then
        -- disconnect request message
        safety:add_le(safety_detailed, buf:range(36, 2))
        safety:add_le(safety_reason, buf:range(38, 2))
    end

    -- check safety code
    if p_rasta.prefs.safety_code_algo == ALGO_MD4 then
        local safety_packet = buf:raw(8, pktlen - 8 - p_rasta.prefs.safety_code_len)
        local md4_a = tonumber(p_rasta.prefs.md4_a, 16)
        local md4_b = tonumber(p_rasta.prefs.md4_b, 16)
        local md4_c = tonumber(p_rasta.prefs.md4_c, 16)
        local md4_d = tonumber(p_rasta.prefs.md4_d, 16)
        local packet_md4 = MD4()
            .init(md4_a, md4_b, md4_c, md4_d)
            .update(Stream.fromString(safety_packet))
            .finish()
            .asHex()

        local expected_md4 = packet_md4:sub(0, p_rasta.prefs.safety_code_len * 2):lower()
        local actual_md4 = Stream.toHex(Stream.fromString(buf:raw(36 + data_length - 8, 8))):lower()

        local treeItm = safety:add(safety_safety_code, buf:range(36 + data_length - 8, 8))

        if ( expected_md4 == actual_md4 ) then
          -- valid MD4
          valid_item = safety:add(safety_safety_code_valid, buf:range(36 + data_length - 8, 8), true)
          valid_item:set_generated()
        else
          -- invalid MD4
          treeItm:add_expert_info(PI_CHECKSUM, PI_WARN, "Invalid Checksum, expected " .. expected_md4)

          valid_item = safety:add(safety_safety_code_valid, buf:range(36 + data_length - 8, 8), false)
          valid_item:set_generated()
        end
    else
        -- blake2b and siphash-2-4 not supported
        safety:add_expert_info(PI_CHECKSUM, PI_WARN, "Checksum algorithm not supported")
    end

    return pktlen
end

local function heuristic_checker(buffer, pinfo, tree)
    -- guard for length
    length = buffer:len()
    if length < 36 then return false end

    -- reserve in redundancy layer
    local potential_proto_flag = buffer(2,2):uint()
    if potential_proto_flag ~= 0x0000 then return false end

    -- RaSTA SR message type
    local potential_msg_type = buffer(10,2):le_uint()

    if get_rasta_type_short(potential_msg_type) ~= "unknown type"
    then
        p_rasta.dissector(buffer, pinfo, tree)
        return true
    else return false end
end

p_rasta:register_heuristic("tcp", heuristic_checker)
p_rasta:register_heuristic("udp", heuristic_checker)


-- HELPER FUNCTION SECTION

function get_rasta_type_short(type)
    if      (type == 6200) then  return "ConnReq"
    elseif  (type == 6201) then  return "ConnResp"
    elseif  (type == 6212) then  return "RetrReq"
    elseif  (type == 6213) then  return "RetrResp"
    elseif  (type == 6216) then  return "DiscReq"
    elseif  (type == 6220) then  return "HB"
    elseif  (type == 6240) then  return "Data"
    elseif  (type == 6241) then  return "RetrData"
    else                            return "unknown type"
    end
end

function swap_endianness(num)
    local b0 = bit32.lshift(bit32.band(num, 0x000000ff), 24)
    local b1 = bit32.lshift(bit32.band(num, 0x0000ff00), 8)
    local b2 = bit32.rshift(bit32.band(num, 0x00ff0000), 8)
    local b3 = bit32.rshift(bit32.band(num, 0xff000000), 24)

    return bit32.bor(b0, b1, b2, b3)
end
