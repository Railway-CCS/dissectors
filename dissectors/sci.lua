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
    description = "Dissector to parse Standard Communication Interface (SCI) protocols.",
    repository = "https://github.com/Railway-CCS/dissectors"
}

set_plugin_info(my_info)

------------------------
--- SCI-P & SCI-LS -----
--
------------------------

local p_sci = Proto("sci", "SCI Protocol")
local valuestring_zs3 = {
    [0x00] = "Not used",
    [0x01] = "Number 1",
    [0x02] = "Number 2",
    [0x03] = "Number 3",
    [0x04] = "Number 4",
    [0x05] = "Number 5",
    [0x06] = "Number 6",
    [0x07] = "Number 7",
    [0x08] = "Number 8",
    [0x09] = "Number 9",
    [0x0A] = "Number 10",
    [0x0B] = "Number 11",
    [0x0C] = "Number 12",
    [0x0D] = "Number 13",
    [0x0E] = "Number 14",
    [0x0F] = "Number 15",
    [0xFF] = "Off"
}

valuestring_zs2 = {    
    [0x00] = "Not used",
    [0x01] = "Character A",
    [0x02] = "Character B",
    [0x03] = "Character C",
    [0x04] = "Character D",
    [0x05] = "Character E",
    [0x06] = "Character F",
    [0x07] = "Character G",
    [0x08] = "Character H",
    [0x09] = "Character I",
    [0x0A] = "Character J",
    [0x0B] = "Character K",
    [0x0C] = "Character L",
    [0x0D] = "Character M",
    [0x0E] = "Character N",
    [0x0F] = "Character O",
    [0x10] = "Character P",
    [0x11] = "Character Q",
    [0x12] = "Character R",
    [0x13] = "Character S",
    [0x14] = "Character T",
    [0x15] = "Character U",
    [0x16] = "Character V",
    [0x17] = "Character W",
    [0x18] = "Character X",
    [0x19] = "Character Y",
    [0x1A] = "Character Z",
    [0xFF] = "Off"
}


-- sci properties
local sci_packet_length     = ProtoField.uint16("sci.packet_length", "Packet Length")
local sci_protocol_type     = ProtoField.uint8("sci.type", "Protocol Type", base.HEX, {
    [0x30] = "SCI-LS",
    [0x40] = "SCI-P"
})

local sci_ls_msg_types = {
        [0x0024] = "Request for version comparison",
        [0x0025] = "Response to version comparison",
        [0x0021] = "Request for sending of status information",
        [0x0022] = "Transmission of status information begins",
        [0x0023] = "Transmission of status information ended",
        [0x0001] = "Indicate Signal Aspect Command",
        [0x0002] = "Set Luminosity Command",
        [0x0003] = "Indicate Signal Aspect Message",
        [0x0004] = "Set Luminosity Message"
}

local sci_ls_message_type   = ProtoField.uint16("sci.message_type", "Message Type", base.HEX, sci_ls_msg_types)

local sci_p_msg_types = {
        [0x0024] = "Request for version comparison",
        [0x0025] = "Response to version comparison",
        [0x0021] = "Request for sending of status information",
        [0x0022] = "Transmission of status information begins",
        [0x0023] = "Transmission of status information ended",
        [0x0001] = "Move Point Command",
        [0x000B] = "Point Position Message",
        [0x000C] = "Timeout Message"
}

local sci_p_message_type    = ProtoField.uint16("sci.message_type", "Message Type", base.HEX, sci_p_msg_types)

local sci_src_id            = ProtoField.string("sci.src_id", "Sender Identifier")
local sci_dest_id           = ProtoField.string("sci.dest_id", "Receiver Identifier")
local sci_btp_version       = ProtoField.uint8("sci.btp_version", "BTP Version")
local sci_btp_version_2     = ProtoField.uint8("sci.btp_version", "BTP Version in Subsystem")
local sci_btp_version_cmp   = ProtoField.uint8("sci.btp_version_cmp", "Result of BTP Version Comparison")
local sci_crc_length        = ProtoField.uint8("sci.crc_length", "Length of Check Code")
local sci_crc               = ProtoField.uint64("sci.crc", "Check Code")
local sci_nd1               = ProtoField.uint8("sci.nd1", "Basic Aspect Type", base.HEX, {
    [0x00] = "Not used",
    [0x01] = "Hp0",
    [0x02] = "Hp0 + Sh1",
    [0x03] = "Hp0 with departure signal",
    [0x04] = "Ks1",
    [0x05] = "Ks1 blinking",
    [0x06] = "Ks1 blinking and additional light",
    [0x07] = "Ks2",
    [0x08] = "Ks2 with additional light",
    [0x09] = "Sh1",
    [0x0A] = "Kennlicht",
    [0xA0] = "Hp0 (EXT)",
    [0xA1] = "Hp1 (EXT)",
    [0xA2] = "Hp2 (EXT)",
    [0xB0] = "Vr0 (EXT)",
    [0xB1] = "Vr1 (EXT)",
    [0xB2] = "Vr2 (EXT)",
    [0xFF] = "Off"
})
local sci_nd2               = ProtoField.uint8("sci.nd2", "Extension of Basic Aspect Type", base.HEX, {
    [0x00] = "Not used",
    [0x01] = "Zs1",
    [0x02] = "Zs7",
    [0x03] = "Zs8",
    [0x04] = "Zs6",
    [0x05] = "Zs13",
    [0xFF] = "Off"
})
local sci_nd3               = ProtoField.uint8("sci.nd3", "Speed Indicator", base.HEX, valuestring_zs3)
local sci_nd4               = ProtoField.uint8("sci.nd4", "Speed Indicator Announcement", base.HEX, valuestring_zs3)
local sci_nd5               = ProtoField.uint8("sci.nd5", "Direction Indicator", base.HEX, valuestring_zs2)
local sci_nd6               = ProtoField.uint8("sci.nd6", "Direction Indicator Announcement", base.HEX, valuestring_zs2)
local sci_nd7               = ProtoField.uint8("sci.nd7", "Downgrade Information", base.HEX, {
    [0x00] = "Not used",
    [0x01] = "Type1 (Hp0 instead of Ks2)",
    [0x02] = "Type2 (additional light on/off for Ks2)",
    [0x03] = "Type3 (Zs3v visible yes/no)",
    [0xFF] = "No Information"    
})
local sci_nd8               = ProtoField.uint8("sci.nd8", "Route Information")
local sci_nd9               = ProtoField.uint8("sci.nd9", "Signal Aspect Intentionally Dark", base.HEX, {
    [0x00] = "Not used",
    [0x01] = "Indicated in set luminosity",
    [0xFF] = "Indicated to be dark"
})
local sci_nd10              = ProtoField.uint8("sci.nd10", "Luminosity")
local sci_gate              = ProtoField.uint8("sci.gate", "Point Position")
local sci_gate_2            = ProtoField.uint8("sci.gate_2", "Point Position")

p_sci.fields = {
    -- sci packet
        sci_packet_length,
        sci_protocol_type,
        sci_ls_message_type,
        sci_p_message_type,
        sci_dest_id,
        sci_src_id,
        sci_btp_version,
        sci_btp_version_2,
        sci_btp_version_cmp,
        sci_crc_length,
        sci_crc,
        sci_nd1,
        sci_nd2,
        sci_nd3,
        sci_nd4,
        sci_nd5,
        sci_nd6,
        sci_nd7,
        sci_nd8,
        sci_nd9,
        sci_nd10,
        sci_gate,
        sci_gate_2
    }

function p_sci.dissector(buf, pktinfo, root)

    local pktlen = buf:reported_length_remaining()
    local sci = nil
    local position = 0

    -- SCI-P packet
    if (pktlen - position) >= 45 then
        if ((buf:range(position+2, 1):le_uint() == 0x40) or (buf:range(position+2, 1):le_uint() == 0x30)) then 
            sci = root:add(p_sci, buf(), "SCI")
            pktinfo.cols.protocol:set("SCI")
        else
            return
        end
    end

    while (pktlen - position) >= 45 do
        local packet_type = 0;

        if (buf:range(position+2, 1):le_uint() == 0x40) then packet_type = "SCI-P"
        elseif (buf:range(position+2, 1):le_uint() == 0x30) then packet_type = "SCI-LS"
        else packet_type = "not an SCI-X Packet"
        end

        local sci_length = buf(position, 2):le_uint()
        local sci_sub = sci:add(p_sci, buf:range(position, sci_length+2), packet_type)
            -- read packet length
            sci_sub:add_le(sci_packet_length, buf(position, 2))
            position = position + 2
            -- add sci packet
            local sci_type = buf:range(position, 1):le_uint()
            local mtype = buf:range(position + 1, 2):uint()
            sci_sub:add(sci_protocol_type, buf:range(position, 1))
            if (sci_type == 0x30) then
                sci_sub:add_le(sci_ls_message_type, buf:range(position + 1, 2))

				local msgType = sci_ls_msg_types[buf:range(position + 1, 2):le_uint()];
				if msgType == nil then
					pktinfo.cols.info:append(" (Unknown Message Type)")
				else
					pktinfo.cols.info:append(" (" .. msgType .. ")")
				end
            end
            if (sci_type == 0x40) then
                sci_sub:add_le(sci_p_message_type, buf:range(position + 1, 2))

				local msgType = sci_p_msg_types[buf:range(position + 1, 2):le_uint()];
				if msgType == nil then
					pktinfo.cols.info:append(" (Unknown Message Type)")
				else
					pktinfo.cols.info:append(" (" .. msgType .. ")")
				end
            end

			

            sci_sub:add(sci_src_id , buf:range(position + 3, 20))
            sci_sub:add(sci_dest_id , buf:range(position + 23, 20))
            -- data
            format_data(sci_type, mtype, sci_sub, buf, position)
            -- sci_sub:add(sci_data , buf:range(position + 43, sci_length - 43))

            -- increase position
            position = position + sci_length
    end

end


-------
------- HELPER FUNCTIONS
-------

function format_data(sci_type, mtype, sci_sub, buf, position)
    -- SCI-LS
    if (sci_type == 0x30) then
        if (mtype == 0x0024) then
            sci_sub:add(sci_btp_version, buf:range(43+position, 1))
        end
        if (mtype == 0x0025) then
            sci_sub:add(sci_btp_version_cmp, buf:range(43+position, 1))
            sci_sub:add(sci_btp_version_2, buf:range(44+position, 1))
            sci_sub:add(sci_crc_length, buf:range(45+position, 1))
            local l = buf:range(45+position, 1):le_uint()
            if (l > 0) then
                sci_sub:add(sci_crc, buf:range(46+position, l))
            end
        end
        if (mtype == 0x0001) then
            sci_sub:add(sci_nd1, buf:range(43+position, 1))
            sci_sub:add(sci_nd2, buf:range(44+position, 1))
            sci_sub:add(sci_nd3, buf:range(45+position, 1))
            sci_sub:add(sci_nd4, buf:range(46+position, 1))
            sci_sub:add(sci_nd5, buf:range(47+position, 1))
            sci_sub:add(sci_nd6, buf:range(48+position, 1))
            sci_sub:add(sci_nd7, buf:range(49+position, 1))
            sci_sub:add(sci_nd8, buf:range(50+position, 1))
            sci_sub:add(sci_nd9, buf:range(51+position, 1))
        end
        if (mtype == 0x0002) then
            sci_sub:add(sci_nd10, buf:range(43+position, 1))
        end
        if (mtype == 0x0003) then
            sci_sub:add(sci_nd1, buf:range(43+position, 1))
            sci_sub:add(sci_nd2, buf:range(44+position, 1))
            sci_sub:add(sci_nd3, buf:range(45+position, 1))
            sci_sub:add(sci_nd4, buf:range(46+position, 1))
            sci_sub:add(sci_nd5, buf:range(47+position, 1))
            sci_sub:add(sci_nd6, buf:range(48+position, 1))
            sci_sub:add(sci_nd9, buf:range(49+position, 1))
        end
        if (mtype == 0x0004) then
            sci_sub:add(sci_nd10, buf:range(43+position, 1))
        end
    end
    -- SCI-P
    if (sci_type == 0x40) then
        if (mtype == 0x0024) then
            sci_sub:add(sci_btp_version_2, buf:range(43+position, 1))
        end
        if (mtype == 0x0025) then
            sci_sub:add(sci_btp_version_cmp, buf:range(43+position, 1))
            sci_sub:add(sci_btp_version_2, buf:range(44+position, 1))
            sci_sub:add(sci_crc_length, buf:range(45+position, 1))
            local l = buf:range(45+position, 1):le_uint()
            if (l > 0) then
                sci_sub:add(sci_crc, buf:range(46+position, l))
            end
        end
        if (mtype == 0x0001) then
            sci_sub:add(sci_gate, buf:range(43+position, 1))
        end
        if (mtype == 0x000B) then
            sci_sub:add(sci_gate_2, buf:range(43+position, 1))
        end
    end
end
