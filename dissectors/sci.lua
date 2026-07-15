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
    version = "1.6.0",
    description = "Dissector to parse Standard Communication Interface (SCI) protocols.",
    repository = "https://github.com/Railway-CCS/dissectors"
}

set_plugin_info(my_info)

------------------------
--------- SCI  ---------
------------------------
-- SCI-TDS is baseline 4.3

local p_sci = Proto("sci", "SCI Protocol")

local ENC_BE = 0
local ENC_LE = 1

p_sci.prefs.endianess = Pref.enum("Message Type Endianess", ENC_LE, "Endianess for Message Type Protocol Field", {
    {1, "Little Endian", ENC_LE},
    {2, "Big Endian", ENC_BE}
}, false)

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

local valuestring_zs2 = {    
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
    [0x40] = "SCI-P",
    [0x20] = "SCI-TDS"
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

local sci_tds_msg_types = {
        [0x0024] = "Request for version comparison",
        [0x0025] = "Response to version comparison",
        [0x0021] = "Request for sending of status information",
        [0x0022] = "Transmission of status information begins",
        [0x0023] = "Transmission of status information ended",
        [0x0026] = "Status report completed",
        [0x0027] = "Request to close PDI connection",
        [0x0028] = "Release PDI for maintenance",
        [0x0029] = "PDI available",
        [0x002A] = "PDI connection is not available",
        [0x002B] = "Reset PDI",
        [0x0001] = "FC",
        [0x0002] = "Update filling level",
        [0x0003] = "DRFC",
        [0x0008] = "Cancel",
        [0x0006] = "Command Rejected",
        [0x0007] = "TVPS occupancy status",
        [0x0010] = "TVPS FC-P failed",
        [0x0011] = "TVPS FC-P-A failed",
        [0x0012] = "Additional information",
        [0x000B] = "TDP status"
}

local sci_tds_message_type   = ProtoField.uint16("sci.message_type", "Message Type", base.HEX, sci_tds_msg_types)

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
local sci_btp_version       = ProtoField.uint8("sci.btp_version", "PDI-Version")
local sci_result_pdi_version_check = ProtoField.uint8("sci.sci_result_pdi_version_check", "Result of PDI Version Check", base.HEX, {
    [0x01] = "PDI-Versions from Receiver and Sender do not match.",
    [0x02] = "PDI-Versions from Receiver and Sender do match."
})
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
local sci_close_reason      = ProtoField.uint8("sci.close_reason", "Close Reason")
local sci_reset_reason      = ProtoField.uint8("sci.reset_reason", "Reset Reason")

local sci_tds_occ_status    = ProtoField.uint8("sci.tds_occ_status", "Occupancy Status", base.HEX, {
    [0x01] = "vacant",
    [0x02] = "occupied",
    [0x03] = "disturbed",
    [0x04] = "waiting for a sweeping train after FC-P-A or FC-P command",
    [0x05] = "waiting for an acknowledgment after FC-P-A command",
    [0x06] = "sweeping train detected"
})

local sci_tds_forced_to_clr    = ProtoField.uint8("sci.tds_forced_to_clr", "Ability to be forced to clear", base.HEX, {
    [0x01] = "not able to be forced to clear",
    [0x02] = "able to be forced to clear",
})

local sci_tds_filling_level    = ProtoField.int16("sci.tds_filling_level", "Filling Level", base.DEC)
local sci_tds_na_filling_lvl  = ProtoField.uint16("sci.tds_filling_level_na", "Filling level is not applicable", base.HEX)

local sci_tds_pom    = ProtoField.uint8("sci.tds_pom", "POM Status", base.HEX, {
    [0x01] = "Power supply OK",
    [0x02] = "Power supply not OK",
    [0xFF] = "POM Status is not applicable",
})

local sci_tds_disturbance_status    = ProtoField.uint8("sci.tds_disturbance_status", "Disturbance Status", base.HEX, {
    [0x01] = "Disturbance is operational",
    [0x02] = "Disturbance is technical",
    [0xFF] = "Disturbance status is not applicable",
})

local sci_tds_change_trigger    = ProtoField.uint8("sci.tds_change_trigger", "Change Trigger", base.HEX, {
    [0x01] = "Passing detected",
    [0x02] = "Command from EIL accepted",
    [0x03] = "Command from maintainer accepted",
    [0x04] = "Technical failure",
    [0x05] = "Initial section state",
    [0x06] = "Internal trigger",
    [0xFF] = "Change Trigger is not applicable",
})

local sci_tds_state_of_passing = ProtoField.uint8("sci.tds_state_of_passing", "State of passing", base.HEX, {
    [0x01] = "not passed",
    [0x02] = "passed",
    [0x03] = "disturbed"
})
local sci_tds_dir_of_passing   = ProtoField.uint8("sci.tds_dir_of_passing", "Direction of passing", base.HEX, {
    [0x01] = "reference direction",
    [0x02] = "against reference direction",
    [0x03] = "without indicated direction"
})

local sci_tds_reason_for_rejection   = ProtoField.uint8("sci.tds_reason_for_rejection", "Reason for rejection", base.HEX, {
    [0x01] = "operational rejected",
    [0x02] = "technical rejected"
})

local sci_tds_reason_for_failure   = ProtoField.uint8("sci.tds_reason_for_failure", "Reason for failure", base.HEX, {
    [0x01] = "incorrect count of the sweeping train",
    [0x02] = "Timeout 'Con_tmax_Response_Time_FC_P' had expired",
    [0x03] = "Bounding detection point is configured as not permitted for FC-P",
    [0x04] = "Intentionally deleted",
    [0x05] = "Outgoing axle detected before expiration of minimum timer",
    [0x06] = "Process cancelled"
})

local sci_tds_reason_for_failure2   = ProtoField.uint8("sci.tds_reason_for_failure", "Reason for failure", base.HEX, {
    [0x01] = "incorrect count of the sweeping train",
    [0x02] = "Timeout 'Con_tmax_Response_Time_FC_P_A' had expired",
    [0x03] = "Bounding detection point is configured as not permitted for FC-P-A",
    [0x04] = "Intentionally deleted",
    [0x05] = "Outgoing axle detected before expiration of minimum timer",
    [0x06] = "Process cancelled"
})

local sci_tds_speed    = ProtoField.uint16("sci.tds_speed", "Speed km/h", base.DEC)
local sci_tds_wheel_dia = ProtoField.uint16("sci.tds_wheel_dia", "Wheel dia mm", base.DEC)

local sci_tds_mode_of_fc   = ProtoField.uint8("sci.tds_mode_of_fc", "Mode of FC", base.HEX, {
    [0x01] = "FC-U",
    [0x02] = "FC-C",
    [0x03] = "FC-P-A",
    [0x04] = "FC-P",
    [0x05] = "Acknowledgment after FC-P-A command"
})

p_sci.fields = {
    -- sci packet
        sci_packet_length,
        sci_protocol_type,
        sci_ls_message_type,
        sci_tds_message_type,
        sci_p_message_type,
        sci_dest_id,
        sci_src_id,
        sci_btp_version,
        sci_result_pdi_version_check,
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
        sci_gate_2,
        sci_close_reason,
        sci_reset_reason,
        sci_tds_occ_status,
        sci_tds_forced_to_clr,
        sci_tds_filling_level,
        sci_tds_na_filling_lvl,
        sci_tds_pom,
        sci_tds_disturbance_status,
        sci_tds_change_trigger,
        sci_tds_state_of_passing,
        sci_tds_dir_of_passing,
        sci_tds_reason_for_rejection,
        sci_tds_reason_for_failure,
        sci_tds_reason_for_failure2,
        sci_tds_speed,
        sci_tds_wheel_dia,
        sci_tds_mode_of_fc
    }

local format_data
local bcd16_to_uint

function p_sci.dissector(buf, pktinfo, root)

    local pktlen = buf:reported_length_remaining()
    local sci = nil
    local position = 0

    -- included SCI packet
    if (pktlen - position) >= 45 then
        if ((buf:range(position+2, 1):le_uint() == 0x40) or 
            (buf:range(position+2, 1):le_uint() == 0x30) or
            (buf:range(position+2, 1):le_uint() == 0x20)) then 
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
        elseif (buf:range(position+2, 1):le_uint() == 0x20) then packet_type = "SCI-TDS"
        else packet_type = "not an SCI-X Packet"
        end

        local sci_length = buf(position, 2):le_uint()
        local sci_sub = sci:add(p_sci, buf:range(position, sci_length+2), packet_type)
        -- read packet length
        sci_sub:add_le(sci_packet_length, buf(position, 2))
        position = position + 2
        -- add sci packet
        local sci_type = buf:range(position, 1):le_uint()
        local mtype = nil
        if p_sci.prefs.endianess == ENC_LE then
            mtype = buf:range(position + 1, 2):le_uint()
        else
            mtype = buf:range(position + 1, 2):uint()
        end
        sci_sub:add(sci_protocol_type, buf:range(position, 1))
        if (sci_type == 0x30) then
            if p_sci.prefs.endianess == ENC_LE then
                sci_sub:add_le(sci_ls_message_type, buf:range(position + 1, 2))
            else
                sci_sub:add(sci_ls_message_type, buf:range(position + 1, 2))
            end
			local msgType = sci_ls_msg_types[mtype];
			if msgType == nil then
				pktinfo.cols.info:append(" (Unknown Message Type)")
			else
				pktinfo.cols.info:append(" (" .. msgType .. ")")
			end
        end
        if (sci_type == 0x40) then
            if p_sci.prefs.endianess == ENC_LE then
                sci_sub:add_le(sci_p_message_type, buf:range(position + 1, 2))
            else
                sci_sub:add_le(sci_p_message_type, buf:range(position + 1, 2))
            end
			local msgType = sci_p_msg_types[mtype];
			if msgType == nil then
				pktinfo.cols.info:append(" (Unknown Message Type)")
			else
				pktinfo.cols.info:append(" (" .. msgType .. ")")
			end
        end
        if (sci_type == 0x20) then
            sci_sub:add_le(sci_tds_message_type, buf:range(position + 1, 2))
            local msgType = sci_tds_msg_types[mtype];
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

        -- increase position
        position = position + sci_length
    end
end


-------
------- HELPER FUNCTIONS
-------

-- Decode a 2-byte packed BCD field into a real integer.
-- Returns nil if any nibble isn't a valid BCD digit (0-9).
function bcd16_to_uint(buf_range)
    local raw = buf_range:uint()  -- e.g. 0x1234
    local value = 0
    local mult = 1

    for shift = 0, 12, 4 do
        local nibble = bit.band(bit.rshift(raw, shift), 0xF)
        if nibble > 9 then
            return nil -- invalid BCD digit
        end
        value = value + nibble * mult
        mult = mult * 10
    end

    return value
end

function format_data(sci_type, mtype, sci_sub, buf, position)
    -- SCI-Generic
    if (sci_type == 0x30) or (sci_type == 0x40) or (sci_type == 0x20) then
        if (mtype == 0x0024) then
            sci_sub:add(sci_btp_version, buf:range(43+position, 1))
        end
        if (mtype == 0x0025) then
            sci_sub:add(sci_result_pdi_version_check, buf:range(43+position, 1))
            sci_sub:add(sci_btp_version, buf:range(44+position, 1))
            sci_sub:add(sci_crc_length, buf:range(45+position, 1))
            local l = buf:range(45+position, 1):le_uint()
            if (l > 0) then
                sci_sub:add(sci_crc, buf:range(46+position, l))
            end
        end
        if (mtype == 0x0027) then
            sci_sub:add(sci_close_reason, buf:range(43+position, 1))
        end
        if (mtype == 0x002B) then
            sci_sub:add(sci_reset_reason, buf:range(43+position, 1))
        end
    end
    -- SCI-LS
    if (sci_type == 0x30) then
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
        if (mtype == 0x0001) then
            sci_sub:add(sci_gate, buf:range(43+position, 1))
        end
        if (mtype == 0x000B) then
            sci_sub:add(sci_gate_2, buf:range(43+position, 1))
        end
    end
    -- SCI-TDS
    if (sci_type == 0x20) then
        if (mtype == 0x0006) then
            sci_sub:add(sci_tds_reason_for_rejection, buf:range(43+position, 1))
        end
        if (mtype == 0x0007) then
            sci_sub:add(sci_tds_occ_status, buf:range(43+position, 1))
            sci_sub:add(sci_tds_forced_to_clr, buf:range(44+position, 1))
            local filling_level = buf:range(45+position, 2):le_uint()
            if filling_level == 0xFFFF then
                sci_sub:add(sci_tds_na_filling_lvl, buf:range(45+position, 2))
            else
                sci_sub:add(sci_tds_filling_level, buf:range(45+position, 2))
            end
            sci_sub:add(sci_tds_pom, buf:range(47+position, 1))
            sci_sub:add(sci_tds_disturbance_status, buf:range(48+position, 1))
            sci_sub:add(sci_tds_change_trigger, buf:range(49+position, 1))
        end
        if (mtype == 0x000B) then
            sci_sub:add(sci_tds_state_of_passing, buf:range(43+position, 1))
            sci_sub:add(sci_tds_dir_of_passing, buf:range(44+position, 1))
        end
        if (mtype == 0x0010) then
            sci_sub:add(sci_tds_reason_for_failure, buf:range(43+position, 1))
        end
        if (mtype == 0x0011) then
            sci_sub:add(sci_tds_reason_for_failure2, buf:range(43+position, 1))
        end
        if (mtype == 0x0012) then
            local speed_range = buf:range(43+position, 2)
            local speed_val = bcd16_to_uint(speed_range)
            if speed_val then
                sci_sub:add(sci_tds_speed, speed_range, speed_val)
            else
                -- fall back to showing raw bytes with an "invalid BCD" note
                local item = sci_sub:add(sci_tds_speed, speed_range, 0)
                item:add_expert_info(PI_MALFORMED, PI_WARN, "Invalid BCD value")
            end
            local dia_range = buf:range(45+position, 2)
            local dia_val = bcd16_to_uint(dia_range)
            if dia_val then
                sci_sub:add(sci_tds_wheel_dia, dia_range, dia_val)
            else
                -- fall back to showing raw bytes with an "invalid BCD" note
                local item = sci_sub:add(sci_tds_wheel_dia, dia_range, 0)
                item:add_expert_info(PI_MALFORMED, PI_WARN, "Invalid BCD value")
            end
        end
        if (mtype == 0x0001) then
            sci_sub:add(sci_tds_mode_of_fc, buf:range(43+position, 1))
        end
    end
end
