-- Wireshark dissector for LEGO Wireless Protocol v3
-- Copyright (C) 2018,2021 David Lechner <david@lechnology.com>
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

-- Usage:
--
-- Start from the command line: wireshark -X lua_script:lwp3_bootloader_dissector.lua
--
-- Or place file in "Personal Lua Plugins" directory found under Help (menu) >
-- About Wireshark > Folders (tab). Then after the file has been placed there,
-- Analyze (menu) > Reload Lua Plugins.



---- Protocol: declare the names we will see in Wireshark ---

local lwp3bl_proto = Proto("LWP3BL", "LEGO Wireless Protocol v3 Bootloader Service")

-- Commands
-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#flash-loader-functions-0x01
lwp3bl_proto.fields.command = ProtoField.uint8("lwp3bl.command", "Command", base.HEX)

-- Parameters
-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#flash-loader-functions-message-format
lwp3bl_proto.fields.status = ProtoField.uint8("lwp3bl.status", "Status", base.HEX)
lwp3bl_proto.fields.checksum = ProtoField.uint8("lwp3bl.checksum", "Checksum", base.HEX)
lwp3bl_proto.fields.flash_state = ProtoField.uint8("lwp3bl.flash_state", "Flash State", base.HEX)
lwp3bl_proto.fields.byte_count = ProtoField.uint32("lwp3bl.byte_count", "Byte Count", base.DEC)
lwp3bl_proto.fields.size = ProtoField.uint8("lwp3bl.size", "Size", base.DEC)
lwp3bl_proto.fields.addr = ProtoField.uint32("lwp3bl.addr", "Flash Address", base.HEX)
lwp3bl_proto.fields.payload = ProtoField.bytes("lwp3bl.payload", "Payload", base.SPACE)
lwp3bl_proto.fields.start_addr = ProtoField.uint32("lwp3bl.start_addr", "Flash Start Address", base.HEX)
lwp3bl_proto.fields.end_addr = ProtoField.uint32("lwp3bl.end_addr", "Flash End Address", base.HEX)
lwp3bl_proto.fields.version = ProtoField.string("lwp3bl.version", "Bootloader Version")
lwp3bl_proto.fields.sys_type_id = ProtoField.uint8("lwp3bl.sys_type_id", "System Type ID", base.HEX)


---- Enmerations: lookup tables for enum values ----

local command = {
    [0x11] = "Erase Flash",
    [0x22] = "Program Flash",
    [0x33] = "Start App",
    [0x44] = "Initiate Loader",
    [0x55] = "Get Info  ",
    [0x66] = "Get Checksum",
    [0x77] = "Get Flash State",
    [0x88] = "Disconnect Device",
}

local status = {
    [0x00] = "Success",
    [0xFF] = "Error",
}

local device_numbers = {
    [0x00] = "WeDo Hub",
    [0x20] = "Duplo Train",
    [0x40] = "Boost Hub",
    [0x41] = "2 Port Hub",
    [0x42] = "2 Port Handset",
    [0x80] = "Technic Medium Hub",
    [0x81] = "Technic Large Hub",
}

local flash_state = {
    [0x00] = "No Protection",
    [0x01] = "Level 1 Protection",
    [0x02] = "Level 2 Protection",
}

---- Value parsers: parse single values and add them to the tree ----

-- parses a string
function parse_string(range, offset, subtree, field)
    local range = range:range(offset, range:len() - offset)
    local value = range:string()
    subtree:add_le(field, range, value)
end

-- parses a 1-byte signed integer
function parse_int8(range, offset, subtree, field)
    local range = range:range(offset, 1)
    local value = range:le_int()
    subtree:add_le(field, range, value)
end

-- parses a 1-byte unsigned integer
function parse_uint8(range, offset, subtree, field)
    local range = range:range(offset, 1)
    local value = range:le_uint()
    subtree:add_le(field, range, value)
end

-- parses a 2-byte unsigned integer
function parse_uint16(range, offset, subtree, field)
    local range = range:range(offset, 2)
    local value = range:le_uint()
    subtree:add_le(field, range, value)
end

-- parses a 4-byte unsigned integer
function parse_uint32(range, offset, subtree, field)
    local range = range:range(offset, 4)
    local value = range:le_uint()
    subtree:add_le(field, range, value)
end

-- parses a 1-byte unsigned integer as a Network ID
function parse_net_id(range, offset, subtree, field)
    local range = range:range(offset, 1)
    local value = range:le_uint()
    local net_id_tree = subtree:add_le(field, range, value)

    net_id_tree:append_text(" (" .. last_network_ids[value] .. ")")
end

-- parses a 6-byte Bluetooth address
function parse_bd_addr(range, offset, subtree, field)
    local range = range:range(offset, 6)
    local value = range:ether()
    subtree:add_le(field, range, value)
end

-- parses a 4-byte version number and format's it using LEGO's weird 0.0.00.0000 format
-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#version-number-encoding
function parse_version(range, offset, subtree, field)
    local bcd = range:range(offset + 3, 1):le_uint()
    local major = bit32.rshift(bcd, 4)
    local minor = bit32.band(bcd, 0xf)
    bcd = range:range(offset + 2, 1):le_uint()
    local bug_fix = bit32.rshift(bcd, 4) * 10 + bit32.band(bcd, 0xf)
    bcd = range:range(offset + 1, 1):le_uint()
    local build = bit32.rshift(bcd, 4) * 1000 + bit32.band(bcd, 0xf) * 100
    bcd = range:range(offset, 1):le_uint()
    build = build + bit32.rshift(bcd, 4) * 10 + bit32.band(bcd, 0xf)
    local value = string.format("%d.%d.%02d.%04d", major, minor, bug_fix, build)
    subtree:add_le(field, range:range(offset, 4), value)
end

-- parses a 1-byte status
function parse_status(range, offset, subtree, field)
    local range = range:range(offset, 1)
    local value = range:le_uint()
    local sys_type_id_tree = subtree:add_le(field, range, value)
    sys_type_id_tree:append_text(" (" .. status[value] .. ")")
end

-- parses a 1-byte device id
function parse_sys_type_id(range, offset, subtree, field)
    local range = range:range(offset, 1)
    local value = range:le_uint()
    local sys_type_id_tree = subtree:add_le(field, range, value)
    sys_type_id_tree:append_text(" (" .. device_numbers[value] .. ")")
end

-- parses a 1-byte flash state
function parse_flash_state(range, offset, subtree, field)
    local range = range:range(offset, 1)
    local value = range:le_uint()
    local sys_type_id_tree = subtree:add_le(field, range, value)
    sys_type_id_tree:append_text(" (" .. flash_state[value] .. ")")
end


---- Message parsers: parse the data of specific message types ----

function parse_erase_flash(range, pinfo, subtree)
    if pinfo.p2p_dir == 1 then
        parse_status(range, 0, subtree, lwp3bl_proto.fields.status)
    end
end

function parse_program_flash(range, pinfo, subtree)
    if pinfo.p2p_dir == 1 then
        parse_uint8(range, 0, subtree, lwp3bl_proto.fields.checksum)
        parse_uint32(range, 1, subtree, lwp3bl_proto.fields.byte_count)
    else
        parse_uint8(range, 0, subtree, lwp3bl_proto.fields.size)
        parse_uint32(range, 1, subtree, lwp3bl_proto.fields.addr)
        local payload_range = range(5)
        local payload_tree = subtree:add(lwp3bl_proto.fields.payload, payload_range)
        payload_tree:append_text(" (" .. payload_range:len() .. " bytes)")
    end
end

function parse_start_app(range, pinfo, subtree)
    -- no parameters
end

function parse_init_loader(range, pinfo, subtree)
    if pinfo.p2p_dir == 1 then
        parse_status(range, 0, subtree, lwp3bl_proto.fields.status)
    else
        parse_uint32(range, 0, subtree, lwp3bl_proto.fields.byte_count)
    end
end

function parse_get_info(range, pinfo, subtree)
    if pinfo.p2p_dir == 1 then
        parse_version(range, 0, subtree, lwp3bl_proto.fields.version)
        parse_uint32(range, 4, subtree, lwp3bl_proto.fields.start_addr)
        parse_uint32(range, 8, subtree, lwp3bl_proto.fields.end_addr)
        parse_sys_type_id(range, 12, subtree, lwp3bl_proto.fields.sys_type_id)
    end
end

function parse_get_checksum(range, pinfo, subtree)
    if pinfo.p2p_dir == 1 then
        parse_uint8(range, 0, subtree, lwp3bl_proto.fields.checksum)
    end
end

function parse_get_flash_state(range, pinfo, subtree)
    if pinfo.p2p_dir == 1 then
        parse_flash_state(range, 0, subtree, lwp3bl_proto.fields.flash_state)
    end
end

function parse_disconnect_device(range, pinfo, subtree)
    -- no parameters
end


---- message types: table of possible message types and subcommands ----

-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#flash-loader-functions-0x01
local commands = {
    [0x05] = {
        name = "Generic Error Messages",
        parse_msg = parse_error,
    },
    [0x11] = {
        name = "Erase Flash",
        parse_msg = parse_erase_flash,
    },
    [0x22] = {
        name = "Program Flash",
        parse_msg = parse_program_flash,
    },
    [0x33] = {
        name = "Start App",
        parse_msg = parse_start_app,
    },
    [0x44] = {
        name = "Initiate Loader",
        parse_msg = parse_init_loader,
    },
    [0x55] = {
        name = "Get Info",
        parse_msg = parse_get_info,
    },
    [0x66] = {
        name = "Get Checksum",
        parse_msg = parse_get_checksum,
    },
    [0x77] = {
        name = "Get Flash State",
        parse_msg = parse_get_flash_state,
    },
    [0x88] = {
        name = "Disconnect Device",
        parse_msg = parse_disconnect_device,
    },
}


---- Dissector: the entry point for the dissector ----

function lwp3bl_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then
        return
    end

    pinfo.cols.protocol = lwp3bl_proto.name
    -- TODO: could also set pinfo.cols.info

    local subtree = tree:add(lwp3bl_proto, buffer())

    -- all messages start with the command with the exception of error messages
    local cmd_range = buffer(0, 1)
    local cmd = cmd_range:le_uint()
    -- TODO: if cmd == 0x05, then parse error message
    local cmd_tree = subtree:add_le(lwp3bl_proto.fields.command, cmd_range, cmd)
    local cmd_info = commands[cmd]
    cmd_tree:append_text(" (" .. cmd_info.name .. ")")

    cmd_info.parse_msg(buffer(1), pinfo, subtree)
end

bluetooth_table = DissectorTable.get("bluetooth.uuid")
-- LWP3 Bootloader characteristic UUID
bluetooth_table:add("00001626-1212-efde-1623-785feabcd123", lwp3bl_proto)
