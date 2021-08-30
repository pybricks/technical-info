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
-- Start from the command line: wireshark -X lua_script:lwp3_dissector.lua
--
-- Or place file in "Personal Lua Plugins" directory found under Help (menu) >
-- About Wireshark > Folders (tab). Then after the file has been placed there,
-- Analyze (menu) > Reload Lua Plugins.



---- Protocol: declare the names we will see in Wireshark ---

local lwp3_proto = Proto("LWP3", "LEGO Wireless Protocol v3 Hub Service")

-- Common Message Header
-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#common-message-header
lwp3_proto.fields.msg_len = ProtoField.uint16("lwp3.msg_len", "Message length", base.DEC)
lwp3_proto.fields.hub_id = ProtoField.uint8("lwp3.hub_id", "Hub ID", base.HEX)
lwp3_proto.fields.msg_type = ProtoField.uint8("lwp3.msg_type", "Message Type", base.HEX)


-- Hub Property Message
-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#hub-property-message-format
lwp3_proto.fields.property = ProtoField.uint8("lwp3.property", "Property", base.HEX)
lwp3_proto.fields.operation = ProtoField.uint8("lwp3.operation", "Property Operation", base.HEX)

-- Hub Property Payload
-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#hub-property-payload
lwp3_proto.fields.hub_prop_adv_name = ProtoField.string("lwp3.hub_prop.adv_name", "Advertising Name")
lwp3_proto.fields.hub_prop_btn_state = ProtoField.int8("lwp3.hub_prop.btn_state", "Button State", base.DEC)
lwp3_proto.fields.hub_prop_fw_ver = ProtoField.string("lwp3.hub_prop.fw_ver", "Firmware Version")
lwp3_proto.fields.hub_prop_hw_ver = ProtoField.string("lwp3.hub_prop.hw_ver", "Hardware Version")
lwp3_proto.fields.hub_prop_rssi = ProtoField.int8("lwp3.hub_prop.rssi", "RSSI", base.DEC)
lwp3_proto.fields.hub_prop_batt_pct = ProtoField.int8("lwp3.hub_prop.batt_pct", "Battery Percent", base.DEC)
lwp3_proto.fields.hub_prop_batt_type = ProtoField.uint8("lwp3.hub_prop.batt_type", "Battery Type", base.HEX)
lwp3_proto.fields.hub_prop_mfg = ProtoField.string("lwp3.hub_prop.mfg", "Manufacturer")
lwp3_proto.fields.hub_prop_radio_ver = ProtoField.string("lwp3.hub_prop.radio_ver", "Radio Firmware Version")
lwp3_proto.fields.hub_prop_lwp_ver = ProtoField.string("lwp3.hub_prop.lwp_ver", "LEGO Wireless Protocol Version")
lwp3_proto.fields.hub_prop_sys_type_id = ProtoField.uint8("lwp3.hub_prop.sys_type_id", "System Type ID", base.HEX)
lwp3_proto.fields.hub_prop_hw_net_id = ProtoField.uint8("lwp3.hub_prop.hw_net_id", "Hardware Network ID", base.DEC)
lwp3_proto.fields.hub_prop_bd_addr = ProtoField.ether("lwp3.hub_prop.bd_addr", "Bluetooth Address")
lwp3_proto.fields.hub_prop_loader_bd_addr = ProtoField.ether("lwp3.hub_prop.loader_bd_addr", "Bootloader Bluetooth Address")
lwp3_proto.fields.hub_prop_hw_net_fam = ProtoField.uint8("lwp3.hub_prop.hw_net_fam", "Hardware Network Family", base.HEX)

-- Hub Alerts
-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#hub-alerts
lwp3_proto.fields.hub_alert_type = ProtoField.uint8("lwp3.hub_alert.type", "Alert Type", base.HEX)
lwp3_proto.fields.hub_alert_op = ProtoField.uint8("lwp3.hub_alert.op", "Alert Operation", base.HEX)
lwp3_proto.fields.hub_alert_payload = ProtoField.uint8("lwp3.hub_alert.payload", "Alert Payload", base.HEX)

-- Hub Attached I/O
-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#hub-attached-i-o
lwp3_proto.fields.hub_io_port_id = ProtoField.uint8("lwp3.hub_io.port_id", "Port ID", base.HEX)
lwp3_proto.fields.hub_io_event = ProtoField.uint8("lwp3.hub_io.event", "Event", base.HEX)
lwp3_proto.fields.hub_io_type_id = ProtoField.uint16("lwp3.hub_io.type_id", "IO Type ID", base.HEX)
lwp3_proto.fields.hub_io_hw_ver = ProtoField.string("lwp3.hub_io.hw_ver", "Hardware Version")
lwp3_proto.fields.hub_io_sw_ver = ProtoField.string("lwp3.hub_io.sw_ver", "Software Version")
lwp3_proto.fields.hub_io_port_id_a = ProtoField.uint8("lwp3.hub_io.port_id_a", "Port ID A", base.HEX)
lwp3_proto.fields.hub_io_port_id_b = ProtoField.uint8("lwp3.hub_io.port_id_b", "Port ID B", base.HEX)

-- Port commands
lwp3_proto.fields.port_id = ProtoField.uint8("lwp3.port_id", "Port ID", base.DEC)
lwp3_proto.fields.port_mode = ProtoField.uint8("lwp3.port_mode", "Mode", base.DEC)
lwp3_proto.fields.port_delta_interval = ProtoField.uint32("lwp3.port_delta_interval", "Delta Interval", base.DEC)
lwp3_proto.fields.port_notification_enabled = ProtoField.uint8("lwp3.port_notification_enabled", "Notification Enabled", base.DEC)
lwp3_proto.fields.port_data = ProtoField.bytes("lwp3.port_data", "Data", base.SPACE)
lwp3_proto.fields.port_startup_and_completion = ProtoField.uint8("lwp3.port_startup_and_completion", "Startup and Completion", base.HEX)
lwp3_proto.fields.port_output_subcommand = ProtoField.uint8("lwp3.port_output_subcommand", "Subcommand", base.HEX)
lwp3_proto.fields.port_payload = ProtoField.bytes("lwp3.port_payload", "Payload", base.SPACE)

---- Enmerations: lookup tables for enum values ----

-- property operations are used by Hub Property (0x01) messages
-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#hub-property-operation
local operations = {
    [0x01] = "Set",
    [0x02] = "Enable Updates",
    [0x03] = "Disable Updates",
    [0x04] = "Reset",
    [0x05] = "Request Update",
    [0x06] = "Update",
}

-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#system-type-and-device-number
local system_types = {
    [0x0] = "LEGO Wedo 2.0",
    [0x1] = "LEGO Duplo",
    [0x2] = "LEGO System",
    [0x3] = "LEGO System",
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

-- IO Type ID
-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#io-type-id
local type_ids = {
    [0x0000] = "None",
    [0x0001] = "Medium Motor",
    [0x0002] = "Train Motor",
    [0x0008] = "Lights",
    [0x0014] = "Hub Battery Voltage",
    [0x0015] = "Hub Battery Current",
    [0x0016] = "Hub Piezo Buzzer",
    [0x0017] = "Hub Status Light",
    [0x0022] = "WeDo 2.0 Tilt Sensor",
    [0x0023] = "WeDo 2.0 Motion Sensor",
    [0x0024] = "WeDo 2.0 Generic Sensor",
    [0x0025] = "BOOST Color and Distance Sensor",
    [0x0026] = "BOOST Interactive Motor",
    [0x0027] = "BOOST Move Hub Built-in Motor",
    [0x0028] = "BOOST Move Hub Built-in Tilt Sensor",
    [0x0029] = "DUPLO Train Motor",
    [0x0030] = "DUPLO Train Piezo Buzzer",
    [0x0031] = "DUPLO Train Color Sensor",
    [0x0032] = "DUPLO Train Speed",
    [0x0037] = "Handset Button",
    [0x0038] = "Handset ?",
}

-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#lst-net
local last_network_ids = {
    [0] = "Unknown",
    [251] = "DEFAULT 1, Locked",
    [252] = "DEFAULT 2, NOT Locked",
    [253] = "DEFAULT 3, RSSI Dependent",
    [254] = "DEFAULT 4, DISABLE H/W Network",
    [255] = "DON’T CARE - NOT Implemented",
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

-- parses a 2-byte version number in BCD format
-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#lwp-version-number-encoding
function parse_lwp_version(range, offset, subtree, field)
    local major = range:range(offset + 1, 1):le_uint()
    local minor = range:range(offset, 1):le_uint()
    local value = string.format("%x.%02x", major, minor)
    subtree:add_le(field, range:range(offset, 2), value)
end

-- parses a 1-byte unsigned integer as a Battery Type
function parse_batt_type(range, offset, subtree, field)
    local range = range:range(offset, 1)
    local value = range:le_uint()
    local batt_type_tree = subtree:add_le(field, range, value)

    local batt_type = {
        [0x00] = "Normal",
        [0x01] = "Rechargeable",
    }
    batt_type_tree:append_text(" (" .. batt_type[value] .. ")")
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

-- parses a 1-byte device id
function parse_sys_type_id(range, offset, subtree, field)
    local range = range:range(offset, 1)
    local value = range:le_int()
    local sys_type_id_tree = subtree:add_le(field, range, value)
    sys_type_id_tree:append_text(" (" .. device_numbers[value] .. ")")
end

-- parses a 1-byte port id
function parse_port_id(range, offset, subtree, field)
    local range = range:range(offset, 1)
    local value = range:le_int()
    local port_id_tree = subtree:add_le(field, range, value)
end

-- parses a 2-byte type id
function parse_type_id(range, offset, subtree, field)
    local range = range:range(offset, 2)
    local value = range:le_int()
    local type_id_tree = subtree:add_le(field, range, value)
    type_id_tree:append_text(" (" .. type_ids[value] .. ")")
end


---- Message parsers: parse the data of specific message types ----

-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#hub-property-reference
local hub_properties = {
    [0x01] = {
        name = "Advertising Name",
        field = lwp3_proto.fields.hub_prop_adv_name,
        parse_update_payload = parse_string,
    },
    [0x02] = {
        name = "Button",
        field = lwp3_proto.fields.hub_prop_btn_state,
        parse_update_payload = parse_uint8,
    },
    [0x03] = {
        name = "FW Version",
        field = lwp3_proto.fields.hub_prop_fw_ver,
        parse_update_payload = parse_version,
    },
    [0x04] = {
        name = "HW Version",
        field = lwp3_proto.fields.hub_prop_hw_ver,
        parse_update_payload = parse_version,
    },
    [0x05] = {
        name = "RSSI",
        field = lwp3_proto.fields.hub_prop_rssi,
        parse_update_payload = parse_int8,
    },
    [0x06] = {
        name = "Battery Voltage",
        field = lwp3_proto.fields.hub_prop_batt_pct,
        parse_update_payload = parse_uint8,
    },
    [0x07] = {
        name = "Battery Type",
        field = lwp3_proto.fields.hub_prop_batt_type,
        parse_update_payload = parse_batt_type,
    },
    [0x08] = {
        name = "Manufacturer Name",
        field = lwp3_proto.fields.hub_prop_mfg,
        parse_update_payload = parse_string,
    },
    [0x09] = {
        name = "Radio Firmware Version",
        field = lwp3_proto.fields.hub_prop_radio_ver,
        parse_update_payload = parse_string,
    },
    [0x0A] = {
        name = "LEGO Wireless Protocol Version",
        field = lwp3_proto.fields.hub_prop_lwp_ver,
        parse_update_payload = parse_lwp_version,
    },
    [0x0B] = {
        name = "System Type ID",
        field = lwp3_proto.fields.hub_prop_sys_type_id,
        parse_update_payload = parse_sys_type_id,
    },
    [0x0C] = {
        name = "H/W Network ID",
        field = lwp3_proto.fields.hub_prop_hw_net_id,
        parse_update_payload = parse_net_id,
    },
    [0x0D] = {
        name = "Primary MAC Address",
        field = lwp3_proto.fields.hub_prop_bd_addr,
        parse_update_payload = parse_bd_addr,
    },
    [0x0E] = {
        name = "Secondary MAC Address",
        field = lwp3_proto.fields.hub_prop_loader_bd_addr,
        parse_update_payload = parse_bd_addr,
    },
    [0x0F] = {
        name = "Hardware Network Family",
        field = lwp3_proto.fields.hub_prop_hw_net_fam,
        parse_update_payload = parse_uint8,
    },
}

-- Parses a hub property (0x01) message
function parse_hub_prop(range, subtree)
    local prop_range = range:range(0, 1)
    local prop = prop_range:le_uint()
    local prop_tree = subtree:add_le(lwp3_proto.fields.property, prop_range, prop)
    local prop_info = hub_properties[prop]
    prop_tree:append_text(" (" .. prop_info.name .. ")")

    local operation_range = range:range(1, 1)
    local operation = operation_range:le_uint()
    local operation_tree = subtree:add_le(lwp3_proto.fields.operation, operation_range, operation)
    operation_tree:append_text(" (" .. operations[operation] .. ")")

    if operation == 0x06 then
        prop_info.parse_update_payload(range, 2, subtree, prop_info.field)
    end
end

function parse_hub_alert(range, subtree)
    local alert_type_range = range:range(0, 1)
    local alert_type = alert_type_range:le_uint()
    local alert_type_tree = subtree:add_le(lwp3_proto.fields.hub_alert_type, alert_type_range, alert_type)
    -- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#alert-type
    local alert_types = {
        [0x01] = "Low Voltage",
        [0x02] = "High Current",
        [0x03] = "Low Signal Strength",
        [0x04] = "Over Power Condition",
    }
    alert_type_tree:append_text(" (" .. alert_types[alert_type] .. ")")

    local alert_op_range = range:range(1, 1)
    local alert_op = alert_op_range:le_uint()
    local alert_op_tree = subtree:add_le(lwp3_proto.fields.hub_alert_op, alert_op_range, alert_op)
    -- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#al-op
    local alert_ops = {
        [0x01] = "Enable Updates",
        [0x02] = "Disable Updates",
        [0x03] = "Request Updates",
        [0x04] = "Update",
    }
    alert_op_tree:append_text(" (" .. alert_ops[alert_op] .. ")")

    -- payload only exists in Downstream messages
    if range:len() <= 2 then
        return
    end

    local alert_payload_range = range:range(2, 1)
    local alert_payload = alert_payload_range:le_uint()
    local alert_payload_tree = subtree:add_le(lwp3_proto.fields.hub_alert_payload, alert_payload_range, alert_payload)
    -- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#al-pay
    local alert_payloads = {
        [0x00] = "Status OK",
        [0xFF] = "Alert!",
    }
    alert_payload_tree:append_text(" (" .. alert_payloads[alert_payload] .. ")")
end

-- Parses a Hub Attached I/O (0x04) message
function parse_hub_attached_io(range, subtree)
    parse_port_id(range, 0, subtree, lwp3_proto.fields.hub_io_port_id)
    
    local event_range = range:range(1, 1)
    local event = event_range:le_uint()
    local event_tree = subtree:add_le(lwp3_proto.fields.hub_io_event, event_range, event)
    -- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#event
    local events = {
        [0x00] = "Detached I/O",
        [0x01] = "Attached I/O",
        [0x02] = "Attached Virtual I/O",
    }
    event_tree:append_text(" (" .. events[event] .. ")")

    if event == 0x01 or event == 0x02 then
        parse_type_id(range, 2, subtree, lwp3_proto.fields.hub_io_type_id)
    end

    if event == 0x01 then
        parse_version(range, 4, subtree, lwp3_proto.fields.hub_io_hw_ver)
        parse_version(range, 8, subtree, lwp3_proto.fields.hub_io_sw_ver)
    end
    
    if event == 0x02 then
        parse_port_id(range, 4, subtree, lwp3_proto.fields.hub_io_port_id_a)
        parse_port_id(range, 5, subtree, lwp3_proto.fields.hub_io_port_id_b)
    end
end

-- Parses a Port Input Format Setup (Single) (0x41) message
function parse_port_setup_single(range, subtree)
    parse_port_id(range, 0, subtree, lwp3_proto.fields.port_id)
    parse_uint8(range, 1, subtree, lwp3_proto.fields.port_mode)
    parse_uint32(range, 2, subtree, lwp3_proto.fields.port_delta_interval)
    parse_uint8(range, 2, subtree, lwp3_proto.fields.port_notification_enabled)
end

-- Parses a Port Value (Single) (0x45) message
function parse_port_val_single(range, subtree)
    parse_port_id(range, 0, subtree, lwp3_proto.fields.port_id)
    
    -- TODO: The interpretation of this data depends on previous messages
    -- received. There could also be additional ports in the same message.
    local data_range = range(1)
    local data_tree = subtree:add(lwp3_proto.fields.port_data, data_range)
    data_tree:append_text(" (" .. data_range:len() .. " bytes)")
end

-- Parses a Port Input Format (Single) (0x47) message
function parse_port_fmt_single(range, subtree)
    parse_port_id(range, 0, subtree, lwp3_proto.fields.port_id)
    parse_uint8(range, 1, subtree, lwp3_proto.fields.port_mode)
    parse_uint32(range, 2, subtree, lwp3_proto.fields.port_delta_interval)
    parse_uint8(range, 2, subtree, lwp3_proto.fields.port_notification_enabled)
end

-- Parses a Port Output Command (0x81) message
function parse_port_out_cmd(range, subtree)
    parse_port_id(range, 0, subtree, lwp3_proto.fields.port_id)

    -- startup and completion
    local sc_range = range:range(1, 1)
    local sc_value = sc_range:le_uint()
    local sc_tree = subtree:add_le(lwp3_proto.fields.port_startup_and_completion, sc_range, sc_value)

    -- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#st-comp
    local startup = {
        [0x0] = "Buffer if necessary",
        [0x1] = "Execute immediately",
    }
    local completion = {
        [0x0] = "No action",
        [0x1] = "Command feedback",
    }

    sc_tree:append_text(" (Startup: " .. startup[bit32.rshift(sc_value, 4)] .. ", Completion: " .. completion[bit32.band(sc_value, 0xf)] .. ")")

    -- subcommand
    local subcommand_range = range:range(2, 1)
    local subcommand_value = subcommand_range:le_uint()
    local subcommand_tree = subtree:add_le(lwp3_proto.fields.port_output_subcommand, subcommand_range, subcommand_value)

    local subcommand = {
        [0x01] = "StartPower(Power)",
        [0x02] = "StartPower(Power1, Power2)",
        [0x05] = "SetAccTime (Time, ProfileNo)",
        [0x06] = "SetDecTime (Time, ProfileNo)",
        [0x07] = "StartSpeed (Speed, MaxPower, UseProfile)",
        [0x08] = "StartSpeed (Speed1, Speed2, MaxPower, UseProfile)",
        [0x09] = "StartSpeedForTime (Time, Speed, MaxPower, EndState, UseProfile)",
        [0x0A] = "StartSpeedForTime (Time, Speed, MaxPower, EndState, UseProfile)",
        [0x0B] = "StartSpeedForDegrees(Degrees, Speed, MaxPower, EndState, UseProfile)",
        [0x0C] = "StartSpeedForDegrees(Degrees, SpeedL, SpeedR, MaxPower, EndState, UseProfile)",
        [0x0D] = "GotoAbsolutePosition(AbsPos, Speed, MaxPower, EndState, UseProfile)",
        [0x0E] = "GotoAbsolutePosition(AbsPos1, AbsPos2, Speed, MaxPower, EndState, UseProfile)",
        [0x50] = "WriteDirect(Byte[0],Byte[0 + n])",
        [0x51] = "WriteDirectModeData()",
    }

    subcommand_tree:append_text(" (" .. subcommand[subcommand_value] .. ")")
    
    -- payload
    if subcommand_value == 0x51 then
        -- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#encoding-of-writedirectmodedata-0x81-0x51
        parse_uint8(range, 3, subtree, lwp3_proto.fields.port_mode)
        local payload_range = range(4)
        local payload_tree = subtree:add(lwp3_proto.fields.port_payload, payload_range)
        payload_tree:append_text(" (" .. payload_range:len() .. " bytes)")
    else
        -- TODO: The payload could be interpreted further based on the subcommand.
        local payload_range = range(3)
        local payload_tree = subtree:add(lwp3_proto.fields.port_payload, payload_range)
        payload_tree:append_text(" (" .. payload_range:len() .. " bytes)")
    end
end


---- message types: table of possible message types and subcommands ----

-- https://lego.github.io/lego-ble-wireless-protocol-docs/index.html#message-types
local msg_types = {
    [0x01] = {
        name = "Hub Property",
        parse_msg = parse_hub_prop,
    },
    [0x02] = {
        name = "Hub Actions",
        parse_msg = parse_hub_action,
    },
    [0x03] = {
        name = "Hub Alterts",
        parse_msg = parse_hub_alert,
    },
    [0x04] = {
        name = "Hub Attached I/O",
        parse_msg = parse_hub_attached_io,
    },
    [0x05] = {
        name = "Generic Error Messages",
        parse_msg = parse_error,
    },
    [0x08] = {
        name = "H/W Network Commands",
        parse_msg = parse_hw_network_cmd,
    },
    [0x10] = {
        name = "F/W Update - Go Into Boot Mode",
        parse_msg = parse_fw_boot_mode,
    },
    [0x11] = {
        name = "F/W Update Lock memory",
        parse_msg = parse_fw_lock_mem,
    },
    [0x12] = {
        name = "F/W Update Lock Status Request",
        parse_msg = parse_fw_lock_stat_req,
    },
    [0x13] = {
        name = "F/W Lock Status",
        parse_msg = parse_fw_lock_stat,
    },
    [0x21] = {
        name = "Port Information Request",
        parse_msg = parse_port_info_req,
    },
    [0x22] = {
        name = "Port Mode Information Request",
        parse_msg = parse_port_mode_info_req,
    },
    [0x41] = {
        name = "Port Input Format Setup (Single)",
        parse_msg = parse_port_setup_single,
    },
    [0x42] = {
        name = "Port Input Format Setup (CombinedMode)",
        parse_msg = parse_port_setup_combo,
    },
    [0x43] = {
        name = "Port Information",
        parse_msg = parse_port_info,
    },
    [0x44] = {
        name = "Port Mode Information",
        parse_msg = parse_port_mode_info,
    },
    [0x45] = {
        name = "Port Value (Single)",
        parse_msg = parse_port_val_single,
    },
    [0x46] = {
        name = "Port Value (CombinedMode)",
        parse_msg = parse_port_val_combo,
    },
    [0x47] = {
        name = "Port Input Format (Single)",
        parse_msg = parse_port_fmt_single,
    },
    [0x48] = {
        name = "Port Input Format (CombinedMode)",
        parse_msg = parse_port_fmt_combo,
    },
    [0x61] = {
        name = "Virtual Port Setup",
        parse_msg = parse_virt_port_setup,
    },
    [0x81] = {
        name = "Port Output Command",
        parse_msg = parse_port_out_cmd,
    },
    [0x82] = {
        name = "Port Output Command Feedback",
        parse_msg = parse_port_out_cmd_feedback,
    },
}


---- Dissector: the entry point for the dissector ----

function lwp3_proto.dissector(buffer, pinfo, tree)
    print("buffer: " .. buffer())

    if buffer:len() == 0 then
        return
    end

    pinfo.cols.protocol = lwp3_proto.name
    -- TODO: could also set pinfo.cols.info

    local subtree = tree:add(lwp3_proto, buffer())

    -- message length can be 8 or 16 bits
    local msg_len_range = buffer(0, 1)
    local msg_len = msg_len_range:le_uint()
    local offset = 1
    if bit32.band(msg_len, 0x80) ~= 0 then
        local extra = buffer(1, 1):le_uint()
        msg_len = bit32.band(msg_len, 0x80) + extra * 128
        msg_len_range = buffer(0, 2)
        offset = 2
    end
    subtree:add_le(lwp3_proto.fields.msg_len, msg_len_range, msg_len)

    local hub_id_range = buffer(offset, 1)
    local hub_id = hub_id_range:le_uint()
    local hub_id_tree = subtree:add_le(lwp3_proto.fields.hub_id, hub_id_range, hub_id)

    local msg_type_range = buffer(offset + 1, 1)
    local msg_type = msg_type_range:le_uint()
    local msg_tree = subtree:add_le(lwp3_proto.fields.msg_type, msg_type_range, msg_type)
    local msg_info = msg_types[msg_type]
    msg_tree:append_text(" (" .. msg_info.name .. ")")

    msg_info.parse_msg(buffer(offset + 2), subtree)
end

bluetooth_table = DissectorTable.get("bluetooth.uuid")
-- LWP3 Hub characteristic UUID
bluetooth_table:add("00001624-1212-efde-1623-785feabcd123", lwp3_proto)
