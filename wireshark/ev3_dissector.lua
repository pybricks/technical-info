-- Wireshark dissector for LEGO MINDSTORMS EV3
-- Copyright (C) 2015-2016 David Lechner <david@lechnology.com>
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


-- Credits:
-- based on lms2012 source code
-- with parts from https://wiki.wireshark.org/Lua/Dissectors
-- and http://blog.roisu.org/english-create-a-wireshark-dissector-with-lua/

-- Wireshark API docs:
-- https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html
-- https://wiki.wireshark.org/LuaAPI

-- Usage:
-- wireshark -X lua_script:ev3_dissector.lua

-- declare our protocol
local ev3_proto = Proto("EV3","LEGO MINDSTORMS EV3 Protocol")
ev3_proto.fields.msg_len = ProtoField.uint16("ev3.msg_len", "Message length", base.DEC)
ev3_proto.fields.msg_num = ProtoField.uint16("ev3.msg_num", "Message number", base.DEC)
ev3_proto.fields.cmd_type = ProtoField.uint8("ev3.cmd_type", "Command type", base.HEX)
ev3_proto.fields.sys_cmd = ProtoField.uint8("ev3.sys_cmd", "System command", base.HEX)
ev3_proto.fields.vars = ProtoField.uint16("ev3.vars", "Variables", base.HEX)
ev3_proto.fields.op = ProtoField.uint8("ev3.op", "Op", base.HEX)
ev3_proto.fields.reply_status = ProtoField.uint8("ev3.reply_status", "Reply status", base.HEX)
ev3_proto.fields.file_len = ProtoField.uint32("ev3.file_len", "File length", base.DEC)
ev3_proto.fields.file_name = ProtoField.string("ev3.file_name", "File name", FT_STRING)
ev3_proto.fields.max_bytes = ProtoField.uint16("ev3.max_bytes", "Max bytes to read", base.DEC)
ev3_proto.fields.path_name = ProtoField.string("ev3.path_name", "Path name", FT_STRING)
ev3_proto.fields.handle = ProtoField.uint8("ev3.handle", "Handle", base.DEC)
ev3_proto.fields.list_size = ProtoField.uint32("ev3.list_size", "List size", base.DEC)
ev3_proto.fields.list = ProtoField.string("ev3.list", "List", FT_STRING)
ev3_proto.fields.address = ProtoField.uint32("ev3.address", "Address", base.HEX)
ev3_proto.fields.image_size = ProtoField.uint32("ev3.image_size", "Image Size", base.DEC)
ev3_proto.fields.checksum = ProtoField.uint32("ev3.checksum", "Checksum", base.HEX)
ev3_proto.fields.hardware_id = ProtoField.uint32("ev3.hw_id", "Hardware ID", base.DEC)
ev3_proto.fields.firmware_id = ProtoField.uint32("ev3.fw_id", "Firmware ID", base.DEC)

local system_commands = {
    [0x92] = { "BEGIN_DOWNLOAD" },
    [0x93] = { "CONTINUE_DOWNLOAD" },
    [0x94] = { "BEGIN_UPLOAD" },
    [0x95] = { "CONTINUE_UPLOAD" },
    [0x96] = { "BEGIN_GETFILE" },
    [0x97] = { "CONTINUE_GETFILE" },
    [0x98] = { "CLOSE_FILEHANDLE" },
    [0x99] = { "LIST_FILES" },
    [0x9A] = { "CONTINUE_LIST_FILES" },
    [0x9B] = { "CREATE_DIR" },
    [0x9C] = { "DELETE_FILE" },
    [0x9D] = { "LIST_OPEN_HANDLES" },
    [0x9E] = { "WRITEMAILBOX" },
    [0x9F] = { "BLUETOOTHPIN" },
    [0xA0] = { "ENTERFWUPDATE" },
    [0xA1] = { "SETBUNDLEID" },
    [0xA2] = { "SETBUNDLESEEDID" },
	-- The 0xF? commands only apply to firmware update
	-- names come from TRecoveryCommand in uPBRSimpleTypes.pas in bricxcc
	[0xF0] = { "RECOVERY_BEGIN_DOWNLOAD_WITH_ERASE" },
	[0xF1] = { "RECOVERY_BEGIN_DOWNLOAD" },
	[0xF2] = { "RECOVERY_DOWNLOAD_DATA" },
	[0xF3] = { "RECOVERY_CHIP_ERASE" },
	[0xF4] = { "RECOVERY_START_APP" },
	[0xF5] = { "RECOVERY_GET_CHECKSUM" },
	[0xF6] = { "RECOVERY_GET_VERSION" },
};

local direct_commands = {
    [0x00] = { "ERROR", { } },
    [0x01] = { "NOP", { } },
    [0x02] = { "PROGRAM_STOP", { "PAR16" } },
    [0x03] = { "PROGRAM_START", { "PAR16", "PAR32", "PAR32", "PAR8" } },
    [0x04] = { "OBJECT_STOP", { "PAR16" } },
    [0x05] = { "OBJECT_START", { "PAR16" } },
    [0x06] = { "OBJECT_TRIG", { "PAR16" } },
    [0x07] = { "OBJECT_WAIT", { "PAR16" } },
    [0x08] = { "RETURN", { } },
    [0x09] = { "CALL", { "PAR16", "PARNO" } },
    [0x0A] = { "OBJECT_END", { } },
    [0x0B] = { "SLEEP", { } },
    [0x0C] = { "PROGRAM_INFO", { "SUBP", {
        [0] = { "OBJ_STOP", { "PAR16","PAR16" } },
        [4] = { "OBJ_START", { "PAR16","PAR16" } },
        [22] = { "GET_STATUS", { "PAR16","PAR8" } },
        [23] = { "GET_SPEED", { "PAR16","PAR32" } },
        [24] = { "GET_PRGRESULT", { "PAR16","PAR8" } },
        [25] = { "SET_INSTR", { "PAR16" } },
    } } },
    [0x0D] = { "LABEL", { "PARLAB" } },
    [0x0E] = { "PROBE", { "PAR16", "PAR16", "PAR32", "PAR32" } },
    [0x0F] = { "DO", { "PAR16", "PAR32", "PAR32" } },
    [0x10] = { "ADD8", { "PAR8", "PAR8", "PAR8" } },
    [0x11] = { "ADD16", { "PAR16", "PAR16", "PAR16" } },
    [0x12] = { "ADD32", { "PAR32", "PAR32", "PAR32" } },
    [0x13] = { "ADDF", { "PARF", "PARF", "PARF" } },
    [0x14] = { "SUB8", { "PAR8", "PAR8", "PAR8" } },
    [0x15] = { "SUB16", { "PAR16", "PAR16", "PAR16" } },
    [0x16] = { "SUB32", { "PAR32", "PAR32", "PAR32" } },
    [0x17] = { "SUBF", { "PARF", "PARF", "PARF" } },
    [0x18] = { "MUL8", { "PAR8", "PAR8", "PAR8" } },
    [0x19] = { "MUL16", { "PAR16", "PAR16", "PAR16" } },
    [0x1A] = { "MUL32", { "PAR32", "PAR32", "PAR32" } },
    [0x1B] = { "MULF", { "PARF", "PARF", "PARF" } },
    [0x1C] = { "DIV8", { "PAR8", "PAR8", "PAR8" } },
    [0x1D] = { "DIV16", { "PAR16", "PAR16", "PAR16" } },
    [0x1E] = { "DIV32", { "PAR32", "PAR32", "PAR32" } },
    [0x1F] = { "DIVF", { "PARF", "PARF", "PARF" } },
    [0x20] = { "OR8", { "PAR8", "PAR8", "PAR8" } },
    [0x21] = { "OR16", { "PAR16", "PAR16", "PAR16" } },
    [0x22] = { "OR32", { "PAR32", "PAR32", "PAR32" } },
    [0x24] = { "AND8", { "PAR8", "PAR8", "PAR8" } },
    [0x25] = { "AND16", { "PAR16", "PAR16", "PAR16" } },
    [0x26] = { "AND32", { "PAR32", "PAR32", "PAR32" } },
    [0x28] = { "XOR8", { "PAR8", "PAR8", "PAR8" } },
    [0x29] = { "XOR16", { "PAR16", "PAR16", "PAR16" } },
    [0x2A] = { "XOR32", { "PAR32", "PAR32", "PAR32" } },
    [0x2C] = { "RL8", { "PAR8", "PAR8", "PAR8" } },
    [0x2D] = { "RL16", { "PAR16", "PAR16", "PAR16" } },
    [0x2E] = { "RL32", { "PAR32", "PAR32", "PAR32" } },
    [0x2F] = { "INIT_BYTES", { "PAR8", "PAR32", "PARVALUES", "PAR8" } },
    [0x30] = { "MOVE8_8", { "PAR8", "PAR8" } },
    [0x31] = { "MOVE8_16", { "PAR8", "PAR16" } },
    [0x32] = { "MOVE8_32", { "PAR8", "PAR32" } },
    [0x33] = { "MOVE8_F", { "PAR8", "PARF" } },
    [0x34] = { "MOVE16_8", { "PAR16", "PAR8" } },
    [0x35] = { "MOVE16_16", { "PAR16", "PAR16" } },
    [0x36] = { "MOVE16_32", { "PAR16", "PAR32" } },
    [0x37] = { "MOVE16_F", { "PAR16", "PARF" } },
    [0x38] = { "MOVE32_8", { "PAR32", "PAR8" } },
    [0x39] = { "MOVE32_16", { "PAR32", "PAR16" } },
    [0x3A] = { "MOVE32_32", { "PAR32", "PAR32" } },
    [0x3B] = { "MOVE32_F", { "PAR32", "PARF" } },
    [0x3C] = { "MOVEF_8", { "PARF", "PAR8" } },
    [0x3D] = { "MOVEF_16", { "PARF", "PAR16" } },
    [0x3E] = { "MOVEF_32", { "PARF", "PAR32" } },
    [0x3F] = { "MOVEF_F", { "PARF", "PARF" } },
    [0x40] = { "JR", { "PAR32" } },
    [0x41] = { "JR_FALSE", { "PAR8", "PAR32" } },
    [0x42] = { "JR_TRUE", { "PAR8", "PAR32" } },
    [0x43] = { "JR_NAN", { "PARF", "PAR32" } },
    [0x44] = { "CP_LT8", { "PAR8", "PAR8", "PAR8" } },
    [0x45] = { "CP_LT16", { "PAR16", "PAR16", "PAR8" } },
    [0x46] = { "CP_LT32", { "PAR32", "PAR32", "PAR8" } },
    [0x47] = { "CP_LTF", { "PARF", "PARF", "PAR8" } },
    [0x48] = { "CP_GT8", { "PAR8", "PAR8", "PAR8" } },
    [0x49] = { "CP_GT16", { "PAR16", "PAR16", "PAR8" } },
    [0x4A] = { "CP_GT32", { "PAR32", "PAR32", "PAR8" } },
    [0x4B] = { "CP_GTF", { "PARF", "PARF", "PAR8" } },
    [0x4C] = { "CP_EQ8", { "PAR8", "PAR8", "PAR8" } },
    [0x4D] = { "CP_EQ16", { "PAR16", "PAR16", "PAR8" } },
    [0x4E] = { "CP_EQ32", { "PAR32", "PAR32", "PAR8" } },
    [0x4F] = { "CP_EQF", { "PARF", "PARF", "PAR8" } },
    [0x50] = { "CP_NEQ8", { "PAR8", "PAR8", "PAR8" } },
    [0x51] = { "CP_NEQ16", { "PAR16", "PAR16", "PAR8" } },
    [0x52] = { "CP_NEQ32", { "PAR32", "PAR32", "PAR8" } },
    [0x53] = { "CP_NEQF", { "PARF", "PARF", "PAR8" } },
    [0x54] = { "CP_LTEQ8", { "PAR8", "PAR8", "PAR8" } },
    [0x55] = { "CP_LTEQ16", { "PAR16", "PAR16", "PAR8" } },
    [0x56] = { "CP_LTEQ32", { "PAR32", "PAR32", "PAR8" } },
    [0x57] = { "CP_LTEQF", { "PARF", "PARF", "PAR8" } },
    [0x58] = { "CP_GTEQ8", { "PAR8", "PAR8", "PAR8" } },
    [0x59] = { "CP_GTEQ16", { "PAR16", "PAR16", "PAR8" } },
    [0x5A] = { "CP_GTEQ32", { "PAR32", "PAR32", "PAR8" } },
    [0x5B] = { "CP_GTEQF", { "PARF", "PARF", "PAR8" } },
    [0x5C] = { "SELECT8", { "PAR8", "PAR8", "PAR8", "PAR8" } },
    [0x5D] = { "SELECT16", { "PAR8", "PAR16", "PAR16", "PAR16" } },
    [0x5E] = { "SELECT32", { "PAR8", "PAR32", "PAR32", "PAR32" } },
    [0x5F] = { "SELECTF", { "PAR8", "PARF", "PARF", "PARF" } },
    [0x60] = { "SYSTEM", { "PAR8", "PAR32" } },
    [0x61] = { "PORT_CNV_OUTPUT", { "PAR32", "PAR8", "PAR8", "PAR8" } },
    [0x62] = { "PORT_CNV_INPUT", { "PAR32", "PAR8", "PAR8" } },
    [0x63] = { "NOTE_TO_FREQ", { "PAR8", "PAR16" } },
    [0x64] = { "JR_LT8", { "PAR8", "PAR8", "PAR32" } },
    [0x65] = { "JR_LT16", { "PAR16", "PAR16", "PAR32" } },
    [0x66] = { "JR_LT32", { "PAR32", "PAR32", "PAR32" } },
    [0x67] = { "JR_LTF", { "PARF", "PARF", "PAR32" } },
    [0x68] = { "JR_GT8", { "PAR8", "PAR8", "PAR32" } },
    [0x69] = { "JR_GT16", { "PAR16", "PAR16", "PAR32" } },
    [0x6A] = { "JR_GT32", { "PAR32", "PAR32", "PAR32" } },
    [0x6B] = { "JR_GTF", { "PARF", "PARF", "PAR32" } },
    [0x6C] = { "JR_EQ8", { "PAR8", "PAR8", "PAR32" } },
    [0x6D] = { "JR_EQ16", { "PAR16", "PAR16", "PAR32" } },
    [0x6E] = { "JR_EQ32", { "PAR32", "PAR32", "PAR32" } },
    [0x6F] = { "JR_EQF", { "PARF", "PARF", "PAR32" } },
    [0x70] = { "JR_NEQ8", { "PAR8", "PAR8", "PAR32" } },
    [0x71] = { "JR_NEQ16", { "PAR16", "PAR16", "PAR32" } },
    [0x72] = { "JR_NEQ32", { "PAR32", "PAR32", "PAR32" } },
    [0x73] = { "JR_NEQF", { "PARF", "PARF", "PAR32" } },
    [0x74] = { "JR_LTEQ8", { "PAR8", "PAR8", "PAR32" } },
    [0x75] = { "JR_LTEQ16", { "PAR16", "PAR16", "PAR32" } },
    [0x76] = { "JR_LTEQ32", { "PAR32", "PAR32", "PAR32" } },
    [0x77] = { "JR_LTEQF", { "PARF", "PARF", "PAR32" } },
    [0x78] = { "JR_GTEQ8", { "PAR8", "PAR8", "PAR32" } },
    [0x79] = { "JR_GTEQ16", { "PAR16", "PAR16", "PAR32" } },
    [0x7A] = { "JR_GTEQ32", { "PAR32", "PAR32", "PAR32" } },
    [0x7B] = { "JR_GTEQF", { "PARF", "PARF", "PAR32" } },
    [0x7C] = { "INFO", { "SUBP", {
        [1] = { "SET_ERROR", { "PAR8" } },
        [2] = { "GET_ERROR", { "PAR8" } },
        [3] = { "ERRORTEXT", { "PAR8","PAR8","PAR8" } },
        [4] = { "GET_VOLUME", { "PAR8" } },
        [5] = { "SET_VOLUME", { "PAR8" } },
        [6] = { "GET_MINUTES", { "PAR8" } },
        [7] = { "SET_MINUTES", { "PAR8" } },
        [10] = { "TST_OPEN", { } },
        [11] = { "TST_CLOSE", { } },
        [12] = { "TST_READ_PINS", { "PAR8","PAR8","PAR8" } },
        [13] = { "TST_WRITE_PINS", { "PAR8","PAR8","PAR8" } },
        [14] = { "TST_READ_ADC", { "PAR8","PAR16" } },
        [15] = { "TST_WRITE_UART", { "PAR8","PAR8","PAR8" } },
        [16] = { "TST_READ_UART", { "PAR8","PAR8","PAR8" } },
        [17] = { "TST_ENABLE_UART", { "PAR32" } },
        [18] = { "TST_DISABLE_UART", { } },
        [19] = { "TST_ACCU_SWITCH", { "PAR8" } },
        [20] = { "TST_BOOT_MODE2", { } },
        [21] = { "TST_POLL_MODE2", { "PAR8" } },
        [22] = { "TST_CLOSE_MODE2", { } },
        [23] = { "TST_RAM_CHECK", { "PAR8" } },
    } } },
    [0x7D] = { "STRINGS", { "SUBP", {
        [1] = { "GET_SIZE", { "PAR8","PAR16" } },
        [2] = { "ADD", { "PAR8","PAR8","PAR8" } },
        [3] = { "COMPARE", { "PAR8","PAR8","PAR8" } },
        [5] = { "DUPLICATE", { "PAR8","PAR8" } },
        [6] = { "VALUE_TO_STRING", { "PARF","PAR8","PAR8","PAR8" } },
        [7] = { "STRING_TO_VALUE", { "PAR8","PARF" } },
        [8] = { "STRIP", { "PAR8","PAR8" } },
        [9] = { "NUMBER_TO_STRING", { "PAR16","PAR8","PAR8" } },
        [10] = { "SUB", { "PAR8","PAR8","PAR8" } },
        [11] = { "VALUE_FORMATTED", { "PARF","PAR8","PAR8","PAR8" } },
        [12] = { "NUMBER_FORMATTED", { "PAR32","PAR8","PAR8","PAR8" } },
    } } },
    [0x7E] = { "MEMORY_WRITE", { "PAR16", "PAR16", "PAR32", "PAR32", "PAR8" } },
    [0x7F] = { "MEMORY_READ", { "PAR16", "PAR16", "PAR32", "PAR32", "PAR8" } },
    [0x80] = { "UI_FLUSH", { } },
    [0x81] = { "UI_READ", { "SUBP", {
        [1] = { "GET_VBATT", { "PARF" } },
        [2] = { "GET_IBATT", { "PARF" } },
        [3] = { "GET_OS_VERS", { "PAR8","PAR8" } },
        [4] = { "GET_EVENT", { "PAR8" } },
        [5] = { "GET_TBATT", { "PARF" } },
        [6] = { "GET_IINT", { "PARF" } },
        [7] = { "GET_IMOTOR", { "PARF" } },
        [8] = { "GET_STRING", { "PAR8","PAR8" } },
        [9] = { "GET_HW_VERS", { "PAR8","PAR8" } },
        [10] = { "GET_FW_VERS", { "PAR8","PAR8" } },
        [11] = { "GET_FW_BUILD", { "PAR8","PAR8" } },
        [12] = { "GET_OS_BUILD", { "PAR8","PAR8" } },
        [13] = { "GET_ADDRESS", { "PAR32" } },
        [14] = { "GET_CODE", { "PAR32","PAR32","PAR32","PAR8" } },
        [15] = { "KEY", { "PAR8" } },
        [16] = { "GET_SHUTDOWN", { "PAR8" } },
        [17] = { "GET_WARNING", { "PAR8", } },
        [18] = { "GET_LBATT", { "PAR8", } },
        [21] = { "TEXTBOX_READ", { "PAR8","PAR32","PAR8","PAR8","PAR16","PAR8" } },
        [26] = { "GET_VERSION", { "PAR8","PAR8" } },
        [27] = { "GET_IP", { "PAR8","PAR8" } },
        [29] = { "GET_POWER", { "PARF","PARF","PARF","PARF" } },
        [30] = { "GET_SDCARD", { "PAR8","PAR32","PAR32" } },
        [31] = { "GET_USBSTICK", { "PAR8","PAR32","PAR32" } },
    } } },
    [0x82] = { "UI_WRITE", { "SUBP", {
        [1] = { "WRITE_FLUSH", { } },
        [2] = { "FLOATVALUE", { "PARF","PAR8","PAR8" } },
        [3] = { "STAMP", { "PAR8", } },
        [8] = { "PUT_STRING", { "PAR8", } },
        [9] = { "VALUE8", { "PAR8", } },
        [10] = { "VALUE16", { "PAR16", } },
        [11] = { "VALUE32", { "PAR32", } },
        [12] = { "VALUEF", { "PARF", } },
        [13] = { "ADDRESS", { "PAR32" } },
        [14] = { "CODE", { "PAR8","PAR32" } },
        [15] = { "DOWNLOAD_END", { } },
        [16] = { "SCREEN_BLOCK", { "PAR8", } },
        [17] = { "ALLOW_PULSE", { "PAR8", } },
        [18] = { "SET_PULSE", { "PAR8", } },
        [21] = { "TEXTBOX_APPEND", { "PAR8","PAR32","PAR8","PAR8" } },
        [22] = { "SET_BUSY", { "PAR8", } },
        [24] = { "SET_TESTPIN", { "PAR8", } },
        [25] = { "INIT_RUN", { } },
        [26] = { "UPDATE_RUN", { } },
        [27] = { "LED", { "PAR8", } },
        [29] = { "POWER", { "PAR8", } },
        [30] = { "GRAPH_SAMPLE", { } },
        [31] = { "TERMINAL", { "PAR8", } },
    } } },
    [0x83] = { "UI_BUTTON", { "SUBP", {
        [1] = { "SHORTPRESS", { "PAR8","PAR8" } },
        [2] = { "LONGPRESS", { "PAR8","PAR8" } },
        [3] = { "WAIT_FOR_PRESS", { } },
        [4] = { "FLUSH", { } },
        [5] = { "PRESS", { "PAR8", } },
        [6] = { "RELEASE", { "PAR8", } },
        [7] = { "GET_HORZ", { "PAR16", } },
        [8] = { "GET_VERT", { "PAR16", } },
        [9] = { "PRESSED", { "PAR8","PAR8" } },
        [10] = { "SET_BACK_BLOCK", { "PAR8", } },
        [11] = { "GET_BACK_BLOCK", { "PAR8", } },
        [12] = { "TESTSHORTPRESS", { "PAR8","PAR8" } },
        [13] = { "TESTLONGPRESS", { "PAR8","PAR8" } },
        [14] = { "GET_BUMBED", { "PAR8","PAR8" } },
        [15] = { "GET_CLICK", { "PAR8", } },
    } } },
    [0x84] = { "UI_DRAW", { "SUBP", {
        [0] = { "UPDATE", { } },
        [1] = { "CLEAN", { } },
        [2] = { "PIXEL", { "PAR8","PAR16","PAR16" } },
        [3] = { "LINE", { "PAR8","PAR16","PAR16","PAR16","PAR16" } },
        [4] = { "CIRCLE", { "PAR8","PAR16","PAR16","PAR16" } },
        [5] = { "TEXT", { "PAR8","PAR16","PAR16","PAR8" } },
        [6] = { "ICON", { "PAR8","PAR16","PAR16","PAR8","PAR8" } },
        [7] = { "PICTURE", { "PAR8","PAR16","PAR16","PAR32" } },
        [8] = { "VALUE", { "PAR8","PAR16","PAR16","PARF","PAR8","PAR8" } },
        [9] = { "FILLRECT", { "PAR8","PAR16","PAR16","PAR16","PAR16" } },
        [10] = { "RECT", { "PAR8","PAR16","PAR16","PAR16","PAR16" } },
        [11] = { "NOTIFICATION", { "PAR8","PAR16","PAR16","PAR8","PAR8","PAR8","PAR8","PAR8" } },
        [12] = { "QUESTION", { "PAR8","PAR16","PAR16","PAR8","PAR8","PAR8","PAR8","PAR8" } },
        [13] = { "KEYBOARD", { "PAR8","PAR16","PAR16","PAR8","PAR8","PAR8","PAR8","PAR8" } },
        [14] = { "BROWSE", { "PAR8","PAR16","PAR16","PAR16","PAR16","PAR8","PAR8","PAR8" } },
        [15] = { "VERTBAR", { "PAR8","PAR16","PAR16","PAR16","PAR16","PAR16","PAR16","PAR16" } },
        [16] = { "INVERSERECT", { "PAR16","PAR16","PAR16","PAR16" } },
        [17] = { "SELECT_FONT", { "PAR8", } },
        [18] = { "TOPLINE", { "PAR8", } },
        [19] = { "FILLWINDOW", { "PAR8","PAR16","PAR16" } },
        [20] = { "SCROLL", { "PAR16", } },
        [21] = { "DOTLINE", { "PAR8","PAR16","PAR16","PAR16","PAR16","PAR16","PAR16" } },
        [22] = { "VIEW_VALUE", { "PAR8","PAR16","PAR16","PARF","PAR8","PAR8" } },
        [23] = { "VIEW_UNIT", { "PAR8","PAR16","PAR16","PARF","PAR8","PAR8","PAR8","PAR8" } },
        [24] = { "FILLCIRCLE", { "PAR8","PAR16","PAR16","PAR16" } },
        [25] = { "STORE", { "PAR8", } },
        [26] = { "RESTORE", { "PAR8", } },
        [27] = { "ICON_QUESTION", { "PAR8","PAR16","PAR16","PAR8","PAR32" } },
        [28] = { "BMPFILE", { "PAR8","PAR16","PAR16","PAR8" } },
        [29] = { "POPUP", { "PAR8", } },
        [30] = { "GRAPH_SETUP", { "PAR16","PAR16","PAR16","PAR16","PAR8","PAR16","PAR16","PAR16" } },
        [31] = { "GRAPH_DRAW", { "PAR8","PARF","PARF","PARF","PARF" } },
        [32] = { "TEXTBOX", { "PAR16","PAR16","PAR16","PAR16","PAR8","PAR32","PAR8","PAR8" } },
    } } },
    [0x85] = { "TIMER_WAIT", { "PAR32", "PAR32" } },
    [0x86] = { "TIMER_READY", { "PAR32" } },
    [0x87] = { "TIMER_READ", { "PAR32" } },
    [0x88] = { "BP0", { } },
    [0x89] = { "BP1", { } },
    [0x8A] = { "BP2", { } },
    [0x8B] = { "BP3", { } },
    [0x8C] = { "BP_SET", { "PAR16", "PAR8", "PAR32" } },
    [0x8D] = { "MATH", { "SUBP", {
        [1] = { "EXP", { "PARF","PARF" } },
        [2] = { "MOD", { "PARF","PARF","PARF" } },
        [3] = { "FLOOR", { "PARF","PARF" } },
        [4] = { "CEIL", { "PARF","PARF" } },
        [5] = { "ROUND", { "PARF","PARF" } },
        [6] = { "ABS", { "PARF","PARF" } },
        [7] = { "NEGATE", { "PARF","PARF" } },
        [8] = { "SQRT", { "PARF","PARF" } },
        [9] = { "LOG", { "PARF","PARF" } },
        [10] = { "LN", { "PARF","PARF" } },
        [11] = { "SIN", { "PARF","PARF" } },
        [12] = { "COS", { "PARF","PARF" } },
        [13] = { "TAN", { "PARF","PARF" } },
        [14] = { "ASIN", { "PARF","PARF" } },
        [15] = { "ACOS", { "PARF","PARF" } },
        [16] = { "ATAN", { "PARF","PARF" } },
        [17] = { "MOD8", { "PAR8","PAR8","PAR8" } },
        [18] = { "MOD16", { "PAR16","PAR16","PAR16" } },
        [19] = { "MOD32", { "PAR32","PAR32","PAR32" } },
        [20] = { "POW", { "PARF","PARF","PARF" } },
        [21] = { "TRUNC", { "PARF","PAR8","PARF" } },
    } } },
    [0x8E] = { "RANDOM", { "PAR16", "PAR16", "PAR16" } },
    [0x8F] = { "TIMER_READ_US", { "PAR32" } },
    [0x90] = { "KEEP_ALIVE", { "PAR8" } },
    [0x91] = { "COM_READ", { "SUBP", {
        [14] = { "COMMAND", { "PAR32","PAR32","PAR32","PAR8" } },
    } } },
    [0x92] = { "COM_WRITE", { "SUBP", {
        [14] = { "REPLY", { "PAR32","PAR32","PAR8" } },
    } } },
    [0x94] = { "SOUND", { "SUBP", {
        [0] = { "BREAK", { } },
        [1] = { "TONE", { "PAR8","PAR16","PAR16" } },
        [2] = { "PLAY", { "PAR8","PARS" } },
        [3] = { "REPEAT", { "PAR8","PARS" } },
        [4] = { "SERVICE", { } },
    } } },
    [0x95] = { "SOUND_TEST", { "PAR8" } },
    [0x96] = { "SOUND_READY", { } },
    [0x97] = { "INPUT_SAMPLE", { "PAR32", "PAR16", "PAR16", "PAR8", "PAR8", "PAR8", "PAR8", "PARF" } },
    [0x98] = { "INPUT_DEVICE_LIST", { "PAR8", "PAR8", "PAR8" } },
    [0x99] = { "INPUT_DEVICE", { "SUBP", {
        [1] = { "INSERT_TYPE", { "PAR8","PAR8","PAR8" } },
        [2] = { "GET_FORMAT", { "PAR8","PAR8","PAR8","PAR8","PAR8","PAR8" } },
        [3] = { "CAL_MINMAX", { "PAR8","PAR8","PAR32","PAR32" } },
        [4] = { "CAL_DEFAULT", { "PAR8","PAR8" } },
        [5] = { "GET_TYPEMODE", { "PAR8","PAR8","PAR8","PAR8" } },
        [6] = { "GET_SYMBOL", { "PAR8","PAR8","PAR8","PAR8" } },
        [7] = { "CAL_MIN", { "PAR8","PAR8","PAR32" } },
        [8] = { "CAL_MAX", { "PAR8","PAR8","PAR32" } },
        [9] = { "SETUP", { "PAR8","PAR8","PAR8","PAR16","PAR8","PAR8","PAR8","PAR8" } },
        [10] = { "CLR_ALL", { "PAR8", } },
        [11] = { "GET_RAW", { "PAR8","PAR8","PAR32" } },
        [12] = { "GET_CONNECTION", { "PAR8","PAR8","PAR8" } },
        [13] = { "STOP_ALL", { "PAR8", } },
        [14] = { "SET_TYPEMODE", { "PAR8","PAR8","PAR8","PAR8","PAR8" } },
        [15] = { "READY_IIC", { "PAR8","PAR8","PAR8","PAR8","PAR8","PAR8","PAR8" } },
        [21] = { "GET_NAME", { "PAR8","PAR8","PAR8","PAR8" } },
        [22] = { "GET_MODENAME", { "PAR8","PAR8","PAR8","PAR8","PAR8" } },
        [23] = { "SET_RAW", { "PAR8","PAR8","PAR8","PAR32" } },
        [24] = { "GET_FIGURES", { "PAR8","PAR8","PAR8","PAR8" } },
        [25] = { "GET_CHANGES", { "PAR8","PAR8","PARF" } },
        [26] = { "CLR_CHANGES", { "PAR8","PAR8" } },
        [27] = { "READY_PCT", { "PAR8","PAR8","PAR8","PAR8","PARNO" } },
        [28] = { "READY_RAW", { "PAR8","PAR8","PAR8","PAR8","PARNO" } },
        [29] = { "READY_SI", { "PAR8","PAR8","PAR8","PAR8","PARNO" } },
        [30] = { "GET_MINMAX", { "PAR8","PAR8","PARF","PARF" } },
        [31] = { "GET_BUMPS", { "PAR8","PAR8","PARF" } },
    } } },
    [0x9A] = { "INPUT_READ", { "PAR8", "PAR8", "PAR8", "PAR8", "PAR8" } },
    [0x9B] = { "INPUT_TEST", { "PAR8", "PAR8", "PAR8" } },
    [0x9C] = { "INPUT_READY", { "PAR8", "PAR8" } },
    [0x9D] = { "INPUT_READSI", { "PAR8", "PAR8", "PAR8", "PAR8", "PARF" } },
    [0x9E] = { "INPUT_READEXT", { "PAR8", "PAR8", "PAR8", "PAR8", "PAR8", "PARNO" } },
    [0x9F] = { "INPUT_WRITE", { "PAR8", "PAR8", "PAR8", "PAR8", } },
    [0xA0] = { "OUTPUT_GET_TYPE", { "PAR8", "PAR8", "PAR8", "PAR8" } },
    [0xA1] = { "OUTPUT_SET_TYPE", { "PAR8", "PAR8", "PAR8" } },
    [0xA2] = { "OUTPUT_RESET", { "PAR8", "PAR8" } },
    [0xA3] = { "OUTPUT_STOP", { "PAR8", "PAR8", "PAR8" } },
    [0xA4] = { "OUTPUT_POWER", { "PAR8", "PAR8", "PAR8" } },
    [0xA5] = { "OUTPUT_SPEED", { "PAR8", "PAR8", "PAR8" } },
    [0xA6] = { "OUTPUT_START", { "PAR8", "PAR8" } },
    [0xA7] = { "OUTPUT_POLARITY", { "PAR8", "PAR8", "PAR8" } },
    [0xA8] = { "OUTPUT_READ", { "PAR8", "PAR8", "PAR8", "PAR32" } },
    [0xA9] = { "OUTPUT_TEST", { "PAR8", "PAR8" } },
    [0xAA] = { "OUTPUT_READY", { "PAR8", "PAR8", "PAR8" } },
    [0xAB] = { "OUTPUT_POSITION", { "PAR8", "PAR8", "PAR8", "PAR32", "PAR32", "PAR32", "PAR8" } },
    [0xAC] = { "OUTPUT_STEP_POWER", {"PAR8", "PAR8", "PAR8", "PAR32", "PAR32", "PAR32", "PAR8" } },
    [0xAD] = { "OUTPUT_TIME_POWER", { "PAR8", "PAR8", "PAR8", "PAR32", "PAR32", "PAR32", "PAR8" } },
    [0xAE] = { "OUTPUT_STEP_SPEED", { "PAR8", "PAR8", "PAR8", "PAR32", "PAR32", "PAR32", "PAR8" } },
    [0xAF] = { "OUTPUT_TIME_SPEED", { "PAR8", "PAR8", "PAR8", "PAR32", "PAR32", "PAR32", "PAR8" } },
    [0xB0] = { "OUTPUT_STEP_SYNC", { "PAR8", "PAR8", "PAR8", "PAR16", "PAR32", "PAR8" } },
    [0xB1] = { "OUTPUT_TIME_SYNC", { "PAR8", "PAR8", "PAR8", "PAR16", "PAR32", "PAR8" } },
    [0xB2] = { "OUTPUT_CLR_COUNT", { "PAR8", "PAR8" } },
    [0xB3] = { "OUTPUT_GET_COUNT", { "PAR8", "PAR8", "PAR32" } },
    [0xB4] = { "OUTPUT_PRG_STOP", { } },
    [0xC0] = { "FILE", { "SUBP", {
        [0] = { "OPEN_APPEND", { "PAR8","PAR16" } },
        [1] = { "OPEN_READ", { "PAR8","PAR16","PAR32" } },
        [2] = { "OPEN_WRITE", { "PAR8","PAR16" } },
        [3] = { "READ_VALUE", { "PAR16","PAR8","PARF" } },
        [4] = { "WRITE_VALUE", { "PAR16","PAR8","PARF","PAR8","PAR8" } },
        [5] = { "READ_TEXT", { "PAR16","PAR8","PAR16","PAR8" } },
        [6] = { "WRITE_TEXT", { "PAR16","PAR8","PAR8" } },
        [7] = { "CLOSE", { "PAR16", } },
        [8] = { "LOAD_IMAGE", { "PAR16","PAR8","PAR32","PAR32" } },
        [9] = { "GET_HANDLE", { "PAR8","PAR16","PAR8" } },
        [10] = { "MAKE_FOLDER", { "PAR8","PAR8" } },
        [11] = { "GET_POOL", { "PAR32","PAR16","PAR32" } },
        [12] = { "SET_LOG_SYNC_TIME", { "PAR32","PAR32" } },
        [13] = { "GET_FOLDERS", { "PAR8","PAR8" } },
        [14] = { "GET_LOG_SYNC_TIME", { "PAR32","PAR32" } },
        [15] = { "GET_SUBFOLDER_NAME", { "PAR8","PAR8","PAR8","PAR8" } },
        [16] = { "WRITE_LOG", { "PAR16","PAR32","PAR8","PARF" } },
        [17] = { "CLOSE_LOG", { "PAR16","PAR8" } },
        [18] = { "GET_IMAGE", { "PAR8","PAR16","PAR8","PAR32" } },
        [19] = { "GET_ITEM", { "PAR8","PAR8","PAR8" } },
        [20] = { "GET_CACHE_FILES", { "PAR8", } },
        [21] = { "PUT_CACHE_FILE", { "PAR8", } },
        [22] = { "GET_CACHE_FILE", { "PAR8","PAR8","PAR8" } },
        [23] = { "DEL_CACHE_FILE", { "PAR8", } },
        [24] = { "DEL_SUBFOLDER", { "PAR8","PAR8" } },
        [25] = { "GET_LOG_NAME", { "PAR8","PAR8" } },
        [27] = { "OPEN_LOG", { "PAR8","PAR32","PAR32","PAR32","PAR32","PAR32","PAR8","PAR16" } },
        [28] = { "READ_BYTES", { "PAR16","PAR16","PAR8" } },
        [29] = { "WRITE_BYTES", { "PAR16","PAR16","PAR8" } },
        [30] = { "REMOVE", { "PAR8", } },
        [31] = { "MOVE", { "PAR8","PAR8" } },
    } } },
    [0xC1] = { "ARRAY", { "SUBP", {
        [0] = { "DELETE", { "PAR16", } },
        [1] = { "CREATE8", { "PAR32","PAR16" } },
        [2] = { "CREATE16", { "PAR32","PAR16" } },
        [3] = { "CREATE32", { "PAR32","PAR16" } },
        [4] = { "CREATEF", { "PAR32","PAR16" } },
        [5] = { "RESIZE", { "PAR16","PAR32" } },
        [6] = { "FILL", { "PAR16","PARV" } },
        [7] = { "COPY", { "PAR16","PAR16" } },
        [8] = { "INIT8", { "PAR16","PAR32","PAR32","PARVALUES","PAR8" } },
        [9] = { "INIT16", { "PAR16","PAR32","PAR32","PARVALUES","PAR16" } },
        [10] = { "INIT32", { "PAR16","PAR32","PAR32","PARVALUES","PAR32" } },
        [11] = { "INITF", { "PAR16","PAR32","PAR32","PARVALUES","PARF" } },
        [12] = { "SIZE", { "PAR16","PAR32" } },
        [13] = { "READ_CONTENT", { "PAR16","PAR16","PAR32","PAR32","PAR8" } },
        [14] = { "WRITE_CONTENT", { "PAR16","PAR16","PAR32","PAR32","PAR8" } },
        [15] = { "READ_SIZE", { "PAR16","PAR16","PAR32" } },
    } } },
    [0xC2] = { "ARRAY_WRITE", { "PAR16", "PAR32", "PARV" } },
    [0xC3] = { "ARRAY_READ", { "PAR16", "PAR32", "PARV" } },
    [0xC4] = { "ARRAY_APPEND", { "PAR16", "PARV" } },
    [0xC5] = { "MEMORY_USAGE", { "PAR32", "PAR32" } },
    [0xC6] = { "FILENAME", { "SUBP", {
        [0] = { "DELETE", { "PAR16", } },
        [1] = { "CREATE8", { "PAR32","PAR16" } },
        [2] = { "CREATE16", { "PAR32","PAR16" } },
        [3] = { "CREATE32", { "PAR32","PAR16" } },
        [4] = { "CREATEF", { "PAR32","PAR16" } },
        [5] = { "RESIZE", { "PAR16","PAR32" } },
        [6] = { "FILL", { "PAR16","PARV" } },
        [7] = { "COPY", { "PAR16","PAR16" } },
        [8] = { "INIT8", { "PAR16","PAR32","PAR32","PARVALUES","PAR8" } },
        [9] = { "INIT16", { "PAR16","PAR32","PAR32","PARVALUES","PAR16" } },
        [10] = { "INIT32", { "PAR16","PAR32","PAR32","PARVALUES","PAR32" } },
        [11] = { "INITF", { "PAR16","PAR32","PAR32","PARVALUES","PARF" } },
        [12] = { "SIZE", { "PAR16","PAR32" } },
        [13] = { "READ_CONTENT", { "PAR16","PAR16","PAR32","PAR32","PAR8" } },
        [14] = { "WRITE_CONTENT", { "PAR16","PAR16","PAR32","PAR32","PAR8" } },
        [15] = { "READ_SIZE", { "PAR16","PAR16","PAR32" } },
        [16] = { "EXIST", { "PAR8","PAR8" } },
        [17] = { "TOTALSIZE", { "PAR8","PAR32","PAR32" } },
        [18] = { "SPLIT", { "PAR8","PAR8","PAR8","PAR8","PAR8" } },
        [19] = { "MERGE", { "PAR8","PAR8","PAR8","PAR8","PAR8" } },
        [20] = { "CHECK", { "PAR8","PAR8" } },
        [21] = { "PACK", { "PAR8", } },
        [22] = { "UNPACK", { "PAR8", } },
        [23] = { "GET_FOLDERNAME", { "PAR8","PAR8" } },
    } } },
    [0xC8] = { "READ8", { "PAR8", "PAR8", "PAR8" } },
    [0xC9] = { "READ16", { "PAR16", "PAR8", "PAR16" } },
    [0xCA] = { "READ32", { "PAR32", "PAR8", "PAR32" } },
    [0xCB] = { "READF", { "PARF", "PAR8", "PARF" } },
    [0xCC] = { "WRITE8", { "PAR8", "PAR8", "PAR8" } },
    [0xCD] = { "WRITE16", { "PAR16", "PAR8", "PAR16" } },
    [0xCE] = { "WRITE32", { "PAR32", "PAR8", "PAR32" } },
    [0xCF] = { "WRITEF", { "PARF", "PAR8", "PARF" } },
    [0xD0] = { "COM_READY", { "PAR8", "PAR8" } },
    [0xD1] = { "COM_READDATA", { "PAR8", "PAR8", "PAR16", "PAR8" } },
    [0xD2] = { "COM_WRITEDATA", { "PAR8", "PAR8", "PAR16", "PAR8" } },
    [0xD3] = { "COM_GET", { "SUBP", {
        [1] = { "GET_ON_OFF", { "PAR8","PAR8" } },
        [2] = { "GET_VISIBLE", { "PAR8","PAR8" } },
        [4] = { "GET_RESULT", { "PAR8","PAR8","PAR8" } },
        [5] = { "GET_PIN", { "PAR8","PAR8","PAR8","PAR8" } },
        [8] = { "SEARCH_ITEMS", { "PAR8","PAR8" } },
        [9] = { "SEARCH_ITEM", { "PAR8","PAR8","PAR8","PAR8","PAR8","PAR8","PAR8","PAR8" } },
        [10] = { "FAVOUR_ITEMS", { "PAR8","PAR8" } },
        [11] = { "FAVOUR_ITEM", { "PAR8","PAR8","PAR8","PAR8","PAR8","PAR8","PAR8" } },
        [12] = { "GET_ID", { "PAR8","PAR8","PAR8" } },
        [13] = { "GET_BRICKNAME", { "PAR8","PARS" } },
        [14] = { "GET_NETWORK", { "PAR8","PAR8","PAR8","PAR8","PAR8" } },
        [15] = { "GET_PRESENT", { "PAR8","PAR8" } },
        [16] = { "GET_ENCRYPT", { "PAR8","PAR8","PAR8" } },
        [17] = { "CONNEC_ITEMS", { "PAR8","PAR8" } },
        [18] = { "CONNEC_ITEM", { "PAR8","PAR8","PAR8","PAR8","PAR8" } },
        [19] = { "GET_INCOMING", { "PAR8","PAR8","PAR8","PAR8" } },
        [20] = { "GET_MODE2", { "PAR8","PAR8" } },
    } } },
    [0xD4] = { "COM_SET", { "SUBP", {
        [1] = { "SET_ON_OFF", { "PAR8","PAR8" } },
        [2] = { "SET_VISIBLE", { "PAR8","PAR8" } },
        [3] = { "SET_SEARCH", { "PAR8","PAR8" } },
        [5] = { "SET_PIN", { "PAR8","PAR8","PAR8" } },
        [6] = { "SET_PASSKEY", { "PAR8","PAR8" } },
        [7] = { "SET_CONNECTION", { "PAR8","PAR8","PAR8" } },
        [8] = { "SET_BRICKNAME", { "PAR8", } },
        [9] = { "SET_MOVEUP", { "PAR8","PAR8" } },
        [10] = { "SET_MOVEDOWN", { "PAR8","PAR8" } },
        [11] = { "SET_ENCRYPT", { "PAR8","PAR8","PAR8" } },
        [12] = { "SET_SSID", { "PAR8","PAR8" } },
        [13] = { "SET_MODE2", { "PAR8","PAR8" } },
    } } },
    [0xD5] = { "COM_TEST", { "PAR8", "PAR8", "PAR8" } },
    [0xD6] = { "COM_REMOVE", { "PAR8", "PAR8" } },
    [0xD7] = { "COM_WRITEFILE", { "PAR8", "PAR8", "PAR8", "PAR8" } },
    [0xD8] = { "MAILBOX_OPEN", { "PAR8", "PAR8", "PAR8", "PAR8", "PAR8" } },
    [0xD9] = { "MAILBOX_WRITE", { "PAR8", "PAR8", "PAR8", "PAR8", "PARNO" } },
    [0xDA] = { "MAILBOX_READ", { "PAR8", "PAR8", "PARNO" } },
    [0xDB] = { "MAILBOX_TEST", { "PAR8", "PAR8" } },
    [0xDC] = { "MAILBOX_READY", { "PAR8" } },
    [0xDD] = { "MAILBOX_CLOSE", { "PAR8" } },
    [0xFF] = { "TST", { } } 
};

-- used to hold global variable definitions between DIRECT_COMMAND_REPLY and
-- DIRECT_REPLY messages
local global_vars = {}

function system_command_dissector(buffer,pinfo,subtree)
    local cmd = buffer(5,1):le_uint()
	local name = system_commands[cmd][1]
    if name == "BEGIN_DOWNLOAD" then
        subtree:add_le(ev3_proto.fields.file_len, buffer(6,4))
        subtree:add_le(ev3_proto.fields.file_name, buffer(10,buffer:len() - 10))
    elseif name == "LIST_FILES" then
        subtree:add_le(ev3_proto.fields.max_bytes, buffer(6,2))
        subtree:add_le(ev3_proto.fields.path_name, buffer(8,buffer:len() - 8))
    elseif name == "CONTINUE_LIST_FILES" then
        subtree:add_le(ev3_proto.fields.handle, buffer(6,1))
        subtree:add_le(ev3_proto.fields.max_bytes, buffer(7,2))
	elseif name == "RECOVERY_BEGIN_DOWNLOAD_WITH_ERASE" or name == "RECOVERY_BEGIN_DOWNLOAD" or name == "RECOVERY_GET_CHECKSUM" then
		subtree:add_le(ev3_proto.fields.address, buffer(6,4))
		subtree:add_le(ev3_proto.fields.image_size, buffer(10,4))
    end
end

function system_reply_dissector(buffer,pinfo,subtree)
    local cmd = buffer(5,1):le_uint()
	local name = system_commands[cmd][1]
    if name == "BEGIN_DOWNLOAD" then
        subtree:add_le(ev3_proto.fields.handle, buffer(7,1))
    elseif name == "LIST_FILES" then
        subtree:add_le(ev3_proto.fields.list_size, buffer(7,4))
        subtree:add_le(ev3_proto.fields.handle, buffer(11,1))
        subtree:add_le(ev3_proto.fields.list, buffer(12,buffer:len() - 12))
    elseif name == "CONTINUE_LIST_FILES" then
        subtree:add_le(ev3_proto.fields.handle, buffer(7,1))
        subtree:add_le(ev3_proto.fields.list, buffer(8,buffer:len() - 8))
	elseif name == "RECOVERY_GET_CHECKSUM" then
		subtree:add_le(ev3_proto.fields.checksum, buffer(7,4))
	elseif name == "RECOVERY_GET_VERSION" then
		subtree:add_le(ev3_proto.fields.hardware_id, buffer(7,4))
		subtree:add_le(ev3_proto.fields.firmware_id, buffer(11,4))
    end
end

function parameter_dissector(globals,start,param_type,buffer,subtree)
    local flags = {}
    local value = nil
    table.insert(flags, param_type)
    local first_byte = buffer(start, 1):le_uint()
    local new_start = start + 1
    if bit32.band(first_byte, 0x80) > 0 then -- PRIMPAR_LONG
        table.insert(flags, "PRIMPAR_LONG")
        if bit32.band(first_byte, 0x10) > 0 then -- PRIMPAR_HANDLE
            table.insert(flags, "PRIMPAR_HANDLE")
        elseif bit32.band(first_byte, 0x08) > 0 then -- PRIMPAR_ADDR
            table.insert(flags, "PRIMPAR_ADDR")
        end
        if bit32.band(first_byte, 0x40) > 0 then -- PRIMPAR_VARIABLE
            table.insert(flags, "PRIMPAR_VARIABLE")
            if bit32.band(first_byte, 0x20) > 0 then -- PRIMPAR_GLOBAL
                table.insert(flags, "PRIMPAR_GLOBAL")
            else
                table.insert(flags, "PRIMPAR_LOCAL")
            end
            local bytes = bit32.band(first_byte,0x07) -- PRIMPAR_BYTES
            local index = 0
            if bytes == 1 then -- PRIMPAR_1_BYTE
                table.insert(flags, "PRIMPAR_1_BYTE")
                index = buffer(new_start,1):le_uint()
                new_start = new_start + 1
            elseif bytes == 2 then -- PRIMPAR_2_BYTE
                table.insert(flags, "PRIMPAR_2_BYTE")
                index = buffer(new_start,2):le_uint()
                new_start = new_start + 2
            elseif bytes == 3 then -- PRIMPAR_4_BYTE
                table.insert(flags, "PRIMPAR_4_BYTE")
                index = buffer(new_start,4):le_uint()
                new_start = new_start + 4
            end
            table.insert(globals, { index, param_type })
            table.insert(flags, "Index: " .. index)
        else -- PRIMPAR_CONST
            table.insert(flags, "PRIMPAR_CONST")
            if bit32.band(first_byte, 0x20) > 0 then -- PRIMPAR_LABEL
                table.insert(flags, "PRIMPAR_LABEL")
                table.insert(flags, "Label: " .. buffer(new_start,1):le_uint())
                    new_start = new_start + 1
            else
                table.insert(flags, "PRIMPAR_VALUE")
                local bytes = bit32.band(first_byte,0x07) -- PRIMPAR_BYTES
                if bytes == 0 or bytes == 4 then
                    if bytes == 0 then -- PRIMPAR_STRING_OLD
                        table.insert(flags, "PRIMPAR_STRING_OLD")
                    else  -- PRIMPAR_STRING
                        table.insert(flags, "PRIMPAR_STRING")
                    end
                    local str_start = new_start
                    while buffer(new_start,1):le_uint() > 0 do
                        new_start = new_start + 1
                    end
                    value = buffer(str_start,new_start-start):string()
                    new_start = new_start + 1
                elseif bytes == 1 then -- PRIMPAR_1_BYTE:
                    table.insert(flags, "PRIMPAR_1_BYTE")
                    value = buffer(new_start,1):le_int()
                    new_start = new_start + 1
                elseif bytes == 2 then -- PRIMPAR_2_BYTES:
                    table.insert(flags, "PRIMPAR_2_BYTE")
                    value = buffer(new_start,2):le_int()
                    new_start = new_start + 2
                elseif bytes == 3 then -- PRIMPAR_4_BYTES:
                    table.insert(flags, "PRIMPAR_4_BYTE")
                    if param_type == "PARF" then
                        value = buffer(new_start,4):le_float()
                    else
                        value = buffer(new_start,4):le_int()
                    end
                    new_start = new_start + 4
                end
                table.insert(flags, "Value: " .. value)
            end
        end
    else -- PRIMPAR_SHORT
        table.insert(flags, "PRIMPAR_SHORT")
        if bit32.band(first_byte, 0x40) > 0 then -- PRIMPAR_VARIABLE
            local index = bit32.band(first_byte,0x1F) -- PRIMPAR_INDEX
            table.insert(flags, "PRIMPAR_VARIABLE")
            if bit32.band(first_byte, 0x20) > 0 then -- PRIMPAR_GLOBAL
                table.insert(flags, "PRIMPAR_GLOBAL")
                table.insert(globals, { index, param_type } )
            else -- PRIMPAR_LOCAL
                table.insert(flags, "PRIMPAR_LOCAL")
            end
            table.insert(flags, "Index: " .. index)
        else -- PRIMPAR_CONST
            table.insert(flags, "PRIMPAR_CONST")
            value = bit32.band(first_byte, 0x3F) -- PRIMPAR_VALUE
            if bit32.band(first_byte, 0x20) > 0 then -- PRIMPAR_CONST_SIGN
                value = value - (0x3F + 1) -- PRIMPAR_VALUE
            end
            table.insert(flags, "Value: " .. value)
        end
    end
    subtree:add(buffer(start,new_start-start), "Parameter: 0x"
        .. buffer(start,new_start-start)
        .. " (" .. table.concat(flags, ", ") ..")")
    return new_start, value
end

function direct_command_dissector(globals,start,buffer,pinfo,subtree)
    local cmd = buffer(start,1):le_uint()
    subtree:add_le(ev3_proto.fields.op, buffer(start,1)):append_text(" ("
        .. direct_commands[cmd][1] .. ")")
    start = start + 1
    local is_subparam = false
    local is_parvalues = false
    local num_parvalues = 0
    local value = nil
    -- iterate parameters
    for i, param_type in ipairs(direct_commands[cmd][2]) do
        if is_subparam then
            is_subparam = false
            subcmd = buffer(start,1):le_uint()
            subtree:add(buffer(start,1), "Parameter: 0x" .. buffer(start,1)
                .. " (SUBP Command:" .. param_type[subcmd][1] .. ")")
            start = start + 1
            for j, subparam_type in ipairs(param_type[subcmd][2]) do
                start, value = parameter_dissector(globals,start,subparam_type,buffer,subtree)
                if subparam_type == "PARNO" then
                    local num_parno = value
                    for j = 1, num_parno do
                        start, value = parameter_dissector(globals,start,"PARV",buffer,subtree)
                    end
                end
            end
        elseif is_parvalues then
            for j = 1, num_parvalues do
                start, value = parameter_dissector(globals,start,param_type,buffer,subtree)
            end
        else
            if param_type == "SUBP" then
                is_subparam = true
            elseif param_type == "PARVALUES" then
                is_parvalues = true
                num_parvalues = value -- param before PARVALUES is always the number of params to follow
            else
                start, value = parameter_dissector(globals,start,param_type,buffer,subtree)
                if param_type == "PARNO" then
                    local num_parno = value
                    for j = 1, num_parno do
                        start, value = parameter_dissector(globals,start,"PARV",buffer,subtree)
                    end
                end
            end
        end
    end

    return start
end

-- create a function to dissect it
function ev3_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "EV3"

    -- check to see if we have the whole message
    local msg_len = buffer(0,2):le_uint() + 2
    if buffer:len() < msg_len then

        -- First packet sent to establish connection
        if buffer:len() >= 27 and buffer(0,3):string() == "GET" then
            local subtree = tree:add(ev3_proto,buffer(),"EV3 Request")
            subtree:add(buffer(15,12), "Serial number: " .. buffer(15,2):string()
                .. ":" .. buffer(17,2):string() .. ":" .. buffer(19,2):string()
                .. ":" .. buffer(21,2):string() .. ":" .. buffer(23,2):string()
                .. ":" .. buffer(25,2):string())
            return
        end
        -- response to above
        if buffer:len() >= 7 and buffer(0,7):string() == "Accept:" then
            local subtree = tree:add(ev3_proto,buffer(),"EV3 Accept")
            return
        end

        pinfo.desegment_length = msg_len - buffer:len()
        pinfo.desegment_offset = 0
        return
    end

    local subtree = tree:add(ev3_proto,buffer(),"EV3 Message")

    -- first two bytes are always length
    subtree:add_le(ev3_proto.fields.msg_len,buffer(0,2))

    -- then a message number (unique identifier for message)
    subtree:add_le(ev3_proto.fields.msg_num,buffer(2,2))
    local msg_num = buffer(2,2):le_uint()

    -- then the command type
    local cmd_type_tree = subtree:add_le(ev3_proto.fields.cmd_type,buffer(4,1))
    local cmd_type = buffer(4,1):le_uint()
    -- these values could be made more clear, but they come from lms2012,
    -- so leaving as-is for now
    if cmd_type == 0x01 then
        cmd_type_tree:append_text(" (SYSTEM_COMMAND_REPLY)")
    elseif cmd_type == 0x81 then
        cmd_type_tree:append_text(" (SYSTEM_COMMAND_NO_REPLY)")
    elseif cmd_type == 0x03 then
        cmd_type_tree:append_text(" (SYSTEM_REPLY)")
    elseif cmd_type == 0x05 then
        cmd_type_tree:append_text(" (SYSTEM_REPLY_ERROR)")
    elseif cmd_type == 0x00 then
        cmd_type_tree:append_text(" (DIRECT_COMMAND_REPLY)")
    elseif cmd_type == 0x80 then
        cmd_type_tree:append_text(" (DIRECT_COMMAND_NO_REPLY)")
    elseif cmd_type == 0x02 then
        cmd_type_tree:append_text(" (DIRECT_REPLY)")
    elseif cmd_type == 0x04 then
        cmd_type_tree:append_text(" (DIRECT_REPLY_ERROR)")
    end

    -- remainder of dissection depends on the command type

    if bit32.band(cmd_type, 0x01) > 0 then -- system command
        subtree:add_le(ev3_proto.fields.sys_cmd,buffer(5,1)):append_text(" ("
            .. system_commands[buffer(5,1):le_uint()][1] .. ")")
        if bit32.band(cmd_type, 0x02) > 0 then -- reply
            subtree:add_le(ev3_proto.fields.reply_status,buffer(6,1))
            if bit32.band(cmd_type, 0x04) == 0 then -- no error
                system_reply_dissector(buffer,pinfo,subtree)
            end
        else -- command
            system_command_dissector(buffer,pinfo,subtree)
        end
    else -- direct command
        if bit32.band(cmd_type, 0x04) > 0 then -- error
            -- nothing to do for direct reply error
        elseif bit32.band(cmd_type, 0x02) > 0 then -- reply
            for i, param in ipairs(global_vars[msg_num]) do
                local value = nil
                local length = 0
                if param[2] == "PAR8" then
                    value = buffer(5+param[1],1):le_int()
                    if value == -128 then
                        value = "DATA8_NAN"
                    end
                    length = 1
                elseif param[2] == "PAR16" then
                    value = buffer(5+param[1],2):le_int()
                    if value == -32768 then
                        value = "DATA16_NAN"
                    end
                    length = 2
                elseif param[2] == "PAR32" then
                    value = buffer(5+param[1],4):le_int()
                    if value == -2147483648 then
                        value = "DATA32_NAN"
                    end
                    length = 4
                elseif param[2] == "PARF" then
                    value = buffer(5+param[1],4):le_float()
                    if buffer(5+param[1],4):le_uint() == 0x7FC00000 then
                        value = "DATAF_NAN"
                    elseif buffer(5+param[1],4):le_int() == -2147483647 then
                        value = "DATAF_MIN"
                    elseif buffer(5+param[1],4):le_int() == 2147483647 then
                        value = "DATAF_MAX"
                    end
                    length = 4
                elseif param[2] == "PARS" then
                    value = buffer(5+param[1],buffer:len()-(5+param[1])):stringz()
                    length = value:len()
                    -- TODO: this is not the actual length
                end
                subtree:add(buffer(5+param[1],length), "Global variable: 0x"
                    .. buffer(5+param[1],length) .. " (Index: " .. param[1]
                    .. ", Type: " .. param[2] .. ", Value: " .. value .. ")")
            end
            -- free the memory used by this message
            global_vars[msg_num] = nil
        else -- command
            global_vars[msg_num] = {}
            local globals = buffer(5,1):le_uint()
                + bit32.lshift(bit32.band(buffer(6,1):le_uint(), 0x03), 8)
            local locals = bit32.rshift(buffer(6,1):le_uint(), 2)
            subtree:add_le(ev3_proto.fields.vars,buffer(5,2)):append_text(" (Globals: "
            .. globals .. " bytes, Locals: " .. locals .. " bytes)")
            local start = 7
            while start < buffer:len() do
                start = direct_command_dissector(global_vars[msg_num],start,buffer,pinfo,subtree)
            end
        end
    end
    pinfo.desegment_len = 0
    pinfo.desegment_offset = msg_len
end

-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol to handle tcp port 5555
tcp_table:add(5555,ev3_proto)

usb_table = DissectorTable.get("usb.interrupt")
--IF_CLASS_UNKNOWN = 0xffff
usb_table:add(0xffff,ev3_proto)

bluetooth_table = DissectorTable.get("btrfcomm.dlci")
bluetooth_table:add(2,ev3_proto)
