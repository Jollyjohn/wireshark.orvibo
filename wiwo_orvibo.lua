-- Copyright (c) 2016 Frederic Leroy.  All rights reserved.
-- Author: Frederic Leroy <fredo@starox.org>
--
--    This program is free software: you can redistribute it and/or modify
--    it under the terms of the GNU General Public License as published by
--    the Free Software Foundation, either version 2 of the License, or
--    (at your option) any later version.
--
--    This program is distributed in the hope that it will be useful,
--    but WITHOUT ANY WARRANTY; without even the implied warranty of
--    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--    GNU General Public License for more details.
--
--    You should have received a copy of the GNU General Public License
--    along with this program.  If not, see <http://www.gnu.org/licenses/>.

local debug_level = {
	DISABLED = 0,
	LEVEL_1  = 1,
	LEVEL_2  = 2
}

local DEBUG = debug_level.LEVEL_1

local default_settings =
{
	debug_level  = DEBUG,
	port         = 10000,
	heur_enabled = true,
}

-- for testing purposes, we want to be able to pass in changes to the defaults
-- from the command line; because you can't set lua preferences from the command
-- line using the '-o' switch (the preferences don't exist until this script is
-- loaded, so the command line thinks they're invalid preferences being set)
-- so we pass them in as command arguments insetad, and handle it here:
local args={...} -- get passed-in args
if args and #args > 0 then
	for _, arg in ipairs(args) do
		local name, value = arg:match("(.+)=(.+)")
		if name and value then
			if tonumber(value) then
				value = tonumber(value)
			elseif value == "true" or value == "TRUE" then
				value = true
			elseif value == "false" or value == "FALSE" then
				value = false
			elseif value == "DISABLED" then
				value = debug_level.DISABLED
			elseif value == "LEVEL_1" then
				value = debug_level.LEVEL_1
			elseif value == "LEVEL_2" then
				value = debug_level.LEVEL_2
			else
				error("invalid commandline argument value")
			end
		else
			error("invalid commandline argument syntax")
		end
		default_settings[name] = value
	end
end

local dprint = function() end
local dprint2 = function() end

local
	function reset_debug_level()
		if default_settings.debug_level > debug_level.DISABLED then
			dprint = function(...)
			print(table.concat({"Lua:", ...}," "))
		end

		if default_settings.debug_level > debug_level.LEVEL_1 then
			dprint2 = dprint
		end
	end
end

-- call it now
reset_debug_level()

dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)

----------------------------------------
-- Unfortunately, the older Wireshark/Tshark versions have bugs, and part of the point
-- of this script is to test those bugs are now fixed.  So we need to check the version
-- end error out if it's too old.
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
	error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
	"This script needs Wireshark/Tshark version 1.11.3 or higher.\n" )
end

-- more sanity checking
-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

----------------------------------------
-- creates a Proto object, but doesn't register it yet
local orvibo = Proto("orvibo","Wiwo orvibo Protocol")

--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

-- a "enum" table for our enum pref, as required by Pref.enum()
-- having the "index" number makes ZERO sense, and is completely illogical
-- but it's what the code has expected it to be for a long time. Ugh.
local debug_pref_enum = {
	{ 1,  "Disabled", debug_level.DISABLED },
	{ 2,  "Level 1",  debug_level.LEVEL_1  },
	{ 3,  "Level 2",  debug_level.LEVEL_2  },
}

orvibo.prefs.debug = Pref.enum("Debug", default_settings.debug_level,
								"The debug printing level", debug_pref_enum)

orvibo.prefs.port  = Pref.uint("Port number", default_settings.port,
								"The UDP port number for orvibo")

orvibo.prefs.heur  = Pref.bool("Heuristic enabled", default_settings.heur_enabled,
								"Whether heuristic dissection is enabled or not")

----------------------------------------
-- a function for handling prefs being changed
function orvibo.prefs_changed()
	dprint2("prefs_changed called")

	default_settings.debug_level  = orvibo.prefs.debug
	reset_debug_level()

	default_settings.heur_enabled = orvibo.prefs.heur

	if default_settings.port ~= orvibo.prefs.port then
		-- remove old one, if not 0
		if default_settings.port ~= 0 then
			dprint2("removing Orvibo from port",default_settings.port)
			DissectorTable.get("udp.port"):remove(default_settings.port, orvibo)
		end
		-- set our new default
		default_settings.port = orvibo.prefs.port
		-- add new one, if not 0
		if default_settings.port ~= 0 then
			dprint2("adding Orvibo to port",default_settings.port)
			DissectorTable.get("udp.port"):add(default_settings.port, orvibo)
		end
	end

end

dprint2("Orvibo Prefs registered")

----------------------------------------

local HDR_LEN = 6

local header_magic_type = {
	["hd"] = "magic header"
}

local opcodes_type = {
	cd = "???",
	cl = "CLaim",
	cs = "???",
	dc = "set Direct Current - power on/off ???",
	dl = "only from controller to orvibo gw ??? distant link ?",
	gt = "Get Time",
	hb = "HeartBeat",
	lt = "Leave Terminal ??? / Load Table",
	mp = "Modify Password",
	qa = "Query All - can also be emitted by devices",
	qg = "Query Get",
	rt = "Read Table",
	sf = "State Flip ???",
	tm = "Table Modify",
	ts = "Time Set ???",
}

local table_type = {
	[0] = "end marker",
	[1] = "table 1 - list of tables availables",
	[3] = "table 3",
	[4] = "table 4 - device configuration",
}

local icon_type = {
	[0] = "light bulb",
	[1] = "fan",
	[2] = "thermostat",
	[3] = "switch",
	[4] = "plug",
}

local onoff_type = {
	[0] = "off",
	[1] = "on",
}

local yesno_type = {
	[0] = "no",
	[1] = "yes",
}

local ip_mode_type = {
	[0] = "static",
	[1] = "dhcp",
}

local countdown_mode_type = {
	[0x00ff] = "disabled",
	[0x0100] = "enabled",
}

local role_device = 0
local role_controller = 1
local role_gateway = 2
local role_all_device = 3
local role_all_controller = 4
local role_type = {
	[role_device] = "device",
	[role_controller] = "controller",
	[role_gateway] = "gateway",
	[role_all_device] = "all device",
	[role_all_controller] = "all controller",
}

-- fields

-- notes:
--		discoverable is "lock device" on android app

local fields = {
	["orvibo.addr"]             = ProtoField.ether("orvibo.addr", "hardware address", base.HEX),
	["orvibo.cookie"]           = ProtoField.uint32("orvibo.cookie", "cookie", base.HEX),
	["orvibo.countdown"]        = ProtoField.uint16("orvibo.countdown", "countdown seconds"),
	["orvibo.countdown_mode"]   = ProtoField.uint16("orvibo.countdown_mode", "countdown mode", base.HEX, countdown_mode_type),
	["orvibo.date"]             = ProtoField.uint32("orvibo.date", "epoch date"),
	["orvibo.date_str"]         = ProtoField.string("orvibo.date_str", "date"),
	["orvibo.device"]           = ProtoField.string("orvibo.device", "device", FT_STRING),
	["orvibo.discoverable"]     = ProtoField.uint8("orvibo.discoverable", "discoverable", base.HEX, yesno_type),
	["orvibo.firmware_version"] = ProtoField.uint32("orvibo.firmware_version", "firmware_version"),
	["orvibo.flags.action"]     = ProtoField.bool("orvibo.flags.action", "action", base.BOOL, {"response","query"}),
	["orvibo.flags.src"]        = ProtoField.uint8("orvibo.flags.src", "src", base.DEC, role_type),
	["orvibo.gw"]               = ProtoField.ipv4("orvibo.gw", "gw"),
	["orvibo.hardware_version"] = ProtoField.uint32("orvibo.hardware_version", "hardware_version"),
	["orvibo.header_magic"]     = ProtoField.string("orvibo.header_magic", "header", FT_STRING, header_magic_type),
	["orvibo.icon"]             = ProtoField.uint16("orvibo.icon", "icon", base.DEC, icon_type),
	["orvibo.ip"]               = ProtoField.ipv4("orvibo.ip", "ip"),
	["orvibo.ip_mode"]          = ProtoField.uint8("orvibo.ip_mode", "ip_mode", base.HEX, ip_mode_type),
	["orvibo.length"]           = ProtoField.uint16("orvibo.length", "length"),
	["orvibo.mysterious"]       = ProtoField.uint8("orvibo.mysterious", "mysterious", base.HEX),
	["orvibo.name"]             = ProtoField.string("orvibo.name", "name", FT_STRING),
	["orvibo.netmask"]          = ProtoField.ipv4("orvibo.netmask", "netmask"),
	["orvibo.new_password"]     = ProtoField.string("orvibo.new_password", "new password", FT_STRING),
	["orvibo.opcode"]           = ProtoField.string("orvibo.opcode", "opcode", FT_STRING, opcodes_type),
	["orvibo.padding"]          = ProtoField.bytes("orvibo.padding", "padding", base.HEX),
	["orvibo.password"]         = ProtoField.string("orvibo.password", "password", FT_STRING),
	["orvibo.port"]             = ProtoField.uint16("orvibo.port", "port"),
	["orvibo.raddr"]            = ProtoField.ether("orvibo.raddr", "reverse hardware address", base.HEX),
	["orvibo.record"]           = ProtoField.uint16("orvibo.record", "record", base.DEC),
	["orvibo.record_count"]     = ProtoField.uint16("orvibo.record_count", "record_count", base.DEC),
	["orvibo.record_length"]    = ProtoField.uint16("orvibo.record_length", "record length", base.DEC),
	["orvibo.server_ip"]        = ProtoField.ipv4("orvibo.server_ip", "server_ip"),
	["orvibo.server_name"]      = ProtoField.string("orvibo.server_name", "server_name"),
	["orvibo.server_port"]      = ProtoField.uint16("orvibo.server_port", "server_port"),
	["orvibo.state"]            = ProtoField.uint8("orvibo.state", "state", base.HEX, onoff_type),
	["orvibo.table"]            = ProtoField.uint16("orvibo.table", "table", base.DEC, table_type),
	["orvibo.table_version"]    = ProtoField.uint16("orvibo.table_version", "table_version", base.DEC),
	["orvibo.timestamp"]        = ProtoField.uint32("orvibo.timestamp", "timestamp", base.DEC),
	["orvibo.timezone"]         = ProtoField.uint8("orvibo.timezone", "timezone"),
	["orvibo.timezone_set"]     = ProtoField.uint8("orvibo.timezone_set", "timezone set ???"),
	["orvibo.unknown"]          = ProtoField.bytes("orvibo.unknown", "unknown", base.HEX),
	["orvibo.version"]          = ProtoField.uint16("orvibo.version", "version", base.HEX),
	["orvibo.wifi_version"]     = ProtoField.uint32("orvibo.wifi_version", "wifi_version"),
}

-- XXX this is weird, we can't get string maps from protofields, so we must have another
-- helper table
local fields_string_maps = {
	["orvibo.countdown_mode"] = countdown_mode_type,
	["orvibo.discoverable"]   = yesno_type,
	["orvibo.icon"]           = icon_type,
	["orvibo.ip_mode"]        = ip_mode_type,
	["orvibo.opcode"]         = opcodes_type,
	["orvibo.state"]          = onoff_type,
	["orvibo.table"]          = table_type,
}

orvibo.fields = {}
for key,value in pairs(fields) do
	table.insert(orvibo.fields, value)
end

-- expert fields

local expert_fields = {
	["orvibo.expert.bad_header"] = ProtoExpert.new("orvibo.expert.bad_header", "bad header",
									expert.group.MALFORMED, expert.severity.ERROR),
	["orvibo.expert.bad_length"] = ProtoExpert.new("orvibo.expert.bad_length", "length mismatch",
									expert.group.MALFORMED, expert.severity.ERROR),
	["orvibo.expert.unknown_value"] = ProtoExpert.new("orvibo.expert.unknown_value", "value is unknown",
									expert.group.PROTOCOL, expert.severity.WARN),
	["orvibo.expert.too_short"] = ProtoExpert.new("orvibo.expert.too_short", "packet too short",
									expert.group.MALFORMED, expert.severity.ERROR),
	["orvibo.expert.mac_reverse_mismatch"] = ProtoExpert.new("orvibo.expert.mac_reverse_mismatch", "addr and reverse addr mismatch",
									expert.group.PROTOCOL, expert.severity.ERROR),
	["orvibo.expert.mac_mismatch"] = ProtoExpert.new("orvibo.expert.mac_mismatch", "addr and ethernet hardware address mismatch",
									expert.group.PROTOCOL, expert.severity.WARN),
	["orvibo.expert.clear_password"] = ProtoExpert.new("orvibo.expert.clear_password", "You can find the password here !",
									expert.group.SECURITY, expert.severity.WARN),
	["orvibo.expert.query"] = ProtoExpert.new("orvibo.expert.query", "This is a query",
									expert.group.REQUEST_CODE, expert.severity.CHAT),
	["orvibo.expert.response"] = ProtoExpert.new("orvibo.expert.response", "This is a response",
									expert.group.RESPONSE_CODE, expert.severity.CHAT),
	["orvibo.expert.unknown_opcode"] = ProtoExpert.new("orvibo.expert.unknown_opcode", "This opcode is unknown",
									expert.group.UNDECODED, expert.severity.WARN),
	["orvibo.expert.unknown_data"] = ProtoExpert.new("orvibo.expert.unknown_data", "The packet contain unknown data",
									expert.group.UNDECODED, expert.severity.WARN),
	["orvibo.expert.bad_padding"] = ProtoExpert.new("orvibo.expert.bad_padding", "bad padding",
									expert.group.PROTOCOL, expert.severity.WARN),
}

orvibo.experts = {}
for key,value in pairs(expert_fields) do
	table.insert(orvibo.experts, value)
end

-- extractors

extractors = {}
for key, value in pairs(fields) do
	extractors[key] = Field.new(key)
end

get_ip_src = Field.new("ip.src")
get_ip_dst = Field.new("ip.dst")
get_eth_src = Field.new("eth.src")
get_eth_dst = Field.new("eth.dst")

-- dissectors helpers

function _add_field(tree, buf, pos, len, name, msg, expert, le)
	if len == -1 then
		len = buf:reported_length_remaining() - pos
	end
	if le == false then
		item = tree:add(fields[name], buf(pos, len))
	else
		item = tree:add_le(fields[name], buf(pos, len))
	end
	if msg then
		TreeItem.append_text(item, " - " .. msg )
	end
	-- TODO check strings maps
	if fields_string_maps[name] then
		local value = extractors[name]().value
		if not fields_string_maps[name][value] then
			item:add_proto_expert_info(expert_fields["orvibo.expert.unknown_value"])
		end
	end
	if expert then
		item:add_proto_expert_info(expert_fields[expert])
	end
	return pos + len
end

function add_field(tree, buf, pos, len, name, msg, expert)
	return _add_field(tree, buf, pos, len, name, msg, expert, false)
end

function add_field_le(tree, buf, pos, len, name, msg, expert)
	return _add_field(tree, buf, pos, len, name, msg, expert, true)
end

function add_padding(tree, buf, pos, len, value)
	if len == -1 then
		len = buf:reported_length_remaining() - pos
	end
	local padding = buf(pos, len)
	local item = tree:add(fields["orvibo.padding"], padding)
	TreeItem.append_text(item, " - should be padded with " .. string.format("0x%x", value) )
	pos = pos + len
	-- check padding
	for l=0, len - 1 do
		if padding(i,1):int() ~= value then
			item:add_proto_expert_info(expert_fields["orvibo.expert.bad_padding"])
			return pos
		end
	end
	return pos
end

function get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 6, "orvibo.addr")
	if not ( extractors["orvibo.addr"]().value == get_eth_src().value or extractors["orvibo.addr"]().value == get_eth_dst().value ) then
		item:add_proto_expert_info(expert_fields["orvibo.expert.mac_mismatch"])
	end
	return add_padding(tree, buf, pos, 6, 32)
end

function reverse_bytes(buf)
	local l = buf:len() - 1
	local c = ByteArray.new()
	for i=0,l do
		c:append(buf(l-i,1):bytes())
	end
	return c
end

function get_rmac_and_padding(buf, pos, tree)
	rmac = buf(pos, 6)
	item = tree:add(fields["orvibo.raddr"], rmac)
	pos = add_padding(tree, buf, pos + 6, 6, 32)
	mac_bytes = extractors["orvibo.addr"]().range():bytes()
	rmac_reversed_bytes = reverse_bytes(rmac)
	if mac_bytes ~= rmac_reversed_bytes then
		item:add_proto_expert_info(expert_fields["orvibo.expert.mac_reverse_mismatch"])
	end
	return pos
end

function get_mac_and_rmac(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = get_rmac_and_padding(buf, pos, tree)
	return pos
end

-- sub dissectors

function add_timestamp(buf, pos, tree)
	item = tree:add_le(fields["orvibo.timestamp"], buf(pos, 4))
	TreeItem.append_text(item, " - seconds since 1900-01-01 00:00:00")
	-- $ python
	-- Python 2.7.10 (default, Oct 14 2015, 16:09:02)
	-- [GCC 5.2.1 20151010] on linux2
	-- Type "help", "copyright", "credits" or "license" for more information.
	-- >>> import time
	-- >>> from datetime import date
	-- >>> ref1900 = date(1900, 01, 01)
	-- >>> refepoch = date(1970, 01, 01)
	-- >>> diff = ref1900 - refepoch
	-- >>> diff.total_seconds()
	-- -2208988800.0
	-- >>>
	local epoch_date_in_seconds = extractors["orvibo.timestamp"]().value - 2208988800
	local tmp = item:add(fields["orvibo.date"], epoch_date_in_seconds)
	tmp:set_generated()
	tmp = item:add(fields["orvibo.date_str"], format_date(epoch_date_in_seconds))
	tmp:set_generated()
	return pos + 4
end

function dissector_device_standard_response(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie")
	pos = add_field(tree, buf, pos, 1, "orvibo.state")
	return pos
end

function dissector_cl_query_from_controller_to_device(buf, pos, tree)
	pos = get_mac_and_rmac(buf, pos, tree)
	return pos
end

function dissector_cl_response_from_device(buf, pos, tree)
	local pktlen = buf:reported_length_remaining()
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie", "???")
	-- two byte left !
	return pos
end

function dissector_cl_response_from_gateway_to_device(buf, pos, tree)
	local pktlen = buf:reported_length_remaining()
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie", "???")
	pos = get_rmac_and_padding(buf, pos, tree)
	return pos
end

function dissector_cl_response_from_irda_gateway_to_controller(buf, pos, tree)
	local pktlen = buf:reported_length_remaining()
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie", "???")
	pos = add_field(tree, buf, pos, 1, "orvibo.unknown", nil, "orvibo.expert.unknown_data")
	pos = add_field(tree, buf, pos, 6, "orvibo.device")
	return pos
end

function dissector_cl_query_from_controller_to_gateway(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 6, "orvibo.password", nil, "orvibo.expert.clear_password")
	pos = add_padding(tree, buf, pos, 6, 32)
	pos = add_field(tree, buf, pos, 40, "orvibo.server_name")
	return pos
end

function dissector_cs_query(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie")
	return pos
end

function dissector_dl_query(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie")
	pos = get_rmac_and_padding(buf, pos, tree)
	return pos
end

function dissector_gt_query(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie")
	return pos
end

function dissector_gt_response(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie")
	return pos
end

function dissector_hb_query(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie")
	return pos
end

function dissector_hb_response(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie")
	pos = add_padding(tree, buf, pos, 1, 0)
	return pos
end


function dissector_lt_from_device_to_gateway(buf, pos, tree)
	return add_field(tree, buf, pos, 4, "orvibo.cookie")
end

function dissector_lt_from_controller_to_device(buf, pos, tree)
	return get_mac_and_padding(buf, pos, tree)
end

function dissector_mp_query(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie")
	pos = add_field(tree, buf, pos, 6, "orvibo.password",nil,"orvibo.expert.clear_password")
	pos = add_padding(tree, buf, pos, 6, 32)
	pos = add_field(tree, buf, pos, 6, "orvibo.new_password",nil,"orvibo.expert.clear_password")
	pos = add_padding(tree, buf, pos, 6, 32)
	return pos
end

function dissector_mp_response_from_gw(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie")
	pos = add_field(tree, buf, pos, 1, "orvibo.unknown", nil, "orvibo.expert.unknown_data")
	pos = add_field(tree, buf, pos, 6, "orvibo.password",nil,"orvibo.expert.clear_password")
	pos = add_padding(tree, buf, pos, 6, 32)
	return pos
end

function dissector_qa_query(buf, pos, tree)
	return pos
end

function dissector_qa_response(buf, pos, tree)
	pos = add_padding(tree, buf, pos, 1, 0) -- always 0 in every opcode, only from device
	pos = get_mac_and_rmac(buf, pos, tree)
	pos = add_field(tree, buf, pos, 6, "orvibo.device", "device type ??? can change !")
	pos = add_timestamp(buf, pos, tree)
	pos = add_field(tree, buf, pos, 1, "orvibo.state")
	return pos
end

function dissector_qg_query(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	return pos
end

function dissector_qg_response(buf, pos, tree)
	pos = add_padding(tree, buf, pos, 1, 0) -- always 0 in every opcode, only from device
	pos = get_mac_and_rmac(buf, pos, tree)
	pos = add_field(tree, buf, pos, 6, "orvibo.device")
	pos = add_timestamp(buf, pos, tree)
	pos = add_field(tree, buf, pos, 1, "orvibo.state")
	return pos
end

function dissector_record_table_version(buf, pos, tree)
	pos = add_field_le(tree, buf, pos, 2, "orvibo.table")
	pos = add_field_le(tree, buf, pos, 2, "orvibo.table_version")
	return pos
end

function dissector_record_socket_description(buf, pos, tree)
	pos = add_field(tree, buf, pos, 2, "orvibo.version")
	pos = get_mac_and_rmac(buf, pos, tree)
	pos = add_field(tree, buf, pos, 6, "orvibo.password",nil,"orvibo.expert.clear_password")
	pos = add_padding(tree, buf, pos, 6, 32)
	pos = add_field(tree, buf, pos, 16, "orvibo.name", " -> padded with space or all 0xff if not initialized")
	pos = add_field_le(tree, buf, pos, 2, "orvibo.icon")
	pos = add_field_le(tree, buf, pos, 4, "orvibo.hardware_version")
	pos = add_field_le(tree, buf, pos, 4, "orvibo.firmware_version")
	pos = add_field_le(tree, buf, pos, 4, "orvibo.wifi_version")
	pos = add_field_le(tree, buf, pos, 2, "orvibo.port")
	pos = add_field(tree, buf, pos, 4, "orvibo.server_ip")
	pos = add_field_le(tree, buf, pos, 2, "orvibo.server_port")
	pos = add_field(tree, buf, pos, 40, "orvibo.server_name")
	pos = add_field(tree, buf, pos, 4, "orvibo.ip")
	pos = add_field(tree, buf, pos, 4, "orvibo.gw")
	pos = add_field(tree, buf, pos, 4, "orvibo.netmask")
	pos = add_field(tree, buf, pos, 1, "orvibo.ip_mode")
	pos = add_field(tree, buf, pos, 1, "orvibo.discoverable")
	pos = add_field(tree, buf, pos, 1, "orvibo.timezone_set")
	pos = add_field(tree, buf, pos, 1, "orvibo.timezone")
	pos = add_field(tree, buf, pos, 2, "orvibo.countdown_mode")
	pos = add_field_le(tree, buf, pos, 2, "orvibo.countdown", "seconds")
	pos = add_field(tree, buf, pos, 12, "orvibo.unknown", "-> there is a date and  two fields with hours in seconds", "orvibo.expert.unknown_data")
	pos = add_field(tree, buf, pos, 20, "orvibo.date_str","???")
	pos = add_field(tree, buf, pos, 20, "orvibo.date_str","???")
	return pos
end

table_record_dissector = {
	[1] = {
		[4] = dissector_record_table_version
		},
	[4] = {
		[1] = dissector_record_socket_description
	}
}

function dissector_rt_query_to_device(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie")
	pos = add_field_le(tree, buf, pos, 2, "orvibo.table")
	return pos
end

function dissector_rt(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie", "???")
	pos = add_field(tree, buf, pos, 2, "orvibo.table")
	pos = add_field(tree, buf, pos, 2, "orvibo.record_count")
	pos = add_field(tree, buf, pos, 2, "orvibo.unknown", nil, "orvibo.expert.unknown_data")
	count = extractors["orvibo.record_count"]().value
	while count > 0 do
		pos = add_field_le(tree, buf, pos, 2, "orvibo.record_length")
		pos = add_field_le(tree, buf, pos, 2, "orvibo.record")
		pos = table_record_dissector[extractors["orvibo.table"]().value][extractors["orvibo.record"]().value](buf, pos, tree)
		count = count - 1
	end

	return pos
end

function dissector_tm(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie", "???")
	pos = add_field_le(tree, buf, pos, 2, "orvibo.table")
	pos = add_field_le(tree, buf, pos, 1, "orvibo.record_count")
	count = extractors["orvibo.record_count"]().value
	while count > 0 do
		pos = add_field_le(tree, buf, pos, 2, "orvibo.record_length")
		pos = add_field_le(tree, buf, pos, 2, "orvibo.record")
		pos = table_record_dissector[extractors["orvibo.table"]().value][extractors["orvibo.record"]().value](buf, pos, tree)
		count = count - 1
	end
	return pos
end

function dissector_ts_query(buf, pos, tree)
	pos = get_mac_and_padding(buf, pos, tree)
	pos = add_field(tree, buf, pos, 4, "orvibo.cookie")
	return pos
end

orvibo_dissectors = {
	rt = dissector_rt,
	tm = dissector_tm,
}

orvibo_dissectors_by_size = {
	cl = {
		[30] = { dissector_cl_query_from_controller_to_device, false, },
		[24] = { dissector_cl_response_from_device, true, },
		[29] = { dissector_cl_response_from_irda_gateway_to_controller, true, },
		[34] = { dissector_cl_response_from_gateway_to_device, true, },
		[70] = { dissector_cl_query_from_controller_to_gateway, false, },
	},
	cs = {
		[26] = { dissector_cs_query, false, },
		[23] = { dissector_hb_response, true, },
	},
	dc = {
		[23] = { dissector_device_standard_response, nil, },
	},
	dl = {
		[34] = { dissector_dl_query, false, },
		[23] = { dissector_device_standard_response, true, },
	},
	gt = {
		[24] = { dissector_gt_query, false, },
		[73] = { dissector_gt_response, true, },
	},
	hb = {
		[22] = { dissector_hb_query, false, },
		[23] = { dissector_device_standard_response, true, },
	},
	lt = {
		[10] = { dissector_lt_from_device_to_gateway, nil, },
		[18] = { dissector_lt_from_controller_to_device, nil, },
	},
	mp = {
		[46] = { dissector_mp_query, false, },
		[35] = { dissector_mp_response_from_gw, true, },
		[23] = { dissector_device_standard_response, true, },
	},
	qa = {
		[6] = { dissector_qa_query, false, },
		[42] = { dissector_qa_response, true, },
	},
	qg = {
		[18] = { dissector_qg_query, false, },
		[42] = { dissector_qg_response, true, },
	},
	sf = {
		[23] = { dissector_device_standard_response, true, },
	},
	rt = {
		[29] = { dissector_rt_query_to_device, false, },
	},
	tm = {
		[23] = { dissector_device_standard_response, true, },
	},
	ts = {
		[34] = { dissector_ts_query, false, },
		[23] = { dissector_device_standard_response, true, },
	},
}

-- dissector

action_table = {}

function dissector_1st_pass(buf, pktinfo, root)
	dprint2("orvibo.dissector 1 called")
	-- determine query/response and local controller/gateway controller/device
	local pktlen = buf:reported_length_remaining()
	local opcode = buf(4,2):string()
	if	orvibo_dissectors_by_size[opcode] and
			orvibo_dissectors_by_size[opcode][pktlen] ~= nil and
			orvibo_dissectors_by_size[opcode][pktlen][2] ~= nil then
		action_table[pktinfo.number] = orvibo_dissectors_by_size[opcode][pktlen][2]
		return
	end
	if opcode == "rt" then
		action_table[pktinfo.number] = true
		return
	end
	if opcode == "tm" then
		action_table[pktinfo.number] = true
		return
	end
end

function dissector_2nd_pass(buf, pktinfo, root)
	dprint2("orvibo.dissector 2 called")
	pktinfo.cols.protocol:set("Orvibo")
	local pktlen = buf:reported_length_remaining()
	local tree = root:add(orvibo, buf:range(0,pktlen))

	if pktlen < HDR_LEN then
		tree:add_proto_expert_info(expert_fields["orvibo.expert.too_short"])
		dprint("packet ",pktinfo.number," length",pktlen,"too short")
		return 0
	end

	header = buf(0,2):string()
	tree:add(fields["orvibo.header_magic"], header)
	if header ~= "hd" then
		tree:add_proto_expert_info(expert_fields["orvibo.expert.bad_header"])
	end

	tree:add(fields["orvibo.length"], buf(2,2))
	if extractors["orvibo.length"]().value ~= pktlen then
		tree:add_proto_expert_info(expert_fields["orvibo.expert.bad_length"])
	end

	local opcode = buf(4,2):string()
	t = tree:add(fields["orvibo.opcode"], opcode)
	if opcodes_type[opcode] then
		TreeItem.append_text(t, " - " .. opcodes_type[opcode])
	end

	pos = HDR_LEN

	if orvibo_dissectors_by_size[opcode] and orvibo_dissectors_by_size[opcode][pktlen] then
		-- dissectors based on payload size
		pos = orvibo_dissectors_by_size[opcode][pktlen][1](buf, pos, tree)
	elseif orvibo_dissectors[opcode] then
		-- default dissectors
		pos = orvibo_dissectors[opcode](buf, pos, tree)
	else
		tree:add_proto_expert_info(expert_fields["orvibo.expert.unknown_opcode"])
	end

	if pos ~= pktlen then
		pos = add_field(tree, buf, pos, -1, "unknown", nil, "orvibo.expert.unknown_data")
	end

	-- expert info and generated fields
	local action = ""
	if action_table[pktinfo.number] ~= nil then
		tree:add(fields["orvibo.flags.action"], action_table[pktinfo.number]):set_generated()
		if  action_table[pktinfo.number] then
			action = "response"
		else
			action = "query"
		end
	end

	state = ""
	if  extractors["orvibo.state"]() ~= nil then
		state = " state " .. onoff_type[extractors["orvibo.state"]().value]
	end

	-- column info
	pktinfo.cols.info:set(opcode .. " " .. action .. state)

	return pktlen
end

function orvibo.dissector(buf, pktinfo, root)
	if not pktinfo.visited then
		dissector_1st_pass(buf, pktinfo, root)
	else
		dissector_2nd_pass(buf, pktinfo, root)
	end
end

DissectorTable.get("udp.port"):add(default_settings.port, orvibo)

-- we just check the header size and the magic header to catch as much as possible
-- packets. The purpose of this plugin is to reverse enginer the protocol and so
-- we need to accept also unknown and malformed packet
function heur_dissect_orvibo(buf,pktinfo,root)
	dprint2("heur_dissect_orvibo called")

	if not default_settings.heur_enabled then
		return false
	end

	local pktlen = buf:reported_length_remaining()

	if pktlen < HDR_LEN then
		return false
	end

	header = buf(0,2):string()
	if header == "hd" then
		return true
	end

	return false
end

orvibo:register_heuristic("udp",heur_dissect_orvibo)
