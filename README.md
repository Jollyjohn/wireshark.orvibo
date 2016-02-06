wireshark dissector for orvibo protocol
=======================================

# Description

**wiwo_orvibo.lua** is a wireshark dissector plugin to decode the orvibo S20 protocol.
It can decode most of the message protocol and ease the analysis of the protocol.

# Running

You can use this script with the following command :

    wireshark -X lua_script:wiwo_orvibo.lua

For convenience, I put some traces with this plugin.

# Notes

Many fields are unknown, incomplete or incorrect. For example :

- cd
- cs
- gt

Not all traffic is on the UDP port :

- The Orvibo S20 does some NTP query on a predefined NTP server.
- It also does some http check to the external gateway.

I didn't have a trace with the timing *table 3*, hence it is not decoded.

# License

- wiwo_orvibo.lua is under the gpl v2.0 or higher license.
- pcaps are under public domain

# Credits

This work is based on personal notes and on work made by other people.

[Reverse engineering Orvibo S20 socket](https://stikonas.eu/wordpress/2015/02/24/reverse-engineering-orvibo-s20-socket/)

Greetings to Andrius Štikonas

Have Fun !
