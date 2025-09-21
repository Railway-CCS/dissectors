# Example RaSTA and SCI dumps

## rasta_c_ESTW_C.pcapng

Dump of a demo interlocking (ESTW) controlling a light signal (C).
Connection establishment, some heartbeats, some data, and connection termination.
Two redundancy channels via different ports (not NICs).

Created with the open source RaSTA implementation: https://github.com/Railway-CCS/rasta-protocol

Make sure the dissectors are configured as follows:

| Dissector | Property               | Value          |
| --------- | ---------------------- | -------------- |
| RaSTA     | CRC Type               | Option A: None |
| RaSTA     | Safety Code            | Lower Half     |
| RaSTA     | MD4 IV                 | default        |
| RaSTA     | Payload Packetization  | no             |
| SCI       | Message Type Endianess | Big Endian     |

## rasta_from_standard.pcapng

A dump containing 6 manually created heartbeats taken from the RaSTA standard.

| No  | Safety Code Length | IV       |
| --- | ------------------ | -------- |
| 1   | No                 | Default  |
| 2   | Lower Half         | Default  |
| 3   | Full               | Default  |
| 4   | No                 | Modified |
| 5   | Lower Half         | Modified |
| 6   | Full               | Modified |

| Part  | Default  | Modified |
| ---   | -------- | -------- |
| MD4 A | 67452301 | afb16782 |
| MD4 B | efcdab89 | 304c59de |
| MD4 C | 98badcfe | 98badcfe |
| MD4 D | 10325476 | 10325476 |
