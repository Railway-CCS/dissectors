# RaSTA and SCI Dissector Implementations

Dissector for the following protocols:

* RaSTA
* SCI-LS
* SCI-P

## RaSTA Packet Types

| Type | Name                    | Shortcut | Length     |
| ---- | ----------------------- | -------- | ---------- |
| 6200 | Connection Request      | ConnReq  | 50         |
| 6201 | Connection response     | ConnResp | 50         |
| 6212 | Retransmission Request  | RetrReq  | 36         |
| 6213 | Retransmission Response | RetrResp | 36         |
| 6216 | Disconnection Request   | DiscReq  | 40         |
| 6220 | Heartbeat               | HB       | 36         |
| 6240 | Data                    | Data     | 28 + n + 8 |
| 6241 | Retransmitted Data      | RetrData | 28 + n + 8 |

## SCI Magic Bytes

| Protocol | Byte   |
| -------- | ------ |
| SCI-ILS  | `0x01` |
| SCI-TDS  | `0x20` |
| SCI-LS   | `0x30` |
| SCI-P    | `0x40` |
| SCI-TWSS?| `0x50` |
| SCI-LX   | `0x60` |
| SCI-CC   | `0x70` |
| SCI-RBC  | `0x80` |
| SCI-IO   | `0x90` |

Note: Several versions of named SCI-Protocols are used in various environments.