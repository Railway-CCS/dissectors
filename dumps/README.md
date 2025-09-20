# Example RaSTA and SCI dumps

## rasta_c_ESTW_C.pcapng

Dump of a demo interlocking (ESTW) controlling a light signal (C).
Connection establishment, some heartbeats, some data, and connection termination.
Two redundancy channels via different ports (not NICs).

Created with the open source RaSTA implementation: https://github.com/Railway-CCS/rasta-protocol

| Safety Code           | Lower Half |
| MD4 IV                | default    |
| Payload Packetization | yes        |

## rasta_from_standard.pcapng

A dump containing 6 manually created heartbeats taken from the RaSTA standard.

| No  | Safety Code Length | IV       |
| --- | ---                | ---      |
| 1   | No                 | Default  |
| 2   | Lower Half         | Default  |
| 3   | Full               | Default  |
| 4   | No                 | Modified |
| 5   | Lower Half         | Modified |
| 6   | Full               | Modified |

