# Railway Dissectors

Wireshark dissectors for protocols of a railway signalling network.

## Currently available protocols

  * RaSTA
  * SCI-P
  * SCI-LS

## Installation

See https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html

### Linux

  * Copy or symlink to `~/.local/lib/wireshark/plugins` or `$XDG_CONFIG_HOME/wireshark/plugins` for Wireshark < 2.5

## Safety Code Default Values

Due to limitation in Wireshark the initial values for MD4 and the key for Blake2b/SipHash2-4 can only be specified in decimal format in the protocol preferences.

For MD4 the default initial values in decimal are

| Part  | Value      |
| ---   | ---------: |
| MD4 A | 1732584193 |
| MD4 B | 4023233417 |
| MD4 C | 2562383102 |
| MD4 D |  271733878 |

You can convert any other hex value to decimal using the following shell command:
```shell
printf '%d\n' [Hex with leading 0x]
```
(should work on Bash, Zsh and most other shells)

## Development

Useful links:

* https://wiki.wireshark.org/Lua
* https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html
* https://wiki.wireshark.org/LuaAPI
* https://wiki.wireshark.org/Lua/Examples?action=AttachFile&do=get&target=dissector.lua
* https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html

## Contact

This repository is maintained by Markus Heinrich ([rasta@0x25.net](mailto:rasta@0x25.net))
