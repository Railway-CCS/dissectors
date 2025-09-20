# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add two example dumps.

### Changed

- Make `Safety Code Length` option an enum instead of integer.
- Capitalize protocol field names.

### Fixed

- Fix MD4 implementation with Lua 5.3 bitwise operators.
- Fix dissector messing up the length of the safety code.

## [1.3.0] - 2025-04-04

### Added

- Utilize Lua 5.3 bitwise operators [#14](https://github.com/Railway-CCS/dissectors/issues/14). Thanks to [Krydderbarn](https://github.com/Krydderbarn).

### Fixed

- Fix assuming wrong endianess: [#13](https://github.com/Railway-CCS/dissectors/issues/13). Thanks to [m435r0](https://github.com/m435r0).

## [1.2.0] - 2024-06-19

### Added

- Learn to enable and disable packetization (see §5.5.10 in the standard) via protocol preferences.
- Learn to enable and disable to handover the payload to the SCI dissector via protocol preferences.

### Changed

- Update profile to Wireshark 4.2.5

### Fixed

- Fix profile default values for RaSTA IV.

## [1.1.0] - 2024-02-23

Release v1.1.0

### Fixed

- Fixed endless loop for unknown SCI types.
- Fixed ignoring packets of exactly 45 bytes length.
- Field types are now uint32 instead of uint16.
- Messages are now interpreted as little endian.

## [1.0.0] - 2021-08-20

- Initial release

[Unreleased]: https://github.com/Railway-CCS/dissectors/compare/v1.3.0...main
[1.3.0]: https://github.com/Railway-CCS/dissectors/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Railway-CCS/dissectors/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Railway-CCS/dissectors/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Railway-CCS/dissectors/releases/tag/v1.0.0

