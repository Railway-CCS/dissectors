# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Learned to enable and disable packetization (see §5.5.10 in the standard) via protocol preferences.
- Learned to enable and disable to handover the payload to the SCI dissector via protocol preferences.

## [1.1.0] - 2024-02-23

Release v1.1.0

### Fixed

- Fixed endless loop for unknown SCI types.
- Fixed ignoring packets of exactly 45 bytes length.
- Field types are now uint32 instead of uint16.
- Messages are now interpreted as little endian.

## [1.0.0] - 2021-08-20

- Initial release

[Unreleased]: https://github.com/Railway-CCS/dissectors/compare/v1.1.0...main
[1.1.0]: https://github.com/Railway-CCS/dissectors/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Railway-CCS/dissectors/releases/tag/v1.0.0

