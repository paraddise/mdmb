# Changelog

## Unreleased

### Added

- Terminal interface for device inventory, MDM polling, profile inspection,
  certificate viewing, SCEP enrollment, and diagnostics.
- Jamf policy catalog with manual check-in using a registered Jamf Framework
  identity. View script metadata, packages, and other actions, with previous
  policy versions saved per device.
- Typed inventory overrides, simulated application state, and declarative
  management synchronization.
- Device creation flags for name, serial number, and UDID.

### Changed

- Inventory overrides are stored per device in place of the `-config` flag.
- The CLI and TUI share command handlers for profile, application, and
  certificate inventory.
- SCEP tests use a local fixture server. Builds use published Go dependencies.

### Fixed

- Handle signed, encrypted, and binary configuration profiles in the profile
  viewer and use the active MDM identity for decryption.
- Validate SCEP replies against the request and verify that issued certificates
  match their keys.
