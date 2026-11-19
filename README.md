# mdmb

mdmb simulates Apple devices for MDM protocol testing, load testing, and validation. It can enroll test devices, poll MDM commands, and track simulated inventory.

*mdmb* creates sets of fake Apple devices and allows you to enroll in, connect to, and thereby interact with Apple MDM servers. Interactions include receiving and responding to MDM commands and some common device actions like installing profiles and responding to information commands.

The goal of this project is to facilitate testing of Apple MDM servers in various ways. I.e:

  - Load & scalability testing
  - MDM protocol testing & feature development
  - Monitoring & validation
  - CI/CD

## Limitations

### Device simulation

The device simulation tries to be *similar* to a real Apple device. As such *mdmb* simulates a device Keychain, Configuration Profile store, Profile and per-Profile Payload processing (for profile installation & removal), an MDM Client, and more which are used when interacting with Apple MDM servers.

That said, *mdmb*'s device simulation is only meant to serve its ability to test MDM servers. This means many MDM commands, Configuration Profile payloads, and other aspects of simulating devices are missing, incomplete, erroneous, out of scope, or otherwise broken.

### APNs

A key component of Apple MDM is Apple's Push Notification service (APNs). However, as we are only simulating devices we cannot authenticate to Apple's APNs service. Therefore this part of the MDM communication channel simply doesn't work. We generate fake [push tokens and push magic](https://developer.apple.com/documentation/devicemanagement/tokenupdaterequest?language=objc) as we enroll with the MDM server. As such the MDM server attempting to send push notifications to our simulated devices will not succeed. Even if the notifications were processed by Apple's servers `mdmb` wouldn't be able to *receive* those notifications anyway.

Because the MDM server can't signal the device to connect to it we instead simulate a device receiving a push notification by specifically requesting that it connect to the MDM server on demand, shown below.

### OTA & ADE enrollment

OTA & ADE (DEP) enrollments ostensibly validate the initial enrollment data signature against an Apple CA for which *only Apple devices* can recieve a certificate. Again becasue were merely simulate Apple devices we cannot obtain one of these certificates that are signed by Apple's Device CA. This means that in order to support OTA or ADE/DEP enrollments the MDM server must not have implemented or have disabled their device certificate validation. Practically this means simulated OTA and ADE enrollments are not supported.

## Getting started

### Installing & Building

Build with Go 1.21 or newer. Run `make` for the host-specific binary, or
build a binary named `mdmb` for the commands below.

```sh
go build -o mdmb ./cmd/mdmb
./mdmb tui
```

Run `go test ./...` to check the simulator and the local protocol fixtures.
See [CHANGELOG.md](CHANGELOG.md) for release notes.

### Terminal interface

Run `mdmb tui` in a terminal. To open a different database, run
`mdmb -db path/to/mdmb.db tui`. The interface uses the same devices and
profiles as the CLI. Close the TUI before running another command on the same
database.

- **Devices** · Use the arrow keys to move, `/` to search by name, serial, or
  UDID, `Enter` to open a device, and `n` to create one.
- **Inventory** · Press `i` in the device view to edit JSON, `Ctrl+S` to save,
  and `v` from the device view to see effective MDM values.
- **Profiles** · Press `p` in the device view, `Enter` to inspect an installed
  profile, and `e` to export the original `.mobileconfig` bytes. The profile
  viewer decrypts encrypted payloads locally when the device has the matching
  MDM identity.
- **Jamf Policies** · Press `j` to view the device's saved policy catalog.
  Open a policy with `Enter` to see its script names and order, packages,
  printers, maintenance, and restart settings. Press `r` to request a recurring
  check-in, then confirm the Jamf address. Use a dedicated test device because
  Jamf may update its inventory and mark returned policies as running.
  The catalog keeps metadata for previous versions and survives restarts.
  Refresh requires an HTTPS Jamf enrollment profile and a Jamf Management
  Framework certificate already registered for the selected device. Launch the
  TUI with `mdmb -db path/to/mdmb.db tui -jamf-cert framework.pem -jamf-key framework-key.pem`.
  The certificate can be PEM or DER, and the key must be PEM. The certificate
  common name must match the device UDID.
  The TUI loads the identity for the session. The database stores policy
  metadata. If known, set `QueryResponses.JamfBinaryVersion` in the inventory
  editor to include it in the check-in.
- **Certificates** · Press `k` from the device view to list certificates in its
  System keychain. The active MDM certificate carries the **MDM identity** label.
  Open a certificate with `Enter`, switch between text and PEM with `t`, and
  export the current format with `e`. Export requires a destination that
  does not already exist.
- **SCEP** · In a profile with SCEP payloads, press `s`, select a payload,
  and press `e` to review the payload name and server host before enrolling.
  Press `Esc` during enrollment to cancel, or `Enter` on an issued payload
  to view its certificate.
- **MDM** · Press `c` from the device or profiles view to poll MDM and `Esc`
  to cancel. Press `a` in the device view to toggle **Auto SCEP Enroll** for
  that device. It defaults to off. When enabled, both **Poll MDM** and
  `devices-connect` enroll eligible payloads in stored profiles and profiles
  delivered by MDM. MDM acknowledges the original profile before attempting
  issuance. Press `l` to see diagnostics.

Successful SCEP issuance is recorded per device, profile, and payload version.
A failed, cancelled, or interrupted version requires manual enrollment to
retry. Earlier certificates remain in the System keychain after a payload
changes. MDM polling and profile decryption continue to use the active MDM
identity.

Inventory is stored per device in place of the previous `-config` flag.
In the JSON editor, `QueryResponses` accepts typed values. For example,
`"BatteryLevel": 0.85` represents 85%, `"IsSupervised": true` is a boolean,
and `"ActiveManagedUsers": []` is an array. Use RFC 3339 for dates and
base64 for data fields such as `PushToken`. Existing string overrides for
known fields are converted when read. `SecurityInfo` accepts settings such
as `"PasscodeCompliant": false`, `"PasscodeLockGracePeriod": 0`, and
`"FDE_Enabled": true`. Press `v` to see the effective responses.

Use `devices-profiles-install` for initial enrollment or local profile
installation, and `devices-profiles-remove` to remove a profile.

### Simulated MDM commands

Both `devices-connect` and **Poll MDM** use the same command handlers.
Profile and application installs update the simulated inventory for the
current device. `CertificateList` includes public certificates from installed
profiles alongside the device's keychain certificates. Removing a profile
removes its public certificate from inventory when no other source supplies
it. Separately issued SCEP identities stay in the keychain.

Application installation resolves the bundle identifier from the command, the
inline enterprise manifest, or the device's `Applications` catalog in the
inventory editor. Catalog entries can map a Store ID or an HTTPS manifest URL
to a bundle identifier and optional display metadata.

```json
"Applications": [
  {
    "Identifier": "com.example.app",
    "Name": "Example App",
    "Version": "2",
    "ShortVersion": "2.0",
    "StoreID": 123456789
  }
]
```

Package URLs identify catalog entries. The simulator installs application
records in BoltDB and handles managed app configuration and attributes through
`Settings`. `EraseDevice` and power, lock, and account commands return
simulated acknowledgments and appear in diagnostics.

Declarative management uses the configured MDM CheckIn URL on the device
channel. The simulator synchronizes and caches declarations per device, then
reports the downloaded declarations as inactive. Failed downloads preserve the
previous snapshot, and failed status reports are retried on the next sync.

The test suite uses synthetic device records and local servers for MDM, Jamf
policy retrieval, declarative management, and SCEP.

### CLI quick start

Create a test device and use its generated ID to install an enrollment
profile.

```sh
device_id=$(./mdmb devices-create | tail -n 1)
./mdmb -uuids "$device_id" devices-profiles-install -f enrollment.mobileconfig
./mdmb -uuids "$device_id" devices-connect
```

List saved devices with `./mdmb devices-list`. Create multiple devices with
`./mdmb devices-create -n 3`. Use `-uuids all` to select every device or
`-uuids -` to read one ID per line from standard input.

The CLI and TUI store devices in `mdmb.db` by default. Use `-db path/to/mdmb.db`
to work with a different database. The database can contain enrollment
profiles and device private keys.
