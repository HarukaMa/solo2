# Agent Guide

## Prerequisites

```
sudo apt-get install -y clang llvm libclang-dev build-essential gcc-arm-none-eabi libudev-dev
rustup toolchain install 1.93.0
rustup target add thumbv8m.main-none-eabi --toolchain 1.93.0
cargo install flip-link probe-rs-tools
```

## Udev Rules (Linux)

Required for probe-rs and device access:

```
# /etc/udev/rules.d/99-solo2.rules
ATTRS{idVendor}=="1fc9", ATTRS{idProduct}=="0090", MODE="0666", TAG+="uaccess"
ATTRS{idVendor}=="1fc9", ATTRS{idProduct}=="0021", MODE="0666", TAG+="uaccess"
ATTRS{product}=="*CMSIS-DAP*", MODE="0666", TAG+="uaccess"
ATTRS{idVendor}=="1209", ATTRS{idProduct}=="beee", MODE="0666", TAG+="uaccess"
KERNEL=="hidraw*", ATTRS{idVendor}=="1fc9", ATTRS{idProduct}=="0021", MODE="0666", TAG+="uaccess"
KERNEL=="hidraw*", ATTRS{idVendor}=="1209", ATTRS{idProduct}=="beee", MODE="0666", TAG+="uaccess"
```

Then: `sudo udevadm control --reload-rules && sudo udevadm trigger`

## Build

### LPC55 firmware (embedded target)

```
cd runners/lpc55
cargo +1.93.0 build --release --features board-lpcxpresso55,develop
```

Board features: `board-lpcxpresso55`, `board-solo2`, `board-okdoe1`

### PC runner (host simulation)

```
cd runners/pc
# NOTE: .cargo/config sets runner=lldb which breaks cargo test/run.
# Rename it before building: mv .cargo/config .cargo/config.bak
cargo build --features test-up-control,fast-button-timeout
# Restore: mv .cargo/config.bak .cargo/config
```

The PC runner binary is `target/debug/main`. It listens on `/tmp/solo2-sim.sock`
and speaks CTAPHID (64-byte packets) over the Unix socket.

## Flash & Run

Requires LPC-LINK2 CMSIS-DAP probe connected via SWD debug port.

```
cd runners/lpc55
cargo +1.93.0 run --release --features board-lpcxpresso55,develop
```

This invokes `probe-rs run --chip LPC55S69JBD100`. Flash takes ~60s.
The reset warning `Dap(FaultResponse)` is normal for LPC55.

### Reset without reflashing

```
probe-rs reset --chip LPC55S69JBD100
```

Much faster than reflashing (~1s vs ~60s). Useful when tests need a device reboot.

### Recovery from NXP ROM bootloader

If the target enumerates as `1fc9:0021` instead of Solo `1209:beee`, it is in the NXP
ROM HID bootloader, not USB DFU. `probe-rs` may be unavailable or unreliable in this state.

Check the USB IDs:

```
lsusb | rg '1fc9:0021|1fc9:0090|1209:beee'
```

The ROM bootloader talks over `hidraw`, so host permissions matter. If needed:

```
sudo chmod 666 /dev/hidraw<N>
```

Install the recovery tool once:

```
cargo install --locked lpc55 --root ~/.local/cargo-lpc55
```

Useful commands:

```
~/.local/cargo-lpc55/bin/lpc55 ls
~/.local/cargo-lpc55/bin/lpc55 reboot
```

If the stock CLI cannot recover the board cleanly, the ROM protocol can still erase/write/reboot
the flash image directly using the `lpc55` crate. In this session, that was enough to restore the
board from `1fc9:0021` back to Solo firmware (`1209:beee`).

## USB

- VID:PID = `1209:beee`
- Interface 0: CCID (smartcard) — PIV/OATH APDUs
- Interface 1: HID (CTAPHID) — FIDO2/WebAuthn
- The target USB port (HS) must be connected separately from the debug port
- Board must be reset after connecting target USB for enumeration

## Testing

### Running tests against LPC55 hardware

```
make test
```

This runs 31 Rust integration tests over USB HID against the LPC55 dev board.
Requires the device to be flashed with test firmware (features: `test-up-control,fast-button-timeout`).

To flash test firmware: `make test-lpcxpresso55-build && make test-lpcxpresso55-flash`

### Running tests against PC runner simulator (WIP)

```
make test-build-pc
rm -f /tmp/solo2-sim.sock && target/debug/main &
# wait for socket
cargo test --features test-up-control,fast-button-timeout --test fido2 -- --test-threads=1
```

**Status:** The simulator starts and handles CTAPHID INIT correctly, but CBOR response
parsing has a bug. See `PR.md` for details.

### Test architecture

Tests live in `runners/pc/tests/fido2/` with one file per test area:

| File | Tests | Description |
|------|-------|-------------|
| `get_info.rs` | 12 | Table-driven GetInfo field checks |
| `make_credential.rs` | 6 | MC success, error table, exclude list |
| `get_assertion.rs` | 5 | GA success, corrupt cred, wrong RP |
| `reset.rs` | 3 | Reset, credential invalidation, reboot persistence |
| `user_presence.rs` | 5 | UP approve/deny via test-up-control |

The `with_authenticator!` macro in `fido2.rs` creates an authenticator handle and passes
`&mut dyn TestAuthenticator` to the test body. Tests never branch on backend.

### Test feature flags

| Feature | Where | Description |
|---------|-------|-------------|
| `test-up-control` | PC + LPC55 | Programmatic button press control |
| `fast-button-timeout` | fido-authenticator (vendored) | 5s UP timeout instead of 30s |

### UP control (automated button press)

**PC runner:** `solo_pc::up_control` module — shared `AtomicU8` read by `check_user_presence()`.
Tests call `up::approve()` / `up::deny()` which sets the atomic.

**LPC55 device:** `UP_CONTROL` static at a known RAM address (in `.uninit` section).
Tests call `probe-rs write b8 <addr> 1 --chip LPC55S69JBD100` to approve.
The address is extracted from the ELF: `nm <elf> | grep UP_CONTROL`.

The `support/up.rs` module abstracts both backends — selected by `UP_BACKEND` env var.

### Vendored fido-authenticator

`vendor/fido-authenticator/` is a patched copy of fido-authenticator 0.1.1.
Changes:
- `src/constants.rs`: `fast-button-timeout` feature reduces `FIDO2_UP_TIMEOUT` from 30s to 5s
- `src/lib.rs`: `#![allow(unexpected_cfgs, unused_variables)]` to suppress warnings on embedded

Both `runners/pc/Cargo.toml` and `runners/lpc55/Cargo.toml` have `[patch.crates-io]` pointing to it.

## Project Structure

```
runners/lpc55/          # Main firmware (RTIC, thumbv8m.main-none-eabi)
runners/lpc55/board/    # Board HAL (pin config, NFC, storage, USB)
runners/pc/             # PC simulation runner
runners/pc/tests/       # Rust integration tests
runners/pc/tests/fido2/ # Test modules (get_info, make_credential, etc.)
runners/pc/tests/support/ # Test helpers (ctaphid client, transport, UP control)
vendor/fido-authenticator/ # Patched fido-authenticator
components/fm11nc08/    # FM11NC08 NFC chip SPI driver
components/nfc-device/  # ISO14443-4 PICC protocol handler
components/ndef-app/    # NFC NDEF tag (serves solokeys.com URL)
components/provisioner-app/  # Factory provisioning (keys, certs)
```

## Key Features

| Feature | Description |
|---------|-------------|
| `develop` | No encrypted storage, dev-friendly defaults |
| `board-lpcxpresso55` | LPCXpresso55S69 dev board |
| `board-solo2` | Production Solo 2 hardware |
| `usbfs-peripheral` | Use USB FS instead of HS |
| `highspeed` | Enable USB high-speed mode |
| `log-defmt` | Enable defmt RTT logging |
| `no-buttons` | Auto-succeed user presence checks |
| `no-encrypted-storage` | Skip PRINCE flash encryption |
| `test-up-control` | Programmatic UP control for testing |
| `fast-button-timeout` | 5s UP timeout (vendored fido-authenticator) |

## Known Issues

### Cargo caching with `.cargo/config`

The `.cargo/config` sets `runner = "lldb"` which makes `cargo test` try to run tests through
lldb (which isn't installed). Rename the file before building/testing.

Also, `[profile.dev] opt-level = 2` and `[profile.test] opt-level = 2` in `Cargo.toml`
sometimes cause cargo to miss source changes. Delete the target binary to force a rebuild.

### Stack overflow in debug builds

CTAP2 types are large (`Request` = 6KB, `Response` = 2KB, `heapless::Vec<u8, 7609>` = 7.6KB).
In unoptimized debug builds, stack frames can exceed the default thread stack size. Solutions:
- `[profile.test] opt-level = 2` in Cargo.toml
- `run_in_thread()` with 256KB stack for tests
- `Box::leak` for storage types (~40KB each)

### CTAP2 Reset time window

The authenticator only allows Reset within 10 seconds of boot. For device tests, the reset
test reboots the device via `probe-rs reset` before sending the CTAP2 Reset command.

## Clippy

LPC55 runner has `-Dwarnings` in `.cargo/config.toml` — clippy will error on `type_complexity` and other warnings. Use `--release` to match CI build profile.

## CI

GitHub Actions (`.github/workflows/ci.yml`) builds both LPC55 (lpcxpresso55 + solo2 boards) and PC runner on Ubuntu.
