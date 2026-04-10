# PR: Rust Test Suite with CTAPHID Socket Transport

## Summary

This PR adds a Rust-based FIDO2 test suite that replaces the external Python fido2-tests.
Tests communicate over the real CTAPHID protocol — either to a PC runner simulator
(Unix socket) or to physical LPC55 hardware (USB HID + probe-rs).

## What's Working

### Test infrastructure
- **31 tests** across 5 modules: GetInfo, MakeCredential, GetAssertion, Reset, UserPresence
- Table-driven test pattern (see `get_info.rs` for the cleanest example)
- `with_authenticator!` macro provides `&mut dyn TestAuthenticator` — tests never branch on backend
- `make test` runs all tests against the LPC55 dev board over USB HID — **31/31 pass**
- User presence control: `up::approve()` / `up::deny()` works via probe-rs memory writes on device

### PC runner simulator (`runners/pc/src/bin/main.rs`)
- Speaks real 64-byte CTAPHID packet protocol over a Unix socket (`/tmp/solo2-sim.sock`)
- CTAPHID INIT (channel allocation), PING, and CBOR command dispatch all work
- Uses `ctaphid_dispatch::App` trait to dispatch to `fido_authenticator::Authenticator`
- Successfully handles a full GetInfo request/response cycle

### Feature flags
- `test-up-control`: enables programmatic button control (atomic for PC, probe-rs for device)
- `fast-button-timeout`: vendored fido-authenticator with 5s UP timeout instead of 30s

## What's Broken (Current Bug)

### CBOR response parsing (`InvalidCbor`)

The PC runner simulator sends responses through `App::call()` which writes `status_byte + CBOR`
into a `heapless::Vec<u8, 7609>`. The test client receives the bytes but fails to parse the
CBOR with `InvalidCbor`.

**Debug state:** Both server and client hex-dump prints have been added but haven't been tested
yet (the binary needs a rebuild cycle — see the cargo caching note below).

**Likely cause:** The `App::call` response format may differ slightly from what the client's
`deserialize_response()` expects. The client was originally written for the LPC55 device which
goes through the real USB HID stack. The `App::call` path may include different framing.

**To debug:**
1. Kill any running simulator: `pkill -f "target/debug/main"`
2. Rebuild: `cd runners/pc && mv .cargo/config .cargo/config.bak && cargo build --features test-up-control,fast-button-timeout && cargo test --features test-up-control,fast-button-timeout --test fido2 --no-run && mv .cargo/config.bak .cargo/config`
3. Start simulator: `rm -f /tmp/solo2-sim.sock && target/debug/main &`
4. Wait for socket: `while [ ! -S /tmp/solo2-sim.sock ]; do sleep 0.1; done`
5. Run one test: `target/debug/deps/fido2-* --test-threads=1 --nocapture info_fido_2_0`
6. Check both `[sim]` and `[client]` hex dumps to compare expected vs actual bytes
7. Fix the mismatch in `support/transport.rs:deserialize_response()` or `main.rs:handle_packet()`

**Note on cargo caching:** The `.cargo/config` file sets `runner = "lldb"` which breaks
`cargo test`. Rename it before building/testing. Also, `[profile.dev] opt-level = 2` causes
cargo to sometimes skip recompilation even when source changes. Delete `target/debug/main`
to force a rebuild if needed.

### Previous crash (`free(): invalid pointer`)

When using `Box<heapless::Vec<u8, 7609>>` for the request/response messages, the simulator
crashes with heap corruption after processing a full test's worth of CTAP2 commands. This was
fixed by using stack-allocated messages instead. The root cause is unknown — possibly an
alignment or size issue with boxing 7609-byte heapless vecs.

## Architecture

```
tests/fido2.rs                     # Crate root: macros, helpers, mod declarations
tests/fido2/                       # One file per test area
    get_info.rs                    # Table-driven GetInfo field checks
    make_credential.rs             # MC success, error table, exclude list tests
    get_assertion.rs               # GA success, corrupt cred, wrong RP tests
    reset.rs                       # Reset, credential invalidation, reboot persistence
    user_presence.rs               # UP approve/deny via test-up-control
tests/support/
    ctaphid.rs                     # CTAPHID client (socket + HID backends)
    transport.rs                   # TestAuthenticator trait + DeviceTransport
    dispatch.rs                    # In-process CTAPHID dispatch (unused, for future)
    up.rs                          # UP control (atomic or probe-rs)

runners/pc/src/bin/main.rs         # PC runner simulator (socket CTAPHID server)
runners/pc/src/lib.rs              # Platform types + up_control module

vendor/fido-authenticator/         # Patched fido-authenticator (fast-button-timeout feature)

runners/lpc55/board/src/trussed.rs # UP_CONTROL static for probe-rs writes
```

### Transport flow

```
Test code
  → with_authenticator! macro
    → DeviceTransport::open_socket() or open_hid()
      → CtapHidClient (64-byte CTAPHID packets)
        → Unix socket (PC runner) or USB HID (LPC55 device)
          → Authenticator processes request
          → Response sent back as CTAPHID packets
        → Client reassembles and parses CBOR
      → TestAuthenticator::call_ctap2() returns Result<Response, Error>
```

### Key design decisions

- **`with_authenticator!` uses closures, not `Box<dyn>`** — the trussed service lives on
  the stack and the authenticator borrows it. Leaking the service caused hangs due to stale
  `TrussedInterchange` state between tests.

- **UP control is cross-process for device, in-process for PC** — on device, `probe-rs write`
  to a known RAM address. On PC, the simulator uses `Silent` UP (no button) since UP control
  would need IPC between test and simulator processes.

- **Global shared `CtapHidClient`** — `Mutex<Option<CtapHidClient>>` in transport.rs reuses
  one socket/HID connection across all tests in a run.

## Remaining Work

1. **Fix the `InvalidCbor` bug** — debug the response byte format mismatch
2. **Add UP control to the PC simulator** — either via a sideband socket command or by
   embedding the UP atomic in shared memory
3. **Port remaining ~140 tests** from the Python fido2-tests suite:
   - Resident key tests (19 tests)
   - PIN lifecycle (33 tests)
   - HMAC-Secret extension (12 tests)
   - CredProtect extension (10 tests)
   - Credential management (15 tests)
   - HID transport tests (19 tests)
   - CTAP1/U2F tests (13 tests)
4. **Table-driven test expansion** — the `McErrorCase` pattern in `make_credential.rs` should
   be extended with raw CBOR injection for "bad type" tests
5. **`make test` should use the socket simulator** instead of direct in-process calls

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make test` | Runs tests against LPC55 device (requires hardware) |
| `make test-build-pc` | Builds PC runner and test binary |
| `make test-lpcxpresso55` | Builds LPC55 firmware with test features, flashes, runs tests |
| `make test-lpcxpresso55-build` | Just builds LPC55 test firmware |

## Files Changed

| File | Change |
|------|--------|
| `Makefile` | Test targets for PC and LPC55 |
| `runners/pc/Cargo.toml` | Features, dev-deps (hidapi, paste, heapless), profile, patch |
| `runners/pc/src/lib.rs` | `up_control` module, storage size fixes |
| `runners/pc/src/bin/main.rs` | CTAPHID socket server (complete rewrite) |
| `runners/pc/tests/` | Entire test suite (new) |
| `runners/lpc55/Cargo.toml` | `test-up-control`, `fast-button-timeout` features |
| `runners/lpc55/board/Cargo.toml` | `test-up-control` feature |
| `runners/lpc55/board/src/trussed.rs` | `UP_CONTROL` static + gated `check_user_presence` |
| `vendor/fido-authenticator/` | Vendored with `fast-button-timeout` feature |
