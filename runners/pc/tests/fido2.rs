//! FIDO2 authenticator test suite.
//!
//! Runs against either an in-process PC runner or a real USB device.
//! Set `FIDO2_TRANSPORT=device` to target hardware.

use littlefs2::const_ram_storage;
use littlefs2::fs::{Allocation, Filesystem};
use trussed::types::{LfsResult, LfsStorage};
use trussed::{platform, store};
use trussed::pipe::TrussedInterchange;
use trussed::service::SeedableRng;
use interchange::Interchange;

use fido_authenticator::{Authenticator, Config, Silent, Conforming};
use ctap_types::ctap2::{self, Request, Response};

use serial_test::serial;
use paste::paste;

mod support;
use support::up;
use support::transport::{self, Backend, TestAuthenticator, DeviceTransport};

// --- Test platform types ---

const_ram_storage!(InternalStorage, 4096 * 10);
const_ram_storage!(ExternalStorage, 4096 * 10);
const_ram_storage!(VolatileStorage, 4096 * 10);

pub struct TestUserInterface {
    start: std::time::Instant,
}

impl Default for TestUserInterface {
    fn default() -> Self {
        Self { start: std::time::Instant::now() }
    }
}

impl trussed::platform::UserInterface for TestUserInterface {
    fn check_user_presence(&mut self) -> trussed::platform::consent::Level {
        let level = solo_pc::up_control::take();
        if level == trussed::platform::consent::Level::None {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        level
    }
    fn set_status(&mut self, _status: trussed::platform::ui::Status) {}
    fn refresh(&mut self) {}
    fn uptime(&mut self) -> core::time::Duration { self.start.elapsed() }
    fn reboot(&mut self, _to: trussed::platform::reboot::To) -> ! {
        panic!("reboot called in test");
    }
    fn wink(&mut self, _duration: core::time::Duration) {}
}

// --- Memory setup (heap-allocated to avoid stack overflow) ---

struct TestMemory {
    internal_storage: Box<InternalStorage>,
    internal_alloc: Box<Allocation<InternalStorage>>,
    external_storage: Box<ExternalStorage>,
    external_alloc: Box<Allocation<ExternalStorage>>,
    volatile_storage: Box<VolatileStorage>,
    volatile_alloc: Box<Allocation<VolatileStorage>>,
}

impl TestMemory {
    fn new() -> Self {
        Self {
            internal_storage: Box::new(InternalStorage::new()),
            internal_alloc: Box::new(Filesystem::allocate()),
            external_storage: Box::new(ExternalStorage::new()),
            external_alloc: Box::new(Filesystem::allocate()),
            volatile_storage: Box::new(VolatileStorage::new()),
            volatile_alloc: Box::new(Filesystem::allocate()),
        }
    }
}

fn leak_memory(mem: TestMemory) -> (
    &'static mut Allocation<InternalStorage>,
    &'static mut InternalStorage,
    &'static mut Allocation<ExternalStorage>,
    &'static mut ExternalStorage,
    &'static mut Allocation<VolatileStorage>,
    &'static mut VolatileStorage,
) {
    let mem = Box::leak(Box::new(mem));
    (
        &mut *mem.internal_alloc, &mut *mem.internal_storage,
        &mut *mem.external_alloc, &mut *mem.external_storage,
        &mut *mem.volatile_alloc, &mut *mem.volatile_storage,
    )
}

fn run_in_thread<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    const ISOLATED_ENV: &str = "FIDO2_ISOLATED_TEST";

    if transport::backend() == Backend::Sim {
        if let Some(test_name) = std::thread::current().name() {
            if std::env::var(ISOLATED_ENV).ok().as_deref() != Some(test_name) {
                let status = std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("--exact")
                    .arg(test_name)
                    .arg("--test-threads=1")
                    .env(ISOLATED_ENV, test_name)
                    .status()
                    .expect("spawn isolated test subprocess");

                assert!(status.success(), "isolated test subprocess failed: {}", test_name);
                return;
            }
        }
    }

    std::thread::Builder::new()
        .name("fido-test".into())
        .stack_size(256 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

fn run_isolated_in_sim<F>(test_name: &str, f: F)
where
    F: FnOnce() + Send + 'static,
{
    const ISOLATED_ENV: &str = "FIDO2_ISOLATED_TEST";

    if transport::backend() != Backend::Sim
        || std::env::var(ISOLATED_ENV).ok().as_deref() == Some(test_name)
    {
        f();
        return;
    }

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(test_name)
        .arg("--test-threads=1")
        .env(ISOLATED_ENV, test_name)
        .status()
        .expect("spawn isolated test subprocess");

    assert!(status.success(), "isolated test subprocess failed: {}", test_name);
}

// =============================================================================
// The core abstraction: `authenticator!` returns a `Box<dyn TestAuthenticator>`
// regardless of backend. Tests never branch on transport mode.
// =============================================================================

/// Run test body against any authenticator backend.
///
/// - `FIDO2_TRANSPORT=device`: USB HID to real hardware
/// - `FIDO2_TRANSPORT=socket`: Unix socket to PC runner simulator
/// - unset/default: in-process simulator
///
/// The `$body` receives `&mut dyn TestAuthenticator`.
macro_rules! with_authenticator {
    ($name:ident, |$authn:ident| $body:block) => {
        with_authenticator!($name, Conforming {}, |$authn| $body)
    };
    ($name:ident, $up:expr, |$authn:ident| $body:block) => {
        match transport::backend() {
            Backend::Device => {
                let mut dev = DeviceTransport::open_hid();
                let $authn: &mut dyn TestAuthenticator = &mut dev;
                $body
            }
            Backend::Socket => {
                let mut sock = DeviceTransport::open_socket();
                let $authn: &mut dyn TestAuthenticator = &mut sock;
                $body
            }
            Backend::Sim => {
                let memory = leak_memory(TestMemory::new());
                paste! {
                    store!([<$name Store>], Internal: InternalStorage, External: ExternalStorage, Volatile: VolatileStorage);
                    platform!([<$name Platform>], R: chacha20::ChaCha8Rng, S: [<$name Store>], UI: TestUserInterface,);
                    let store = [<$name Store>]::claim().unwrap();
                    store.mount(memory.0, memory.1, memory.2, memory.3, memory.4, memory.5, true).unwrap();
                    let mut svc = trussed::service::Service::new(
                        [<$name Platform>]::new(
                            chacha20::ChaCha8Rng::from_seed([0u8; 32]),
                            store,
                            TestUserInterface::default(),
                        ),
                    );
                    unsafe { TrussedInterchange::reset_claims(); }
                    let (req, resp) = TrussedInterchange::claim().unwrap();
                    assert!(svc.add_endpoint(resp, "fido".into()).is_ok());
                    svc.set_seed_if_uninitialized(&[0u8; 32]);
                    let mut sim = Authenticator::new(
                        trussed::ClientImplementation::new(req, &mut svc),
                        $up,
                        Config { max_msg_size: 7609, skip_up_timeout: None },
                    );
                    let $authn: &mut dyn TestAuthenticator = &mut sim;
                    $body
                }
            }
        }
    };
}

// --- Shared request builders ---

fn make_credential_request() -> ctap2::make_credential::Request {
    make_credential_request_for("example.com", &[0x01; 16], "testuser", false)
}

fn make_credential_request_for(
    rp_id: &str,
    user_id: &[u8],
    user_name: &str,
    resident_key: bool,
) -> ctap2::make_credential::Request {
    use ctap_types::webauthn::*;
    use ctap_types::Bytes;
    ctap2::make_credential::Request {
        client_data_hash: Bytes::from_slice(&[0xcd; 32]).unwrap(),
        rp: PublicKeyCredentialRpEntity { id: rp_id.into(), name: Some("Example".into()), url: None },
        user: PublicKeyCredentialUserEntity {
            id: Bytes::from_slice(user_id).unwrap(),
            icon: None, name: Some(user_name.into()), display_name: Some("Test User".into()),
        },
        pub_key_cred_params: {
            let mut v = ctap_types::Vec::new();
            v.push(PublicKeyCredentialParameters::public_key_with_alg(-7)).unwrap();
            v
        },
        exclude_list: None,
        extensions: None,
        options: resident_key.then_some(ctap2::AuthenticatorOptions { rk: Some(true), up: None, uv: None }),
        pin_auth: None,
        pin_protocol: None,
    }
}

fn get_assertion_request(credential_id: &[u8]) -> ctap2::get_assertion::Request {
    get_assertion_request_for("example.com", Some(single_allow_list(credential_id)))
}

fn get_assertion_request_for(
    rp_id: &str,
    allow_list: Option<ctap2::get_assertion::AllowList>,
) -> ctap2::get_assertion::Request {
    use ctap_types::Bytes;
    ctap2::get_assertion::Request {
        rp_id: rp_id.into(),
        client_data_hash: Bytes::from_slice(&[0xcd; 32]).unwrap(),
        allow_list,
        extensions: None, options: None, pin_auth: None, pin_protocol: None,
    }
}

fn single_allow_list(credential_id: &[u8]) -> ctap2::get_assertion::AllowList {
    use ctap_types::webauthn::*;
    use ctap_types::Bytes;
    let mut allow_list: ctap2::get_assertion::AllowList = ctap_types::Vec::new();
    allow_list.push(PublicKeyCredentialDescriptor {
        id: Bytes::from_slice(credential_id).unwrap(), key_type: "public-key".into(),
    }).unwrap();
    allow_list
}

fn extract_credential_id(auth_data: &[u8]) -> Vec<u8> {
    let offset = 32 + 1 + 4 + 16;
    let len = u16::from_be_bytes([auth_data[offset], auth_data[offset + 1]]) as usize;
    auth_data[offset + 2..offset + 2 + len].to_vec()
}

fn make_credential(authn: &mut dyn TestAuthenticator) -> Vec<u8> {
    let resp = authn.call_ctap2(&Request::MakeCredential(make_credential_request()))
        .expect("MakeCredential failed");
    match resp {
        Response::MakeCredential(mc) => extract_credential_id(&mc.auth_data),
        other => panic!("Expected MakeCredential, got {:?}", other),
    }
}

// --- Device reset helper ---

/// Reboot the device (device mode only) so CTAP2 Reset is within the 10s window.
fn device_reboot() {
    if !transport::is_device_mode() { return; }
    let chip = std::env::var("PROBE_RS_CHIP").unwrap_or("LPC55S69JBD100".into());
    let protocol = std::env::var("PROBE_RS_PROTOCOL").ok();
    let speed = std::env::var("PROBE_RS_SPEED").ok();
    let mut cmd = std::process::Command::new("probe-rs");
    cmd.args(["reset", "--chip", &chip]);
    if let Some(p) = protocol.as_deref() { cmd.args(["--protocol", p]); }
    if let Some(s) = speed.as_deref() { cmd.args(["--speed", s]); }
    let _ = cmd.status();
    std::thread::sleep(std::time::Duration::from_secs(1));
}

/// Reset the authenticator to a clean state (no credentials, no PIN).
/// Reboots the device (device mode), reconnects, then sends CTAP2 Reset.
fn reset_authenticator(authn: &mut dyn TestAuthenticator) {
    device_reboot();
    authn.reconnect();
    up::approve();
    let _ = authn.call_ctap2(&Request::Reset);
}

// --- Submodules ---

#[path = "fido2/get_info.rs"]
mod get_info;

#[path = "fido2/make_credential.rs"]
mod make_credential;

#[path = "fido2/get_assertion.rs"]
mod get_assertion;

#[path = "fido2/get_assertion_parity.rs"]
mod get_assertion_parity;

#[path = "fido2/resident_key.rs"]
mod resident_key;

#[path = "fido2/credential_management.rs"]
mod credential_management;

#[path = "fido2/pin.rs"]
mod pin;

#[path = "fido2/reset.rs"]
mod reset;

#[path = "fido2/user_presence.rs"]
mod user_presence;

#[path = "fido2/cred_protect.rs"]
mod cred_protect;

#[path = "fido2/hmac_secret.rs"]
mod hmac_secret;
