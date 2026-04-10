//! Transport abstraction for FIDO2 tests.
//!
//! - Default: in-process simulator
//! - `FIDO2_TRANSPORT=socket`: simulator over CTAPHID Unix socket
//! - `FIDO2_TRANSPORT=device`: USB HID to a real FIDO2 device

use ctap_types::ctap2::{self, Request, Response};

/// The single interface tests use to talk to any authenticator backend.
pub trait TestAuthenticator {
    fn call_ctap2(&mut self, request: &Request) -> Result<Response, ctap2::Error>;
    fn call_ctap2_raw(&mut self, command: u8, payload: &[u8]) -> Result<(u8, Vec<u8>), ctap2::Error>;
    /// Reconnect to the device after a reboot. No-op for in-process backends.
    fn reconnect(&mut self) {}
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Backend {
    Sim,
    Socket,
    Device,
}

pub fn backend() -> Backend {
    match std::env::var("FIDO2_TRANSPORT").as_deref() {
        Ok("device") => Backend::Device,
        Ok("socket") => Backend::Socket,
        _ => Backend::Sim,
    }
}

/// Returns true if tests should target a real USB device.
pub fn is_device_mode() -> bool {
    backend() == Backend::Device
}

// ---------------------------------------------------------------------------
// Blanket impl: any fido_authenticator::Authenticator is a TestAuthenticator
// ---------------------------------------------------------------------------

impl<UP, T> TestAuthenticator for fido_authenticator::Authenticator<UP, T>
where
    UP: fido_authenticator::UserPresence,
    T: fido_authenticator::TrussedRequirements,
{
    fn call_ctap2(&mut self, request: &Request) -> Result<Response, ctap2::Error> {
        ctap2::Authenticator::call_ctap2(self, request)
    }

    fn call_ctap2_raw(&mut self, command: u8, payload: &[u8]) -> Result<(u8, Vec<u8>), ctap2::Error> {
        use ctaphid_dispatch::app::{App, Command, Message};

        let mut request: Message = heapless::Vec::new();
        request.push(command).map_err(|_| ctap2::Error::RequestTooLarge)?;
        request.extend_from_slice(payload).map_err(|_| ctap2::Error::RequestTooLarge)?;

        let mut response: Message = heapless::Vec::new();
        App::call(self, Command::Cbor, &request, &mut response).map_err(|_| ctap2::Error::Other)?;

        if response.is_empty() {
            return Err(ctap2::Error::Other);
        }

        Ok((response[0], response[1..].to_vec()))
    }
}

// ---------------------------------------------------------------------------
// Device/socket backend: CTAPHID
// ---------------------------------------------------------------------------

pub struct DeviceTransport {
    client: super::ctaphid::CtapHidClient,
}

impl DeviceTransport {
    pub fn open_hid() -> Self {
        Self {
            client: super::ctaphid::CtapHidClient::open_hid(),
        }
    }

    pub fn open_socket() -> Self {
        Self {
            client: super::ctaphid::CtapHidClient::connect_socket(),
        }
    }
}

impl TestAuthenticator for DeviceTransport {
    fn call_ctap2(&mut self, request: &Request) -> Result<Response, ctap2::Error> {
        let mut buf = [0u8; 4096];
        let data = serialize_request(request, &mut buf);
        let timeout = std::time::Duration::from_secs(30);

        let (status, cbor) = self.client.ctap2(data, timeout)
            .map_err(|e| { eprintln!("[transport] error: {e}"); ctap2::Error::Other })?;

        if status != 0 {
            return Err(error_from_byte(status));
        }

        deserialize_response(request, &cbor)
    }

    fn call_ctap2_raw(&mut self, command: u8, payload: &[u8]) -> Result<(u8, Vec<u8>), ctap2::Error> {
        let mut data = Vec::with_capacity(1 + payload.len());
        data.push(command);
        data.extend_from_slice(payload);
        self.client.ctap2(&data, std::time::Duration::from_secs(30))
            .map_err(|_| ctap2::Error::Other)
    }

    fn reconnect(&mut self) {
        self.client = super::ctaphid::CtapHidClient::open_hid();
    }
}

pub fn serialize_request<'a>(request: &Request, buf: &'a mut [u8]) -> &'a [u8] {
    match request {
        Request::GetInfo => {
            buf[0] = 0x04;
            &buf[..1]
        }
        Request::MakeCredential(req) => {
            buf[0] = 0x01;
            let cbor = ctap_types::serde::cbor_serialize(req, &mut buf[1..])
                .expect("CBOR serialize MakeCredential");
            let len = 1 + cbor.len();
            &buf[..len]
        }
        Request::GetAssertion(req) => {
            buf[0] = 0x02;
            let cbor = ctap_types::serde::cbor_serialize(req, &mut buf[1..])
                .expect("CBOR serialize GetAssertion");
            let len = 1 + cbor.len();
            &buf[..len]
        }
        Request::Reset => {
            buf[0] = 0x07;
            &buf[..1]
        }
        Request::ClientPin(req) => {
            buf[0] = 0x06;
            let cbor = ctap_types::serde::cbor_serialize(req, &mut buf[1..])
                .expect("CBOR serialize ClientPin");
            let len = 1 + cbor.len();
            &buf[..len]
        }
        Request::CredentialManagement(req) => {
            buf[0] = 0x0A;
            let cbor = ctap_types::serde::cbor_serialize(req, &mut buf[1..])
                .expect("CBOR serialize CredentialManagement");
            let len = 1 + cbor.len();
            &buf[..len]
        }
        Request::GetNextAssertion => {
            buf[0] = 0x08;
            &buf[..1]
        }
        Request::Selection => {
            buf[0] = 0x0B;
            &buf[..1]
        }
        Request::Vendor(op) => {
            buf[0] = u8::from(*op);
            &buf[..1]
        }
    }
}

pub fn deserialize_response(request: &Request, cbor: &[u8]) -> Result<Response, ctap2::Error> {
    match request {
        Request::GetInfo => {
            let info: ctap2::get_info::Response = ctap_types::serde::cbor_deserialize(cbor)
                .map_err(|_| ctap2::Error::InvalidCbor)?;
            Ok(Response::GetInfo(info))
        }
        Request::GetAssertion(_) => {
            let resp: ctap2::get_assertion::Response = ctap_types::serde::cbor_deserialize(cbor)
                .map_err(|_| ctap2::Error::InvalidCbor)?;
            Ok(Response::GetAssertion(resp))
        }
        Request::GetNextAssertion => {
            let resp: ctap2::get_assertion::Response = ctap_types::serde::cbor_deserialize(cbor)
                .map_err(|_| ctap2::Error::InvalidCbor)?;
            Ok(Response::GetNextAssertion(resp))
        }
        Request::MakeCredential(_) => {
            parse_make_credential_response(cbor)
        }
        Request::Reset => Ok(Response::Reset),
        Request::Selection => Ok(Response::Selection),
        Request::ClientPin(_) => {
            let resp: ctap2::client_pin::Response = ctap_types::serde::cbor_deserialize(cbor)
                .map_err(|_| ctap2::Error::InvalidCbor)?;
            Ok(Response::ClientPin(resp))
        }
        Request::CredentialManagement(_) => {
            Err(ctap2::Error::Other)
        }
        Request::Vendor(_) => Ok(Response::Vendor),
    }
}

/// Parse MakeCredential CBOR response manually (Response type is serialize-only).
fn parse_make_credential_response(cbor: &[u8]) -> Result<Response, ctap2::Error> {
    let mut fmt = ctap_types::String::from("none");
    let mut auth_data = ctap_types::Bytes::new();

    let mut pos = 0;
    if pos >= cbor.len() { return Err(ctap2::Error::InvalidCbor); }

    let map_len = match cbor[pos] {
        b @ 0xa0..=0xa7 => { pos += 1; (b - 0xa0) as usize }
        0xb8 => { pos += 1; let n = cbor[pos] as usize; pos += 1; n }
        _ => return Err(ctap2::Error::InvalidCbor),
    };

    for _ in 0..map_len {
        if pos >= cbor.len() { break; }
        let key = match cbor[pos] {
            b @ 0x00..=0x17 => { pos += 1; b as u32 }
            0x18 => { pos += 1; let v = cbor[pos] as u32; pos += 1; v }
            _ => return Err(ctap2::Error::InvalidCbor),
        };
        if pos >= cbor.len() { return Err(ctap2::Error::InvalidCbor); }
        match key {
            1 => { let (s, p) = parse_cbor_text(cbor, pos)?; fmt = ctap_types::String::from(s.as_str()); pos = p; }
            2 => { let (b, p) = parse_cbor_bytes(cbor, pos)?; auth_data = ctap_types::Bytes::from_slice(&b).map_err(|_| ctap2::Error::InvalidCbor)?; pos = p; }
            _ => { pos = skip_cbor_value(cbor, pos)?; }
        }
    }

    Ok(Response::MakeCredential(ctap2::make_credential::Response {
        fmt,
        auth_data,
        att_stmt: ctap2::make_credential::AttestationStatement::None(
            ctap2::make_credential::NoneAttestationStatement {}
        ),
    }))
}

fn parse_cbor_text(cbor: &[u8], pos: usize) -> Result<(String, usize), ctap2::Error> {
    let (len, mut p) = parse_cbor_len(cbor, pos, 0x60)?;
    let s = std::str::from_utf8(&cbor[p..p + len]).map_err(|_| ctap2::Error::InvalidCbor)?;
    p += len;
    Ok((s.to_string(), p))
}

fn parse_cbor_bytes(cbor: &[u8], pos: usize) -> Result<(Vec<u8>, usize), ctap2::Error> {
    let (len, mut p) = parse_cbor_len(cbor, pos, 0x40)?;
    let b = cbor[p..p + len].to_vec();
    p += len;
    Ok((b, p))
}

fn parse_cbor_len(cbor: &[u8], pos: usize, major: u8) -> Result<(usize, usize), ctap2::Error> {
    let b = cbor[pos];
    if b & 0xe0 != major { return Err(ctap2::Error::InvalidCbor); }
    let additional = b & 0x1f;
    let mut p = pos + 1;
    let len = match additional {
        n @ 0..=23 => n as usize,
        24 => { let v = cbor[p] as usize; p += 1; v }
        25 => { let v = u16::from_be_bytes([cbor[p], cbor[p + 1]]) as usize; p += 2; v }
        _ => return Err(ctap2::Error::InvalidCbor),
    };
    Ok((len, p))
}

fn skip_cbor_value(cbor: &[u8], pos: usize) -> Result<usize, ctap2::Error> {
    if pos >= cbor.len() { return Err(ctap2::Error::InvalidCbor); }
    let major = cbor[pos] >> 5;
    let additional = cbor[pos] & 0x1f;
    let mut p = pos + 1;
    let arg = match additional {
        n @ 0..=23 => n as usize,
        24 => { let v = cbor[p] as usize; p += 1; v }
        25 => { let v = u16::from_be_bytes([cbor[p], cbor[p + 1]]) as usize; p += 2; v }
        26 => { let v = u32::from_be_bytes([cbor[p], cbor[p+1], cbor[p+2], cbor[p+3]]) as usize; p += 4; v }
        _ => return Err(ctap2::Error::InvalidCbor),
    };
    match major {
        0 | 1 => Ok(p),
        2 | 3 => Ok(p + arg),
        4 => { for _ in 0..arg { p = skip_cbor_value(cbor, p)?; } Ok(p) }
        5 => { for _ in 0..arg { p = skip_cbor_value(cbor, p)?; p = skip_cbor_value(cbor, p)?; } Ok(p) }
        7 => Ok(p),
        _ => Err(ctap2::Error::InvalidCbor),
    }
}

pub fn error_from_byte(b: u8) -> ctap2::Error {
    match b {
        0x01 => ctap2::Error::InvalidCommand,
        0x02 => ctap2::Error::InvalidParameter,
        0x03 => ctap2::Error::InvalidLength,
        0x14 => ctap2::Error::MissingParameter,
        0x19 => ctap2::Error::CredentialExcluded,
        0x22 => ctap2::Error::InvalidCredential,
        0x26 => ctap2::Error::UnsupportedAlgorithm,
        0x27 => ctap2::Error::OperationDenied,
        0x2E => ctap2::Error::NoCredentials,
        0x2F => ctap2::Error::UserActionTimeout,
        0x30 => ctap2::Error::NotAllowed,
        0x31 => ctap2::Error::PinInvalid,
        0x32 => ctap2::Error::PinBlocked,
        0x33 => ctap2::Error::PinAuthInvalid,
        0x34 => ctap2::Error::PinAuthBlocked,
        0x35 => ctap2::Error::PinNotSet,
        0x36 => ctap2::Error::PinRequired,
        0x37 => ctap2::Error::PinPolicyViolation,
        0x38 => ctap2::Error::PinTokenExpired,
        0x3B => ctap2::Error::UpRequired,
        _ => ctap2::Error::Other,
    }
}
