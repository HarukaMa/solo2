//! In-process CTAPHID dispatch transport.
//!
//! Serializes CTAP2 requests to CBOR, dispatches through the ctaphid App
//! trait, and deserializes the response. Tests the full serialization +
//! dispatch stack without needing a separate process or socket.

use ctap_types::ctap2::{self, Request, Response};
use ctaphid_dispatch::app::{self as ctaphid, App, Command};
use super::transport::TestAuthenticator;

/// Wraps any `ctaphid::App` implementor and dispatches through the
/// CTAPHID CBOR command path (serialize → App::call → deserialize).
pub struct DispatchTransport<'a, A: App> {
    app: &'a mut A,
}

impl<'a, A: App> DispatchTransport<'a, A> {
    pub fn new(app: &'a mut A) -> Self {
        Self { app }
    }
}

impl<'a, A: App> TestAuthenticator for DispatchTransport<'a, A> {
    fn call_ctap2(&mut self, request: &Request) -> Result<Response, ctap2::Error> {
        // Serialize request to CBOR (same as wire format)
        let mut buf = [0u8; 4096];
        let data = serialize_request(request, &mut buf);

        // Build CTAPHID message
        let mut request_msg: ctaphid::Message = heapless::Vec::new();
        request_msg.extend_from_slice(data)
            .map_err(|_| ctap2::Error::RequestTooLarge)?;
        let mut response_msg: ctaphid::Message = heapless::Vec::new();

        // Dispatch through App trait
        self.app.call(Command::Cbor, &request_msg, &mut response_msg)
            .map_err(|_| ctap2::Error::Other)?;

        // Parse response: status byte + CBOR
        if response_msg.is_empty() {
            return Err(ctap2::Error::Other);
        }
        let status = response_msg[0];
        if status != 0 {
            return Err(super::transport::error_from_byte(status));
        }

        let cbor = &response_msg[1..];
        super::transport::deserialize_response(request, cbor)
    }

    fn call_ctap2_raw(&mut self, command: u8, payload: &[u8]) -> Result<(u8, Vec<u8>), ctap2::Error> {
        let mut request_msg: ctaphid::Message = heapless::Vec::new();
        request_msg.push(command).map_err(|_| ctap2::Error::RequestTooLarge)?;
        request_msg
            .extend_from_slice(payload)
            .map_err(|_| ctap2::Error::RequestTooLarge)?;

        let mut response_msg: ctaphid::Message = heapless::Vec::new();
        self.app
            .call(Command::Cbor, &request_msg, &mut response_msg)
            .map_err(|_| ctap2::Error::Other)?;

        if response_msg.is_empty() {
            return Err(ctap2::Error::Other);
        }

        Ok((response_msg[0], response_msg[1..].to_vec()))
    }
}

fn serialize_request<'a>(request: &Request, buf: &'a mut [u8]) -> &'a [u8] {
    super::transport::serialize_request(request, buf)
}
