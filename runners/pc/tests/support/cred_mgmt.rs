use serde_cbor::Value;

use ctap_types::ctap2;

use super::pin::PinSession;
use super::transport::TestAuthenticator;

pub struct CredentialManagementSession<'a> {
    authn: &'a mut dyn TestAuthenticator,
    pin: PinSession,
}

impl<'a> CredentialManagementSession<'a> {
    pub fn new(authn: &'a mut dyn TestAuthenticator, pin: PinSession) -> Self {
        Self { authn, pin }
    }

    pub fn get_metadata(&mut self) -> Value {
        self.call(ctap2::credential_management::Subcommand::GetCredsMetadata, None)
    }

    pub fn enumerate_rps_begin(&mut self) -> Value {
        self.call(ctap2::credential_management::Subcommand::EnumerateRpsBegin, None)
    }

    pub fn enumerate_rps_next(&mut self) -> Result<Value, ctap2::Error> {
        self.call_continuation(ctap2::credential_management::Subcommand::EnumerateRpsGetNextRp)
    }

    pub fn enumerate_creds_begin(&mut self, rp_id_hash: &[u8; 32]) -> Value {
        self.call(
            ctap2::credential_management::Subcommand::EnumerateCredentialsBegin,
            Some(ctap2::credential_management::SubcommandParameters {
                rp_id_hash: Some(ctap_types::Bytes::from_slice(rp_id_hash).unwrap()),
                credential_id: None,
            }),
        )
    }

    pub fn enumerate_creds_next(&mut self) -> Result<Value, ctap2::Error> {
        self.call_continuation(ctap2::credential_management::Subcommand::EnumerateCredentialsGetNextCredential)
    }

    pub fn delete_credential(&mut self, credential_id: &[u8]) -> Value {
        self.call(
            ctap2::credential_management::Subcommand::DeleteCredential,
            Some(ctap2::credential_management::SubcommandParameters {
                rp_id_hash: None,
                credential_id: Some(ctap_types::webauthn::PublicKeyCredentialDescriptor {
                    id: ctap_types::Bytes::from_slice(credential_id).unwrap(),
                    key_type: "public-key".into(),
                }),
            }),
        )
    }

    fn call(
        &mut self,
        sub_command: ctap2::credential_management::Subcommand,
        params: Option<ctap2::credential_management::SubcommandParameters>,
    ) -> Value {
        let pin_auth = self.pin.pin_auth_for_credential_management(sub_command, params.as_ref());
        let request = ctap2::credential_management::Request {
            sub_command,
            sub_command_params: params,
            pin_protocol: Some(self.pin.protocol()),
            pin_auth: Some(ctap_types::Bytes::from_slice(&pin_auth).unwrap()),
        };
        raw_credential_management(self.authn, &request).expect("credential management command should succeed")
    }

    fn call_continuation(
        &mut self,
        sub_command: ctap2::credential_management::Subcommand,
    ) -> Result<Value, ctap2::Error> {
        let request = ctap2::credential_management::Request {
            sub_command,
            sub_command_params: None,
            pin_protocol: None,
            pin_auth: None,
        };
        raw_credential_management(self.authn, &request)
    }
}

pub fn raw_credential_management(
    authn: &mut dyn TestAuthenticator,
    request: &ctap2::credential_management::Request,
) -> Result<Value, ctap2::Error> {
    let mut payload = [0u8; 512];
    let encoded = ctap_types::serde::cbor_serialize(request, &mut payload).map_err(|_| ctap2::Error::Other)?;
    let (status, response) = authn.call_ctap2_raw(0x0A, encoded)?;
    if status != 0 {
        return Err(super::transport::error_from_byte(status));
    }
    serde_cbor::from_slice(&response).map_err(|_| ctap2::Error::InvalidCbor)
}

pub fn map_get<'a>(value: &'a Value, key: i128) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected CBOR map, got {:?}", value);
    };
    entries
        .iter()
        .find_map(|(entry_key, entry_value)| match entry_key {
            Value::Integer(found) if *found == key => Some(entry_value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing key {} in {:?}", key, value))
}

pub fn map_get_optional<'a>(value: &'a Value, key: i128) -> Option<&'a Value> {
    let Value::Map(entries) = value else {
        panic!("expected CBOR map, got {:?}", value);
    };
    entries.iter().find_map(|(entry_key, entry_value)| match entry_key {
        Value::Integer(found) if *found == key => Some(entry_value),
        _ => None,
    })
}

pub fn map_get_text<'a>(value: &'a Value, key: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected CBOR map, got {:?}", value);
    };
    entries
        .iter()
        .find_map(|(entry_key, entry_value)| match entry_key {
            Value::Text(found) if found == key => Some(entry_value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing key {:?} in {:?}", key, value))
}

pub fn as_u64(value: &Value) -> u64 {
    match value {
        Value::Integer(number) if *number >= 0 => *number as u64,
        _ => panic!("expected positive integer, got {:?}", value),
    }
}

pub fn as_bytes(value: &Value) -> &[u8] {
    match value {
        Value::Bytes(bytes) => bytes.as_slice(),
        _ => panic!("expected bytes, got {:?}", value),
    }
}

pub fn as_text(value: &Value) -> &str {
    match value {
        Value::Text(text) => text.as_str(),
        _ => panic!("expected text, got {:?}", value),
    }
}
