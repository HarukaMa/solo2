//! Reset and reboot tests.

use super::*;

#[test]
#[serial]
fn reset_group() {
    run_in_thread(|| {
        // --- basic reset ---
        with_authenticator!(reset1, Conforming {}, |authn| {
            reset_authenticator(authn);
        });

        // --- reset invalidates credentials ---
        with_authenticator!(reset2, Conforming {}, |authn| {
            reset_authenticator(authn);
            up::approve_sticky();
            let mut req = make_credential_request();
            req.options = Some(ctap2::AuthenticatorOptions { rk: Some(true), up: None, uv: None });
            authn.call_ctap2(&Request::MakeCredential(req)).expect("MC should succeed");

            // Now reset again
            reset_authenticator(authn);

            // Credential should be gone
            up::approve();
            let ga = get_assertion_request_for("example.com", None);
            assert!(authn.call_ctap2(&Request::GetAssertion(ga)).is_err(), "credential should be gone");
        });
    });
}

/// Reboot persistence — in-process only.
#[test]
#[serial]
fn reboot_persistence() {
    if transport::is_device_mode() { return; }
    if transport::backend() == transport::Backend::Socket { return; }
    run_in_thread(|| {
        let memory = leak_memory(TestMemory::new());

        {
            let mem = unsafe {(
                &mut *(memory.0 as *mut Allocation<InternalStorage>),
                &mut *(memory.1 as *mut InternalStorage),
                &mut *(memory.2 as *mut Allocation<ExternalStorage>),
                &mut *(memory.3 as *mut ExternalStorage),
                &mut *(memory.4 as *mut Allocation<VolatileStorage>),
                &mut *(memory.5 as *mut VolatileStorage),
            )};
            paste! {
                store!(RbtS1, Internal: InternalStorage, External: ExternalStorage, Volatile: VolatileStorage);
                platform!(RbtP1, R: chacha20::ChaCha8Rng, S: RbtS1, UI: TestUserInterface,);
                let store = RbtS1::claim().unwrap();
                store.mount(mem.0, mem.1, mem.2, mem.3, mem.4, mem.5, true).unwrap();
                let mut svc = trussed::service::Service::new(
                    RbtP1::new(chacha20::ChaCha8Rng::from_seed([0u8; 32]), store, TestUserInterface::default()),
                );
                unsafe { TrussedInterchange::reset_claims(); }
                let (req, resp) = TrussedInterchange::claim().unwrap();
                assert!(svc.add_endpoint(resp, "fido".into()).is_ok());
                svc.set_seed_if_uninitialized(&[0u8; 32]);
                let mut authn = Authenticator::new(
                    trussed::ClientImplementation::new(req, &mut svc),
                    Silent {}, Config { max_msg_size: 7609, skip_up_timeout: None },
                );
                let authn: &mut dyn TestAuthenticator = &mut authn;
            }
            let mut mc = make_credential_request();
            mc.options = Some(ctap2::AuthenticatorOptions { rk: Some(true), up: None, uv: None });
            authn.call_ctap2(&Request::MakeCredential(mc)).expect("MC should succeed");
        }

        {
            let mem = unsafe {(
                &mut *(memory.0 as *mut Allocation<InternalStorage>),
                &mut *(memory.1 as *mut InternalStorage),
                &mut *(memory.2 as *mut Allocation<ExternalStorage>),
                &mut *(memory.3 as *mut ExternalStorage),
                &mut *(memory.4 as *mut Allocation<VolatileStorage>),
                &mut *(memory.5 as *mut VolatileStorage),
            )};
            paste! {
                store!(RbtS2, Internal: InternalStorage, External: ExternalStorage, Volatile: VolatileStorage);
                platform!(RbtP2, R: chacha20::ChaCha8Rng, S: RbtS2, UI: TestUserInterface,);
                let store = RbtS2::claim().unwrap();
                store.mount(mem.0, mem.1, mem.2, mem.3, mem.4, mem.5, false).unwrap();
                let mut svc = trussed::service::Service::new(
                    RbtP2::new(chacha20::ChaCha8Rng::from_seed([0u8; 32]), store, TestUserInterface::default()),
                );
                unsafe { TrussedInterchange::reset_claims(); }
                let (req, resp) = TrussedInterchange::claim().unwrap();
                assert!(svc.add_endpoint(resp, "fido".into()).is_ok());
                svc.set_seed_if_uninitialized(&[0u8; 32]);
                let mut authn = Authenticator::new(
                    trussed::ClientImplementation::new(req, &mut svc),
                    Silent {}, Config { max_msg_size: 7609, skip_up_timeout: None },
                );
                let authn: &mut dyn TestAuthenticator = &mut authn;
            }
            let ga = get_assertion_request_for("example.com", None);
            authn.call_ctap2(&Request::GetAssertion(ga)).expect("credential should persist");
        }
    });
}
