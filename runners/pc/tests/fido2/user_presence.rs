//! User presence tests — approve/deny via the test-up-control backchannel.

use super::*;

#[test]
#[serial]
fn up_group() {
    run_in_thread(|| with_authenticator!(up_group, Conforming {}, |authn| {
        reset_authenticator(authn);

        // MC approved
        up::approve();
        let resp = authn.call_ctap2(&Request::MakeCredential(make_credential_request()))
            .expect("MC with UP should succeed");
        assert!(matches!(resp, Response::MakeCredential(_)));

        // MC denied
        up::deny();
        let result = authn.call_ctap2(&Request::MakeCredential(make_credential_request()));
        assert!(result.is_err(), "MC should fail when UP denied");
        up::reset();

        // GA approved
        up::approve_sticky();
        let cred_id = make_credential(authn);
        let resp = authn.call_ctap2(&Request::GetAssertion(
            get_assertion_request_for("example.com", Some(single_allow_list(&cred_id)))
        )).expect("GA with UP should succeed");
        assert!(matches!(resp, Response::GetAssertion(_)));

        // GA denied
        up::deny();
        let result = authn.call_ctap2(&Request::GetAssertion(
            get_assertion_request_for("example.com", Some(single_allow_list(&cred_id)))
        ));
        assert!(result.is_err(), "GA should fail when UP denied");
        up::reset();
    }));
}
