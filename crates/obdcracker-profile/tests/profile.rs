//! Parsing and validating vehicle profiles, and the built-in A7 profile.

use obdcracker_core::isotp::Addressing;
use obdcracker_profile::{Decode, Profile, ProfileError, Protocol};
use obdcracker_safety::{Policy, Target};
use proptest::prelude::*;

const MINIMAL: &str = r#"
name = "test car"
bitrate = 500000

[[module]]
name = "engine"
vag_address = 0x01
request_id = 0x7E0
response_id = 0x7E8
protocol = "uds"

[[module.did]]
id = 0xF190
name = "VIN"
decode = "text"
"#;

fn with_module(module: &str) -> String {
    format!("name = \"test car\"\nbitrate = 500000\n{module}")
}

#[test]
fn parses_a_minimal_profile() {
    let profile = Profile::from_toml(MINIMAL).unwrap();
    assert_eq!(profile.name, "test car");
    assert_eq!(profile.bitrate, 500_000);
    let [engine] = profile.modules.as_slice() else {
        panic!("one module expected");
    };
    assert_eq!(engine.name, "engine");
    assert_eq!(engine.vag_address, Some(0x01));
    assert_eq!(engine.request_id, 0x7E0);
    assert_eq!(engine.response_id, 0x7E8);
    assert_eq!(engine.protocol, Protocol::Uds);
    assert_eq!(engine.addressing(), Addressing::Normal);
    assert_eq!(engine.dids.len(), 1);
    assert_eq!(engine.dids[0].id, 0xF190);
    assert_eq!(engine.dids[0].decode, Decode::Text);
}

#[test]
fn extended_address_byte_selects_extended_addressing() {
    let toml = with_module(
        "[[module]]\nname = \"body\"\nrequest_id = 0x750\nresponse_id = 0x758\n\
         protocol = \"kwp2000\"\nextended_address = 0x40\n",
    );
    let profile = Profile::from_toml(&toml).unwrap();
    assert_eq!(profile.modules[0].addressing(), Addressing::Extended(0x40));
    assert_eq!(profile.modules[0].protocol, Protocol::Kwp2000);
}

#[test]
fn finds_modules_by_name() {
    let profile = Profile::from_toml(MINIMAL).unwrap();
    assert_eq!(profile.module("engine").unwrap().request_id, 0x7E0);
    assert!(profile.module("gateway").is_none());
}

#[test]
fn rejects_invalid_toml_and_unknown_fields() {
    assert!(matches!(
        Profile::from_toml("name = "),
        Err(ProfileError::Toml(_))
    ));
    // A typo must not silently drop a setting.
    let typo = MINIMAL.replace("response_id", "respons_id");
    assert!(matches!(
        Profile::from_toml(&typo),
        Err(ProfileError::Toml(_))
    ));
}

#[test]
fn rejects_unsupported_bitrates() {
    let toml = MINIMAL.replace("500000", "125000");
    assert_eq!(
        Profile::from_toml(&toml).unwrap_err(),
        ProfileError::Bitrate(125_000)
    );
}

#[test]
fn rejects_ids_outside_the_11_bit_diagnostic_range() {
    for id in ["0x6FF", "0x800", "0x18DA10F1"] {
        let toml = MINIMAL.replace("0x7E0", id);
        assert!(
            matches!(Profile::from_toml(&toml), Err(ProfileError::Id { .. })),
            "{id}"
        );
    }
}

#[test]
fn rejects_the_obd_functional_id() {
    let toml = MINIMAL.replace("0x7E0", "0x7DF");
    assert!(matches!(
        Profile::from_toml(&toml),
        Err(ProfileError::Id { id: 0x7DF, .. })
    ));
}

#[test]
fn rejects_a_module_answering_on_its_own_request_id() {
    let toml = MINIMAL.replace("0x7E8", "0x7E0");
    assert!(matches!(
        Profile::from_toml(&toml),
        Err(ProfileError::DuplicateId(0x7E0))
    ));
}

#[test]
fn rejects_ids_shared_between_modules() {
    let toml = format!(
        "{MINIMAL}\n[[module]]\nname = \"tcu\"\nrequest_id = 0x7E1\nresponse_id = 0x7E8\nprotocol = \"uds\"\n"
    );
    assert_eq!(
        Profile::from_toml(&toml).unwrap_err(),
        ProfileError::DuplicateId(0x7E8)
    );
}

#[test]
fn rejects_duplicate_names_and_vag_addresses() {
    let same_name = format!(
        "{MINIMAL}\n[[module]]\nname = \"engine\"\nrequest_id = 0x7E1\nresponse_id = 0x7E9\nprotocol = \"uds\"\n"
    );
    assert_eq!(
        Profile::from_toml(&same_name).unwrap_err(),
        ProfileError::DuplicateName("engine".into())
    );
    let same_address = format!(
        "{MINIMAL}\n[[module]]\nname = \"tcu\"\nvag_address = 0x01\nrequest_id = 0x7E1\nresponse_id = 0x7E9\nprotocol = \"uds\"\n"
    );
    assert_eq!(
        Profile::from_toml(&same_address).unwrap_err(),
        ProfileError::DuplicateVagAddress(0x01)
    );
}

#[test]
fn rejects_duplicate_dids_in_a_module() {
    let toml =
        format!("{MINIMAL}\n[[module.did]]\nid = 0xF190\nname = \"again\"\ndecode = \"hex\"\n");
    assert_eq!(
        Profile::from_toml(&toml).unwrap_err(),
        ProfileError::DuplicateDid {
            module: "engine".into(),
            did: 0xF190
        }
    );
}

#[test]
fn unknown_builtin_is_an_error() {
    assert_eq!(
        Profile::builtin("delorean").unwrap_err(),
        ProfileError::UnknownBuiltin("delorean".into())
    );
}

#[test]
fn every_builtin_profile_parses() {
    for name in Profile::BUILTIN {
        Profile::builtin(name).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn a7_profile_has_the_expected_uds_modules() {
    let a7 = Profile::builtin("a7").unwrap();
    assert_eq!(a7.bitrate, 500_000);
    for (name, address, request, response) in [
        ("engine", 0x01, 0x7E0, 0x7E8),
        ("transmission", 0x02, 0x7E1, 0x7E9),
        ("gateway", 0x19, 0x710, 0x77A),
        ("instruments", 0x17, 0x714, 0x77E),
    ] {
        let module = a7.module(name).unwrap_or_else(|| panic!("{name} missing"));
        assert_eq!(module.vag_address, Some(address), "{name}");
        assert_eq!(module.request_id, request, "{name}");
        assert_eq!(module.response_id, response, "{name}");
        assert_eq!(module.protocol, Protocol::Uds, "{name}");
        assert_eq!(module.addressing(), Addressing::Normal, "{name}");
    }
}

// A profile only names where requests go; what may be sent is still the policy's decision.
#[test]
fn a7_modules_are_targets_the_policy_still_checks() {
    let a7 = Profile::builtin("a7").unwrap();
    let policy = Policy::read_only();
    for module in &a7.modules {
        let target = Target::Physical(module.request_id);
        assert!(policy.approve(target, &[0x22, 0xF1, 0x90]).is_ok());
        assert!(policy.approve(target, &[0x10, 0x02]).is_err());
        assert!(policy.approve(target, &[0x2E, 0xF1, 0x90, 0x00]).is_err());
    }
}

proptest! {
    // Profiles can come from users, so no input may panic the parser.
    #[test]
    fn never_panics_on_arbitrary_text(text in ".{0,512}") {
        let _ = Profile::from_toml(&text);
    }

    #[test]
    fn never_panics_on_mutated_profiles(cut in 0..MINIMAL.len(), insert in ".{0,16}") {
        let mut text = MINIMAL.to_owned();
        if text.is_char_boundary(cut) {
            text.insert_str(cut, &insert);
        }
        let _ = Profile::from_toml(&text);
    }
}
