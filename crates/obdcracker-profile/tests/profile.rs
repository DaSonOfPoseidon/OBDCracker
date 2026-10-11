//! Parsing and validating vehicle profiles, and the built-in A7 profile.

use obdcracker_core::isotp::Addressing;
use obdcracker_profile::{
    Decode, MAX_DID_LENGTH, Profile, ProfileError, Protocol, standard_decode,
};
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
    // Names that differ only in case are too easy to mix up.
    let toml = format!(
        "{MINIMAL}\n[[module]]\nname = \"Engine\"\nrequest_id = 0x7E1\nresponse_id = 0x7E9\nprotocol = \"uds\"\n"
    );
    assert_eq!(
        Profile::from_toml(&toml).unwrap_err(),
        ProfileError::DuplicateName("Engine".into())
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
        format!("{MINIMAL}\n[[module.did]]\nid = 0xF190\nname = \"again\"\ndecode = \"text\"\n");
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

#[test]
fn a7_profile_narrows_the_policy_to_its_modules() {
    let a7 = Profile::builtin("a7").unwrap();
    let policy = a7.narrow(Policy::read_only()).unwrap();
    let read = [0x22, 0xF1, 0x87];
    for module in &a7.modules {
        let approved = policy
            .approve(Target::Physical(module.request_id), &read)
            .unwrap();
        assert_eq!(approved.reply_id(), Some(module.response_id));
        assert!(
            policy
                .approve(Target::Physical(module.response_id), &read)
                .is_err()
        );
    }
    // In 0x700..=0x7FF, but no A7 module listens there.
    assert!(policy.approve(Target::Physical(0x711), &read).is_err());
    assert!(policy.approve(Target::ObdFunctional, &[0x09, 0x02]).is_ok());
}

#[test]
fn a_hand_built_profile_with_inconsistent_ids_cant_narrow() {
    let mut a7 = Profile::builtin("a7").unwrap();
    // The gateway's request ID is now the instruments' reply ID.
    a7.modules[2].request_id = 0x77E;
    assert!(a7.narrow(Policy::read_only()).is_err());
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

const TOYOTA_BODY: &str = r#"
name = "body modules behind one gateway ID"
bitrate = 500000

[[module]]
name = "body"
request_id = 0x750
response_id = 0x758
protocol = "kwp2000"
extended_address = 0x40

[[module]]
name = "door"
request_id = 0x750
response_id = 0x758
protocol = "kwp2000"
extended_address = 0x90
"#;

#[test]
fn extended_addressing_lets_modules_share_can_ids() {
    let profile = Profile::from_toml(TOYOTA_BODY).unwrap();
    assert_eq!(profile.modules.len(), 2);
}

#[test]
fn rejects_two_modules_with_the_same_id_and_sub_address() {
    let toml = TOYOTA_BODY.replace("0x90", "0x40");
    assert_eq!(
        Profile::from_toml(&toml).unwrap_err(),
        ProfileError::DuplicateId(0x750)
    );
}

#[test]
fn rejects_mixing_normal_and_extended_addressing_on_one_id() {
    let toml = TOYOTA_BODY.replace("extended_address = 0x90\n", "");
    assert_eq!(
        Profile::from_toml(&toml).unwrap_err(),
        ProfileError::DuplicateId(0x750)
    );
}

#[test]
fn rejects_empty_names() {
    assert_eq!(
        Profile::from_toml(&MINIMAL.replace("name = \"engine\"", "name = \"\"")).unwrap_err(),
        ProfileError::EmptyName
    );
    assert_eq!(
        Profile::from_toml(&MINIMAL.replace("name = \"test car\"", "name = \" \"")).unwrap_err(),
        ProfileError::EmptyName
    );
    for blank in ["", "  "] {
        let toml = MINIMAL.replace("name = \"VIN\"", &format!("name = \"{blank}\""));
        assert_eq!(
            Profile::from_toml(&toml).unwrap_err(),
            ProfileError::EmptyName,
            "{blank:?}"
        );
    }
}

#[test]
fn rejects_names_with_surrounding_spaces() {
    // Modules are looked up by exact name, so " engine" could never be found as "engine".
    for (from, to) in [
        ("name = \"engine\"", "name = \" engine\""),
        ("name = \"test car\"", "name = \"test car \""),
        ("name = \"VIN\"", "name = \"VIN\\t\""),
    ] {
        let padded = to.split('"').nth(1).unwrap().replace("\\t", "\t");
        assert_eq!(
            Profile::from_toml(&MINIMAL.replace(from, to)).unwrap_err(),
            ProfileError::PaddedName(padded),
            "{to}"
        );
    }
}

#[test]
fn standard_dids_keep_their_iso_format() {
    // F190 is the VIN and F187 the spare part number: text in ISO 14229-1, whatever a profile says.
    for (did, decode) in [(0xF190, "hex"), (0xF187, "hex"), (0xF19E, "hex")] {
        let toml = MINIMAL.replace(
            "id = 0xF190\nname = \"VIN\"\ndecode = \"text\"",
            &format!("id = {did}\nname = \"x\"\ndecode = \"{decode}\""),
        );
        assert_eq!(
            Profile::from_toml(&toml).unwrap_err(),
            ProfileError::StandardDidFormat {
                module: "engine".into(),
                did
            },
            "0x{did:04X}"
        );
    }
    // Standard DIDs without a fixed format, such as F18B (manufacturing date), can be either.
    for decode in ["hex", "text"] {
        let toml = MINIMAL.replace(
            "id = 0xF190\nname = \"VIN\"\ndecode = \"text\"",
            &format!("id = 0xF18B\nname = \"date\"\ndecode = \"{decode}\""),
        );
        assert!(Profile::from_toml(&toml).is_ok(), "{decode}");
    }
    assert_eq!(standard_decode(0xF190), Some(Decode::Text));
    assert_eq!(standard_decode(0xF18B), None);
    assert_eq!(standard_decode(0x0600), None);
}

#[test]
fn a_did_can_give_its_length() {
    let toml = MINIMAL.replace("decode = \"text\"", "decode = \"text\"\nlength = 17");
    let profile = Profile::from_toml(&toml).unwrap();
    assert_eq!(profile.modules[0].dids[0].length, Some(17));
    // Without one, the length is unknown.
    assert_eq!(
        Profile::from_toml(MINIMAL).unwrap().modules[0].dids[0].length,
        None
    );
}

#[test]
fn rejects_a_did_length_no_reply_can_have() {
    for length in [0, MAX_DID_LENGTH + 1, u16::MAX] {
        let toml = MINIMAL.replace(
            "decode = \"text\"",
            &format!("decode = \"text\"\nlength = {length}"),
        );
        assert_eq!(
            Profile::from_toml(&toml).unwrap_err(),
            ProfileError::DidLength {
                module: "engine".into(),
                did: 0xF190
            },
            "{length}"
        );
    }
    let toml = MINIMAL.replace(
        "decode = \"text\"",
        &format!("decode = \"text\"\nlength = {MAX_DID_LENGTH}"),
    );
    assert!(Profile::from_toml(&toml).is_ok());
}

#[test]
fn a_did_layout_needs_every_length() {
    let toml = format!(
        "{}\n[[module.did]]\nid = 0x0600\nname = \"coding\"\ndecode = \"hex\"\nlength = 10\n\
         [[module.did]]\nid = 0xF1A3\nname = \"hardware version\"\ndecode = \"text\"\n",
        MINIMAL.replace("decode = \"text\"", "decode = \"text\"\nlength = 17")
    );
    let engine = &Profile::from_toml(&toml).unwrap().modules[0];
    assert_eq!(
        engine.did_layout(&[0x0600, 0xF190]),
        Some(vec![(0x0600, 10), (0xF190, 17)])
    );
    assert_eq!(engine.did_layout(&[]), Some(vec![]));
    // F1A3 has no length, and F187 isn't listed at all.
    assert_eq!(engine.did_layout(&[0xF190, 0xF1A3]), None);
    assert_eq!(engine.did_layout(&[0xF187]), None);
}
