//! Parsing and validating vehicle profiles, and the built-in A7 profile.

use obdcracker_core::isotp::Addressing;
use obdcracker_profile::{Decode, DidSession, Profile, ProfileError, Protocol, standard_decode};
use obdcracker_safety::{ModuleIds, Policy, Target};
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
    // The head-up display, which `scan --discover` found in #54 (J898, VAG address 0x82).
    let hud = a7.module("head-up display").unwrap();
    assert_eq!(
        (hud.vag_address, hud.request_id, hud.response_id),
        (Some(0x82), 0x71B, 0x785)
    );
    // The 22 modules discovery found in #54, plus the engine and transmission on the OBD-II IDs,
    // which its range doesn't reach.
    assert_eq!(a7.modules.len(), 24);
    // Each reads its coding, except the transmission and the three modules that refused 0600 as
    // out of range in #86.
    let no_coding = [
        "transmission",
        "sensor cluster",
        "tire pressure",
        "parking brake",
    ];
    for module in &a7.modules {
        assert_eq!(
            module.dids.iter().any(|did| did.id == 0x0600),
            !no_coding.contains(&module.name.as_str()),
            "{}",
            module.name
        );
    }
}

// The head-up display's DIDs that the #86 sweeps of 0000..=0FFF found: 0100 and 0102 answered only
// in the extended session, and 028D was refused for want of security access (`7F 22 33`).
#[test]
fn a7_hud_lists_the_dids_its_sweeps_found() {
    let a7 = Profile::builtin("a7").unwrap();
    let hud = a7.module("head-up display").unwrap();
    let found: Vec<(u16, DidSession)> = hud
        .dids
        .iter()
        .filter(|did| did.id < 0x1000)
        .map(|did| (did.id, did.session))
        .collect();
    let extended = [0x0100, 0x0102];
    let expected: Vec<(u16, DidSession)> = [
        0x0100, 0x0102, 0x0103, 0x0286, 0x028D, 0x0405, 0x0407, 0x0408, 0x040F, 0x0501, 0x0502,
        0x0600, 0x0902,
    ]
    .into_iter()
    .map(|id| {
        let session = if extended.contains(&id) {
            DidSession::Extended
        } else {
            DidSession::Default
        };
        (id, session)
    })
    .collect();
    assert_eq!(found, expected);
    // The refused one has no length: no reply gave it one.
    let refused = hud.dids.iter().find(|did| did.id == 0x028D).unwrap();
    assert_eq!(refused.length, None);
}

// A profile only names where requests go; what may be sent is still the policy's decision.
#[test]
fn a7_modules_are_targets_the_policy_still_checks() {
    let a7 = Profile::builtin("a7").unwrap();
    let policy = Policy::read_only();
    for module in &a7.modules {
        let target = Target::Physical(module.request_id);
        assert!(
            policy
                .approve(
                    obdcracker_safety::Protocol::Uds,
                    target,
                    &[0x22, 0xF1, 0x90]
                )
                .is_ok()
        );
        assert!(
            policy
                .approve(obdcracker_safety::Protocol::Uds, target, &[0x10, 0x02])
                .is_err()
        );
        assert!(
            policy
                .approve(
                    obdcracker_safety::Protocol::Uds,
                    target,
                    &[0x2E, 0xF1, 0x90, 0x00]
                )
                .is_err()
        );
    }
}

#[test]
fn a7_profile_narrows_the_policy_to_its_modules() {
    let a7 = Profile::builtin("a7").unwrap();
    let policy = a7.narrow(Policy::read_only()).unwrap();
    let read = [0x22, 0xF1, 0x87];
    for module in &a7.modules {
        let approved = policy
            .approve(
                obdcracker_safety::Protocol::Uds,
                Target::Physical(module.request_id),
                &read,
            )
            .unwrap();
        assert_eq!(approved.reply_id(), Some(module.response_id));
        assert!(
            policy
                .approve(
                    obdcracker_safety::Protocol::Uds,
                    Target::Physical(module.response_id),
                    &read
                )
                .is_err()
        );
    }
    // In 0x700..=0x7FF, but no A7 module listens there.
    assert!(
        policy
            .approve(
                obdcracker_safety::Protocol::Uds,
                Target::Physical(0x711),
                &read
            )
            .is_err()
    );
    assert!(
        policy
            .approve(
                obdcracker_safety::Protocol::Uds,
                Target::ObdFunctional,
                &[0x09, 0x02]
            )
            .is_ok()
    );
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
fn a_did_can_need_the_extended_session() {
    let toml = MINIMAL.replace(
        "decode = \"text\"",
        "decode = \"text\"\nsession = \"extended\"",
    );
    let profile = Profile::from_toml(&toml).unwrap();
    assert_eq!(profile.modules[0].dids[0].session, DidSession::Extended);
    assert_eq!(
        Profile::from_toml(MINIMAL).unwrap().modules[0].dids[0].session,
        DidSession::Default
    );
    // The programming session isn't one a DID can name.
    let toml = MINIMAL.replace(
        "decode = \"text\"",
        "decode = \"text\"\nsession = \"programming\"",
    );
    assert!(matches!(
        Profile::from_toml(&toml),
        Err(ProfileError::Toml(_))
    ));
}

#[test]
fn a_did_can_give_its_length() {
    let toml = MINIMAL.replace("decode = \"text\"", "decode = \"text\"\nlength = 17");
    let profile = Profile::from_toml(&toml).unwrap();
    assert_eq!(profile.modules[0].dids[0].length, Some(17));
    assert_eq!(
        Profile::from_toml(MINIMAL).unwrap().modules[0].dids[0].length,
        None
    );
}

#[test]
fn rejects_a_did_length_of_0() {
    let with_length = |length: u16| {
        MINIMAL.replace(
            "decode = \"text\"",
            &format!("decode = \"text\"\nlength = {length}"),
        )
    };
    assert_eq!(
        Profile::from_toml(&with_length(0)).unwrap_err(),
        ProfileError::DidLength {
            module: "engine".into(),
            did: 0xF190
        }
    );
    // ISO-TP's escaped first frame carries more than 4095 bytes, so any other length is fine.
    for length in [1, 4092, 4093, u16::MAX] {
        assert!(Profile::from_toml(&with_length(length)).is_ok(), "{length}");
    }
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

// MINIMAL's engine (0x7E0/0x7E8) with a gateway at 0x710/0x77A, and a discovery range.
fn with_discovery(first: u32, last: u32, offset: u32) -> String {
    format!(
        "{MINIMAL}\n[[module]]\nname = \"gateway\"\nrequest_id = 0x710\nresponse_id = 0x77A\n\
         protocol = \"uds\"\n\n[discovery]\nfirst_request_id = {first}\nlast_request_id = {last}\n\
         reply_offset = {offset}\n"
    )
}

#[test]
fn a_discovery_range_lists_each_candidate_and_its_reply_id() {
    let profile = Profile::from_toml(&with_discovery(0x70E, 0x710, 0x6A)).unwrap();
    assert_eq!(
        profile.candidates(),
        [
            ModuleIds {
                request: 0x70E,
                reply: 0x778
            },
            ModuleIds {
                request: 0x70F,
                reply: 0x779
            },
            // A listed module may be a candidate too, with its own reply ID.
            ModuleIds {
                request: 0x710,
                reply: 0x77A
            },
        ]
    );
    assert_eq!(Profile::from_toml(MINIMAL).unwrap().candidates(), []);
}

#[test]
fn the_a7_profile_discovers_0x700_to_0x769() {
    let a7 = Profile::builtin("a7").unwrap();
    let candidates = a7.candidates();
    assert_eq!(candidates.len(), 0x6A);
    assert_eq!(candidates[0].request, 0x700);
    assert_eq!(candidates.last().unwrap().request, 0x769);
    assert!(candidates.iter().all(|c| c.reply == c.request + 0x6A));
}

#[test]
fn a_discovery_policy_allows_candidates_but_never_their_reply_ids() {
    let profile = Profile::from_toml(&with_discovery(0x700, 0x769, 0x6A)).unwrap();
    let read = [0x22, 0xF1, 0x87];
    let modules_only = profile.narrow(Policy::read_only()).unwrap();
    let discovery = profile.narrow_for_discovery(Policy::read_only()).unwrap();
    let approved = discovery
        .approve(
            obdcracker_safety::Protocol::Uds,
            Target::Physical(0x74F),
            &read,
        )
        .unwrap();
    assert_eq!(approved.reply_id(), Some(0x7B9));
    // A plain narrowed policy still refuses modules the profile doesn't list.
    assert!(
        modules_only
            .approve(
                obdcracker_safety::Protocol::Uds,
                Target::Physical(0x74F),
                &read
            )
            .is_err()
    );
    for reply in [0x76A, 0x77A, 0x7B9, 0x7D3, 0x7E8] {
        assert!(
            discovery
                .approve(
                    obdcracker_safety::Protocol::Uds,
                    Target::Physical(reply),
                    &read
                )
                .is_err(),
            "{reply:03X}"
        );
    }
}

#[test]
fn rejects_a_discovery_range_that_would_send_on_a_reply_id() {
    for (first, last, offset) in [
        // 0x70E..=0x77A includes the gateway's reply ID 0x77A.
        (0x70E, 0x77A, 0x6A),
        // Replies at +0x10 make 0x710 (a candidate's and the gateway's request) a reply ID.
        (0x700, 0x710, 0x10),
        // Outside the diagnostic IDs, or the broadcast.
        (0x6FF, 0x700, 0x6A),
        (0x7DF, 0x7DF, 0x01),
        (0x7A0, 0x7A0, 0x60),
        // The OBD-II reply IDs.
        (0x7E8, 0x7E8, 0x01),
        // The gateway's request ID with another reply ID.
        (0x710, 0x710, 0x10),
    ] {
        assert!(
            matches!(
                Profile::from_toml(&with_discovery(first, last, offset)),
                Err(ProfileError::Discovery(_))
            ),
            "{first:03X}..={last:03X} +{offset:X}"
        );
    }
    assert_eq!(
        Profile::from_toml(&with_discovery(0x769, 0x700, 0x6A)).unwrap_err(),
        ProfileError::DiscoveryRange
    );
}

#[test]
fn rejects_a_discovery_candidate_that_reverses_a_listed_module() {
    // A module at 0x770 that replies on 0x700, and a candidate 0x700 -> 0x770: the candidate
    // would send on the module's reply ID. `candidates` leaves it out (its reply is the
    // module's request ID), but the range is still wrong and must be refused.
    let toml = format!(
        "{MINIMAL}\n[[module]]\nname = \"reversed\"\nrequest_id = 0x770\nresponse_id = 0x700\n\
         protocol = \"uds\"\n\n[discovery]\nfirst_request_id = 0x700\nlast_request_id = 0x700\n\
         reply_offset = 0x70\n"
    );
    assert!(
        matches!(Profile::from_toml(&toml), Err(ProfileError::Discovery(_))),
        "{:?}",
        Profile::from_toml(&toml)
    );
}

// `with_discovery`, plus a wide range up to `wide_last`.
fn with_wide_discovery(first: u32, last: u32, offset: u32, wide_last: u32) -> String {
    format!(
        "{}wide_last_request_id = {wide_last}\n",
        with_discovery(first, last, offset)
    )
}

#[test]
fn wide_candidates_skip_every_known_request_and_reply_id() {
    // Pass 1 covers 0x700..=0x769, replies 0x76A..=0x7D3; the wide range takes all of those.
    let profile = Profile::from_toml(&with_wide_discovery(0x700, 0x769, 0x6A, 0x7D3)).unwrap();
    // A module pass 1 found that the profile doesn't list.
    let found = [ModuleIds {
        request: 0x705,
        reply: 0x76F,
    }];
    let wide = profile.wide_candidates(&found);
    let requests: Vec<u32> = wide.iter().map(|c| c.request).collect();
    assert_eq!(requests.first(), Some(&0x76A));
    assert!(wide.iter().all(|c| c.reply == c.request + 0x6A), "{wide:?}");
    // Every reply fits an 11-bit ID: 0x795 + 0x6A = 0x7FF.
    assert_eq!(requests.last(), Some(&0x795));
    for skipped in [
        0x76F, // the found module's reply ID
        0x77A, // the gateway's reply ID
        0x7E8, // the engine's reply ID
        0x775, // its reply would be 0x7DF, the OBD-II broadcast
        0x77E, // its reply would be 0x7E8, an OBD-II reply ID
        0x776, // its reply would be 0x7E0, the engine's request ID
    ] {
        assert!(
            !requests.contains(&skipped),
            "{skipped:03X} in {requests:X?}"
        );
    }
    // 0x773 is pass 1's reply ID for 0x709, but nothing answered there.
    assert!(requests.contains(&0x773));
    let narrow = Profile::from_toml(&with_discovery(0x700, 0x769, 0x6A)).unwrap();
    assert_eq!(narrow.wide_candidates(&[]), []);
}

#[test]
fn a_wide_discovery_policy_allows_wide_candidates_and_what_was_found() {
    let profile = Profile::from_toml(&with_wide_discovery(0x700, 0x769, 0x6A, 0x795)).unwrap();
    let read = [0x22, 0xF1, 0x87];
    let found = [ModuleIds {
        request: 0x705,
        reply: 0x76F,
    }];
    let mut extra = found.to_vec();
    extra.extend(profile.wide_candidates(&found));
    let policy = profile.narrow_with(Policy::read_only(), &extra).unwrap();
    let mmi = policy
        .approve(
            obdcracker_safety::Protocol::Uds,
            Target::Physical(0x773),
            &read,
        )
        .unwrap();
    assert_eq!(mmi.reply_id(), Some(0x7DD));
    let module = policy
        .approve(
            obdcracker_safety::Protocol::Uds,
            Target::Physical(0x705),
            &read,
        )
        .unwrap();
    assert_eq!(module.reply_id(), Some(0x76F));
    // Pass 1's other candidates aren't allowed any more, and replies never are.
    for refused in [0x700, 0x76F, 0x77A] {
        assert!(
            policy
                .approve(
                    obdcracker_safety::Protocol::Uds,
                    Target::Physical(refused),
                    &read
                )
                .is_err(),
            "{refused:03X}"
        );
    }
}

#[test]
fn recheck_candidates_are_the_silent_first_pass_ids_whose_reply_the_wide_pass_would_send_on() {
    // Pass 1 covers 0x700..=0x769, replies 0x76A..=0x7D3; the wide pass sends to 0x76A..=0x795.
    let profile = Profile::from_toml(&with_wide_discovery(0x700, 0x769, 0x6A, 0x795)).unwrap();
    let found = [ModuleIds {
        request: 0x705,
        reply: 0x76F,
    }];
    let recheck = profile.recheck_candidates(&found);
    let wide = profile.wide_candidates(&found);
    // Exactly the first-pass candidates whose reply ID a wide candidate sends to.
    let expected: Vec<ModuleIds> = profile
        .candidates()
        .into_iter()
        .filter(|c| wide.iter().any(|w| w.request == c.reply))
        .collect();
    assert_eq!(recheck, expected);
    assert_eq!(recheck.first().map(|c| c.request), Some(0x700));
    // 0x709's reply, 0x773, is where VW's MQB MMI answers.
    assert!(recheck.contains(&ModuleIds {
        request: 0x709,
        reply: 0x773
    }));
    // The module found answers on 0x76F, so the wide pass skips it and there's nothing to recheck.
    assert!(!recheck.iter().any(|c| c.request == 0x705));
    // The gateway (0x710) answers on 0x77A, which the wide pass skips too.
    assert!(!recheck.iter().any(|c| c.request == 0x710));
    // Replies past 0x795 aren't sent to.
    assert!(recheck.iter().all(|c| c.reply <= 0x795), "{recheck:?}");
    let narrow = Profile::from_toml(&with_discovery(0x700, 0x769, 0x6A)).unwrap();
    assert_eq!(narrow.recheck_candidates(&[]), []);
}

#[test]
fn a_module_listed_in_the_wide_range_keeps_the_first_pass_off_its_request_id() {
    // Once wide discovery finds a module at 0x773, the profile can list it: the first pass then
    // skips 0x709, whose reply ID that is.
    let toml = format!(
        "{}\n[[module]]\nname = \"mmi\"\nrequest_id = 0x773\nresponse_id = 0x7DD\n\
         protocol = \"uds\"\n",
        with_wide_discovery(0x700, 0x769, 0x6A, 0x795)
    );
    let profile = Profile::from_toml(&toml).unwrap();
    let first: Vec<u32> = profile.candidates().iter().map(|c| c.request).collect();
    assert_eq!(first.len(), 0x6A - 1);
    assert!(!first.contains(&0x709));
    let wide = profile.wide_candidates(&[]);
    assert!(wide.contains(&ModuleIds {
        request: 0x773,
        reply: 0x7DD
    }));
    profile.narrow_for_discovery(Policy::read_only()).unwrap();
}

#[test]
fn rejects_a_wide_range_outside_the_first_passs_reply_ids() {
    for (last, wide_last) in [
        (0x709, 0x709),
        (0x709, 0x700),
        (0x709, 0x800),
        // The first pass listens on 0x76A..=0x773, so 0x70A wasn't checked for a reply.
        (0x709, 0x70A),
        // 0x76A..=0x7D4: one past the first pass's last reply ID, 0x7D3.
        (0x769, 0x7D4),
    ] {
        assert!(
            matches!(
                Profile::from_toml(&with_wide_discovery(0x700, last, 0x6A, wide_last)),
                Err(ProfileError::WideDiscoveryRange)
            ),
            "{last:03X} then up to {wide_last:03X}"
        );
    }
}

#[test]
fn the_a7_profile_looks_wider_only_where_no_known_module_answers() {
    let a7 = Profile::builtin("a7").unwrap();
    let wide = a7.wide_candidates(&[]);
    let requests: Vec<u32> = wide.iter().map(|c| c.request).collect();
    assert_eq!(requests.first(), Some(&0x76A));
    assert_eq!(requests.last(), Some(&0x795));
    // VW's MQB MMI IDs (5F), unconfirmed on the C7.
    assert!(requests.contains(&0x773));
    for module in &a7.modules {
        assert!(!requests.contains(&module.response_id), "{}", module.name);
    }
    a7.narrow_with(Policy::read_only(), &wide).unwrap();
}

// Each A7 DID length is what the car sent, counted from the data, not the whole reply (#62).
// Every length must come from a real reply, and every real reply must have that length.
#[test]
fn a7_did_lengths_match_the_cars_replies() {
    let a7 = Profile::builtin("a7").unwrap();
    let replies: Vec<(u32, Vec<u8>)> = include_str!("data/a7-did-replies.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.split(' ');
            let id = u32::from_str_radix(fields.next().unwrap(), 16).unwrap();
            let bytes = fields.map(|b| u8::from_str_radix(b, 16).unwrap()).collect();
            (id, bytes)
        })
        .collect();
    for module in &a7.modules {
        for did in &module.dids {
            let Some(length) = did.length else { continue };
            let [high, low] = did.id.to_be_bytes();
            let lengths: Vec<usize> = replies
                .iter()
                .filter(|(id, reply)| *id == module.response_id && reply[..3] == [0x62, high, low])
                .map(|(_, reply)| reply.len() - 3)
                .collect();
            assert!(
                !lengths.is_empty(),
                "{} {:04X}: no reply from the car gives its length",
                module.name,
                did.id
            );
            assert!(
                lengths.iter().all(|&got| got == usize::from(length)),
                "{} {:04X}: profile says {length}, the car sent {lengths:?}",
                module.name,
                did.id
            );
        }
    }
}

fn with_29_bit_discovery(first: u32, last: u32, offset: u32) -> String {
    format!(
        "{MINIMAL}\n[discovery_29bit]\nfirst_request_id = {first}\nlast_request_id = {last}\n\
         reply_offset = {offset}\n"
    )
}

#[test]
fn a_29_bit_discovery_range_lists_each_candidate_and_its_reply_id() {
    let profile =
        Profile::from_toml(&with_29_bit_discovery(0x17FC_0000, 0x17FC_0002, 0x2_0000)).unwrap();
    assert_eq!(
        profile.candidates_29bit(),
        [0x17FC_0000, 0x17FC_0001, 0x17FC_0002].map(|request| ModuleIds {
            request,
            reply: request + 0x2_0000,
        })
    );
    assert_eq!(profile.candidates(), Vec::<ModuleIds>::new());
    let policy = profile
        .narrow_with(Policy::read_only(), &profile.candidates_29bit())
        .unwrap();
    let approved = policy
        .approve(
            obdcracker_safety::Protocol::Uds,
            Target::Physical29(0x17FC_0001),
            &[0x22, 0xF1, 0x87],
        )
        .unwrap();
    assert_eq!(approved.reply_id(), Some(0x17FE_0001));
    assert_eq!(
        Profile::from_toml(MINIMAL).unwrap().candidates_29bit(),
        Vec::<ModuleIds>::new()
    );
}

#[test]
fn rejects_29_bit_discovery_ranges_the_policy_refuses_or_that_are_too_long() {
    for (first, last, offset) in [
        (0x700, 0x710, 0x6A),
        // Past VAG's request range, or onto a request ID.
        (0x17FC_00FF, 0x17FC_0100, 0x2_0000),
        (0x17FC_0000, 0x17FC_0001, 0x1),
    ] {
        assert!(
            matches!(
                Profile::from_toml(&with_29_bit_discovery(first, last, offset)),
                Err(ProfileError::Discovery(_))
            ),
            "{first:X}-{last:X} +{offset:X}"
        );
    }
    assert_eq!(
        Profile::from_toml(&with_29_bit_discovery(0x17FC_0002, 0x17FC_0000, 0x2_0000)).unwrap_err(),
        ProfileError::DiscoveryRange
    );
    // More than 256 IDs, in order: the error says so, not that the range is backwards.
    for (first, last) in [(0x17FC_0000, 0x17FC_0100), (0x18DA_00F1, 0x18DA_FFF1)] {
        let error = Profile::from_toml(&with_29_bit_discovery(first, last, 0x2_0000)).unwrap_err();
        assert_eq!(
            error,
            ProfileError::Discovery29TooLong,
            "{first:X}-{last:X}"
        );
        assert_eq!(
            error.to_string(),
            "discovery_29bit: the range holds more than 256 request IDs"
        );
    }
    assert!(Profile::from_toml(&with_29_bit_discovery(0x17FC_0000, 0x17FC_00FF, 0x2_0000)).is_ok());
}

#[test]
fn the_a7_profile_has_a_29_bit_discovery_range_over_vags_ids() {
    let profile = Profile::builtin("a7").unwrap();
    let candidates = profile.candidates_29bit();
    assert_eq!(candidates.len(), 256);
    assert_eq!(
        candidates[0x5F],
        ModuleIds {
            request: 0x17FC_005F,
            reply: 0x17FE_005F,
        }
    );
}

fn with_tp20_discovery(addresses: &str) -> String {
    format!("{MINIMAL}\n[discovery_tp20]\naddresses = [{addresses}]\n")
}

#[test]
fn a_profile_narrows_tp20_channel_setups_to_its_addresses() {
    let profile = Profile::from_toml(&with_tp20_discovery("0x5F, 0x09")).unwrap();
    assert_eq!(profile.tp20_addresses(), [0x5F, 0x09]);
    let narrowed = [
        profile.narrow(Policy::read_only()).unwrap(),
        profile.narrow_for_discovery(Policy::read_only()).unwrap(),
        profile.narrow_with(Policy::read_only(), &[]).unwrap(),
    ];
    for policy in narrowed {
        assert!(policy.approve_tp20_setup(0x5F).is_ok());
        assert!(policy.approve_tp20_setup(0x01).is_err());
    }
    // Without a list, a profile allows no channel setup at all.
    let none = Profile::from_toml(MINIMAL).unwrap();
    assert_eq!(none.tp20_addresses(), Vec::<u8>::new());
    assert!(
        none.narrow(Policy::read_only())
            .unwrap()
            .approve_tp20_setup(0x5F)
            .is_err()
    );
}

#[test]
fn rejects_tp20_address_lists_that_are_empty_repeat_or_name_the_tester_or_a_broadcast() {
    for (addresses, error) in [
        ("", ProfileError::EmptyTp20Discovery),
        ("0x00", ProfileError::Tp20Address(0x00)),
        ("0x5F, 0xF0", ProfileError::Tp20Address(0xF0)),
        ("0xFF", ProfileError::Tp20Address(0xFF)),
        ("0x5F, 0x09, 0x5F", ProfileError::Tp20Address(0x5F)),
    ] {
        assert_eq!(
            Profile::from_toml(&with_tp20_discovery(addresses)),
            Err(error),
            "{addresses}"
        );
    }
    assert!(Profile::from_toml(&with_tp20_discovery("0x01, 0xEF")).is_ok());
    assert!(matches!(
        Profile::from_toml(&with_tp20_discovery("0x100")),
        Err(ProfileError::Toml(_))
    ));
}

#[test]
fn the_a7_profile_lists_the_modules_silent_on_iso_tp_for_tp20() {
    let profile = Profile::builtin("a7").unwrap();
    assert_eq!(
        profile.tp20_addresses(),
        [
            0x05, 0x09, 0x0E, 0x16, 0x36, 0x42, 0x46, 0x47, 0x52, 0x56, 0x5F, 0x62, 0x72,
            // The gateway's 2A29 table marks these 02, as it does 52 (#124). Some may be modules
            // that answer on ISO-TP: a setup to one is still a read, and shows what 02 means.
            0x06, 0x10, 0x14, 0x18, 0x1E, 0x20, 0x2E, 0x30, 0x3C, 0x3D, 0x3E, 0x48, 0x57, 0x5B,
            0x69, 0x7F
        ]
    );
    // None is the VAG address of a module the profile reaches on ISO-TP, where the profile knows
    // that module's address.
    for module in &profile.modules {
        if let Some(address) = module.vag_address {
            assert!(
                !profile.tp20_addresses().contains(&address),
                "{address:02X}"
            );
        }
    }
}
