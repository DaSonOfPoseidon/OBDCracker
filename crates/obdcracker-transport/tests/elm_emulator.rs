//! The ELM driver against an ELM327 we didn't write: Ircama's ELM327-emulator
//! (<https://github.com/Ircama/ELM327-emulator>), run as a separate process over TCP like a
//! Wi-Fi adapter. Its licence (CC BY-NC-SA 4.0) means nothing from it is copied here.
//!
//! Ignored by default. To run it: `uv tool install ELM327-emulator`, then
//! `cargo test -p obdcracker-transport --test elm_emulator -- --ignored`. Set
//! `ELM327_EMULATOR` if the `elm` command isn't on the `PATH`.

use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use obdcracker_core::{obd, uds};
use obdcracker_safety::{Policy, Target};
use obdcracker_transport::elm::Elm;
use obdcracker_transport::link::TcpLink;
use obdcracker_transport::{Audited, Expect, Response, exchange};

// The emulator, killed when the test ends however it ends. With `ELM327_EMULATOR_ADDR` set,
// an emulator that's already running at that address is used instead.
struct Emulator {
    child: Option<Child>,
    addr: String,
    dir: std::path::PathBuf,
}

impl Emulator {
    fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("obdcracker-emulator-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        if let Ok(addr) = std::env::var("ELM327_EMULATOR_ADDR") {
            return Self {
                child: None,
                addr,
                dir,
            };
        }
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let program = std::env::var("ELM327_EMULATOR").unwrap_or_else(|_| "elm".into());
        let child = Command::new(&program)
            .args(["-n", &port.to_string(), "-s", "car", "-b"])
            .arg(dir.join("batch.out"))
            // Batch mode never reads its input; keep it from inheriting the terminal.
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("can't start {program}: {e}; see this file's docs"));
        let addr = format!("127.0.0.1:{port}");
        let emulator = Self {
            child: Some(child),
            addr,
            dir,
        };
        let give_up = Instant::now() + Duration::from_secs(30);
        while TcpStream::connect(&emulator.addr).is_err() {
            assert!(
                Instant::now() < give_up,
                "the emulator didn't start listening"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        emulator
    }

    fn connect(&self) -> Elm<TcpLink> {
        let link = TcpLink::connect(self.addr.as_str(), Duration::from_secs(5)).unwrap();
        Elm::connect(link).unwrap()
    }
}

impl Drop for Emulator {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// One read through the policy, the audit log and the driver; it must get exactly one answer.
fn read(
    elm: &mut Audited<Elm<TcpLink>>,
    target: Target,
    payload: &[u8],
    expect: Expect,
) -> Response {
    let request = Policy::read_only().approve(target, payload).unwrap();
    let mut replies = exchange(elm, &request, expect, Elm::<TcpLink>::timing())
        .unwrap_or_else(|e| panic!("{payload:02X?}: {e}"));
    assert_eq!(replies.len(), 1, "{payload:02X?}: {replies:02X?}");
    replies.remove(0)
}

const BROADCAST: (Target, Expect) = (Target::ObdFunctional, Expect::ObdEcus);
const ENGINE: (Target, Expect) = (Target::Physical(0x7E0), Expect::Module(0x7E8));

// Every read-only OBD-II request the emulator's `car` scenario answers, single and multi-frame,
// broadcast and physical, decoded by obdcracker-core. The emulator doesn't implement UDS 0x19 or
// the standard identification DIDs, so UDS is covered by 0x22 on DIDs it does answer.
#[test]
#[ignore = "needs ELM327-emulator; see the file's docs"]
fn reads_through_an_independent_elm327() {
    let emulator = Emulator::start();
    let log = emulator.dir.join("session.audit.jsonl");
    let mut elm = Audited::open(&log, emulator.connect(), "tcp").unwrap();

    for (target, expect) in [BROADCAST, ENGINE] {
        let vin = read(&mut elm, target, &obd::vehicle_info(0x02), expect);
        assert_eq!(vin.source, 0x7E8);
        assert_eq!(obd::decode_vin(&vin.payload).unwrap().len(), 17);
    }
    let (target, expect) = BROADCAST;
    let calids = read(&mut elm, target, &obd::vehicle_info(0x04), expect);
    assert!(obd::decode_calids(&calids.payload).unwrap().count() > 0);
    let cvns = read(&mut elm, target, &obd::vehicle_info(0x06), expect);
    assert!(obd::decode_cvns(&cvns.payload).unwrap().count() > 0);
    let name = read(&mut elm, target, &obd::vehicle_info(0x0A), expect);
    obd::decode_ecu_name(&name.payload).unwrap();
    let dtcs = read(&mut elm, target, &obd::stored_dtcs(), expect);
    obd::decode_stored_dtcs(&dtcs.payload).unwrap();
    // Not PID 00: the emulator answers the first 01 00 with SEARCHING... unless it was sent
    // ATTP, even with a fixed protocol set, which a real adapter doesn't (datasheet p. 36), and
    // the driver stops at SEARCHING....
    let supported = read(&mut elm, target, &obd::current_data(0x20), expect);
    obd::decode_current_data(&supported.payload).unwrap();
    let data = read(&mut elm, target, &[0x01, 0x05, 0x0C, 0x0D], expect);
    assert_eq!(obd::decode_current_data(&data.payload).unwrap().count(), 3);

    for (target, source) in [
        (Target::Physical(0x7E0), 0x7E8),
        (Target::Physical(0x7E5), 0x7ED),
    ] {
        let reply = read(
            &mut elm,
            target,
            &uds::read_did(0x0200),
            Expect::Module(source),
        );
        uds::decode_did(&reply.payload, 0x0200).unwrap();
    }

    let audit = std::fs::read_to_string(&log).unwrap();
    assert_eq!(audit.lines().count(), 20, "{audit}");
    assert!(
        audit
            .lines()
            .all(|line| line.ends_with(r#","link":"tcp"}"#)),
        "{audit}"
    );
}
