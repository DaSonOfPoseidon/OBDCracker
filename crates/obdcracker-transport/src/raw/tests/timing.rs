//! #42 requirement 6: `STmin`. The first tests count sleeps with a stand-in for `thread::sleep`, so
//! they are exact on every OS. The `#[ignore]`d ones read the real clock, which only means
//! something on the OS whose timers are coarse: the CI job `timing-windows` runs them there (and
//! `raw::pace`'s) with `--include-ignored`, and `scripts/cargo.sh test ... -- --ignored` runs them
//! anywhere else.

use std::cell::RefCell;
use std::time::{Duration, Instant};

use obdcracker_safety::Target;

use super::{
    CanPort, Error, Fake, Filter, Logged, PortEvent, RawCan, TxFrame, long_request,
    module_flow_control,
};
use crate::Transport;

thread_local! {
    static NAPS: RefCell<Vec<Duration>> = const { RefCell::new(Vec::new()) };
}

fn nap(d: Duration) {
    NAPS.with(|naps| naps.borrow_mut().push(d));
}

fn naps() -> Vec<Duration> {
    NAPS.with(|naps| std::mem::take(&mut *naps.borrow_mut()))
}

#[test]
fn st_min_zero_never_sleeps() {
    naps();
    let mut can = RawCan::new(module_flow_control(0x7E8, 0)).with_sleeper(nap);
    can.send(&long_request(Target::Physical(0x7E0), 200))
        .unwrap();
    assert_eq!(naps(), Vec::<Duration>::new());
}

#[test]
fn a_short_st_min_is_waited_by_spinning_and_never_cut_short() {
    // 0xF5 is 500 us; 0x01 is 1 ms
    for (code, gap) in [
        (0xF5, Duration::from_micros(500)),
        (0x01, Duration::from_millis(1)),
    ] {
        naps();
        let mut can = RawCan::new(module_flow_control(0x7E8, code)).with_sleeper(nap);
        can.send(&long_request(Target::Physical(0x7E0), 40))
            .unwrap();
        assert_eq!(naps(), Vec::<Duration>::new());
        let times: Vec<Instant> = can
            .port
            .log
            .iter()
            .filter_map(|entry| match entry {
                Logged::Write(_, at) => Some(*at),
                Logged::Filters(_) => None,
            })
            .collect();
        for pair in times[1..].windows(2) {
            assert!(
                pair[1] - pair[0] >= gap,
                "{:?} < {gap:?}",
                pair[1] - pair[0]
            );
        }
    }
}

#[test]
fn a_long_st_min_sleeps_for_less_than_it_asks() {
    naps();
    let mut can = RawCan::new(module_flow_control(0x7E8, 20)).with_sleeper(nap);
    can.send(&long_request(Target::Physical(0x7E0), 14))
        .unwrap();
    let naps = naps();
    assert_ne!(naps.len(), 0);
    assert!(naps.iter().all(|nap| *nap < Duration::from_millis(20)));
}

#[test]
fn the_gap_counts_from_the_confirmed_frame_not_before() {
    // A port that takes 5 ms to confirm each frame. Stamped before the write, a 1 ms gap would
    // already be over when it returned.
    #[derive(Debug)]
    struct Slow(Fake);
    impl CanPort for Slow {
        fn set_filters(&mut self, filters: &[Filter]) -> Result<(), Error> {
            self.0.set_filters(filters)
        }
        fn write(&mut self, frame: &TxFrame) -> Result<(), Error> {
            std::thread::sleep(Duration::from_millis(5));
            self.0.write(frame)
        }
        fn read(&mut self, timeout: Duration) -> Result<PortEvent, Error> {
            self.0.read(timeout)
        }
    }
    let mut can = RawCan::new(Slow(module_flow_control(0x7E8, 1)));
    can.send(&long_request(Target::Physical(0x7E0), 21))
        .unwrap();
    let times: Vec<Instant> = can
        .port
        .0
        .log
        .iter()
        .filter_map(|entry| match entry {
            Logged::Write(_, at) => Some(*at),
            Logged::Filters(_) => None,
        })
        .collect();
    for pair in times[1..].windows(2) {
        assert!(pair[1] - pair[0] >= Duration::from_millis(6));
    }
}

// ---- The real clock

// A shared runner can stall a thread for tens of milliseconds at any moment, so nothing below says
// that every gap was on time. A gap is never short, which is a hard bound (the clock is
// monotonic), and the *fastest* of many gaps is within a budget: a stall spoils some of them but
// not all 60, while code that sleeps where it should spin is late every time.
const TRIALS: usize = 15;

// A spun gap has no timer in it: only the scheduler can add to it.
const SPIN_BUDGET: Duration = Duration::from_millis(5);
// A slept gap rounds up to the next timer tick: about 15.6 ms on a Windows timer without high
// resolution.
const SLEEP_BUDGET: Duration = Duration::from_millis(25);

fn write_times(can: &RawCan<Fake>) -> Vec<Instant> {
    can.port
        .log
        .iter()
        .filter_map(|entry| match entry {
            Logged::Write(_, at) => Some(*at),
            Logged::Filters(_) => None,
        })
        .collect()
}

// Every gap between consecutive frames of a 40-byte request (a first frame and five consecutive
// frames, so four gaps a trial), over the real clock and the real sleep.
fn gaps(st_min: u8) -> Vec<Duration> {
    let mut all = Vec::new();
    for _ in 0..TRIALS {
        let mut can = RawCan::new(module_flow_control(0x7E8, st_min));
        can.send(&long_request(Target::Physical(0x7E0), 40))
            .unwrap();
        let times = write_times(&can);
        assert_eq!(times.len(), 6);
        all.extend(times[1..].windows(2).map(|pair| pair[1] - pair[0]));
    }
    assert_eq!(all.len(), TRIALS * 4, "the measurement itself went missing");
    all
}

fn fastest(gaps: &[Duration]) -> Duration {
    *gaps.iter().min().unwrap()
}

#[test]
#[ignore = "reads the real clock; run by the CI job timing-windows"]
fn short_gaps_are_spun_and_the_fastest_is_on_time() {
    // 0xF5 is 500 us; 0x01 is 1 ms; 0x02 is 2 ms, the longest that is only spun
    for (code, gap) in [
        (0xF5, Duration::from_micros(500)),
        (0x01, Duration::from_millis(1)),
        (0x02, Duration::from_millis(2)),
    ] {
        let fastest = fastest(&gaps(code));
        assert!(
            fastest >= gap,
            "a gap of {fastest:?} is shorter than {gap:?}"
        );
        assert!(
            fastest <= gap + SPIN_BUDGET,
            "even the fastest gap took {fastest:?} for {gap:?}: a sleep is in the way"
        );
    }
}

#[test]
#[ignore = "reads the real clock; run by the CI job timing-windows"]
fn a_long_gap_is_never_short_and_the_fastest_loses_less_than_a_timer_tick() {
    let gap = Duration::from_millis(20);
    let fastest = fastest(&gaps(20));
    assert!(
        fastest >= gap,
        "a gap of {fastest:?} is shorter than {gap:?}"
    );
    assert!(
        fastest <= gap + SLEEP_BUDGET,
        "even the fastest gap took {fastest:?} for {gap:?}"
    );
}

#[test]
#[ignore = "reads the real clock; run by the CI job timing-windows"]
fn st_min_zero_sends_a_long_request_without_waiting() {
    // 200 bytes are 29 frames. A sleep(0) between frames takes up to one timer tick on Windows,
    // which would make this about 400 ms.
    let mut fastest = Duration::MAX;
    for _ in 0..TRIALS {
        let mut can = RawCan::new(module_flow_control(0x7E8, 0));
        let request = long_request(Target::Physical(0x7E0), 200);
        let start = Instant::now();
        can.send(&request).unwrap();
        fastest = fastest.min(start.elapsed());
        assert_eq!(can.port.written().len(), 29);
    }
    assert!(
        fastest < SLEEP_BUDGET,
        "even the fastest of {TRIALS} sends took {fastest:?}"
    );
}
