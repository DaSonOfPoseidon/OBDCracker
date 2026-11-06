use std::time::{Duration, Instant};

// Below this a sleep is no help: Windows timers round up to about 15 ms, and Linux's to 50 us or
// more. Past it, sleeping covers the bulk and the spin finishes. A sleep that overshoots only
// lengthens a gap that is a minimum (docs/raw-can.md#separation-time).
const SPIN_ONLY: Duration = Duration::from_millis(2);

/// Waits until `gap` has passed since `since`. A zero gap, or one already over, returns without
/// sleeping or spinning.
pub(super) fn wait_gap(since: Instant, gap: Duration, sleep: fn(Duration)) {
    if gap.is_zero() {
        return;
    }
    let until = since + gap;
    let left = until.saturating_duration_since(Instant::now());
    if left > SPIN_ONLY {
        sleep(left.saturating_sub(SPIN_ONLY));
    }
    while Instant::now() < until {
        std::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    thread_local! {
        static SLEPT: RefCell<Vec<Duration>> = const { RefCell::new(Vec::new()) };
    }

    fn record(d: Duration) {
        SLEPT.with(|s| s.borrow_mut().push(d));
    }

    fn slept() -> Vec<Duration> {
        SLEPT.with(|s| std::mem::take(&mut *s.borrow_mut()))
    }

    #[test]
    fn a_zero_gap_never_sleeps_or_waits() {
        slept();
        // A shared runner can stall any one call, so the fastest of many must be quick.
        let fastest = (0..20)
            .map(|_| {
                let start = Instant::now();
                wait_gap(start, Duration::ZERO, record);
                start.elapsed()
            })
            .min()
            .unwrap();
        assert_eq!(slept(), Vec::<Duration>::new());
        assert!(fastest < Duration::from_millis(1), "{fastest:?}");
    }

    #[test]
    fn a_gap_already_over_never_sleeps() {
        slept();
        let long_ago = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        wait_gap(long_ago, Duration::from_millis(50), record);
        assert_eq!(slept(), Vec::<Duration>::new());
    }

    #[test]
    fn a_short_gap_spins_instead_of_sleeping_and_is_never_short() {
        slept();
        for gap in [
            Duration::from_micros(100),
            Duration::from_micros(900),
            Duration::from_millis(2),
        ] {
            let start = Instant::now();
            wait_gap(start, gap, record);
            assert!(start.elapsed() >= gap);
        }
        assert_eq!(slept(), Vec::<Duration>::new());
    }

    #[test]
    fn a_long_gap_sleeps_less_than_it_asks_and_spins_the_rest() {
        slept();
        let gap = Duration::from_millis(40);
        let start = Instant::now();
        wait_gap(start, gap, record);
        assert!(start.elapsed() >= gap);
        let naps = slept();
        assert_eq!(naps.len(), 1);
        assert!(naps[0] <= gap.saturating_sub(SPIN_ONLY));
    }
}
