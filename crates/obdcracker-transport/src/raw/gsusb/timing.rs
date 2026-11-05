//! The bit timing for a bitrate, from the device's clock and limits.

use super::wire::{BitTiming, BtConst};

// The sample point to aim for, in per mille (87.5%: what Linux's CAN stack uses up to 500 kbit/s),
// and the range a timing must land in: ISO 11898 puts it between 75% and 90%.
const TARGET: u64 = 875;
const LOWEST: u64 = 750;
const HIGHEST: u64 = 900;
// No controller has more time quanta in a bit than this; a device claiming more is not believed.
const MAX_QUANTA: u64 = 1024;

/// The prescaler and segment lengths that give `bitrate` **exactly**, with the sample point
/// closest to 87.5%. It never rounds to a nearby bitrate: a controller at the wrong rate puts
/// error frames on the bus.
pub(super) fn compute(bitrate: u32, limits: &BtConst) -> Result<BitTiming, String> {
    let (fclk, rate) = (u64::from(limits.fclk_can), u64::from(bitrate));
    if rate == 0 || fclk == 0 || fclk % rate != 0 {
        return Err(format!(
            "the controller's {fclk} Hz clock can't give exactly {bitrate} bit/s"
        ));
    }
    // brp * quanta = clocks per bit; a quantum is the sync segment plus both time segments.
    let clocks_per_bit = fclk / rate;
    let tseg1_min = u64::from(limits.tseg1_min).max(1);
    let tseg2_min = u64::from(limits.tseg2_min).max(1);
    let (tseg1_max, tseg2_max) = (u64::from(limits.tseg1_max), u64::from(limits.tseg2_max));
    let step = u64::from(limits.brp_inc).max(1);
    let (brp_min, brp_max) = (u64::from(limits.brp_min), u64::from(limits.brp_max));
    let max_quanta = (1 + tseg1_max + tseg2_max)
        .min(clocks_per_bit)
        .min(MAX_QUANTA);
    let mut best: Option<(u64, u64, BitTiming)> = None;
    if limits.sjw_max >= 1 {
        for quanta in (1 + tseg1_min + tseg2_min)..=max_quanta {
            if clocks_per_bit % quanta != 0 {
                continue;
            }
            let brp = clocks_per_bit / quanta;
            if brp < brp_min.max(1) || brp > brp_max || (brp - brp_min) % step != 0 {
                continue;
            }
            for tseg2 in tseg2_min..=tseg2_max.min(quanta - 2) {
                let tseg1 = quanta - 1 - tseg2;
                if tseg1 < tseg1_min || tseg1 > tseg1_max {
                    continue;
                }
                let sample = (1 + tseg1) * 1000 / quanta;
                let distance = sample.abs_diff(TARGET);
                if best.is_none_or(|(best_distance, ..)| distance <= best_distance) {
                    best = Some((distance, sample, split(tseg1, tseg2, brp)));
                }
            }
        }
    }
    match best {
        Some((_, sample, timing)) if (LOWEST..=HIGHEST).contains(&sample) => Ok(timing),
        Some((_, sample, _)) => Err(format!(
            "the best sample point the controller can give at {bitrate} bit/s is {}.{}%, \
             outside 75% to 90%",
            sample / 10,
            sample % 10
        )),
        None => Err(format!(
            "the controller can't give exactly {bitrate} bit/s with its prescaler and segment limits"
        )),
    }
}

// The device adds the propagation and first phase segments, so how tseg1 splits is for show; the
// kernel's driver halves it.
fn split(tseg1: u64, tseg2: u64, brp: u64) -> BitTiming {
    // Each is within a u32 limit the device gave.
    let narrow = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
    BitTiming {
        prop_seg: narrow(tseg1 / 2),
        phase_seg1: narrow(tseg1 - tseg1 / 2),
        phase_seg2: narrow(tseg2),
        sjw: 1,
        brp: narrow(brp),
    }
}
