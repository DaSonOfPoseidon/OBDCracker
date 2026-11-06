# Raw CAN

The [`gsusb`](gsusb.md) and [`socketcan`](socketcan.md) backends put ISO-TP and [VW TP2.0](#vw-tp20) frames on the bus
themselves, with no adapter doing the framing. They share one transport, `RawCan`, in `crates/obdcracker-transport/src/raw/`, over a crate-private `CanPort` trait (set
filters, write one frame, read a frame or bus event). Only `RawCan` calls `CanPort::write`, and it writes only the
frames of an approved request (a TP2.0 frame is an approved request too) and the flow control frames `obdcracker-safety`
mints, so no importer can put a raw frame on the bus. The requirements come from other projects' field reports (#42); [each has a test on the transport and on each
backend](#the-requirements-and-their-tests).

## Frames

- Every ISO-TP frame is padded to 8 bytes with `0xAA`, as ISO 15765-4 requires; many ECUs drop a shorter one
  (`TxFrame::padded`). A VW TP2.0 frame is the opposite: it goes out at its own length, with nothing added
  (`TxFrame::exact`, [below](#vw-tp20)). A port sends the DLC the frame carries (`TxFrame::bytes`), never a fixed 8.
- A port confirms a frame went out before `write` returns, and `RawCan` sends the next one only after that, so a
  transfer's frames can't pass each other (PCAN with several TX mailboxes did, python-can-isotp #66). A frame that
  isn't confirmed is an error and ends the transfer.
- Receiving, `RawCan` feeds frames to a `ReplyWindow` opened from the approved request. A frame whose ID width differs
  from the request's is ignored, so a 29-bit frame never reads as an 11-bit module's. The echo check on a reply
  (service, DID) stays with the caller, as for every transport.
- A request is sent as one frame or as a segmented transfer. A multi-frame request needs a known reply ID (the module
  that sends its flow control); without one it is refused before any frame goes out. A reply with no known reply ID
  gets no flow control; `recv` times out as usual and the audit log gets a status line saying why.

## Separation time

STmin 0 never sleeps. A gap of 2 ms or less is spun, and a longer one is slept except for its last 2 ms, which are
spun. Windows timers round up to about 15 ms, so a sleep may overshoot, which only lengthens a gap that is a minimum.
The gap counts from when the port confirmed the previous frame (or from the flow control frame that allowed the block),
not from before the write, so a slow port's confirmation doesn't eat it.

## Waiting for flow control

The module has 1 s (ISO 15765-2's N_Bs) to send flow control; each wait frame restarts that, and an eleventh wait
frame in a row ends the transfer. An overflow status ends it at once. A timeout, a wait limit or an overflow is an adapter
error. Frames from other IDs while waiting are ignored, and the wait still ends on time under a flood.

## Filters and overruns

Before each request is written, `RawCan` sets the port's filters from the approved target: the broadcast takes
`0x7E8..=0x7EF`; a physical target its reply ID, at its width; a physical target with no known reply ID the 11-bit
diagnostic range `0x700..=0x7FF` (or any 29-bit ID). A port with no hardware filtering may hand over more, as
`RawCan` checks every frame itself. Frames left over from the last request are read and dropped first (and logged as
unread lines), so a late reply can't answer the next request. The drain reads at most 256 frames, then one more to see
whether the queue is empty. If that 257th frame exists, the send fails with an adapter error and writes nothing,
because what is left could be a late reply. The 257th frame is logged like the others. The frames behind it stay
queued, and the next send drains them, so none of them answers a request.

A receive overrun is an adapter error, and what was half-received is dropped: it never reads as a short reply. The
overrun does not latch.

A reply that never completed (a first frame and then silence), and a reply that completed but nobody took, are reported
as unread lines when the next request starts, the transfer fails, or the transport is settled (`Audited` does that when
it is dropped). A reply that the same module's next frame abandons (a new single or first frame, or a bad frame, such as a
consecutive frame with the wrong sequence number) is reported as soon as that frame arrives, together with the bad
frame itself, so the reply that follows doesn't take its bytes with it. Frames kept from other modules stay kept. A failed `send`
leaves no early answer to be returned by a later `recv`.

A flow control that isn't confirmed, one the caller's `before_send` refuses, and a port read that fails (not a timeout)
each end the transfer: the module may send the rest anyway, or frames may be lost, and neither can complete a reply the
caller was told failed.

## Bus state

Bus-off, error-passive and an error frame are errors, and each **latches**: `send` and `recv` fail with the same
message, and nothing more is written (not even flow control a reply asked for). A node sending into a bus it is
disrupting is the main way a diagnostic tool affects a running car. Only a new connection clears it.

## VW TP2.0

A channel setup, or a frame on a channel a module opened, that the policy approved (`Protocol::Tp20Channel`, see
[tp20.md](tp20.md)) goes out as **one frame** of exactly the approved bytes on the approved ID, at 11 bits: the setup is
7 bytes on `0x200`, a parameters frame 6, a keep-alive, ACK and disconnect 1, a request's data frame 3 plus the request.
There is no segmentation, flow control, padding or separation time, because TP2.0 does its own sequencing, ACKs and
timing in `tp20::ChannelSession`, which only needs `send` and `recv` and runs over this transport as over the ELM
driver. The ELM driver sends the same bytes (`AT V1`, variable DLC; [elm327.md](elm327.md#vw-tp20-channel-frames)), and
the vcan test checks the kernel takes them at those lengths.

- **One frame in flight, confirmed before `send` returns,** the bus-off latch, listen-only (the port refuses every
  write) and `&Approved` only are the ISO-TP rules, unchanged. A frame that isn't confirmed is an error and ends the
  conversation.
- **Receiving:** every frame from the conversation's source, at 11 bits, is a reply **as the module sent it**, with
  its own length: not parsed, not reassembled, not padded or trimmed. The source is the setup answer's ID (`0x200` plus
  the address) after a setup, and the channel's receive ID (`0x300`) after a frame on the channel. A frame from any other
  ID, or a 29-bit one with the same number, is ignored, and a flood of them can't hold `recv` past its timeout. `recv`
  waits its whole timeout, so the session never sees the early timeout an ELM327's prompt gives.
- **A module that pads its frames** (an ACK `B1 AA AA AA AA AA AA AA`, a setup answer of 8 bytes) is not understood: the
  decoders check every length, as they do over the ELM driver, so the session closes the channel (`Framing`,
  `Undecodable`). The passenger door's setup answer and disconnect (session 6) were exact lengths; whether its other
  frames are is for the next car session to confirm.
- **Filters:** the setup answer's ID only, then the channel's receive ID only, then the ISO-TP reply IDs again when an
  ISO-TP request follows, each set when it changes.
- **What is dropped and what is kept.** A *setup* starts a conversation like an ISO-TP request does: the frames the last
  one left are read and dropped (and logged as unread) before it is written, so a late data frame of a closed channel,
  which arrives on the same `0x300` as the next channel's, can't pass for it. A frame *on an open channel* continues the
  conversation: the frames already queued (the module's ACK, its next data frame) are **kept** for the session to read next,
  because the session ACKs a frame while the module may already be sending the next. Before such a frame is written the
  port is still read once to its end, so a bus fault queued behind them latches before anything goes out; the same
  bound as the drain applies (256 events, the 257th handled first and logged), and a queue past it fails the send. An
  overrun in the middle of a channel ends the conversation (a lost frame would break the session's sequence numbers).
  After an ISO-TP request, TP2.0 frames from the old channel's ID are nobody's reply.

## The requirements and their tests

The seven requirements of #42, each with the test that pins it on the shared transport (`raw/tests.rs`,
`raw/tests/timing.rs`, `raw/tests/tp20.rs`) and on each backend. A backend's tests are in its `connect_tests.rs`
(a session over the fake device, through the public `Transport`) and `port_tests.rs` (the port alone). A cell with
"shared" means the backend has no code of its own for it: the transport's test covers it, and the backends' sessions
run it too wherever a test is named.

**ISO-TP**

| # | Requirement | Transport (`RawCan`) | gs_usb | SocketCAN |
|---|---|---|---|---|
| 1 | Every frame padded to DLC 8 | `every_frame_written_has_eight_bytes_padded`, `flow_control_written_is_padded_to_eight_bytes` | `a_request_goes_out_padded_and_its_reply_comes_back`, `every_frame_of_a_long_request_is_padded_and_confirmed_before_the_next`, `a_transmitted_frame_is_twenty_bytes` | `a_request_goes_out_padded_and_its_reply_comes_back_with_or_without_an_echo`, `every_frame_of_a_long_request_is_padded_and_confirmed_before_the_next`, `a_transmitted_frame_is_sixteen_bytes_with_dlc_eight` |
| 2 | One frame in flight, in order; confirmed before the next | `consecutive_frames_go_out_in_order_with_wrapping_sequence_numbers`, `an_unconfirmed_frame_stops_the_transfer` | `every_frame_of_a_long_request_is_padded_and_confirmed_before_the_next` (the fake counts a write made while a confirmation was unread), `a_multi_frame_request_sends_each_frame_after_the_last_was_confirmed`, `an_unacknowledged_request_is_an_error_that_stops_later_sends`, `a_wrong_echo_id_is_an_error_and_stops_the_port` | the same long-request and unacknowledged tests, with a driver echo and without (`FakeDevice::can0` and `vcan`: the transmit counter confirms), `without_an_echo_the_transmit_counter_confirms_each_frame` |
| 3 | Filter to the expected reply IDs; an overrun is an error | `filters_come_from_the_approved_target_and_are_set_before_any_frame`, `a_receive_overrun_is_an_adapter_error_and_drops_the_partial_reply` | `the_port_is_given_the_replies_of_the_request_only` (software filter: the device has none), `a_frame_from_another_module_is_not_the_requests_reply`, `a_receive_overrun_in_a_reply_is_an_error_and_the_half_reply_is_dropped`, `the_overflow_flag_is_an_overrun_before_the_frame_it_rode_on` | `the_kernel_is_asked_for_the_replies_of_the_request_only`, `the_kernel_filter_follows_each_request_and_keeps_to_its_width` (kernel filter), `a_receive_overrun_in_a_reply_is_an_error_and_the_half_reply_is_dropped`, `the_sockets_drop_counter_is_an_overrun_before_the_frame_it_rode_on` |
| 4 | Bus-off, error-passive and error frames are errors and stop sending | `bus_off_error_passive_and_error_frames_are_errors_and_latch`, `a_bus_fault_while_waiting_for_flow_control_latches_and_sends_no_more` | `a_bus_off_latches_and_nothing_more_is_written`, `error_frames_map_to_bus_states` | `a_bus_off_latches_and_nothing_more_is_written`, `error_frames_map_to_bus_states` |
| 5 | Check the bitrate before going active | n/a: each backend's connect step | `connect_checks_the_bitrate_listening_before_it_goes_active`, `error_frames_in_the_window_refuse_to_go_active`, `silence_with_no_chosen_bitrate_refuses_to_go_active`, `frames_heard_in_the_window_cannot_answer_a_request` | no listen-only open (the kernel owns the interface): `another_bitrate_than_the_one_asked_for_is_refused_and_not_changed`, `an_interface_that_reports_no_bitrate_is_unconfirmed_with_a_note`, `the_bitrate_check_writes_nothing_and_reads_the_interface_once`, `the_backend_never_changes_an_interface` |
| 6 | STmin without trusting OS sleeps | `st_min_zero_never_sleeps`, `a_short_st_min_is_waited_by_spinning_and_never_cut_short`, `the_gap_counts_from_the_confirmed_frame_not_before`; on the real clock, in the CI job `timing-windows`: `short_gaps_are_spun_and_the_fastest_is_on_time`, `st_min_zero_sends_a_long_request_without_waiting` | shared | shared |
| 7 | Flow control to the responder's physical ID | `flow_control_after_a_broadcast_goes_to_the_responders_physical_id`, `two_responders_to_a_broadcast_each_get_their_own_flow_control` | `flow_control_after_a_broadcast_goes_to_the_physical_id_and_the_reply_completes` | `flow_control_after_a_broadcast_goes_to_the_physical_id_and_the_reply_completes` |

**VW TP2.0** (requirements 5 to 7 are the same code as above, or don't apply: TP2.0 has no flow control or STmin,
and `tp20::ChannelSession` does its own timing)

| # | Requirement | Transport (`RawCan`) | gs_usb | SocketCAN |
|---|---|---|---|---|
| 1 | Each frame at its own length, nothing added | `every_tp20_frame_goes_out_as_one_frame_of_its_own_length`, `iso_tp_frames_are_still_padded_to_eight_bytes` | `a_tp20_session_runs_over_usb_with_every_frame_at_its_own_length`, `a_frame_of_exact_length_goes_out_at_its_own_dlc_and_is_confirmed` | `a_tp20_session_runs_over_the_interface_with_or_without_an_echo`, `a_frame_of_exact_length_is_written_at_its_own_dlc_and_its_echo_confirms_it` |
| 2 | One frame in flight, confirmed before the next | `an_unconfirmed_frame_is_an_error_and_leaves_no_answer_to_be_read` | `a_tp20_session_runs_over_usb_with_every_frame_at_its_own_length` (also counts overlaps), `a_tp20_frame_nobody_acknowledges_is_an_error_that_stops_later_sends` | `a_tp20_session_runs_over_the_interface_with_or_without_an_echo` (also counts overlaps), `a_tp20_frame_nobody_acknowledges_is_an_error_that_stops_later_sends` |
| 3 | Filter to the conversation; an overrun ends it | `filters_follow_the_conversation_and_are_set_only_when_they_change`, `a_receive_overrun_in_the_middle_of_a_session_ends_it_without_another_frame` | shared | shared |
| 4 | Bus faults stop sending | `a_bus_off_in_the_middle_of_a_session_ends_it_without_another_frame`, `a_bus_fault_queued_behind_other_frames_latches_before_a_channel_frame_is_written` | `a_bus_off_before_a_channel_frame_latches_and_nothing_more_is_written` | `a_bus_off_before_a_channel_frame_latches_and_nothing_more_is_written` |

How requirement 6 is tested: the first tests count sleeps with a stand-in for `thread::sleep`, so they are exact on
every OS. The rest read the real clock, which only means something where timers are coarse, so they are `#[ignore]`d
(the required `check` job never runs them on its loaded runner) and run by the CI job `timing-windows` on a Windows
runner. A shared runner can stall a thread for tens of milliseconds at any moment, so they say only that no gap is ever
short and that the *fastest* of 60 gaps is within 5 ms of an STmin that is spun, or within 25 ms of one that is slept:
a stall spoils some gaps, not all of them, while a sleep where there should be a spin makes every gap late (a 16 ms
sleep put into the spin fails them). The job counts the tests its filters match and the tests that ran, because
`cargo test` passes when a filter matches nothing.

## Not here yet

- Requirement 5 on SocketCAN is a check, not a listen-only open: the kernel owns the interface, so the backend only
  confirms the bitrate the interface reports is the one asked for, and never sets it ([details](socketcan.md#connecting)).
  An interface that reports none (`vcan`, some drivers) is unconfirmed and says so; a profile bitrate that is right
  for the interface but wrong for the bus shows as an unacknowledged first frame (requirement 2) or error frames
  (requirement 4), which stop the session.
- STmin and receive latency through a real adapter and driver, on Windows too, have not been measured; the fake ports
  confirm a frame at once. Both backends' "Not yet checked on hardware" lists have the rest
  ([gs_usb](gsusb.md#not-yet-checked-on-hardware), [SocketCAN](socketcan.md#not-yet-checked-on-hardware)).
