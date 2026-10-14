use proptest::prelude::*;

use _native::reassembly::{reassemble, OverlapPolicy, ReassemblyInput};
use _native::seq::{sort_segments, Segment, SeqTracker};

fn arb_segment() -> impl Strategy<Value = Segment> {
    (0u32..1000u32, 1usize..32, 1u32..100u32).prop_map(|(seq, len, frame)| {
        let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_add(frame as u8)).collect();
        Segment::new(seq, len, frame, data)
    })
}

proptest! {
    #[test]
    fn permuted_segments_same_result(mut segs in prop::collection::vec(arb_segment(), 1..20)) {
        let policy = OverlapPolicy::FirstWins;
        let syn = Some(0u32);
        let a = reassemble(ReassemblyInput::new(segs.clone(), syn, policy));
        segs.reverse();
        let b = reassemble(ReassemblyInput::new(segs, syn, policy));
        prop_assert_eq!(a.data, b.data);
    }

    #[test]
    fn duplicate_segments_no_change(mut segs in prop::collection::vec(arb_segment(), 1..10)) {
        let base = reassemble(ReassemblyInput::new(segs.clone(), Some(0), OverlapPolicy::FirstWins));
        if let Some(first) = segs.first().cloned() {
            segs.push(first);
        }
        let with_dup = reassemble(ReassemblyInput::new(segs, Some(0), OverlapPolicy::FirstWins));
        prop_assert_eq!(base.data, with_dup.data);
    }

    #[test]
    fn sort_is_idempotent(mut segs in prop::collection::vec(arb_segment(), 0..30)) {
        sort_segments(&mut segs);
        let snapshot = segs.clone();
        sort_segments(&mut segs);
        prop_assert_eq!(snapshot.len(), segs.len());
        for (a, b) in snapshot.iter().zip(segs.iter()) {
            prop_assert_eq!(a.abs_seq, b.abs_seq);
            prop_assert_eq!(a.frame_number, b.frame_number);
        }
    }

    #[test]
    fn wraparound_tracker(seq in 0u32..u32::MAX) {
        let mut t = SeqTracker::new(Some(seq));
        prop_assert!(t.try_advance(seq.wrapping_add(10)));
        prop_assert_eq!(t.reference(), seq.wrapping_add(10));
    }
}