/// Sequence number tracker with RFC 9293 wraparound handling.
///
/// Reference point is the maximum contiguous sequence number (not the last seen).
/// Seed from SYN if present, otherwise from minimum observed sequence.
/// Window is ±2^31 from reference point.
/// Reference point updates only on confirmed continuity.
use std::cmp::Ordering;

pub const SEQ_WINDOW: u32 = 1 << 31; // ±2^31

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqTracker {
    reference: u32,
    initialized: bool,
    isn: Option<u32>,
}

impl SeqTracker {
    pub fn new(syn_seq: Option<u32>) -> Self {
        match syn_seq {
            Some(isn) => SeqTracker {
                reference: isn.wrapping_add(1),
                initialized: true,
                isn: Some(isn),
            },
            None => SeqTracker {
                reference: 0,
                initialized: false,
                isn: None,
            },
        }
    }

    pub fn reference(&self) -> u32 {
        self.reference
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn isn(&self) -> Option<u32> {
        self.isn
    }

    /// Convert absolute sequence number to offset from stream start.
    /// Returns None if seq is outside the valid window.
    pub fn seq_to_offset(&self, abs_seq: u32) -> Option<u64> {
        if !self.initialized {
            return None;
        }
        // Use RFC 9293 serial number arithmetic
        match self.cmp_seq(abs_seq, self.reference) {
            Ordering::Less | Ordering::Equal => {
                let diff = self.reference.wrapping_sub(abs_seq);
                if diff < SEQ_WINDOW {
                    Some(diff as u64)
                } else {
                    None // too old
                }
            }
            Ordering::Greater => {
                let diff = abs_seq.wrapping_sub(self.reference);
                if diff < SEQ_WINDOW {
                    Some(diff as u64)
                } else {
                    None // too far ahead
                }
            }
        }
    }

    /// Try to update the reference point with a new contiguous sequence number.
    /// Returns true if reference was updated.
    pub fn try_advance(&mut self, new_contiguous_seq: u32) -> bool {
        if !self.initialized {
            self.reference = new_contiguous_seq;
            self.initialized = true;
            if self.isn.is_none() {
                self.isn = Some(new_contiguous_seq);
            }
            return true;
        }
        // Check if new_contiguous_seq is strictly ahead and within window
        match self.cmp_seq(new_contiguous_seq, self.reference) {
            Ordering::Greater => {
                let diff = new_contiguous_seq.wrapping_sub(self.reference);
                if diff < SEQ_WINDOW {
                    self.reference = new_contiguous_seq;
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Compare two sequence numbers in the context of this tracker's window.
    pub fn cmp_seq(&self, a: u32, b: u32) -> Ordering {
        let diff = a.wrapping_sub(b);
        if diff == 0 {
            Ordering::Equal
        } else if diff < SEQ_WINDOW {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }

    /// Check if a sequence number is within the valid receive window.
    pub fn in_window(&self, seq: u32) -> bool {
        if !self.initialized {
            return false;
        }
        match self.cmp_seq(seq, self.reference) {
            Ordering::Less | Ordering::Equal => {
                let diff = self.reference.wrapping_sub(seq);
                diff < SEQ_WINDOW
            }
            Ordering::Greater => {
                let diff = seq.wrapping_sub(self.reference);
                diff < SEQ_WINDOW
            }
        }
    }

    /// Get the absolute sequence number for a given offset from stream start.
    pub fn offset_to_seq(&self, offset: u64) -> Option<u32> {
        if !self.initialized {
            return None;
        }
        if offset >= SEQ_WINDOW as u64 {
            return None;
        }
        Some(self.reference.wrapping_add(offset as u32))
    }
}

impl Default for SeqTracker {
    fn default() -> Self {
        SeqTracker::new(None)
    }
}

/// Segment for reassembly: represents a contiguous piece of data with sequence info.
#[derive(Debug, Clone)]
pub struct Segment {
    pub abs_seq: u32,
    pub len: usize,
    pub frame_number: u32,
    pub is_retransmission: bool,
    pub has_conflict: bool,
    pub data: Vec<u8>,
}

impl Segment {
    pub fn new(abs_seq: u32, len: usize, frame_number: u32, data: Vec<u8>) -> Self {
        Segment {
            abs_seq,
            len,
            frame_number,
            is_retransmission: false,
            has_conflict: false,
            data,
        }
    }

    pub fn end_seq(&self) -> u32 {
        self.abs_seq.wrapping_add(self.len as u32)
    }

    #[allow(dead_code)]
    pub fn overlaps(&self, other: &Segment) -> bool {
        let self_end = self.end_seq();
        let other_end = other.end_seq();
        let self_before_other = self_end == other.abs_seq
            || self_end.wrapping_sub(other.abs_seq) > SEQ_WINDOW;
        let other_before_self = other_end == self.abs_seq
            || other_end.wrapping_sub(self.abs_seq) > SEQ_WINDOW;
        !(self_before_other || other_before_self)
    }

    #[allow(dead_code)]
    pub fn is_before(&self, other: &Segment) -> bool {
        let self_end = self.end_seq();
        self_end == other.abs_seq || self_end.wrapping_sub(other.abs_seq) > SEQ_WINDOW
    }
}

/// Sort segments by (abs_seq, frame_number) for deterministic ordering.
/// Uses RFC 9293 sequence number arithmetic: a < b iff (a - b) > 2^31.
pub fn sort_segments(segments: &mut [Segment]) {
    let tracker = SeqTracker::new(None);
    segments.sort_by(|a, b| {
        match tracker.cmp_seq(a.abs_seq, b.abs_seq) {
            Ordering::Equal => a.frame_number.cmp(&b.frame_number),
            other => other,
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seq_tracker_with_syn() {
        let mut tracker = SeqTracker::new(Some(1000));
        assert_eq!(tracker.reference(), 1001);
        assert!(tracker.is_initialized());
        assert_eq!(tracker.isn(), Some(1000));
    }

    #[test]
    fn test_seq_tracker_without_syn() {
        let tracker = SeqTracker::new(None);
        assert!(!tracker.is_initialized());
        assert_eq!(tracker.isn(), None);
    }

    #[test]
    fn test_wraparound() {
        let mut tracker = SeqTracker::new(Some(0xFFFF_FFFF));
        assert_eq!(tracker.reference(), 0);
        assert!(tracker.try_advance(5));
        assert_eq!(tracker.reference(), 5);
    }
}