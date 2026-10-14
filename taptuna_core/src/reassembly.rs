/// Stream reassembly: converts TCP segments into directional byte streams
/// with gap/ambiguity tracking and configurable overlap policies.
use crate::seq::{Segment, SeqTracker, sort_segments};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapPolicy {
    FirstWins,
    LastWins,
    HaltAndMark,
}

impl Default for OverlapPolicy {
    fn default() -> Self {
        OverlapPolicy::FirstWins
    }
}

impl OverlapPolicy {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "first_wins" => Some(OverlapPolicy::FirstWins),
            "last_wins" => Some(OverlapPolicy::LastWins),
            "halt_and_mark" => Some(OverlapPolicy::HaltAndMark),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Gap {
    pub offset: u64,
    pub length: u64,
    pub frames: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct Ambiguity {
    pub offset: u64,
    pub length: u64,
    pub frames: Vec<u32>,
    pub policy: OverlapPolicy,
}

#[derive(Debug, Clone)]
pub struct StreamSegmentInfo {
    pub stream_offset: u64,
    pub length: usize,
    pub abs_seq_start: u32,
    pub abs_seq_end: u32,
    pub status: SegmentStatus,
    pub first_frame: u32,
    pub last_frame: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentStatus {
    Clean,
    Overlap,
    GapBefore,
}

#[derive(Debug, Clone)]
pub struct ReassembledStream {
    /// Reassembled bytes (only known data, no zero-fill for gaps).
    pub data: Vec<u8>,
    /// Gaps in the stream (unknown regions).
    pub gaps: Vec<Gap>,
    /// Ambiguities (overlaps with different data).
    pub ambiguities: Vec<Ambiguity>,
    /// Total bytes reassembled (including gaps).
    pub total_bytes: u64,
    /// Stream start absolute sequence number.
    pub stream_start_abs_seq: u32,
    /// Whether roles established (SYN seen).
    pub roles_established: bool,
    /// Per-segment info for byte_map.
    pub segments: Vec<StreamSegmentInfo>,
    /// Mapping from stream offset to frame number (byte_map).
    pub byte_map: Vec<(u64, u32)>,
}

#[derive(Debug, Clone)]
pub struct ReassemblyInput {
    pub segments: Vec<Segment>,
    pub syn_seq: Option<u32>,
    pub overlap_policy: OverlapPolicy,
    pub max_stream_bytes: Option<u64>,
}

impl ReassemblyInput {
    pub fn new(
        segments: Vec<Segment>,
        syn_seq: Option<u32>,
        overlap_policy: OverlapPolicy,
    ) -> Self {
        ReassemblyInput {
            segments,
            syn_seq,
            overlap_policy,
            max_stream_bytes: None,
        }
    }
}

pub fn reassemble(input: ReassemblyInput) -> ReassembledStream {
    let mut segments = input.segments;
    sort_segments(&mut segments);

    let mut tracker = SeqTracker::new(input.syn_seq);
    let roles_established = input.syn_seq.is_some();

    // Filter out zero-length segments
    segments.retain(|s| s.len > 0);

    // Deduplicate identical retransmissions but keep all frame info
    let mut deduped: Vec<Segment> = Vec::new();
    for seg in segments {
        if let Some(last) = deduped.last_mut() {
            if last.abs_seq == seg.abs_seq
                && last.len == seg.len
                && last.data == seg.data
            {
                continue;
            }
        }
        deduped.push(seg);
    }
    let segments = deduped;

    // Initialize tracker if no SYN
    let stream_start_abs_seq = if roles_established {
        tracker.reference()
    } else if let Some(first_seg) = segments.first() {
        tracker = SeqTracker::new(Some(first_seg.abs_seq.wrapping_sub(1)));
        first_seg.abs_seq
    } else {
        0
    };

    let mut known_data: Vec<(u64, u8)> = Vec::new();
    let mut gaps: Vec<Gap> = Vec::new();
    let mut ambiguities: Vec<Ambiguity> = Vec::new();
    let mut stream_segments: Vec<StreamSegmentInfo> = Vec::new();
    let mut byte_map: Vec<(u64, u32)> = Vec::new();

    let mut contiguous_end_offset: u64 = 0;
    let max_bytes = input.max_stream_bytes.unwrap_or(u64::MAX);

    for seg in &segments {
        let seg_offset = match tracker.seq_to_offset(seg.abs_seq) {
            Some(o) => o,
            None => continue,
        };
        let seg_end_seq = seg.end_seq();

        if seg_offset + seg.len as u64 > max_bytes {
            continue;
        }

        // Check for gap before this segment
        if seg_offset > contiguous_end_offset {
            let gap_len = seg_offset - contiguous_end_offset;
            gaps.push(Gap {
                offset: contiguous_end_offset,
                length: gap_len,
                frames: vec![seg.frame_number],
            });
            stream_segments.push(StreamSegmentInfo {
                stream_offset: contiguous_end_offset,
                length: 0,
                abs_seq_start: tracker
                    .offset_to_seq(contiguous_end_offset)
                    .unwrap_or(0),
                abs_seq_end: tracker
                    .offset_to_seq(contiguous_end_offset)
                    .unwrap_or(0)
                    .wrapping_sub(1),
                status: SegmentStatus::GapBefore,
                first_frame: seg.frame_number,
                last_frame: seg.frame_number,
            });
            contiguous_end_offset = seg_offset;
        }

        // Check for overlap with already written data
        let data_end_offset = seg_offset + seg.len as u64;
        let overlap_len = if data_end_offset >= contiguous_end_offset
            && seg_offset < contiguous_end_offset
        {
            contiguous_end_offset - seg_offset
        } else {
            0
        };

        if overlap_len > 0 && overlap_len <= seg.len as u64 {
            let existing_data: Vec<u8> = known_data
                .iter()
                .filter(|(off, _)| *off >= seg_offset && *off < seg_offset + overlap_len)
                .map(|(_, b)| *b)
                .collect();
            let new_data = &seg.data[0..overlap_len as usize];
            let has_conflict = existing_data != new_data;
            if has_conflict {
                ambiguities.push(Ambiguity {
                    offset: seg_offset,
                    length: overlap_len,
                    frames: vec![seg.frame_number],
                    policy: input.overlap_policy,
                });
                match input.overlap_policy {
                    OverlapPolicy::FirstWins => {}
                    OverlapPolicy::LastWins => {
                        known_data.retain(|(off, _)| {
                            *off < seg_offset || *off >= seg_offset + overlap_len
                        });
                        for (i, &byte) in seg.data[0..overlap_len as usize].iter().enumerate() {
                            known_data.push((seg_offset + i as u64, byte));
                        }
                    }
                    OverlapPolicy::HaltAndMark => {}
                }
            }
        }

        // Write non-overlapping tail
        let tail_start = overlap_len as usize;
        if tail_start < seg.data.len() {
            let tail = &seg.data[tail_start..];
            let tail_offset = seg_offset + tail_start as u64;
            for (i, &byte) in tail.iter().enumerate() {
                known_data.push((tail_offset + i as u64, byte));
            }
            byte_map.push((tail_offset, seg.frame_number));
        }

        // Update contiguous_end_offset
        if seg_offset <= contiguous_end_offset && data_end_offset > contiguous_end_offset {
            contiguous_end_offset = data_end_offset;
        } else if seg_offset == contiguous_end_offset {
            contiguous_end_offset = data_end_offset;
        }

        // Record segment info
        let status = if overlap_len > 0 {
            SegmentStatus::Overlap
        } else if seg_offset > contiguous_end_offset {
            SegmentStatus::GapBefore
        } else {
            SegmentStatus::Clean
        };
        stream_segments.push(StreamSegmentInfo {
            stream_offset: seg_offset,
            length: seg.len,
            abs_seq_start: seg.abs_seq,
            abs_seq_end: seg_end_seq.wrapping_sub(1),
            status,
            first_frame: seg.frame_number,
            last_frame: seg.frame_number,
        });
    }

    known_data.sort_by_key(|(off, _)| *off);
    let data: Vec<u8> = known_data.iter().map(|(_, b)| *b).collect();

    ReassembledStream {
        data,
        gaps,
        ambiguities,
        total_bytes: contiguous_end_offset,
        stream_start_abs_seq,
        roles_established,
        segments: stream_segments,
        byte_map,
    }
}