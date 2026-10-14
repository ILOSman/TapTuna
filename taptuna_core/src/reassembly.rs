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

/// Interval mapping a byte range in the reassembled stream to the frame
/// that contributed it. Intervals are disjoint and sorted by `start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteMapEntry {
    pub start: u64,
    pub end: u64,
    pub frame: u32,
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
    pub byte_map: Vec<ByteMapEntry>,
}

impl ReassembledStream {
    /// Find the frame that contributed the byte at `offset`, if known.
    pub fn frame_at(&self, offset: u64) -> Option<u32> {
        let mut lo = 0usize;
        let mut hi = self.byte_map.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            let e = self.byte_map[mid];
            if offset < e.start {
                hi = mid;
            } else if offset >= e.end {
                lo = mid + 1;
            } else {
                return Some(e.frame);
            }
        }
        None
    }
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

    // Рабочий буфер + интервалы записанных байт.
    // Вместо Vec<(u64, u8)> (16 байт на байт данных) держим Vec<u8>
    // и список неперекрывающихся интервалов [start, end).
    let mut data: Vec<u8> = Vec::new();
    let mut written: Vec<(u64, u64)> = Vec::new();

    let mut gaps: Vec<Gap> = Vec::new();
    let mut ambiguities: Vec<Ambiguity> = Vec::new();
    let mut stream_segments: Vec<StreamSegmentInfo> = Vec::new();
    let mut byte_map: Vec<ByteMapEntry> = Vec::new();

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

        // Gap перед сегментом
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

        // Перекрытие с уже записанными данными
        let data_end_offset = seg_offset + seg.len as u64;
        let overlap_len = if data_end_offset >= contiguous_end_offset
            && seg_offset < contiguous_end_offset
        {
            contiguous_end_offset - seg_offset
        } else {
            0
        };

        if overlap_len > 0 && overlap_len <= seg.len as u64 {
            let existing_data = read_range(&data, &written, seg_offset, overlap_len);
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
                        write_range(&mut data, &mut written, seg_offset, new_data);
                    }
                    OverlapPolicy::HaltAndMark => {}
                }
            }
        }

        // Хвост без перекрытия
        let tail_start = overlap_len as usize;
        if tail_start < seg.data.len() {
            let tail = &seg.data[tail_start..];
            let tail_offset = seg_offset + tail_start as u64;
            write_range(&mut data, &mut written, tail_offset, tail);
            byte_map.push(ByteMapEntry {
                start: tail_offset,
                end: tail_offset + tail.len() as u64,
                frame: seg.frame_number,
            });
        }

        // Обновление contiguous_end_offset
        if seg_offset <= contiguous_end_offset && data_end_offset > contiguous_end_offset {
            contiguous_end_offset = data_end_offset;
        }

        // Запись сегмента
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

    // Собираем результат из written интервалов по порядку.
    // Нулевые заполнители на местах gaps не попадают в результат.
    let total_size: usize = written.iter().map(|&(s, e)| (e - s) as usize).sum();
    let mut result_data: Vec<u8> = Vec::with_capacity(total_size);
    for &(s, e) in &written {
        result_data.extend_from_slice(&data[s as usize..e as usize]);
    }

    byte_map.sort_by_key(|e| e.start);

    ReassembledStream {
        data: result_data,
        gaps,
        ambiguities,
        total_bytes: contiguous_end_offset,
        stream_start_abs_seq,
        roles_established,
        segments: stream_segments,
        byte_map,
    }
}

// ---------------------------------------------------------------------------
// Хелперы для работы с интервалами
// ---------------------------------------------------------------------------

/// Записывает байты в `data` по offset, обновляя интервалы `written`.
/// Сливает перекрывающиеся и соседние интервалы.
fn write_range(
    data: &mut Vec<u8>,
    written: &mut Vec<(u64, u64)>,
    offset: u64,
    bytes: &[u8],
) {
    if bytes.is_empty() {
        return;
    }
    let end = offset + bytes.len() as u64;
    if data.len() < end as usize {
        data.resize(end as usize, 0);
    }
    data[offset as usize..end as usize].copy_from_slice(bytes);

    if written.is_empty() {
        written.push((offset, end));
        return;
    }

    // Найти первый интервал, который начинается после offset
    let mut i = 0;
    while i < written.len() && written[i].0 <= offset {
        i += 1;
    }

    let mut new_start = offset;
    let mut new_end = end;
    let mut from = i;

    // Слить с предыдущим
    if i > 0 {
        let (s, e) = written[i - 1];
        if e >= offset {
            new_start = s;
            if e > new_end {
                new_end = e;
            }
            from = i - 1;
        }
    }

    // Слить со следующими
    let mut to = i;
    while to < written.len() && written[to].0 <= new_end {
        if written[to].1 > new_end {
            new_end = written[to].1;
        }
        to += 1;
    }

    written.splice(from..to, [(new_start, new_end)]);
}

/// Читает `len` байт по offset, используя интервалы `written`.
/// Байты вне интервалов (в gaps) остаются нулями — это внутренняя
/// операция сравнения перекрытий, а не вывод результата.
fn read_range(
    data: &[u8],
    written: &[(u64, u64)],
    offset: u64,
    len: u64,
) -> Vec<u8> {
    let end = offset + len;
    let mut out = vec![0u8; len as usize];
    for &(s, e) in written {
        if e <= offset {
            continue;
        }
        if s >= end {
            break;
        }
        let rs = s.max(offset);
        let re = e.min(end);
        let dst_start = (rs - offset) as usize;
        let dst_end = (re - offset) as usize;
        let src_start = rs as usize;
        let src_end = re as usize;
        if src_end <= data.len() {
            out[dst_start..dst_end].copy_from_slice(&data[src_start..src_end]);
        }
    }
    out
}