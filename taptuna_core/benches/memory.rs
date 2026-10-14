//! Измерение пиковой памяти при reassembly (§10 ТЗ МАДРИГАЛ).

use std::env;
use _native::reassembly::{reassemble, OverlapPolicy, ReassemblyInput};
use _native::seq::Segment;

// Глобальный аллокатор = dhat. Все аллокации идут через него.
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn make_stream(bytes: usize, seg_size: usize) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut seq = 1000u32;
    let mut frame = 1u32;
    let payload: Vec<u8> = (0..seg_size).map(|i| (i & 0xFF) as u8).collect();
    let mut remaining = bytes;
    while remaining > 0 {
        let n = seg_size.min(remaining);
        out.push(Segment::new(seq, n, frame, payload[..n].to_vec()));
        seq = seq.wrapping_add(n as u32);
        frame += 1;
        remaining -= n;
    }
    out
}

fn main() {
    // Размер в МиБ из argv (по умолчанию 16).
    let size_mib: usize = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(16);

    let bytes = size_mib * 1024 * 1024;

    // === ВАЖНО: подготовка данных ДО включения profiler'а ===
    // Мы не хотим, чтобы создание сегментов попало в пиковую память
    // reassembly. Иначе max_bytes покажет сумму: сегменты + reassembly.
    let segs = make_stream(bytes, 1400);
    let n_segments = segs.len();

    // Профайлер включается только если DHAT_ENABLE=1.
    let profiling = env::var("DHAT_ENABLE").ok().as_deref() == Some("1");
    let _profiler = if profiling {
        Some(
            dhat::Profiler::builder()
                .file_name(format!("dhat-heap-{}MiB.json", size_mib))
                .build(),
        )
    } else {
        None
    };

    // === Замер: только эта часть попадает в профиль ===
    let input = ReassemblyInput::new(segs, Some(999), OverlapPolicy::FirstWins);
    let result = reassemble(input);

    // === Читаем пиковую ДО того, как _profiler уничтожится ===
    if profiling {
        let stats = dhat::HeapStats::get();
        println!(
            "size:        {} MiB",
            size_mib
        );
        println!(
            "segments:    {}",
            n_segments
        );
        println!(
            "reassembled: {} bytes",
            result.data.len()
        );
        println!(
            "gaps:        {}",
            result.gaps.len()
        );
        println!(
            "ambiguities: {}",
            result.ambiguities.len()
        );
        println!(
            "peak heap:   {:.1} MiB ({} bytes)",
            stats.max_bytes as f64 / (1024.0 * 1024.0),
            stats.max_bytes
        );
        println!(
            "peak blocks: {}",
            stats.max_blocks
        );
        println!(
            "dhat profile: dhat-heap-{}MiB.json",
            size_mib
        );
    } else {
        println!(
            "size: {} MiB, segments: {}, reassembled: {} bytes, gaps: {}, ambiguities: {}",
            size_mib,
            n_segments,
            result.data.len(),
            result.gaps.len(),
            result.ambiguities.len(),
        );
        println!("(run with DHAT_ENABLE=1 to profile heap)");
    }

    // Явное сохранение, чтобы оптимизатор не удалил работу.
    std::hint::black_box(&result);
}