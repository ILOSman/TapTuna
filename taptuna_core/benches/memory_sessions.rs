//! Пиковая память на реалистичной нагрузке §10:
//! 1000 сессий × ~100 КБ, reassembly вызывается по одной.
//!
//! Ключевая идея: пиковая = MAX по сессиям, а не сумма.
//!
//! Запуск:
//!     DHAT_ENABLE=1 cargo bench --bench memory_sessions
//!     DHAT_ENABLE=1 cargo bench --bench memory_sessions -- 1000 100

use std::env;
use _native::reassembly::{reassemble, OverlapPolicy, ReassemblyInput};
use _native::seq::Segment;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn make_session(bytes: usize, seg_size: usize, base_seq: u32) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut seq = base_seq;
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
    let args: Vec<String> = env::args().collect();
    let n_sessions: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let kb_per_session: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100);

    let bytes_per_session = kb_per_session * 1024;
    let total_bytes = n_sessions * bytes_per_session;

    println!(
        "config: {} sessions × {} KiB = {:.1} MiB total",
        n_sessions,
        kb_per_session,
        total_bytes as f64 / (1024.0 * 1024.0),
    );

    // Готовим сессии заранее, чтобы их создание не попало в профиль.
    let mut sessions: Vec<Vec<Segment>> = Vec::with_capacity(n_sessions);
    for i in 0..n_sessions {
        sessions.push(make_session(
            bytes_per_session,
            1400,
            1000 + (i as u32) * 1_000_000,
        ));
    }

    let profiling = env::var("DHAT_ENABLE").ok().as_deref() == Some("1");
    let _profiler = if profiling {
        Some(
            dhat::Profiler::builder()
                .file_name("dhat-heap-sessions.json".to_string())
                .build(),
        )
    } else {
        None
    };

    // Основной цикл: reassembly по одной сессии
    let mut total_reassembled = 0usize;
    for (i, segs) in sessions.into_iter().enumerate() {
        let input = ReassemblyInput::new(
            segs,
            Some(999 + (i as u32) * 1_000_000),
            OverlapPolicy::FirstWins,
        );
        let result = reassemble(input);
        total_reassembled += result.data.len();
        std::hint::black_box(&result);
    }

    println!("total reassembled: {} bytes", total_reassembled);

    if profiling {
        let stats = dhat::HeapStats::get();
        println!(
            "peak heap:   {:.1} MiB ({} bytes)",
            stats.max_bytes as f64 / (1024.0 * 1024.0),
            stats.max_bytes
        );
        println!("peak blocks: {}", stats.max_blocks);
        println!("dhat profile: dhat-heap-sessions.json");
    } else {
        println!("(run with DHAT_ENABLE=1 to profile heap)");
    }
}
