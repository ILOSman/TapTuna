use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use _native::reassembly::{reassemble, OverlapPolicy, ReassemblyInput};
use _native::seq::Segment;

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

fn bench_ingest(c: &mut Criterion) {
    let mut group = c.benchmark_group("reassembly");
    for &size_mib in &[1usize, 16, 100] {
        let bytes = size_mib * 1024 * 1024;
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_function(format!("{}MiB", size_mib), |b| {
            b.iter_batched(
                || make_stream(bytes, 1400),
                |segs| {
                    let input = ReassemblyInput::new(segs, Some(999), OverlapPolicy::FirstWins);
                    let _ = reassemble(input);
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_ingest);
criterion_main!(benches);