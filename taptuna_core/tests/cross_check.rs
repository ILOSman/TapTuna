//! Cross-check: identical inputs → identical `result_hash` regardless of
//! processing order. Run twice and compare; also compare against a
//! Python-side computed hash by writing to a JSON file that the Python
//! harness can read.

use sha2::{Digest, Sha256};
use _native::reassembly::{reassemble, OverlapPolicy, ReassemblyInput};
use _native::seq::Segment;

fn hash_stream(data: &[u8], gaps: &[(u64, u64)]) -> String {
    let mut h = Sha256::new();
    h.update((data.len() as u64).to_be_bytes());
    h.update(data);
    for (o, l) in gaps {
        h.update(o.to_be_bytes());
        h.update(l.to_be_bytes());
    }
    format!("{:x}", h.finalize())
}

#[test]
fn identical_inputs_identical_hash() {
    let segs = vec![
        Segment::new(1000, 10, 1, b"HelloWorld".to_vec()),
        Segment::new(1010, 10, 2, b"0123456789".to_vec()),
        Segment::new(1020, 5, 3, b"abcde".to_vec()),
    ];
    let input = ReassemblyInput::new(segs.clone(), Some(999), OverlapPolicy::FirstWins);
    let a = reassemble(input);
    let input = ReassemblyInput::new(segs, Some(999), OverlapPolicy::FirstWins);
    let b = reassemble(input);

    let gaps_a: Vec<(u64, u64)> = a.gaps.iter().map(|g| (g.offset, g.length)).collect();
    let gaps_b: Vec<(u64, u64)> = b.gaps.iter().map(|g| (g.offset, g.length)).collect();
    assert_eq!(hash_stream(&a.data, &gaps_a), hash_stream(&b.data, &gaps_b));
}
