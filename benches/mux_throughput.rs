use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use openworld::proxy::mux::singmux::{decode_frames, encode_frames, MuxBackpressure, MuxFrame};

fn bench_mux_frame_encode(c: &mut Criterion) {
    let payload = vec![0xABu8; 4096];
    let frame = MuxFrame::data(1, payload);

    c.bench_function("mux_frame_encode_4k", |b| {
        b.iter(|| {
            black_box(frame.encode());
        });
    });
}

fn bench_mux_frame_decode(c: &mut Criterion) {
    let payload = vec![0xABu8; 4096];
    let frame = MuxFrame::data(1, payload);
    let encoded = frame.encode();

    c.bench_function("mux_frame_decode_4k", |b| {
        b.iter(|| {
            black_box(MuxFrame::decode(&encoded).unwrap());
        });
    });
}

fn bench_mux_encode_decode_roundtrip(c: &mut Criterion) {
    let frames: Vec<MuxFrame> = (0..10)
        .map(|i| MuxFrame::data(i, vec![0xCDu8; 1024]))
        .collect();

    c.bench_function("mux_roundtrip_10_frames_1k", |b| {
        b.iter(|| {
            let encoded = encode_frames(&frames);
            let (decoded, _) = decode_frames(&encoded).unwrap();
            black_box(decoded);
        });
    });
}

fn bench_mux_throughput(c: &mut Criterion) {
    let payload_size = 16384;
    let payload = vec![0xFFu8; payload_size];
    let frame = MuxFrame::data(42, payload);

    let mut group = c.benchmark_group("mux_throughput");
    group.throughput(Throughput::Bytes(payload_size as u64));

    group.bench_function("encode_16k", |b| {
        b.iter(|| {
            black_box(frame.encode());
        });
    });

    let encoded = frame.encode();
    group.bench_function("decode_16k", |b| {
        b.iter(|| {
            black_box(MuxFrame::decode(&encoded).unwrap());
        });
    });

    group.finish();
}

fn bench_mux_backpressure(c: &mut Criterion) {
    c.bench_function("backpressure_data_received", |b| {
        let bp = MuxBackpressure::new(262144);
        b.iter(|| {
            black_box(bp.on_data_received(1024));
            bp.on_data_consumed(1024);
        });
    });

    c.bench_function("backpressure_window_full_cycle", |b| {
        b.iter(|| {
            let bp = MuxBackpressure::new(4096);
            for _ in 0..4 {
                bp.on_data_received(1024);
            }
            black_box(bp.is_paused());
            for _ in 0..4 {
                bp.on_data_consumed(1024);
            }
            black_box(bp.is_paused());
        });
    });
}

criterion_group!(
    benches,
    bench_mux_frame_encode,
    bench_mux_frame_decode,
    bench_mux_encode_decode_roundtrip,
    bench_mux_throughput,
    bench_mux_backpressure,
);
criterion_main!(benches);
