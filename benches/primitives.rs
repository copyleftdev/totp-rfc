//! Resource-bounded Criterion benchmarks for the public OTP primitives.
#![allow(missing_docs)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use totp_rfc::{Algorithm, Digits, Hotp, Secret, Totp, ValidationWindow};

const SECRET_SHA1: &[u8] = b"12345678901234567890";
const SECRET_SHA256: &[u8] = b"12345678901234567890123456789012";
const SECRET_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";
const TIMESTAMP: u64 = 1_234_567_890;

fn generation(c: &mut Criterion) {
    let sha1 = Secret::new(SECRET_SHA1).unwrap();
    let sha256 = Secret::new(SECRET_SHA256).unwrap();
    let sha512 = Secret::new(SECRET_SHA512).unwrap();
    let hotp = Hotp::default();
    let totp_sha1 = Totp::default();
    let totp_sha256 = Totp::new(Algorithm::Sha256, Digits::EIGHT, 30, 0).unwrap();
    let totp_sha512 = Totp::new(Algorithm::Sha512, Digits::EIGHT, 30, 0).unwrap();

    let mut group = c.benchmark_group("generate");
    group.throughput(Throughput::Elements(1));
    group.bench_function("hotp_sha1", |b| {
        b.iter(|| hotp.generate(black_box(&sha1), black_box(41)));
    });
    group.bench_function("totp_sha1", |b| {
        b.iter(|| {
            totp_sha1
                .generate(black_box(&sha1), black_box(TIMESTAMP))
                .unwrap()
        });
    });
    group.bench_function("totp_sha256", |b| {
        b.iter(|| {
            totp_sha256
                .generate(black_box(&sha256), black_box(TIMESTAMP))
                .unwrap()
        });
    });
    group.bench_function("totp_sha512", |b| {
        b.iter(|| {
            totp_sha512
                .generate(black_box(&sha512), black_box(TIMESTAMP))
                .unwrap()
        });
    });
    group.finish();
}

fn verification(c: &mut Criterion) {
    let sha1 = Secret::new(SECRET_SHA1).unwrap();
    let sha256 = Secret::new(SECRET_SHA256).unwrap();
    let hotp = Hotp::default();
    let totp = Totp::new(Algorithm::Sha256, Digits::EIGHT, 30, 0).unwrap();
    let hotp_code = hotp.generate(&sha1, 41).to_string();
    let totp_code = totp.generate(&sha256, TIMESTAMP).unwrap().to_string();

    let mut group = c.benchmark_group("verify");
    group.throughput(Throughput::Elements(1));
    group.bench_function("hotp_sha1_exact", |b| {
        b.iter(|| {
            hotp.verify(
                black_box(&sha1),
                black_box(41),
                black_box(hotp_code.as_str()),
            )
            .unwrap()
        });
    });
    group.bench_function("totp_sha256_exact", |b| {
        b.iter(|| {
            totp.verify(
                black_box(&sha256),
                black_box(TIMESTAMP),
                black_box(totp_code.as_str()),
            )
            .unwrap()
        });
    });
    group.finish();
}

fn validation_windows(c: &mut Criterion) {
    let sha1 = Secret::new(SECRET_SHA1).unwrap();
    let sha256 = Secret::new(SECRET_SHA256).unwrap();
    let hotp = Hotp::default();
    let totp = Totp::new(Algorithm::Sha256, Digits::EIGHT, 30, 0).unwrap();

    let hotp_code = hotp.generate(&sha1, 110).to_string();
    let totp_code = totp.generate(&sha256, TIMESTAMP - 60).unwrap().to_string();

    let mut group = c.benchmark_group("verify_window");
    group.throughput(Throughput::Elements(1));
    group.bench_function("hotp_sha1_lookahead_10", |b| {
        b.iter(|| {
            hotp.verify_window(
                black_box(&sha1),
                black_box(100),
                black_box(10),
                black_box(hotp_code.as_str()),
            )
            .unwrap()
        });
    });
    group.bench_function("totp_sha256_past_2_future_2", |b| {
        b.iter(|| {
            totp.verify_window(
                black_box(&sha256),
                black_box(TIMESTAMP),
                black_box(ValidationWindow::new(2, 2)),
                black_box(totp_code.as_str()),
            )
            .unwrap()
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(30)
        .warm_up_time(Duration::from_millis(200))
        .measurement_time(Duration::from_millis(500))
        .nresamples(10_000);
    targets = generation, verification, validation_windows
}
criterion_main!(benches);
