//! Resource-bounded abuse cases written from an attacker's perspective.
//!
//! These tests are deterministic by design. They cover hostile input classes,
//! protocol confusion, arithmetic boundaries, replay assumptions, and a broad
//! model-based sweep without introducing a random-number or fuzzing dependency.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use totp_rfc::{
    Algorithm, Code, CodeError, Digits, Error, Hotp, Secret, Totp, ValidationWindow,
    MIN_SECRET_BYTES,
};

const SIX_DIGIT_ZERO: &[u8; 6] = b"000000";
const CORPUS_CASES: usize = 2_048;
const ORACLE_RANDOM_COUNTERS: usize = 128;
const WINDOW_RADIUS: u16 = 8;
const COLLISION_SEARCH_COUNTERS: u64 = 4_096;

fn next_deterministic(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn key_material() -> [u8; 64] {
    core::array::from_fn(|index| {
        u8::try_from(index)
            .expect("64-byte key index fits in u8")
            .wrapping_mul(37)
            .wrapping_add(11)
    })
}

fn oracle_truncate(output: &[u8], digits: Digits) -> String {
    let offset = usize::from(output[output.len() - 1] & 0x0f);
    let binary = u32::from_be_bytes([
        output[offset],
        output[offset + 1],
        output[offset + 2],
        output[offset + 3],
    ]) & 0x7fff_ffff;
    let modulus = 10_u32.pow(u32::from(digits.get()));
    format!(
        "{:0width$}",
        binary % modulus,
        width = usize::from(digits.get())
    )
}

fn oracle_sha1(key: &[u8], counter: u64, digits: Digits) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(&counter.to_be_bytes());
    oracle_truncate(&mac.finalize().into_bytes(), digits)
}

fn oracle_sha256(key: &[u8], counter: u64, digits: Digits) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(&counter.to_be_bytes());
    oracle_truncate(&mac.finalize().into_bytes(), digits)
}

fn oracle_sha512(key: &[u8], counter: u64, digits: Digits) -> String {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(&counter.to_be_bytes());
    oracle_truncate(&mac.finalize().into_bytes(), digits)
}

fn oracle_totp(algorithm: Algorithm, key: &[u8], counter: u64, digits: Digits) -> String {
    match algorithm {
        Algorithm::Sha1 => oracle_sha1(key, counter, digits),
        Algorithm::Sha256 => oracle_sha256(key, counter, digits),
        Algorithm::Sha512 => oracle_sha512(key, counter, digits),
        _ => panic!("test oracle must be extended for a new algorithm"),
    }
}

#[test]
fn strict_parser_rejects_normalization_confusables_and_control_bytes() {
    let hostile = [
        "",
        "0",
        "00000",
        "0000000",
        " 00000",
        "00000 ",
        "+00000",
        "-00000",
        "000_00",
        "000.00",
        "00/000",
        "00\\000",
        "00000\n",
        "00000\t",
        "00000\0",
        "00000O",
        "００００００",
        "٠٠٠٠٠٠",
        "۰۱۰۲۰۳",
        "00000\u{00a0}",
        "00000\u{200b}",
        "\u{202e}000000",
        "𝟘𝟘𝟘𝟘𝟘𝟘",
    ];

    for candidate in hostile {
        assert!(
            Code::parse(candidate, Digits::SIX).is_err(),
            "hostile candidate was normalized: {candidate:?}"
        );
    }

    let secret = Secret::new(b"12345678901234567890").unwrap();
    let hotp = Hotp::default();
    let totp = Totp::default();

    for position in 0..SIX_DIGIT_ZERO.len() {
        for byte in 0_u8..=0x7f {
            if byte.is_ascii_digit() {
                continue;
            }

            let mut bytes = *SIX_DIGIT_ZERO;
            bytes[position] = byte;
            let candidate = core::str::from_utf8(&bytes).expect("ASCII is valid UTF-8");

            assert!(Code::parse(candidate, Digits::SIX).is_err());
            assert!(hotp.verify_window(&secret, 0, u16::MAX, candidate).is_err());
            assert!(totp
                .verify_window(
                    &secret,
                    0,
                    ValidationWindow::new(u16::MAX, u16::MAX),
                    candidate,
                )
                .is_err());
        }
    }
}

#[test]
fn oversized_candidate_is_rejected_before_value_parsing() {
    let candidate = "0".repeat(64 * 1_024);
    assert_eq!(
        Code::parse(&candidate, Digits::SIX),
        Err(CodeError::InvalidLength {
            actual: 65_536,
            expected: 6,
        })
    );
}

#[test]
fn bounded_ascii_attack_corpus_never_panics() {
    let secret = Secret::new(b"12345678901234567890").unwrap();
    let hotp = Hotp::default();
    let totp = Totp::default();
    let mut state = 0xd1ce_baad_f00d_5eed;

    for _ in 0..CORPUS_CASES {
        let length = usize::try_from(next_deterministic(&mut state) % 65)
            .expect("bounded length fits usize");
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            bytes.push(
                u8::try_from(next_deterministic(&mut state) & 0x7f).expect("masked byte fits u8"),
            );
        }
        let candidate = String::from_utf8(bytes).expect("ASCII corpus is valid UTF-8");

        let _parsed = Code::parse(&candidate, Digits::SIX);
        let _hotp = hotp.verify_window(&secret, u64::MAX - 1, 2, &candidate);
        let _totp = totp.verify_window(&secret, u64::MAX, ValidationWindow::new(2, 2), &candidate);
    }
}

#[test]
fn independent_hmac_oracle_matches_bounded_counter_sweep() {
    let key = key_material();
    let mut counters = vec![
        0,
        1,
        29,
        30,
        31,
        u64::from(u32::MAX) - 1,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX - 1,
        u64::MAX,
    ];
    let mut state = 0xa11c_e5ed_5eed_cafe;
    for _ in 0..ORACLE_RANDOM_COUNTERS {
        counters.push(next_deterministic(&mut state));
    }

    let algorithms = [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512];
    let widths = [Digits::SIX, Digits::SEVEN, Digits::EIGHT];

    for key_len in [16_usize, 20, 32, 64] {
        let secret = Secret::new(&key[..key_len]).unwrap();
        for digits in widths {
            let hotp = Hotp::new(digits);
            for &counter in &counters {
                assert_eq!(
                    hotp.generate(&secret, counter).to_string(),
                    oracle_sha1(secret_bytes(&key, key_len), counter, digits)
                );

                for algorithm in algorithms {
                    let totp = Totp::new(algorithm, digits, 1, 0).unwrap();
                    assert_eq!(
                        totp.generate(&secret, counter).unwrap().to_string(),
                        oracle_totp(algorithm, secret_bytes(&key, key_len), counter, digits)
                    );
                }
            }
        }
    }
}

fn secret_bytes(key: &[u8; 64], length: usize) -> &[u8] {
    &key[..length]
}

#[test]
fn algorithm_secret_width_and_time_parameter_confusion_is_rejected() {
    let key = key_material();
    let mut other_key = key;
    other_key[0] ^= 0xff;
    let secret = Secret::new(&key).unwrap();
    let wrong_secret = Secret::new(&other_key).unwrap();
    let timestamp = 1_700_000_000;

    let configurations = [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512].map(|algorithm| {
        let totp = Totp::new(algorithm, Digits::EIGHT, 30, 0).unwrap();
        let code = totp.generate(&secret, timestamp).unwrap().to_string();
        (algorithm, code)
    });

    for (index, (algorithm, code)) in configurations.iter().enumerate() {
        let verifier = Totp::new(*algorithm, Digits::EIGHT, 30, 0).unwrap();
        assert_eq!(verifier.verify(&secret, timestamp, code), Ok(true));
        assert_eq!(verifier.verify(&wrong_secret, timestamp, code), Ok(false));

        for (other_index, (_, other_code)) in configurations.iter().enumerate() {
            if index == other_index {
                continue;
            }
            assert_ne!(code, other_code, "chosen confusion vector collided");
            assert_eq!(
                verifier.verify(&secret, timestamp, other_code),
                Ok(false),
                "algorithm downgrade or substitution was accepted"
            );
        }
    }

    let canonical = Totp::new(Algorithm::Sha256, Digits::EIGHT, 30, 0).unwrap();
    let code = canonical.generate(&secret, timestamp).unwrap().to_string();
    let wrong_period = Totp::new(Algorithm::Sha256, Digits::EIGHT, 31, 0).unwrap();
    let wrong_epoch = Totp::new(Algorithm::Sha256, Digits::EIGHT, 30, 30).unwrap();
    assert_eq!(
        wrong_period.verify(&secret, timestamp, &code),
        Ok(false),
        "period confusion was accepted"
    );
    assert_eq!(
        wrong_epoch.verify(&secret, timestamp, &code),
        Ok(false),
        "epoch confusion was accepted"
    );

    let six_digits = Totp::new(Algorithm::Sha256, Digits::SIX, 30, 0).unwrap();
    assert_eq!(
        six_digits.verify(&secret, timestamp, &code),
        Err(CodeError::InvalidLength {
            actual: 8,
            expected: 6,
        }
        .into())
    );
}

#[test]
fn bounded_windows_accept_every_in_range_step_and_reject_neighbors() {
    let key = key_material();
    let secret = Secret::new(&key).unwrap();
    let hotp = Hotp::new(Digits::EIGHT);
    let first_counter = 10_000;

    for offset in 0..=u64::from(WINDOW_RADIUS) {
        let target = first_counter + offset;
        let code = hotp.generate(&secret, target).to_string();
        let matched = hotp
            .verify_window(&secret, first_counter, WINDOW_RADIUS, &code)
            .unwrap()
            .expect("in-range HOTP counter must match");
        assert_eq!(matched.counter(), target);
        assert_eq!(matched.next_counter(), target.checked_add(1));
    }

    let outside = hotp
        .generate(&secret, first_counter + u64::from(WINDOW_RADIUS) + 1)
        .to_string();
    assert_eq!(
        hotp.verify_window(&secret, first_counter, WINDOW_RADIUS, &outside),
        Ok(None)
    );

    let totp = Totp::new(Algorithm::Sha512, Digits::EIGHT, 30, 0).unwrap();
    let verifier_counter = 10_000_u64;
    let verifier_timestamp = verifier_counter * 30;
    let window = ValidationWindow::new(WINDOW_RADIUS, WINDOW_RADIUS);

    for drift in -i32::from(WINDOW_RADIUS)..=i32::from(WINDOW_RADIUS) {
        let target_counter =
            u64::try_from(i128::from(verifier_counter) + i128::from(drift)).unwrap();
        let code = totp
            .generate(&secret, target_counter * 30)
            .unwrap()
            .to_string();
        let matched = totp
            .verify_window(&secret, verifier_timestamp, window, &code)
            .unwrap()
            .expect("in-range TOTP counter must match");
        assert_eq!(matched.counter(), target_counter);
        assert_eq!(matched.drift(), drift);
    }

    for drift in [-i32::from(WINDOW_RADIUS) - 1, i32::from(WINDOW_RADIUS) + 1] {
        let target_counter =
            u64::try_from(i128::from(verifier_counter) + i128::from(drift)).unwrap();
        let code = totp
            .generate(&secret, target_counter * 30)
            .unwrap()
            .to_string();
        assert_eq!(
            totp.verify_window(&secret, verifier_timestamp, window, &code),
            Ok(None)
        );
    }
}

#[test]
fn colliding_codes_preserve_the_first_window_match() {
    let key = key_material();
    let secret = Secret::new(&key).unwrap();
    let hotp = Hotp::new(Digits::SIX);
    let mut seen = HashMap::with_capacity(usize::try_from(COLLISION_SEARCH_COUNTERS).unwrap());
    let mut collision = None;

    for counter in 0..COLLISION_SEARCH_COUNTERS {
        let code = hotp.generate(&secret, counter);
        if let Some(first_counter) = seen.insert(code.value(), counter) {
            collision = Some((first_counter, counter, code.to_string()));
            break;
        }
    }

    let (first_counter, second_counter, code) =
        collision.expect("bounded six-digit birthday search must find a collision");
    let distance = u16::try_from(second_counter - first_counter)
        .expect("bounded search distance fits the public window type");

    let hotp_match = hotp
        .verify_window(&secret, first_counter, distance, &code)
        .unwrap()
        .expect("colliding HOTP code must match");
    assert_eq!(hotp_match.counter(), first_counter);

    let totp = Totp::new(Algorithm::Sha1, Digits::SIX, 1, 0).unwrap();
    assert_eq!(
        totp.generate(&secret, first_counter).unwrap().to_string(),
        code
    );
    let totp_match = totp
        .verify_window(
            &secret,
            first_counter,
            ValidationWindow::new(0, distance),
            &code,
        )
        .unwrap()
        .expect("colliding TOTP code must match");
    assert_eq!(totp_match.counter(), first_counter);
    assert_eq!(totp_match.drift(), 0);
}

#[test]
fn counter_and_timestamp_arithmetic_never_wraps_into_an_accepted_code() {
    let key = key_material();
    let secret = Secret::new(&key).unwrap();
    let hotp = Hotp::new(Digits::EIGHT);
    let zero_code = hotp.generate(&secret, 0).to_string();
    assert_ne!(zero_code, hotp.generate(&secret, u64::MAX).to_string());
    assert_eq!(
        hotp.verify_window(&secret, u64::MAX, 4, &zero_code),
        Ok(None)
    );

    let totp = Totp::new(Algorithm::Sha256, Digits::EIGHT, 1, 0).unwrap();
    let max_code = totp.generate(&secret, u64::MAX).unwrap().to_string();
    assert_ne!(zero_code, max_code);
    assert_eq!(
        totp.verify_window(&secret, 0, ValidationWindow::new(4, 0), &max_code),
        Ok(None)
    );
    assert_eq!(
        totp.verify_window(&secret, u64::MAX, ValidationWindow::new(0, 4), &zero_code),
        Ok(None)
    );

    let extreme_epoch = Totp::new(Algorithm::Sha1, Digits::SIX, u64::MAX, u64::MAX).unwrap();
    assert_eq!(extreme_epoch.counter_at(u64::MAX), Ok(0));
    assert_eq!(extreme_epoch.seconds_remaining(u64::MAX), Ok(u64::MAX));
    assert_eq!(
        extreme_epoch.counter_at(u64::MAX - 1),
        Err(Error::TimestampBeforeEpoch {
            timestamp: u64::MAX - 1,
            epoch: u64::MAX,
        })
    );
}

#[test]
fn replay_attempts_expose_the_state_callers_must_persist() {
    let secret = Secret::new(b"12345678901234567890").unwrap();
    let hotp = Hotp::default();
    let hotp_code = hotp.generate(&secret, 0).to_string();
    let first = hotp
        .verify_window(&secret, 0, 0, &hotp_code)
        .unwrap()
        .unwrap();
    let replay = hotp
        .verify_window(&secret, 0, 0, &hotp_code)
        .unwrap()
        .unwrap();
    assert_eq!(first, replay, "the primitive is intentionally stateless");
    assert_eq!(first.next_counter(), Some(1));
    assert_eq!(hotp.verify(&secret, 1, &hotp_code), Ok(false));

    let totp = Totp::default();
    let totp_code = totp.generate(&secret, 59).unwrap().to_string();
    let first = totp
        .verify_window(&secret, 59, ValidationWindow::CURRENT, &totp_code)
        .unwrap()
        .unwrap();
    let replay = totp
        .verify_window(&secret, 59, ValidationWindow::CURRENT, &totp_code)
        .unwrap()
        .unwrap();
    assert_eq!(first, replay, "the primitive is intentionally stateless");
    assert_eq!(first.counter(), 1);
    assert_eq!(totp.verify(&secret, 89, &totp_code), Ok(false));
}

#[test]
fn secret_length_edges_and_long_keys_remain_safe() {
    for length in 0..MIN_SECRET_BYTES {
        assert_eq!(
            Secret::new(&vec![0xa5; length]).err(),
            Some(Error::SecretTooShort {
                actual: length,
                minimum: MIN_SECRET_BYTES,
            })
        );
    }

    let minimum_key = vec![0xa5; MIN_SECRET_BYTES];
    assert!(Secret::new(&minimum_key).is_ok());

    let long_key = vec![0x5a; 4_096];
    let secret = Secret::new(&long_key).unwrap();
    let totp = Totp::new(Algorithm::Sha512, Digits::EIGHT, 30, 0).unwrap();
    let code = totp.generate(&secret, u64::MAX).unwrap().to_string();
    assert_eq!(totp.verify(&secret, u64::MAX, &code), Ok(true));
}
