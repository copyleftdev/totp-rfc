//! Conformance, boundary, and misuse-resistance tests.

use totp_rfc::{
    Algorithm, Code, CodeError, Digits, Error, Hotp, Secret, Totp, ValidationWindow,
    MIN_SECRET_BYTES,
};

const HOTP_SECRET: &[u8] = b"12345678901234567890";

#[test]
fn rfc_4226_appendix_d_vectors() {
    let secret = Secret::new(HOTP_SECRET).unwrap();
    let hotp = Hotp::default();
    let expected = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];

    for (counter, expected) in expected.into_iter().enumerate() {
        assert_eq!(hotp.generate(&secret, counter as u64).to_string(), expected);
    }
}

#[test]
fn rfc_4226_truncation_supports_every_defined_width() {
    let secret = Secret::new(HOTP_SECRET).unwrap();

    assert_eq!(
        Hotp::new(Digits::SIX).generate(&secret, 0).to_string(),
        "755224"
    );
    assert_eq!(
        Hotp::new(Digits::SEVEN).generate(&secret, 0).to_string(),
        "4755224"
    );
    assert_eq!(
        Hotp::new(Digits::EIGHT).generate(&secret, 0).to_string(),
        "84755224"
    );
}

#[test]
fn rfc_6238_appendix_b_vectors_for_every_algorithm() {
    let timestamps = [
        59_u64,
        1_111_111_109,
        1_111_111_111,
        1_234_567_890,
        2_000_000_000,
        20_000_000_000,
    ];
    let cases = [
        (
            Algorithm::Sha1,
            b"12345678901234567890".as_slice(),
            [
                "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
            ],
        ),
        (
            Algorithm::Sha256,
            b"12345678901234567890123456789012".as_slice(),
            [
                "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
            ],
        ),
        (
            Algorithm::Sha512,
            b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
            [
                "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
            ],
        ),
    ];

    for (algorithm, key, expected) in cases {
        let secret = Secret::new(key).unwrap();
        let totp = Totp::new(algorithm, Digits::EIGHT, 30, 0).unwrap();
        for (timestamp, expected) in timestamps.into_iter().zip(expected) {
            assert_eq!(
                totp.generate(&secret, timestamp).unwrap().to_string(),
                expected
            );
        }
    }
}

#[test]
fn counter_is_64_bit_past_2038() {
    let totp = Totp::new(Algorithm::Sha1, Digits::EIGHT, 1, 0).unwrap();
    assert_eq!(totp.counter_at(u64::from(u32::MAX) + 1).unwrap(), 1 << 32);
}

#[test]
fn custom_epoch_and_floor_are_exact() {
    let totp = Totp::new(Algorithm::Sha1, Digits::SIX, 30, 1_000).unwrap();
    assert_eq!(totp.counter_at(1_000), Ok(0));
    assert_eq!(totp.counter_at(1_029), Ok(0));
    assert_eq!(totp.counter_at(1_030), Ok(1));
    assert_eq!(totp.seconds_remaining(1_000), Ok(30));
    assert_eq!(totp.seconds_remaining(1_029), Ok(1));
    assert_eq!(
        totp.counter_at(999),
        Err(Error::TimestampBeforeEpoch {
            timestamp: 999,
            epoch: 1_000
        })
    );
}

#[test]
fn parameter_validation_is_strict() {
    assert_eq!(
        Secret::new(&[0; MIN_SECRET_BYTES - 1]).err(),
        Some(Error::SecretTooShort {
            actual: MIN_SECRET_BYTES - 1,
            minimum: MIN_SECRET_BYTES
        })
    );
    assert!(Secret::new(&[0; MIN_SECRET_BYTES]).is_ok());
    assert_eq!(Digits::new(5), Err(Error::InvalidDigits { actual: 5 }));
    assert_eq!(Digits::new(9), Err(Error::InvalidDigits { actual: 9 }));
    assert_eq!(
        Totp::new(Algorithm::Sha1, Digits::SIX, 0, 0),
        Err(Error::ZeroPeriod)
    );
}

#[test]
fn code_syntax_is_not_normalized() {
    assert_eq!(Code::parse("000001", Digits::SIX).unwrap().value(), 1);
    assert_eq!(
        Code::parse("000001", Digits::SIX).unwrap().to_string(),
        "000001"
    );
    assert_eq!(
        Code::parse("1", Digits::SIX),
        Err(CodeError::InvalidLength {
            actual: 1,
            expected: 6
        })
    );
    assert_eq!(
        Code::parse(" 00001", Digits::SIX),
        Err(CodeError::NonDecimal { index: 0 })
    );
    assert_eq!(
        Code::parse("00000١", Digits::SIX),
        Err(CodeError::InvalidLength {
            actual: 7,
            expected: 6
        })
    );
}

#[test]
fn hotp_window_returns_counter_transition() {
    let secret = Secret::new(HOTP_SECRET).unwrap();
    let hotp = Hotp::default();
    let found = hotp
        .verify_window(&secret, 3, 4, "287922")
        .unwrap()
        .unwrap();
    assert_eq!(found.counter(), 6);
    assert_eq!(found.next_counter(), Some(7));
    assert_eq!(hotp.verify_window(&secret, 3, 2, "287922").unwrap(), None);
}

#[test]
fn hotp_counter_exhaustion_is_explicit() {
    let secret = Secret::new(HOTP_SECRET).unwrap();
    let hotp = Hotp::default();
    let code = hotp.generate(&secret, u64::MAX).to_string();
    let found = hotp
        .verify_window(&secret, u64::MAX, u16::MAX, &code)
        .unwrap()
        .unwrap();
    assert_eq!(found.counter(), u64::MAX);
    assert_eq!(found.next_counter(), None);
}

#[test]
fn totp_window_reports_past_and_future_drift() {
    let secret = Secret::new(HOTP_SECRET).unwrap();
    let totp = Totp::default();
    let current_timestamp = 90;

    let previous = totp.generate(&secret, 60).unwrap().to_string();
    let found = totp
        .verify_window(
            &secret,
            current_timestamp,
            ValidationWindow::new(1, 1),
            &previous,
        )
        .unwrap()
        .unwrap();
    assert_eq!(found.counter(), 2);
    assert_eq!(found.drift(), -1);

    let next = totp.generate(&secret, 120).unwrap().to_string();
    let found = totp
        .verify_window(
            &secret,
            current_timestamp,
            ValidationWindow::new(1, 1),
            &next,
        )
        .unwrap()
        .unwrap();
    assert_eq!(found.counter(), 4);
    assert_eq!(found.drift(), 1);
}

#[test]
fn totp_window_handles_counter_boundaries_without_wrapping() {
    let secret = Secret::new(HOTP_SECRET).unwrap();
    let totp = Totp::new(Algorithm::Sha1, Digits::SIX, 1, 0).unwrap();
    let code = totp.generate(&secret, 0).unwrap().to_string();
    let found = totp
        .verify_window(&secret, 0, ValidationWindow::new(u16::MAX, 0), &code)
        .unwrap()
        .unwrap();
    assert_eq!(found.counter(), 0);
}
