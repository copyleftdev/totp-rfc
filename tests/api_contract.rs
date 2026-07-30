//! Public API contracts targeted by mutation testing.

use totp_rfc::{
    Algorithm, Code, CodeError, Digits, Error, Hotp, Secret, Totp, ValidationWindow, VerifyError,
};

const SECRET_BYTES: &[u8] = b"12345678901234567890";

#[test]
fn parameter_accessors_preserve_exact_values() {
    let secret = Secret::new(SECRET_BYTES).unwrap();
    assert_eq!(secret.len(), 20);
    assert!(!secret.is_empty());

    assert_eq!(u8::from(Digits::SIX), 6);
    assert_eq!(u8::from(Digits::SEVEN), 7);
    assert_eq!(u8::from(Digits::EIGHT), 8);
    assert_eq!(Digits::try_from(7), Ok(Digits::SEVEN));

    assert_eq!(Algorithm::Sha1.recommended_key_len(), 20);
    assert_eq!(Algorithm::Sha256.recommended_key_len(), 32);
    assert_eq!(Algorithm::Sha512.recommended_key_len(), 64);

    let hotp = Hotp::new(Digits::SEVEN);
    assert_eq!(hotp.digits(), Digits::SEVEN);

    let window = ValidationWindow::new(2, 3);
    assert_eq!(window.past(), 2);
    assert_eq!(window.future(), 3);

    let totp = Totp::new(Algorithm::Sha512, Digits::EIGHT, 17, 1_234).unwrap();
    assert_eq!(totp.algorithm(), Algorithm::Sha512);
    assert_eq!(totp.digits(), Digits::EIGHT);
    assert_eq!(totp.period(), 17);
    assert_eq!(totp.epoch(), 1_234);
}

#[test]
fn code_value_width_format_and_equality_are_observable() {
    let code = Code::parse("123456", Digits::SIX).unwrap();
    let same = Code::parse("123456", Digits::SIX).unwrap();
    let different_value = Code::parse("123457", Digits::SIX).unwrap();
    let different_width = Code::parse("0123456", Digits::SEVEN).unwrap();

    assert_eq!(code.value(), 123_456);
    assert_eq!(code.digits(), Digits::SIX);
    assert_eq!(code.to_string(), "123456");
    assert_eq!(code, same);
    assert_ne!(code, different_value);
    assert_ne!(code, different_width);
}

#[test]
fn error_display_contracts_are_nonempty_and_specific() {
    let parameter = Error::TimestampBeforeEpoch {
        timestamp: 41,
        epoch: 42,
    };
    assert_eq!(
        parameter.to_string(),
        "Unix timestamp 41 precedes the configured TOTP epoch 42"
    );

    let code = CodeError::NonDecimal { index: 3 };
    assert_eq!(
        code.to_string(),
        "OTP contains a non-decimal byte at index 3"
    );

    let verification = VerifyError::from(code);
    assert_eq!(
        verification.to_string(),
        "invalid OTP code: OTP contains a non-decimal byte at index 3"
    );
}

#[cfg(feature = "std")]
#[test]
fn verification_error_preserves_its_source() {
    use std::error::Error as _;

    let code = VerifyError::from(CodeError::NonDecimal { index: 0 });
    assert_eq!(
        code.source().unwrap().to_string(),
        "OTP contains a non-decimal byte at index 0"
    );

    let parameters = VerifyError::from(Error::TimestampBeforeEpoch {
        timestamp: 1,
        epoch: 2,
    });
    assert_eq!(
        parameters.source().unwrap().to_string(),
        "Unix timestamp 1 precedes the configured TOTP epoch 2"
    );
}

#[test]
fn direct_hotp_verification_accepts_only_the_exact_code() {
    let secret = Secret::new(SECRET_BYTES).unwrap();
    let hotp = Hotp::default();

    assert_eq!(hotp.verify(&secret, 1, "287082"), Ok(true));
    assert_eq!(hotp.verify(&secret, 1, "287083"), Ok(false));
    assert_eq!(
        hotp.verify(&secret, 1, "28708x"),
        Err(CodeError::NonDecimal { index: 5 })
    );
}

#[test]
fn direct_totp_verification_and_window_reject_wrong_codes() {
    let secret = Secret::new(SECRET_BYTES).unwrap();
    let totp = Totp::default();

    assert_eq!(totp.verify(&secret, 59, "287082"), Ok(true));
    assert_eq!(totp.verify(&secret, 59, "287083"), Ok(false));
    assert_eq!(
        totp.verify_window(&secret, 59, ValidationWindow::new(2, 3), "287083"),
        Ok(None)
    );
}
