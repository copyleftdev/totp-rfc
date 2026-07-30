//! FFI boundary used only by the Valgrind secret-taint harness.

use core::{slice, str};
use totp_rfc::{Algorithm, Digits, Hotp, Secret, Totp};

fn algorithm_from_id(id: u32) -> Algorithm {
    match id {
        1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        _ => panic!("unsupported public algorithm identifier"),
    }
}

/// Generates an eight-digit TOTP while the caller marks `secret` as tainted.
///
/// # Safety
///
/// `secret` must point to `secret_len` readable bytes for this call.
#[no_mangle]
pub unsafe extern "C" fn totp_rfc_ctgrind_generate(
    secret: *const u8,
    secret_len: usize,
    algorithm: u32,
) -> u32 {
    let secret_bytes = unsafe { slice::from_raw_parts(secret, secret_len) };
    let secret = Secret::new(secret_bytes).expect("the harness supplies an RFC-sized secret");
    let totp = Totp::new(algorithm_from_id(algorithm), Digits::EIGHT, 30, 0)
        .expect("the harness supplies a nonzero period");
    totp.generate(&secret, 59)
        .expect("the public timestamp is after the epoch")
        .value()
}

/// Verifies an eight-digit TOTP while the caller marks `secret` as tainted.
///
/// # Safety
///
/// `secret` must point to `secret_len` readable bytes and `candidate` must
/// point to `candidate_len` readable UTF-8 bytes for this call.
#[no_mangle]
pub unsafe extern "C" fn totp_rfc_ctgrind_verify(
    secret: *const u8,
    secret_len: usize,
    algorithm: u32,
    candidate: *const u8,
    candidate_len: usize,
) -> u8 {
    let secret_bytes = unsafe { slice::from_raw_parts(secret, secret_len) };
    let candidate_bytes = unsafe { slice::from_raw_parts(candidate, candidate_len) };
    let candidate = str::from_utf8(candidate_bytes).expect("the harness supplies ASCII digits");
    let secret = Secret::new(secret_bytes).expect("the harness supplies an RFC-sized secret");
    let totp = Totp::new(algorithm_from_id(algorithm), Digits::EIGHT, 30, 0)
        .expect("the harness supplies a nonzero period");
    u8::from(
        totp.verify(&secret, 59, candidate)
            .expect("the harness supplies a valid code width"),
    )
}

/// Verifies a six-digit HOTP while the caller marks `secret` as tainted.
///
/// # Safety
///
/// `secret` must point to `secret_len` readable bytes and `candidate` must
/// point to `candidate_len` readable UTF-8 bytes for this call.
#[no_mangle]
pub unsafe extern "C" fn totp_rfc_ctgrind_verify_hotp(
    secret: *const u8,
    secret_len: usize,
    candidate: *const u8,
    candidate_len: usize,
) -> u8 {
    let secret_bytes = unsafe { slice::from_raw_parts(secret, secret_len) };
    let candidate_bytes = unsafe { slice::from_raw_parts(candidate, candidate_len) };
    let candidate = str::from_utf8(candidate_bytes).expect("the harness supplies ASCII digits");
    let secret = Secret::new(secret_bytes).expect("the harness supplies an RFC-sized secret");
    u8::from(
        Hotp::default()
            .verify(&secret, 0, candidate)
            .expect("the harness supplies a valid code width"),
    )
}
