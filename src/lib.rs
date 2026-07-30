#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

mod code;
mod error;
mod hotp;
mod secret;
mod totp;

pub use code::{Code, Digits};
pub use error::{CodeError, Error};
pub use hotp::{Hotp, HotpMatch};
pub use secret::{Secret, MIN_SECRET_BYTES};
pub use totp::{Algorithm, Totp, TotpMatch, ValidationWindow, VerifyError};
