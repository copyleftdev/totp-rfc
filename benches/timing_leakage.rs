//! Dudect-style statistical timing-leakage probes.
//!
//! This is an attack laboratory, not a normal performance benchmark. Run it
//! on quiet, pinned hardware through `scripts/timing-test.sh`.

use std::{hint::black_box, path::PathBuf, process::ExitCode};

use dudect_bencher::{
    ctbench::{run_benches_console, BenchMetadata, BenchName, BenchOpts},
    rand::RngExt,
    BenchRng, Class, CtRunner,
};
use totp_rfc::{Algorithm, Code, Digits, Hotp, Secret, Totp, ValidationWindow};

const SAMPLES: usize = 30_000;
const TIMESTAMP: u64 = 1_700_000_000;

fn random_classes(rng: &mut BenchRng) -> Vec<Class> {
    (0..SAMPLES)
        .map(|_| {
            if rng.random::<bool>() {
                Class::Left
            } else {
                Class::Right
            }
        })
        .collect()
}

fn changed_digit(code: &str, index: usize) -> String {
    let mut bytes = code.as_bytes().to_vec();
    bytes[index] = if bytes[index] == b'9' {
        b'0'
    } else {
        bytes[index] + 1
    };
    String::from_utf8(bytes).expect("an ASCII digit mutation remains UTF-8")
}

fn random_code(rng: &mut BenchRng, excluded: &str) -> String {
    loop {
        let bytes: [u8; 8] = core::array::from_fn(|_| b'0' + rng.random::<u8>() % 10);
        let candidate = String::from_utf8(bytes.to_vec()).expect("ASCII digits are UTF-8");
        if candidate != excluded {
            return candidate;
        }
    }
}

fn hotp_code_fixed_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = [0x5a; 32];
    let secret = Secret::new(&key).unwrap();
    let hotp = Hotp::new(Digits::EIGHT);
    let counter = 0x0123_4567_89ab_cdef;
    let valid = hotp.generate(&secret, counter).to_string();
    let inputs: Vec<_> = random_classes(rng)
        .into_iter()
        .map(|class| {
            let candidate = match class {
                Class::Left => valid.clone(),
                Class::Right => random_code(rng, &valid),
            };
            (class, candidate)
        })
        .collect();

    for (class, candidate) in inputs {
        runner.run_one(class, || {
            black_box(
                hotp.verify(
                    black_box(&secret),
                    black_box(counter),
                    black_box(&candidate),
                )
                .unwrap(),
            )
        });
    }
}

fn code_wrong_first_vs_last_digit(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = [0xa5; 32];
    let secret = Secret::new(&key).unwrap();
    let hotp = Hotp::new(Digits::EIGHT);
    let counter = 0xfedc_ba98_7654_3210;
    let valid = hotp.generate(&secret, counter);
    let valid_text = valid.to_string();
    let wrong_first = Code::parse(&changed_digit(&valid_text, 0), Digits::EIGHT).unwrap();
    let wrong_last = Code::parse(
        &changed_digit(&valid_text, valid_text.len() - 1),
        Digits::EIGHT,
    )
    .unwrap();
    assert_ne!(wrong_first, valid);
    assert_ne!(wrong_last, valid);

    for class in random_classes(rng) {
        let candidate = match class {
            Class::Left => wrong_first,
            Class::Right => wrong_last,
        };
        runner.run_one(class, || {
            black_box(black_box(valid) == black_box(candidate))
        });
    }
}

fn secret_fixed_vs_random(algorithm: Algorithm, runner: &mut CtRunner, rng: &mut BenchRng) {
    let fixed_key = [0x3c; 32];
    let totp = Totp::new(algorithm, Digits::EIGHT, 30, 0).unwrap();
    let inputs: Vec<_> = random_classes(rng)
        .into_iter()
        .map(|class| {
            let key = match class {
                Class::Left => fixed_key,
                Class::Right => core::array::from_fn(|_| rng.random::<u8>()),
            };
            (class, key)
        })
        .collect();

    for (class, key) in inputs {
        let secret = Secret::new(&key).unwrap();
        runner.run_one(class, || {
            black_box(
                totp.generate(black_box(&secret), black_box(TIMESTAMP))
                    .unwrap(),
            )
        });
    }
}

fn totp_sha1_secret_fixed_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    secret_fixed_vs_random(Algorithm::Sha1, runner, rng);
}

fn totp_sha256_secret_fixed_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    secret_fixed_vs_random(Algorithm::Sha256, runner, rng);
}

fn totp_sha512_secret_fixed_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    secret_fixed_vs_random(Algorithm::Sha512, runner, rng);
}

fn totp_counter_low_vs_high(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = [0xc3; 32];
    let secret = Secret::new(&key).unwrap();
    let totp = Totp::new(Algorithm::Sha256, Digits::EIGHT, 1, 0).unwrap();
    let low_timestamp = 0;
    let high_timestamp = u64::MAX;
    let low_code = totp.generate(&secret, low_timestamp).unwrap().to_string();
    let high_code = totp.generate(&secret, high_timestamp).unwrap().to_string();
    let candidate = changed_digit(&low_code, 0);
    assert_ne!(candidate, high_code, "chosen timing vector collided");

    for class in random_classes(rng) {
        let timestamp = match class {
            Class::Left => low_timestamp,
            Class::Right => high_timestamp,
        };
        runner.run_one(class, || {
            black_box(
                totp.verify(
                    black_box(&secret),
                    black_box(timestamp),
                    black_box(&candidate),
                )
                .unwrap(),
            )
        });
    }
}

fn totp_window_current_vs_edge(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = [0x69; 64];
    let secret = Secret::new(&key).unwrap();
    let totp = Totp::new(Algorithm::Sha512, Digits::EIGHT, 30, 0).unwrap();
    let counter = 10_000;
    let timestamp = counter * 30;
    let codes: Vec<_> = ((counter - 4)..=(counter + 4))
        .map(|current| totp.generate(&secret, current * 30).unwrap().to_string())
        .collect();
    for (index, code) in codes.iter().enumerate() {
        assert!(
            !codes[..index].contains(code),
            "chosen timing-vector window contains a code collision"
        );
    }
    let current = &codes[4];
    let edge = &codes[8];
    let window = ValidationWindow::new(4, 4);

    for class in random_classes(rng) {
        let candidate = match class {
            Class::Left => current,
            Class::Right => edge,
        };
        runner.run_one(class, || {
            black_box(
                totp.verify_window(
                    black_box(&secret),
                    black_box(timestamp),
                    black_box(window),
                    black_box(candidate),
                )
                .unwrap(),
            )
        });
    }
}

fn calibration_invalid_length_vs_valid_code(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = [0x96; 32];
    let secret = Secret::new(&key).unwrap();
    let hotp = Hotp::new(Digits::EIGHT);
    let counter = 42;
    let valid = hotp.generate(&secret, counter).to_string();
    let wrong = changed_digit(&valid, 0);

    for class in random_classes(rng) {
        let candidate = match class {
            Class::Left => "0",
            Class::Right => &wrong,
        };
        runner.run_one(class, || {
            black_box(hotp.verify(black_box(&secret), black_box(counter), black_box(candidate)))
        });
    }
}

fn parse_options() -> Result<BenchOpts, String> {
    let mut options = BenchOpts::default();
    let mut arguments = std::env::args().skip(1).peekable();

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            // Cargo injects this for every custom benchmark harness.
            "--bench" => {}
            "--filter" => {
                options.filter = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--filter requires a benchmark substring".to_owned())?,
                );
            }
            "--continuous" => {
                options.continuous = true;
                if arguments.peek().is_some_and(|next| !next.starts_with('-')) {
                    options.filter = arguments.next();
                }
            }
            "--out" => {
                options.file_out =
                    Some(PathBuf::from(arguments.next().ok_or_else(|| {
                        "--out requires a CSV file path".to_owned()
                    })?));
            }
            "--help" | "-h" => {
                println!(
                    "Usage: timing_leakage [--filter BENCH] [--continuous [BENCH]] [--out FILE]"
                );
                return Err(String::new());
            }
            unknown => return Err(format!("unrecognized timing-lab argument: {unknown}")),
        }
    }

    Ok(options)
}

fn main() -> ExitCode {
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) if message.is_empty() => return ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let benches = vec![
        BenchMetadata {
            name: BenchName("calibration_invalid_length_vs_valid_code"),
            seed: Some(0x1001),
            benchfn: calibration_invalid_length_vs_valid_code,
        },
        BenchMetadata {
            name: BenchName("hotp_code_fixed_vs_random"),
            seed: Some(0x1002),
            benchfn: hotp_code_fixed_vs_random,
        },
        BenchMetadata {
            name: BenchName("code_wrong_first_vs_last_digit"),
            seed: Some(0x1003),
            benchfn: code_wrong_first_vs_last_digit,
        },
        BenchMetadata {
            name: BenchName("totp_counter_low_vs_high"),
            seed: Some(0x1004),
            benchfn: totp_counter_low_vs_high,
        },
        BenchMetadata {
            name: BenchName("totp_sha1_secret_fixed_vs_random"),
            seed: Some(0x1005),
            benchfn: totp_sha1_secret_fixed_vs_random,
        },
        BenchMetadata {
            name: BenchName("totp_sha256_secret_fixed_vs_random"),
            seed: Some(0x1006),
            benchfn: totp_sha256_secret_fixed_vs_random,
        },
        BenchMetadata {
            name: BenchName("totp_sha512_secret_fixed_vs_random"),
            seed: Some(0x1007),
            benchfn: totp_sha512_secret_fixed_vs_random,
        },
        BenchMetadata {
            name: BenchName("totp_window_current_vs_edge"),
            seed: Some(0x1008),
            benchfn: totp_window_current_vs_edge,
        },
    ];

    match run_benches_console(options, benches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("timing lab failed: {error}");
            ExitCode::FAILURE
        }
    }
}
