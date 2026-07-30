# Security policy

`totp-rfc` is a cryptographic primitive library. Please report suspected
vulnerabilities privately before public disclosure.

## Supported versions

| Version | Supported |
|---|---|
| Latest crates.io release | Yes |
| Older releases | Best effort |
| Unreleased development branch | Yes |

## Reporting a vulnerability

Use GitHub's **Security → Report a vulnerability** flow for this repository.
Include:

- affected versions and features;
- a minimal reproduction using synthetic secrets;
- expected and observed security properties;
- relevant RFC sections;
- known exploitation conditions or mitigations.

Do not include production secrets, active OTP values, user records, or service
credentials. Do not open a public issue for an undisclosed vulnerability.

If private vulnerability reporting is temporarily unavailable, contact the
repository owner through GitHub with only a request for a private reporting
channel. Do not include vulnerability details in that initial public message.

## Security boundary

The crate does not provide secret generation or storage, replay databases,
atomic distributed counters, rate limiting, secure transport, or a complete
authentication protocol. Reports about those application responsibilities may
be redirected unless they expose a defect in the primitive API or its stated
guarantees.
