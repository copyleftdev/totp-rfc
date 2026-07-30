#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <valgrind/memcheck.h>

extern uint32_t totp_rfc_ctgrind_generate(
    const uint8_t *secret,
    size_t secret_len,
    uint32_t algorithm
);
extern uint8_t totp_rfc_ctgrind_verify(
    const uint8_t *secret,
    size_t secret_len,
    uint32_t algorithm,
    const uint8_t *candidate,
    size_t candidate_len
);
extern uint8_t totp_rfc_ctgrind_verify_hotp(
    const uint8_t *secret,
    size_t secret_len,
    const uint8_t *candidate,
    size_t candidate_len
);

static void exercise_totp(
    uint8_t *secret,
    size_t secret_len,
    uint32_t algorithm,
    const char *valid
) {
    static const char wrong[] = "00000000";
    volatile uint32_t generated;
    volatile uint8_t accepted;

    VALGRIND_MAKE_MEM_UNDEFINED(secret, secret_len);

    generated = totp_rfc_ctgrind_generate(secret, secret_len, algorithm);
    VALGRIND_MAKE_MEM_DEFINED((void *)&generated, sizeof(generated));

    accepted = totp_rfc_ctgrind_verify(
        secret,
        secret_len,
        algorithm,
        (const uint8_t *)valid,
        strlen(valid)
    );
    VALGRIND_MAKE_MEM_DEFINED((void *)&accepted, sizeof(accepted));

    accepted = totp_rfc_ctgrind_verify(
        secret,
        secret_len,
        algorithm,
        (const uint8_t *)wrong,
        strlen(wrong)
    );
    VALGRIND_MAKE_MEM_DEFINED((void *)&accepted, sizeof(accepted));

    VALGRIND_MAKE_MEM_DEFINED(secret, secret_len);
}

static int calibration_should_fail(void) {
    volatile uint8_t secret = 1U;

    VALGRIND_MAKE_MEM_UNDEFINED((void *)&secret, sizeof(secret));
    if (secret == 0U) {
        puts("unreachable secret branch");
    }
    VALGRIND_MAKE_MEM_DEFINED((void *)&secret, sizeof(secret));
    return 0;
}

int main(int argc, char **argv) {
    uint8_t sha1_secret[] = "12345678901234567890";
    uint8_t sha256_secret[] = "12345678901234567890123456789012";
    uint8_t sha512_secret[] =
        "1234567890123456789012345678901234567890123456789012345678901234";
    volatile uint8_t accepted;

    if (argc == 2 && strcmp(argv[1], "--calibrate") == 0) {
        return calibration_should_fail();
    }

    exercise_totp(sha1_secret, sizeof(sha1_secret) - 1U, 1U, "94287082");
    exercise_totp(sha256_secret, sizeof(sha256_secret) - 1U, 2U, "46119246");
    exercise_totp(sha512_secret, sizeof(sha512_secret) - 1U, 3U, "90693936");

    VALGRIND_MAKE_MEM_UNDEFINED(sha1_secret, sizeof(sha1_secret) - 1U);
    accepted = totp_rfc_ctgrind_verify_hotp(
        sha1_secret,
        sizeof(sha1_secret) - 1U,
        (const uint8_t *)"755224",
        6U
    );
    VALGRIND_MAKE_MEM_DEFINED((void *)&accepted, sizeof(accepted));
    VALGRIND_MAKE_MEM_DEFINED(sha1_secret, sizeof(sha1_secret) - 1U);

    puts("ctgrind secret-taint paths completed");
    return 0;
}
