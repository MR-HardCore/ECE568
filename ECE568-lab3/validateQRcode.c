#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "lib/sha1.h"

#define SECRET_LEN 20
// Number of digits in the otp
#define CODE_DIGIT 6
#define TIME_STEP 30

int char_to_int(char c) {
    if (c >= 48 && c <= 57) {  // 0 to 9
        return c - 48;
    } else if (c >= 65 && c <= 70) {  // A to F
        return c - 65 + 10;
    } else if (c >= 97 && c <= 102) {  // a to f
        return c - 97 + 10;
    } else {
        return -1;
    }
}

void parse_hex(const char* input, uint8_t* result) {
    assert(strlen(input) == 20);
	int i;
    for (i = 0; i < 20; i += 2) {
        result[i / 2] = char_to_int(input[i]) * 16 + char_to_int(input[i + 1]);
    }
}

// 1 for HOTP
// else for TOTP
static int validateGeneral(char* secret_hex, char* OTP_string, int protocol) {
    uint8_t encoded_secret[10];
    parse_hex(secret_hex, encoded_secret);

    SHA1_INFO ctx;
    uint8_t inner_sha[SHA1_DIGEST_LENGTH];
    uint8_t outer_sha[SHA1_DIGEST_LENGTH];

    unsigned char k_ipad[65];
    unsigned char k_opad[65];
    memset(k_ipad, sizeof(k_ipad), 0);
    memset(k_opad, sizeof(k_opad), 0);
    memcpy(k_ipad, encoded_secret, 10);
    memcpy(k_opad, encoded_secret, 10);
	int i;
    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    uint8_t text[8];
    uint64_t counter;
    if (protocol == 1) {
        counter = 1;
    } else {
        counter = (time(NULL)) / TIME_STEP;
    }

    for (i = 7; i >= 0; i--) {
		text[i] = (uint8_t)(counter & 0xff);
		counter >>= 8;
    }

    sha1_init(&ctx);
    sha1_update(&ctx, k_ipad, 64);
    sha1_update(&ctx, text, 8);
    sha1_final(&ctx, inner_sha);
    sha1_init(&ctx);
    sha1_update(&ctx, k_opad, 64);
    sha1_update(&ctx, inner_sha, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, outer_sha);

    int offset = outer_sha[SHA1_DIGEST_LENGTH - 1] & 0xf;
    int binary = ((outer_sha[offset] & 0x7f) << 24) |
                 ((outer_sha[offset + 1] & 0xff) << 16) |
                 ((outer_sha[offset + 2] & 0xff) << 8) |
                 (outer_sha[offset + 3] & 0xff);
    int otp = binary % (int)pow(10, CODE_DIGIT);
    printf("otp is %d\n", otp);
    return otp == atoi(OTP_string);
}

static int validateHOTP(char* secret_hex, char* HOTP_string) {
    return validateGeneral(secret_hex, HOTP_string, 1);
}

static int validateTOTP(char* secret_hex, char* TOTP_string) {
    return validateGeneral(secret_hex, TOTP_string, 0);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
        return (-1);
    }

    char* secret_hex = argv[1];
    char* HOTP_value = argv[2];
    char* TOTP_value = argv[3];

    assert(strlen(secret_hex) <= 20);
    assert(strlen(HOTP_value) == 6);
    assert(strlen(TOTP_value) == 6);

    printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
           secret_hex, HOTP_value,
           validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
           TOTP_value,
           validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

    return (0);
}
