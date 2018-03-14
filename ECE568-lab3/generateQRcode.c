#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/encoding.h"
#define MAX_AUTH_LEN 512

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
    for (size_t i = 0; i < 20; i += 2) {
        result[i / 2] = char_to_int(input[i]) * 16 + char_to_int(input[i + 1]);
    }
}

void genQRcode(const char* encoded_account, const char* encoded_issuer,
               const char* encoded_secret, const char* protocol) {
    char auth_str[MAX_AUTH_LEN];
    char* protocol_field = "unknown";
    int field_val = 0;
    if (strcmp(protocol, "hotp") == 0) {
        protocol_field = "counter";  // period
        field_val = 1;               // 30
    } else if (strcmp(protocol, "totp") == 0) {
        protocol_field = "period";
        field_val = 30;
    } else {
        printf("Bad protocol!\n");
        exit(1);
    }

    snprintf(auth_str, MAX_AUTH_LEN,
             "otpauth://%s/%s?issuer=%s&secret=%s&%s=%d", protocol,
             encoded_account, encoded_issuer, encoded_secret, protocol_field,
             field_val);

    printf("auth string: %s\n", auth_str);
    displayQRcode(auth_str);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
        return (-1);
    }

    char* issuer = argv[1];
    char* accountName = argv[2];
    char* secret_hex = argv[3];

    assert(strlen(secret_hex) <= 20);

    printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n", issuer,
           accountName, secret_hex);

    // Create an otpauth:// URI and display a QR code that's compatible
    // with Google Authenticator
    const char* encoded_issuer = urlEncode(issuer);
    const char* encoded_account = urlEncode(accountName);

    uint8_t secret[10];
    parse_hex(secret_hex, secret);
    char encoded_secret[20];
    base32_encode(secret, 10, (uint8_t*)encoded_secret, 16);

    genQRcode(encoded_account, encoded_issuer, encoded_secret, "hotp");
    genQRcode(encoded_account, encoded_issuer, encoded_secret, "totp");
    return (0);
}
