// Base32, urlEncode and QR-code implementations
//
// Derived from work:
// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Modifications are Copyright 2016 by Courtney Gibson <gibson@eecg.utoronto.ca>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Encode and decode from base32 encoding using the following alphabet:
//   ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
// This alphabet is documented in RFC 4668/3548
//
// We allow white-space and hyphens, but all other characters are considered
// invalid.
//
// All functions return the number of output bytes or -1 on error. If the
// output buffer is too small, the result will silently be truncated.

#ifndef _ENCODING_H_
#define _ENCODING_H_

#include <stdint.h>

int base32_decode(const uint8_t *encoded, uint8_t *result, int bufSize)
    __attribute__((visibility("hidden")));
int base32_encode(const uint8_t *data, int length, uint8_t *result,
                  int bufSize)
    __attribute__((visibility("hidden")));

const char * urlEncode(const char * s);

void displayQRcode(const char * URI);

#endif /* _ENCODING_H_ */
