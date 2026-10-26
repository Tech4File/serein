#!/usr/bin/env bash
# Host C ABI link/runtime smoke for the Rust static library and ratchet handles.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cat "$ROOT/VERSION")"
cargo build --manifest-path "$ROOT/crates/serein-core/Cargo.toml" --locked --release
ARCHIVE="$ROOT/target/release/libserein_core.a"
[[ -s "$ARCHIVE" ]] || { echo "Rust static library is missing: $ARCHIVE" >&2; exit 2; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/ffi-smoke.c" <<'C'
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "serein_core.h"

int main(int argc, char **argv) {
    if (argc != 2 || strcmp((const char *)serein_core_version(), argv[1]) != 0) return 10;
    const uint8_t username[] = "serein_user";
    if (serein_core_validate_username(username, sizeof(username) - 1) != 1) return 11;
    const uint8_t bootstrap[32] = {1};
    const uint8_t session[16] = {2};
    uint8_t chains[64] = {0};
    if (serein_core_ratchet_derive_chains(bootstrap, session, 0, chains) != 1) return 12;
    SereinRatchet *alice = serein_core_ratchet_new(session, 0, chains, chains + 32);
    SereinRatchet *bob = serein_core_ratchet_new(session, 1, chains + 32, chains);
    if (alice == NULL || bob == NULL) return 13;
    const uint8_t nonce[12] = {3};
    const uint8_t plaintext[] = "linked C ABI ratchet";
    const uint8_t aad[] = "session smoke";
    uint8_t header[SEREIN_RATCHET_HEADER_LEN] = {0};
    uint8_t ciphertext[sizeof(plaintext) + 16] = {0};
    uint8_t opened[sizeof(plaintext)] = {0};
    intptr_t sealed = serein_core_ratchet_encrypt(alice, nonce, plaintext, sizeof(plaintext) - 1,
        aad, sizeof(aad) - 1, header, sizeof(header), ciphertext, sizeof(ciphertext));
    if (sealed != (intptr_t)(sizeof(plaintext) - 1 + 16)) return 14;
    intptr_t clear_len = serein_core_ratchet_decrypt(bob, header, nonce, ciphertext, (size_t)sealed,
        aad, sizeof(aad) - 1, opened, sizeof(opened));
    if (clear_len != (intptr_t)(sizeof(plaintext) - 1) || memcmp(opened, plaintext, (size_t)clear_len) != 0) return 15;
    serein_core_ratchet_free(alice);
    serein_core_ratchet_free(bob);
    puts("Rust static C ABI smoke passed.");
    return 0;
}
C
cc -std=c11 -Wall -Wextra -Werror -I"$ROOT/crates/serein-core/include" "$TMP/ffi-smoke.c" "$ARCHIVE" -ldl -lpthread -lm -o "$TMP/ffi-smoke"
"$TMP/ffi-smoke" "$VERSION"
