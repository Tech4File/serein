#ifndef SEREIN_CORE_H
#define SEREIN_CORE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum {
    SEREIN_PASSWORD_REQ_LENGTH = 1u << 0,
    SEREIN_PASSWORD_REQ_ASCII_UPPER = 1u << 1,
    SEREIN_PASSWORD_REQ_ASCII_LOWER = 1u << 2,
    SEREIN_PASSWORD_REQ_ASCII_DIGIT = 1u << 3,
    SEREIN_PASSWORD_REQ_UTF8_LIMIT = 1u << 4,
    SEREIN_PASSWORD_REQ_ALL = (1u << 5) - 1,
    SEREIN_MAX_MESSAGE_CHARACTERS = 4000,
    SEREIN_MESSAGE_COUNTER_WARNING_CHARACTERS = 3600
};
uint32_t serein_core_max_message_characters(void);
uint32_t serein_core_message_warning_characters(void);
/* Counts UTF-8 Unicode scalar values; returns UINT32_MAX for invalid input. */
uint32_t serein_core_message_character_count(const uint8_t *data, size_t len);
uint8_t serein_core_registration_password_requirements(const uint8_t *data, size_t len);
uint8_t serein_core_validate_username(const uint8_t *data, size_t len);
uint8_t serein_core_validate_email(const uint8_t *data, size_t len);
uint8_t serein_core_validate_ciphertext(const uint8_t *iv, size_t iv_len, const uint8_t *cipher, size_t cipher_len);
int64_t serein_core_history_page_limit(int64_t requested);
const uint8_t *serein_core_version(void);
uint8_t *serein_core_alloc(size_t len);
void serein_core_dealloc(uint8_t *data, size_t len);

/* Development ratchet foundation: directional symmetric chains + AES-256-GCM.
 * Not a complete Double Ratchet until the DH/key-establishment layer is integrated.
 * Snapshot bytes contain secrets and must be locally AEAD-encrypted before storage. */
#define SEREIN_RATCHET_HEADER_LEN 22
#define SEREIN_RATCHET_MAX_SKIPPED_PER_CHAIN 1000
#define SEREIN_RATCHET_MAX_SKIPPED_PER_SESSION 2000
#define SEREIN_RATCHET_MAX_PLAINTEXT_BYTES 32768
#define SEREIN_RATCHET_MAX_AAD_BYTES 4096
typedef struct SereinRatchet SereinRatchet;
int32_t serein_core_ratchet_derive_chains(const uint8_t bootstrap_secret[32], const uint8_t session_id[16],
                                           uint8_t initiator_direction, uint8_t output[64]);
int32_t serein_core_ratchet_root_step(const uint8_t root_key[32], const uint8_t dh_output[32], uint8_t output[64]);
SereinRatchet *serein_core_ratchet_new(const uint8_t session_id[16], uint8_t send_direction,
                                        const uint8_t send_chain_key[32], const uint8_t receive_chain_key[32]);
SereinRatchet *serein_core_ratchet_restore(const uint8_t *snapshot, size_t snapshot_len);
void serein_core_ratchet_free(SereinRatchet *handle);
size_t serein_core_ratchet_snapshot_len(const SereinRatchet *handle);
intptr_t serein_core_ratchet_snapshot(const SereinRatchet *handle, uint8_t *out, size_t out_capacity);
/* Encrypt returns ciphertext bytes written; decrypt returns plaintext bytes written.
 * Negative results indicate invalid arguments (-1), invalid state/input (-2/-3),
 * session/direction/replay failure (-4), authentication failure (-5), internal
 * counter/KDF failure (-6), or skipped-key bounds (-7). */
intptr_t serein_core_ratchet_encrypt(SereinRatchet *handle, const uint8_t nonce[12],
                                     const uint8_t *plaintext, size_t plaintext_len,
                                     const uint8_t *aad, size_t aad_len,
                                     uint8_t *header_out, size_t header_capacity,
                                     uint8_t *ciphertext_out, size_t ciphertext_capacity);
intptr_t serein_core_ratchet_decrypt(SereinRatchet *handle, const uint8_t *header, const uint8_t nonce[12],
                                     const uint8_t *ciphertext, size_t ciphertext_len,
                                     const uint8_t *aad, size_t aad_len,
                                     uint8_t *plaintext_out, size_t plaintext_capacity);

/* Development X25519 Double Ratchet foundation; session establishment and
 * peer authentication are not provided. Bootstrap secrets and snapshots are
 * sensitive: never persist or transmit them in plaintext. */
#define SEREIN_DOUBLE_RATCHET_HEADER_LEN 58
typedef struct SereinDoubleRatchet SereinDoubleRatchet;
int32_t serein_core_double_ratchet_public_from_private(const uint8_t private_key[32], uint8_t public_key_out[32]);
SereinDoubleRatchet *serein_core_double_ratchet_new_initiator(const uint8_t session_id[16], uint8_t send_direction,
                                                               const uint8_t bootstrap_secret[32],
                                                               const uint8_t local_dh_private[32],
                                                               const uint8_t remote_dh_public[32]);
SereinDoubleRatchet *serein_core_double_ratchet_new_responder(const uint8_t session_id[16], uint8_t send_direction,
                                                               const uint8_t bootstrap_secret[32],
                                                               const uint8_t local_dh_private[32],
                                                               const uint8_t remote_dh_public[32]);
void serein_core_double_ratchet_free(SereinDoubleRatchet *handle);
size_t serein_core_double_ratchet_snapshot_len(const SereinDoubleRatchet *handle);
intptr_t serein_core_double_ratchet_snapshot(const SereinDoubleRatchet *handle, uint8_t *out, size_t out_capacity);
SereinDoubleRatchet *serein_core_double_ratchet_restore(const uint8_t *snapshot, size_t snapshot_len);
/* Encrypt/decrypt return byte count or negative result: -1 invalid pointer/range,
 * -2 invalid state/input, -4 session/direction/replay, -5 authentication,
 * -6 counter/KDF, -7 skipped-key bound. Callers must guarantee unique AES-GCM
 * nonces and provide fresh OS-CSPRNG DH private bytes when needed. */
intptr_t serein_core_double_ratchet_encrypt(SereinDoubleRatchet *handle, const uint8_t nonce[12],
                                             const uint8_t *plaintext, size_t plaintext_len,
                                             const uint8_t *aad, size_t aad_len,
                                             const uint8_t *new_local_dh_private_or_null,
                                             uint8_t *header_out, size_t header_capacity,
                                             uint8_t *ciphertext_out, size_t ciphertext_capacity);
intptr_t serein_core_double_ratchet_decrypt(SereinDoubleRatchet *handle, const uint8_t *header, const uint8_t nonce[12],
                                             const uint8_t *ciphertext, size_t ciphertext_len,
                                             const uint8_t *aad, size_t aad_len,
                                             const uint8_t new_local_dh_private[32],
                                             uint8_t *plaintext_out, size_t plaintext_capacity);

#define SEREIN_PACKET_HEADER_LEN 37
#define SEREIN_MAX_UDP_PACKET_LEN 1232
#define SEREIN_MAX_PACKET_PAYLOAD (SEREIN_MAX_UDP_PACKET_LEN - SEREIN_PACKET_HEADER_LEN)

typedef struct SereinPacketView {
    const uint8_t *sender_id;
    const uint8_t *receiver_id;
    uint8_t payload_type;
    const uint8_t *payload;
    size_t payload_len;
} SereinPacketView;

/* Payload type values: 1=text, 2=audio, 3=video, 4=control.
 * This framing provides no encryption, authentication, replay protection, or reliability.
 * Packet-view pointers borrow packet memory; keep it alive and unchanged while in use.
 * Input/output regions must be valid and non-overlapping where output is mutable. */
uint8_t serein_core_packet_view(const uint8_t *packet, size_t packet_len, SereinPacketView *out_view);
intptr_t serein_core_packet_encode(const uint8_t *sender_id, const uint8_t *receiver_id,
                                   uint8_t payload_type, const uint8_t *payload, size_t payload_len,
                                   uint8_t *output, size_t output_capacity);
#ifdef __cplusplus
}
#endif
#endif
