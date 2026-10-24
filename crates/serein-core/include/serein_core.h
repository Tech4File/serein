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
