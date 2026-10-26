#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "serein_core.h"

static uint8_t *read_array(JNIEnv *env, jbyteArray input, jsize expected, jsize *length) {
    if (input == NULL) return NULL;
    const jsize size = (*env)->GetArrayLength(env, input);
    if (size < 0 || (expected >= 0 && size != expected)) return NULL;
    uint8_t *bytes = (uint8_t *)calloc((size_t)size + 1u, 1u);
    if (bytes == NULL) return NULL;
    if (size > 0) (*env)->GetByteArrayRegion(env, input, 0, size, (jbyte *)bytes);
    if ((*env)->ExceptionCheck(env)) { memset(bytes, 0, (size_t)size + 1u); free(bytes); return NULL; }
    if (length != NULL) *length = size;
    return bytes;
}

static void wipe_bytes(uint8_t *bytes, size_t length) {
    if (bytes != NULL) { volatile uint8_t *p = bytes; for (size_t i = 0; i < length; ++i) p[i] = 0; }
}

static void wipe_free(uint8_t *bytes, size_t length) {
    if (bytes != NULL) { wipe_bytes(bytes, length); free(bytes); }
}

static jbyteArray copy_to_java(JNIEnv *env, const uint8_t *bytes, size_t length) {
    if (length > (size_t)INT32_MAX) return NULL;
    jbyteArray output = (*env)->NewByteArray(env, (jsize)length);
    if (output != NULL && length > 0) (*env)->SetByteArrayRegion(env, output, 0, (jsize)length, (const jbyte *)bytes);
    return output;
}

JNIEXPORT jstring JNICALL
Java_io_serein_chat_SereinCoreNative_nativeVersion(JNIEnv *env, jclass ignored) {
    (void)ignored;
    const uint8_t *version = serein_core_version();
    if (version == NULL) return NULL;
    return (*env)->NewStringUTF(env, (const char *)version);
}

JNIEXPORT jbyteArray JNICALL
Java_io_serein_chat_SereinCoreNative_nativeDeriveChains(JNIEnv *env, jclass ignored, jbyteArray bootstrap, jbyteArray session, jint direction) {
    (void)ignored;
    if (direction < 0 || direction > 1) return NULL;
    uint8_t *secret = read_array(env, bootstrap, 32, NULL), *session_id = read_array(env, session, 16, NULL);
    if (secret == NULL || session_id == NULL) { wipe_free(secret, 32); wipe_free(session_id, 16); return NULL; }
    uint8_t output[64] = {0};
    const int32_t result = serein_core_ratchet_derive_chains(secret, session_id, (uint8_t)direction, output);
    wipe_free(secret, 32); wipe_free(session_id, 16);
    jbyteArray answer = result == 1 ? copy_to_java(env, output, sizeof(output)) : NULL;
    wipe_bytes(output, sizeof(output));
    return answer;
}

JNIEXPORT jlong JNICALL
Java_io_serein_chat_SereinCoreNative_nativeCreateRatchet(JNIEnv *env, jclass ignored, jbyteArray session, jint direction, jbyteArray send_key, jbyteArray receive_key) {
    (void)ignored;
    if (direction < 0 || direction > 1) return 0;
    uint8_t *sid = read_array(env, session, 16, NULL), *send = read_array(env, send_key, 32, NULL), *receive = read_array(env, receive_key, 32, NULL);
    if (sid == NULL || send == NULL || receive == NULL) { wipe_free(sid, 16); wipe_free(send, 32); wipe_free(receive, 32); return 0; }
    SereinRatchet *handle = serein_core_ratchet_new(sid, (uint8_t)direction, send, receive);
    wipe_free(sid, 16); wipe_free(send, 32); wipe_free(receive, 32);
    return (jlong)(uintptr_t)handle;
}

JNIEXPORT jlong JNICALL
Java_io_serein_chat_SereinCoreNative_nativeRestoreRatchet(JNIEnv *env, jclass ignored, jbyteArray snapshot) {
    (void)ignored;
    if (snapshot == NULL || (*env)->GetArrayLength(env, snapshot) > 1024 * 1024) return 0;
    jsize length = 0; uint8_t *bytes = read_array(env, snapshot, -1, &length);
    if (bytes == NULL || length <= 0) { wipe_free(bytes, length > 0 ? (size_t)length : 0u); return 0; }
    SereinRatchet *handle = serein_core_ratchet_restore(bytes, (size_t)length);
    wipe_free(bytes, (size_t)length);
    return (jlong)(uintptr_t)handle;
}

JNIEXPORT jbyteArray JNICALL
Java_io_serein_chat_SereinCoreNative_nativeSnapshotRatchet(JNIEnv *env, jclass ignored, jlong raw_handle) {
    (void)ignored;
    SereinRatchet *handle = (SereinRatchet *)(uintptr_t)raw_handle;
    if (handle == NULL) return NULL;
    const size_t length = serein_core_ratchet_snapshot_len(handle);
    if (length == 0 || length > 1u * 1024u * 1024u) return NULL;
    uint8_t *bytes = (uint8_t *)calloc(length, 1u);
    if (bytes == NULL) return NULL;
    const intptr_t written = serein_core_ratchet_snapshot(handle, bytes, length);
    jbyteArray result = written == (intptr_t)length ? copy_to_java(env, bytes, length) : NULL;
    wipe_free(bytes, length);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_io_serein_chat_SereinCoreNative_nativeEncryptRatchet(JNIEnv *env, jclass ignored, jlong raw_handle, jbyteArray nonce_array, jbyteArray plaintext_array, jbyteArray aad_array) {
    (void)ignored;
    SereinRatchet *handle = (SereinRatchet *)(uintptr_t)raw_handle;
    if (plaintext_array == NULL || aad_array == NULL || (*env)->GetArrayLength(env, plaintext_array) > SEREIN_RATCHET_MAX_PLAINTEXT_BYTES || (*env)->GetArrayLength(env, aad_array) > SEREIN_RATCHET_MAX_AAD_BYTES) return NULL;
    jsize plaintext_len = 0, aad_len = 0;
    uint8_t *nonce = read_array(env, nonce_array, 12, NULL), *plaintext = read_array(env, plaintext_array, -1, &plaintext_len), *aad = read_array(env, aad_array, -1, &aad_len);
    if (handle == NULL || nonce == NULL || plaintext == NULL || aad == NULL || plaintext_len > SEREIN_RATCHET_MAX_PLAINTEXT_BYTES || aad_len > SEREIN_RATCHET_MAX_AAD_BYTES) {
        wipe_free(nonce, 12); wipe_free(plaintext, plaintext_len > 0 ? (size_t)plaintext_len : 0u); wipe_free(aad, aad_len > 0 ? (size_t)aad_len : 0u); return NULL;
    }
    uint8_t header[SEREIN_RATCHET_HEADER_LEN] = {0};
    const size_t cipher_capacity = (size_t)plaintext_len + 16u;
    uint8_t *ciphertext = (uint8_t *)calloc(cipher_capacity, 1u);
    if (ciphertext == NULL) { wipe_free(nonce, 12); wipe_free(plaintext, (size_t)plaintext_len); wipe_free(aad, (size_t)aad_len); return NULL; }
    const intptr_t written = serein_core_ratchet_encrypt(handle, nonce, plaintext, (size_t)plaintext_len, aad, (size_t)aad_len, header, sizeof(header), ciphertext, cipher_capacity);
    jbyteArray result = NULL;
    if (written >= 16 && (size_t)written <= cipher_capacity) {
        const size_t total = sizeof(header) + (size_t)written;
        uint8_t *envelope = (uint8_t *)calloc(total, 1u);
        if (envelope != NULL) { memcpy(envelope, header, sizeof(header)); memcpy(envelope + sizeof(header), ciphertext, (size_t)written); result = copy_to_java(env, envelope, total); wipe_free(envelope, total); }
    }
    wipe_free(nonce, 12); wipe_free(plaintext, (size_t)plaintext_len); wipe_free(aad, (size_t)aad_len); wipe_free(ciphertext, cipher_capacity); wipe_bytes(header, sizeof(header));
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_io_serein_chat_SereinCoreNative_nativeDecryptRatchet(JNIEnv *env, jclass ignored, jlong raw_handle, jbyteArray header_array, jbyteArray nonce_array, jbyteArray ciphertext_array, jbyteArray aad_array) {
    (void)ignored;
    SereinRatchet *handle = (SereinRatchet *)(uintptr_t)raw_handle;
    if (ciphertext_array == NULL || aad_array == NULL || (*env)->GetArrayLength(env, ciphertext_array) > SEREIN_RATCHET_MAX_PLAINTEXT_BYTES + 16 || (*env)->GetArrayLength(env, aad_array) > SEREIN_RATCHET_MAX_AAD_BYTES) return NULL;
    jsize cipher_len = 0, aad_len = 0;
    uint8_t *header = read_array(env, header_array, SEREIN_RATCHET_HEADER_LEN, NULL), *nonce = read_array(env, nonce_array, 12, NULL), *ciphertext = read_array(env, ciphertext_array, -1, &cipher_len), *aad = read_array(env, aad_array, -1, &aad_len);
    if (handle == NULL || header == NULL || nonce == NULL || ciphertext == NULL || aad == NULL || cipher_len < 16 || cipher_len > SEREIN_RATCHET_MAX_PLAINTEXT_BYTES + 16 || aad_len > SEREIN_RATCHET_MAX_AAD_BYTES) {
        wipe_free(header, SEREIN_RATCHET_HEADER_LEN); wipe_free(nonce, 12); wipe_free(ciphertext, cipher_len > 0 ? (size_t)cipher_len : 0u); wipe_free(aad, aad_len > 0 ? (size_t)aad_len : 0u); return NULL;
    }
    const size_t capacity = (size_t)cipher_len - 16u;
    uint8_t *plaintext = (uint8_t *)calloc(capacity + 1u, 1u);
    if (plaintext == NULL) { wipe_free(header, SEREIN_RATCHET_HEADER_LEN); wipe_free(nonce, 12); wipe_free(ciphertext, (size_t)cipher_len); wipe_free(aad, (size_t)aad_len); return NULL; }
    const intptr_t written = serein_core_ratchet_decrypt(handle, header, nonce, ciphertext, (size_t)cipher_len, aad, (size_t)aad_len, plaintext, capacity);
    jbyteArray result = written >= 0 && (size_t)written <= capacity ? copy_to_java(env, plaintext, (size_t)written) : NULL;
    wipe_free(header, SEREIN_RATCHET_HEADER_LEN); wipe_free(nonce, 12); wipe_free(ciphertext, (size_t)cipher_len); wipe_free(aad, (size_t)aad_len); wipe_free(plaintext, capacity + 1u);
    return result;
}

JNIEXPORT void JNICALL
Java_io_serein_chat_SereinCoreNative_nativeFreeRatchet(JNIEnv *env, jclass ignored, jlong raw_handle) {
    (void)env; (void)ignored;
    SereinRatchet *handle = (SereinRatchet *)(uintptr_t)raw_handle;
    if (handle != NULL) serein_core_ratchet_free(handle);
}
