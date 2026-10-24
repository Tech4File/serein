package io.serein.chat;

import android.content.Context;
import android.util.Base64;
import org.json.JSONArray;
import org.json.JSONObject;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.AlgorithmParameters;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Built-in JCA implementation of the Serein P-256/HKDF-SHA256/AES-GCM wire protocol. */
final class SereinDeviceCrypto {
    static final int CHUNK_CIPHERTEXT_BYTES = 256 * 1024;
    static final int CHUNK_PLAINTEXT_BYTES = CHUNK_CIPHERTEXT_BYTES - 16;
    static final int MAX_CHUNKS = 512;
    static final long MAX_FILE_CIPHERTEXT_BYTES = 64L * 1024L * 1024L;
    private static final String LOCAL_KEY_PREFIX = "device-key-v1:";
    private static final byte[] FINGERPRINT_PREFIX = "Serein ECDH P-256 public key v1\0".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();
    private SereinDeviceCrypto() {}

    static KeyPair loadOrCreate(Context context, String userId, String deviceId) throws Exception {
        String storeKey = LOCAL_KEY_PREFIX + userId + ":" + deviceId;
        byte[] saved = SereinSecureVault.get(context, storeKey);
        if (saved != null) {
            JSONObject value = new JSONObject(new String(saved, StandardCharsets.UTF_8));
            byte[] pkcs8 = Base64.decode(value.getString("private_pkcs8"), Base64.NO_WRAP);
            PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(pkcs8));
            PublicKey publicKey = publicKey(value.getJSONObject("public_jwk"));
            Arrays.fill(pkcs8, (byte) 0); Arrays.fill(saved, (byte) 0);
            return new KeyPair(publicKey, privateKey);
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
        KeyPair pair = generator.generateKeyPair();
        JSONObject savedPair = new JSONObject().put("private_pkcs8", Base64.encodeToString(pair.getPrivate().getEncoded(), Base64.NO_WRAP))
                .put("public_jwk", publicJwk(pair));
        SereinSecureVault.put(context, storeKey, savedPair.toString().getBytes(StandardCharsets.UTF_8));
        return pair;
    }

    static JSONObject publicJwk(KeyPair pair) throws Exception {
        java.security.interfaces.ECPublicKey key = (java.security.interfaces.ECPublicKey) pair.getPublic();
        return new JSONObject().put("kty", "EC").put("crv", "P-256")
                .put("x", base64Url(fixed32(key.getW().getAffineX())))
                .put("y", base64Url(fixed32(key.getW().getAffineY())));
    }

    static PublicKey publicKey(JSONObject jwk) throws Exception {
        if (!"EC".equals(jwk.optString("kty")) || !"P-256".equals(jwk.optString("crv"))) throw new IllegalArgumentException("Unsupported public device key.");
        byte[] x = decodeBase64Url(jwk.getString("x")), y = decodeBase64Url(jwk.getString("y"));
        if (x.length != 32 || y.length != 32) throw new IllegalArgumentException("Malformed P-256 public key.");
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC"); parameters.init(new ECGenParameterSpec("secp256r1"));
        java.security.spec.ECParameterSpec ec = parameters.getParameterSpec(java.security.spec.ECParameterSpec.class);
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new java.security.spec.ECPoint(new BigInteger(1, x), new BigInteger(1, y)), ec));
    }

    static String fingerprint(JSONObject jwk) throws Exception {
        byte[] x = decodeBase64Url(jwk.getString("x")), y = decodeBase64Url(jwk.getString("y"));
        if (x.length != 32 || y.length != 32) throw new IllegalArgumentException("Malformed P-256 key coordinates.");
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); digest.update(FINGERPRINT_PREFIX); digest.update(x); digest.update(y);
        return hex(digest.digest());
    }

    static byte[] conversationKey(PrivateKey localPrivate, String localUser, String localDevice,
                                 String peerUser, String peerDevice, JSONObject peerJwk) throws Exception {
        PublicKey peerPublic = publicKey(peerJwk);
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH"); agreement.init(localPrivate); agreement.doPhase(peerPublic, true);
        byte[] shared = agreement.generateSecret();
        String[] parties = new String[]{localUser + ":" + localDevice, peerUser + ":" + peerDevice};
        Arrays.sort(parties);
        String pair = parties[0] + "|" + parties[1];
        byte[] salt = MessageDigest.getInstance("SHA-256").digest(("serein-e2ee-salt-v1|" + pair).getBytes(StandardCharsets.UTF_8));
        byte[] info = ("serein-e2ee-conversation-v1|" + pair).getBytes(StandardCharsets.UTF_8);
        byte[] result = hkdf(shared, salt, info, 32);
        Arrays.fill(shared, (byte) 0); Arrays.fill(salt, (byte) 0);
        return result;
    }

    static JSONObject encryptMessage(byte[] key, JSONObject content, String conversationId, String messageId,
                                     String senderUserId, String senderDeviceId, String recipientUserId, String recipientDeviceId) throws Exception {
        JSONArray fields = new JSONArray().put("serein-message-v1").put(conversationId).put(messageId)
                .put(senderUserId).put(senderDeviceId).put(recipientUserId).put(recipientDeviceId);
        byte[] packed = encrypt(key, content.toString().getBytes(StandardCharsets.UTF_8), fields.toString().getBytes(StandardCharsets.UTF_8), null);
        byte[] iv = Arrays.copyOfRange(packed, 0, 12), ciphertext = Arrays.copyOfRange(packed, 12, packed.length);
        Arrays.fill(packed, (byte) 0);
        return new JSONObject().put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
                .put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP));
    }

    static JSONObject decryptMessage(byte[] key, String ivBase64, String ciphertextBase64, String conversationId,
                                     String messageId, String senderUserId, String senderDeviceId,
                                     String recipientUserId, String recipientDeviceId) throws Exception {
        JSONArray fields = new JSONArray().put("serein-message-v1").put(conversationId).put(messageId)
                .put(senderUserId).put(senderDeviceId).put(recipientUserId).put(recipientDeviceId);
        byte[] clear = decrypt(key, Base64.decode(ivBase64, Base64.DEFAULT), Base64.decode(ciphertextBase64, Base64.DEFAULT), fields.toString().getBytes(StandardCharsets.UTF_8));
        try { return new JSONObject(new String(clear, StandardCharsets.UTF_8)); }
        finally { Arrays.fill(clear, (byte) 0); }
    }

    static JSONObject encryptManifest(byte[] conversationKey, JSONObject manifest, String transferId,
                                      String senderUserId, String senderDeviceId, String recipientUserId, String recipientDeviceId) throws Exception {
        JSONArray fields = new JSONArray().put("serein-transfer-manifest-v1").put(transferId).put(senderUserId).put(senderDeviceId).put(recipientUserId).put(recipientDeviceId);
        byte[] iv = new byte[12]; RANDOM.nextBytes(iv);
        byte[] ciphertext = encrypt(conversationKey, manifest.toString().getBytes(StandardCharsets.UTF_8), fields.toString().getBytes(StandardCharsets.UTF_8), iv);
        return new JSONObject().put("iv", Base64.encodeToString(iv, Base64.NO_WRAP)).put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP));
    }

    static JSONObject decryptManifest(byte[] conversationKey, String ivBase64, String ciphertextBase64,
                                      String transferId, String senderUserId, String senderDeviceId,
                                      String recipientUserId, String recipientDeviceId) throws Exception {
        JSONArray fields = new JSONArray().put("serein-transfer-manifest-v1").put(transferId).put(senderUserId).put(senderDeviceId).put(recipientUserId).put(recipientDeviceId);
        byte[] clear = decrypt(conversationKey, Base64.decode(ivBase64, Base64.DEFAULT), Base64.decode(ciphertextBase64, Base64.DEFAULT), fields.toString().getBytes(StandardCharsets.UTF_8));
        try { return new JSONObject(new String(clear, StandardCharsets.UTF_8)); }
        finally { Arrays.fill(clear, (byte) 0); }
    }

    static byte[] encryptChunk(byte[] fileKey, byte[] noncePrefix, int index, byte[] plaintext,
                               String transferId, String senderUserId, String senderDeviceId, String recipientUserId, int count) throws Exception {
        return encrypt(fileKey, plaintext, chunkAad(transferId, senderUserId, senderDeviceId, recipientUserId, index, count), chunkIv(noncePrefix, index));
    }

    static byte[] decryptChunk(byte[] fileKey, byte[] noncePrefix, int index, byte[] ciphertext,
                               String transferId, String senderUserId, String senderDeviceId, String recipientUserId, int count) throws Exception {
        return decrypt(fileKey, chunkIv(noncePrefix, index), ciphertext, chunkAad(transferId, senderUserId, senderDeviceId, recipientUserId, index, count));
    }

    static byte[] chunkIv(byte[] prefix, int index) {
        if (prefix == null || prefix.length != 4 || index < 0) throw new IllegalArgumentException("Invalid chunk nonce.");
        return ByteBuffer.allocate(12).put(prefix).putInt(0).putInt(index).array();
    }

    static String base64Url(byte[] value) { return Base64.encodeToString(value, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING); }
    static byte[] decodeBase64Url(String value) { return Base64.decode(value, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING); }
    static String sha256Hex(byte[] value) throws Exception { return hex(MessageDigest.getInstance("SHA-256").digest(value)); }
    static byte[] randomBytes(int length) { byte[] value = new byte[length]; RANDOM.nextBytes(value); return value; }
    static String hex(byte[] bytes) { StringBuilder out = new StringBuilder(bytes.length * 2); for (byte b : bytes) out.append(String.format(java.util.Locale.ROOT, "%02x", b & 0xff)); return out.toString(); }

    private static byte[] fixed32(BigInteger value) {
        byte[] source = value.toByteArray(), result = new byte[32];
        int copy = Math.min(source.length, 32); System.arraycopy(source, source.length - copy, result, 32 - copy, copy); return result;
    }
    private static byte[] chunkAad(String transferId, String senderUserId, String senderDeviceId, String recipientUserId, int index, int count) {
        if (index < 0 || count < 1 || index >= count) throw new IllegalArgumentException("Invalid transfer chunk position.");
        return new JSONArray().put("serein-transfer-chunk-v1").put(transferId).put(senderUserId).put(senderDeviceId).put(recipientUserId).put(index).put(count).toString().getBytes(StandardCharsets.UTF_8);
    }
    private static byte[] encrypt(byte[] key, byte[] clear, byte[] aad, byte[] suppliedIv) throws Exception {
        if (key == null || key.length != 32) throw new IllegalArgumentException("Invalid AES-256 key.");
        byte[] iv = suppliedIv == null ? randomBytes(12) : suppliedIv;
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv)); cipher.updateAAD(aad);
        byte[] result = cipher.doFinal(clear);
        return suppliedIv == null ? concat(iv, result) : result;
    }
    private static byte[] decrypt(byte[] key, byte[] iv, byte[] cipherBytes, byte[] aad) throws Exception {
        if (key == null || key.length != 32 || iv == null || iv.length != 12 || cipherBytes == null || cipherBytes.length < 16) throw new IllegalArgumentException("Malformed AES-GCM envelope.");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv)); cipher.updateAAD(aad); return cipher.doFinal(cipherBytes);
    }
    private static byte[] hkdf(byte[] inputKey, byte[] salt, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(salt, "HmacSHA256")); byte[] prk = mac.doFinal(inputKey);
        mac.init(new SecretKeySpec(prk, "HmacSHA256")); mac.update(info); mac.update((byte) 1); byte[] result = Arrays.copyOf(mac.doFinal(), length); Arrays.fill(prk, (byte) 0); return result;
    }
    private static byte[] concat(byte[] first, byte[] second) { byte[] out = Arrays.copyOf(first, first.length + second.length); System.arraycopy(second, 0, out, first.length, second.length); return out; }
}
