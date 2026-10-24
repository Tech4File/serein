package io.serein.chat;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Stores the API session cookie encrypted by a non-exportable Android Keystore AES key. */
final class SessionVault {
    private static final String ALIAS = "io.serein.chat.session.v1";
    private static final String PREFS = "serein_session_v1";
    private static final String VALUE = "sealed_session";
    private final Context context;
    SessionVault(Context context) { this.context = context.getApplicationContext(); }

    synchronized void save(String token, String origin) throws Exception {
        if (token == null || token.isEmpty()) { clear(); return; }
        byte[] iv;
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key()); cipher.updateAAD(origin.getBytes(StandardCharsets.UTF_8)); iv = cipher.getIV();
        if (iv == null || iv.length != 12) throw new IllegalStateException("Unexpected Android Keystore IV length.");
        byte[] encrypted = cipher.doFinal(token.getBytes(StandardCharsets.UTF_8));
        ByteBuffer packed = ByteBuffer.allocate(iv.length + encrypted.length).put(iv).put(encrypted);
        prefs().edit().putString("origin", origin).putString(VALUE, Base64.encodeToString(packed.array(), Base64.NO_WRAP)).apply();
    }
    synchronized String load(String origin) {
        String storedOrigin = prefs().getString("origin", null);
        if (storedOrigin == null || !storedOrigin.equals(origin)) return null;
        String encoded = prefs().getString(VALUE, null); if (encoded == null) return null;
        try {
            byte[] packed = Base64.decode(encoded, Base64.NO_WRAP); if (packed.length < 29) { clear(); return null; }
            byte[] iv = new byte[12], ciphertext = new byte[packed.length - 12];
            ByteBuffer.wrap(packed).get(iv).get(ciphertext);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, iv)); cipher.updateAAD(origin.getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (Exception invalidatedOrCorrupt) { clear(); return null; }
    }
    synchronized void clear() { prefs().edit().remove(VALUE).remove("origin").apply(); }
    private SharedPreferences prefs() { return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE); }
    private SecretKey key() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore"); store.load(null);
        if (store.containsAlias(ALIAS)) return (SecretKey) store.getKey(ALIAS, null);
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build());
        return generator.generateKey();
    }
}
