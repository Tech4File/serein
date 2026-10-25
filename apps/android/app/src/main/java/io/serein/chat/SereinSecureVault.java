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

/** Keystore-backed sealing for device private keys, key trust, and local message history. */
final class SereinSecureVault {
    private static final String ALIAS = "io.serein.chat.local-data.v1";
    private static final String PREFS = "serein_vault_v1";
    private SereinSecureVault() {}

    static synchronized void put(Context context, String name, byte[] cleartext) throws Exception {
        byte[] packed = seal(name, cleartext);
        if (!prefs(context).edit().putString(name, Base64.encodeToString(packed, Base64.NO_WRAP)).commit()) throw new java.io.IOException("Secure Android storage could not be committed.");
    }

    static synchronized byte[] get(Context context, String name) throws Exception {
        String value = prefs(context).getString(name, null);
        return value == null ? null : open(name, Base64.decode(value, Base64.NO_WRAP));
    }

    static synchronized byte[] seal(String name, byte[] cleartext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, key());
        cipher.updateAAD(name.getBytes(StandardCharsets.UTF_8)); byte[] encrypted = cipher.doFinal(cleartext), iv = cipher.getIV();
        if (iv == null || iv.length != 12) throw new IllegalStateException("Unexpected secure-storage nonce.");
        return ByteBuffer.allocate(iv.length + encrypted.length).put(iv).put(encrypted).array();
    }

    static synchronized byte[] open(String name, byte[] packed) throws Exception {
        if (packed == null || packed.length < 28) throw new IllegalStateException("Stored secure data is malformed.");
        byte[] iv = new byte[12], encrypted = new byte[packed.length - 12]; ByteBuffer.wrap(packed).get(iv).get(encrypted);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, iv));
        cipher.updateAAD(name.getBytes(StandardCharsets.UTF_8)); return cipher.doFinal(encrypted);
    }

    static synchronized void remove(Context context, String name) { prefs(context).edit().remove(name).commit(); }
    static synchronized boolean removePrefix(Context context, String prefix) { SharedPreferences values=prefs(context);SharedPreferences.Editor editor=values.edit();for(String key:values.getAll().keySet())if(key.startsWith(prefix))editor.remove(key);return editor.commit(); }
    private static SharedPreferences prefs(Context context) { return context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE); }
    private static SecretKey key() throws Exception {
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
