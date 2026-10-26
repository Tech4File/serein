package io.serein.chat;

/** JNI bridge for the shared Rust symmetric ratchet. Snapshot bytes contain secrets and must be AEAD-encrypted before persistence. */
final class SereinCoreNative {
    private static final boolean LOADED;
    static {
        boolean loaded;
        try { System.loadLibrary("serein_core_jni"); loaded = true; }
        catch (UnsatisfiedLinkError error) { loaded = false; }
        LOADED = loaded;
    }
    private SereinCoreNative() { }
    static boolean isLoaded() { return LOADED; }
    static String version() {
        requireLoaded();
        return nativeVersion();
    }
    static byte[] deriveChains(byte[] bootstrapSecret, byte[] sessionId, int initiatorDirection) {
        requireLoaded();
        byte[] result = nativeDeriveChains(bootstrapSecret, sessionId, initiatorDirection);
        if (result == null || result.length != 64) throw new IllegalStateException("Shared ratchet chain derivation failed.");
        return result;
    }
    static RatchetHandle createRatchet(byte[] sessionId, int sendDirection, byte[] sendChainKey, byte[] receiveChainKey) {
        requireLoaded();
        long handle = nativeCreateRatchet(sessionId, sendDirection, sendChainKey, receiveChainKey);
        if (handle == 0) throw new IllegalArgumentException("Shared ratchet state could not be created.");
        return new RatchetHandle(handle);
    }
    static RatchetHandle restoreRatchet(byte[] locallyDecryptedSnapshot) {
        requireLoaded();
        long handle = nativeRestoreRatchet(locallyDecryptedSnapshot);
        if (handle == 0) throw new IllegalArgumentException("Shared ratchet snapshot could not be restored.");
        return new RatchetHandle(handle);
    }
    private static void requireLoaded() {
        if (!LOADED) throw new IllegalStateException("The shared Rust core native library is unavailable.");
    }

    static final class RatchetHandle implements AutoCloseable {
        private long handle;
        private RatchetHandle(long value) { handle = value; }
        private void requireOpen() { if (handle == 0) throw new IllegalStateException("Ratchet handle is closed."); }
        synchronized byte[] snapshot() {
            requireOpen();
            byte[] result = nativeSnapshotRatchet(handle);
            if (result == null) throw new IllegalStateException("Ratchet snapshot failed.");
            return result;
        }
        /** Returns fixed 22-byte header followed by AES-GCM ciphertext; nonce is supplied separately by the caller. */
        synchronized byte[] encrypt(byte[] nonce, byte[] plaintext, byte[] aad) {
            requireOpen();
            byte[] result = nativeEncryptRatchet(handle, nonce, plaintext, aad);
            if (result == null || result.length < 22 + 16) throw new IllegalArgumentException("Ratchet encryption failed.");
            return result;
        }
        synchronized byte[] decrypt(byte[] header, byte[] nonce, byte[] ciphertext, byte[] aad) {
            requireOpen();
            byte[] result = nativeDecryptRatchet(handle, header, nonce, ciphertext, aad);
            if (result == null) throw new IllegalArgumentException("Ratchet authentication or ordering failed.");
            return result;
        }
        @Override public synchronized void close() {
            if (handle != 0) { nativeFreeRatchet(handle); handle = 0; }
        }
    }

    private static native String nativeVersion();
    private static native byte[] nativeDeriveChains(byte[] bootstrapSecret, byte[] sessionId, int initiatorDirection);
    private static native long nativeCreateRatchet(byte[] sessionId, int sendDirection, byte[] sendChainKey, byte[] receiveChainKey);
    private static native long nativeRestoreRatchet(byte[] snapshot);
    private static native byte[] nativeSnapshotRatchet(long handle);
    private static native byte[] nativeEncryptRatchet(long handle, byte[] nonce, byte[] plaintext, byte[] aad);
    private static native byte[] nativeDecryptRatchet(long handle, byte[] header, byte[] nonce, byte[] ciphertext, byte[] aad);
    private static native void nativeFreeRatchet(long handle);
}
