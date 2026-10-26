package io.serein.chat;

import android.test.AndroidTestCase;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/** Confirms the app packages the shared Rust core and exercises the JNI ratchet bridge. */
public final class SereinCoreLinkTest extends AndroidTestCase {
    public void testRustCoreLoadsAndMatchesApplicationVersion() {
        assertTrue("Rust JNI library must load in the packaged app", SereinCoreNative.isLoaded());
        assertEquals(BuildConfig.VERSION_NAME, SereinCoreNative.version());
    }

    public void testRatchetJniRoundTripAndSnapshotRestore() {
        byte[] bootstrap = new byte[32], session = new byte[16];
        new SecureRandom().nextBytes(bootstrap);
        new SecureRandom().nextBytes(session);
        byte[] chains = SereinCoreNative.deriveChains(bootstrap, session, 0);
        byte[] initiatorToResponder = Arrays.copyOfRange(chains, 0, 32);
        byte[] responderToInitiator = Arrays.copyOfRange(chains, 32, 64);
        byte[] nonce = new byte[12]; new SecureRandom().nextBytes(nonce);
        byte[] aad = "sender=a;recipient=b".getBytes(StandardCharsets.UTF_8);
        byte[] clear = "JNI uses the shared Rust ratchet".getBytes(StandardCharsets.UTF_8);
        try (SereinCoreNative.RatchetHandle alice = SereinCoreNative.createRatchet(session, 0, initiatorToResponder, responderToInitiator);
             SereinCoreNative.RatchetHandle bob = SereinCoreNative.createRatchet(session, 1, responderToInitiator, initiatorToResponder)) {
            byte[] envelope = alice.encrypt(nonce, clear, aad);
            byte[] opened = bob.decrypt(Arrays.copyOfRange(envelope, 0, 22), nonce,
                    Arrays.copyOfRange(envelope, 22, envelope.length), aad);
            assertEquals(new String(clear, StandardCharsets.UTF_8), new String(opened, StandardCharsets.UTF_8));
            byte[] snapshot = bob.snapshot();
            try (SereinCoreNative.RatchetHandle restored = SereinCoreNative.restoreRatchet(snapshot)) {
                assertTrue(restored.snapshot().length > 0);
            } finally { Arrays.fill(snapshot, (byte) 0); }
        } finally {
            Arrays.fill(bootstrap, (byte) 0); Arrays.fill(chains, (byte) 0);
            Arrays.fill(initiatorToResponder, (byte) 0); Arrays.fill(responderToInitiator, (byte) 0);
        }
    }
}
