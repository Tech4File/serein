package io.serein.chat;

import android.test.AndroidTestCase;
import android.util.Base64;
import org.json.JSONObject;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.AEADBadTagException;

/** Device-side regression checks for untrusted P-256 keys and authenticated JSON decoding. */
public final class SereinDeviceCryptoTest extends AndroidTestCase {
    public void testValidP256GeneratorPointIsAccepted() throws Exception {
        JSONObject generator = new JSONObject()
                .put("kty", "EC")
                .put("crv", "P-256")
                .put("x", "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY")
                .put("y", "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU");
        assertNotNull(SereinDeviceCrypto.publicKey(generator));
    }

    public void testOffCurveP256PointIsRejectedBeforeAgreement() throws Exception {
        String zero = SereinDeviceCrypto.base64Url(new byte[32]);
        JSONObject invalid = new JSONObject()
                .put("kty", "EC")
                .put("crv", "P-256")
                .put("x", zero)
                .put("y", zero);
        try {
            SereinDeviceCrypto.publicKey(invalid);
            fail("Off-curve public point must be rejected.");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("not on the curve"));
        }
    }

    public void testNativeEcdhAndNestedAesGcmRoundTripRejectsTampering() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair alice = generator.generateKeyPair();
        KeyPair bob = generator.generateKeyPair();
        JSONObject alicePublic = SereinDeviceCrypto.publicJwk(alice);
        JSONObject bobPublic = SereinDeviceCrypto.publicJwk(bob);
        byte[] aliceLayer1 = SereinDeviceCrypto.conversationKey(alice.getPrivate(), "alice", "alice-device", "bob", "bob-device", bobPublic);
        byte[] bobLayer1 = SereinDeviceCrypto.conversationKey(bob.getPrivate(), "bob", "bob-device", "alice", "alice-device", alicePublic);
        byte[] aliceLayer2 = SereinDeviceCrypto.layer2ConversationKey(alice.getPrivate(), "alice", "alice-device", "bob", "bob-device", bobPublic);
        byte[] bobLayer2 = SereinDeviceCrypto.layer2ConversationKey(bob.getPrivate(), "bob", "bob-device", "alice", "alice-device", alicePublic);
        assertEquals(SereinDeviceCrypto.hex(aliceLayer1), SereinDeviceCrypto.hex(bobLayer1));
        assertEquals(SereinDeviceCrypto.hex(aliceLayer2), SereinDeviceCrypto.hex(bobLayer2));

        JSONObject content = new JSONObject().put("version", 1).put("text", "authenticated Android round trip");
        JSONObject envelope = SereinDeviceCrypto.encryptLayeredMessage(aliceLayer1, aliceLayer2, content,
                "conversation-id", "message-id", "alice", "alice-device", "bob", "bob-device");
        JSONObject opened = SereinDeviceCrypto.decryptLayeredMessage(bobLayer1, bobLayer2, 2,
                envelope.getString("iv"), envelope.getString("ciphertext"), "conversation-id", "message-id",
                "alice", "alice-device", "bob", "bob-device");
        assertEquals(content.getString("text"), opened.getString("text"));

        byte[] tampered = Base64.decode(envelope.getString("ciphertext"), Base64.DEFAULT);
        tampered[0] ^= 1;
        try {
            SereinDeviceCrypto.decryptLayeredMessage(bobLayer1, bobLayer2, 2, envelope.getString("iv"),
                    Base64.encodeToString(tampered, Base64.NO_WRAP), "conversation-id", "message-id",
                    "alice", "alice-device", "bob", "bob-device");
            fail("Tampered AES-GCM ciphertext must not be accepted.");
        } catch (AEADBadTagException expected) {
            assertNotNull(expected);
        }
    }

    public void testLayeredTransferChunkMatchesSharedVector() throws Exception {
        byte[] key1=fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] key2=fromHex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        byte[] prefix1=fromHex("00010203"),prefix2=fromHex("04050607");
        String transfer="00000000-0000-4000-8000-000000000001",sender="00000000-0000-4000-8000-000000000002";
        String device="00000000-0000-4000-8000-000000000003",recipient="00000000-0000-4000-8000-000000000004";
        byte[] clear="Serein dual-layer file chunk vector".getBytes(StandardCharsets.UTF_8);
        byte[] cipher=SereinDeviceCrypto.encryptChunkLayer2(key1,key2,prefix1,prefix2,7,clear,transfer,sender,device,recipient,9);
        assertEquals("66be4a77a33481af29c9ca879b27c37567d959db7f7786cfa2f732ab25172b5773aeb5a63bc6643ddab5f8216c94af231a18e6577241319b00101f696e226bb632e4d9",SereinDeviceCrypto.hex(cipher));
        byte[] opened=SereinDeviceCrypto.decryptChunkLayer2(key1,key2,prefix1,prefix2,7,cipher,transfer,sender,device,recipient,9);
        assertEquals("Serein dual-layer file chunk vector",new String(opened,StandardCharsets.UTF_8));
        try{SereinDeviceCrypto.decryptChunkLayer2(key1,key2,prefix1,prefix2,8,cipher,transfer,sender,device,recipient,9);fail("Chunk index is authenticated.");}catch(AEADBadTagException expected){assertNotNull(expected);}
    }

    private static byte[] fromHex(String value){byte[] out=new byte[value.length()/2];for(int i=0;i<out.length;i++)out[i]=(byte)Integer.parseInt(value.substring(i*2,i*2+2),16);return out;}

    public void testAuthenticatedPayloadMustBeValidUtf8() throws Exception {
        byte[] valid = "{\"text\":\"safe\"}".getBytes(StandardCharsets.UTF_8);
        assertEquals("{\"text\":\"safe\"}", SereinDeviceCrypto.decodeUtf8Strict(valid));
        try {
            SereinDeviceCrypto.decodeUtf8Strict(new byte[] {(byte) 0xC3, 0x28});
            fail("Malformed UTF-8 must not be replacement-decoded.");
        } catch (CharacterCodingException expected) {
            // Expected: authenticated but invalidly encoded JSON is rejected.
        }
    }
}
