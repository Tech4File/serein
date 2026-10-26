package io.serein.chat;

import android.util.Base64;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/** Two independent shared-core symmetric chains. Session bootstrap uses static P-256 ECDH and is experimental. */
final class SereinRatchetSession implements AutoCloseable {
    private static final int HEADER = 22, MAX_PLAINTEXT = 32_710, MAX_CIPHERTEXT = MAX_PLAINTEXT + 16, MAX_OUTER_CIPHERTEXT = MAX_PLAINTEXT + 74;
    private static final byte[] MAGIC = new byte[]{0x53, 0x52, 0x4c, 0x31};
    private final SereinCoreNative.RatchetHandle layer1, layer2;
    private final String layer1Name, layer2Name;

    private SereinRatchetSession(SereinCoreNative.RatchetHandle layer1,SereinCoreNative.RatchetHandle layer2,String name1,String name2){
        this.layer1=layer1;this.layer2=layer2;this.layer1Name=name1;this.layer2Name=name2;
    }

    static SereinRatchetSession open(SereinLocalStore local, java.security.PrivateKey layer1Private,java.security.PrivateKey layer2Private,
                                     String localUser,String localDevice,String ownFingerprint,
                                     SereinChatEngine.Peer peer) throws Exception {
        if (!SereinCoreNative.isLoaded()) throw new IllegalStateException("The shared Rust ratchet core is unavailable.");
        String name1=stateName("layer1",localUser,localDevice,peer.userId,peer.deviceId,ownFingerprint,peer.fingerprint);
        String name2=stateName("layer2",localUser,localDevice,peer.userId,peer.deviceId,ownFingerprint,peer.fingerprint);
        byte[] saved1=local.ratchetSnapshot(name1),saved2=local.ratchetSnapshot(name2);
        try {
            if ((saved1==null)!=(saved2==null)) throw new IllegalStateException("Only one layer of the saved ratchet state exists; refusing to reset it.");
            if(saved1!=null){SereinCoreNative.RatchetHandle first=SereinCoreNative.restoreRatchet(saved1);try{return new SereinRatchetSession(first,SereinCoreNative.restoreRatchet(saved2),name1,name2);}catch(Exception error){first.close();throw error;}}
            SereinCoreNative.RatchetHandle first=null,second=null;
            try {
                first=createLayer(layer1Private,localUser,localDevice,peer.userId,peer.deviceId,peer.fingerprint,ownFingerprint,peer.publicJwk,"layer1");
                second=createLayer(layer2Private,localUser,localDevice,peer.userId,peer.deviceId,peer.fingerprint,ownFingerprint,peer.layer2PublicJwk,"layer2");
                return new SereinRatchetSession(first,second,name1,name2);
            } catch(Exception error){if(first!=null)first.close();if(second!=null)second.close();throw error;}
        } finally { if(saved1!=null)Arrays.fill(saved1,(byte)0);if(saved2!=null)Arrays.fill(saved2,(byte)0); }
    }

    private static SereinCoreNative.RatchetHandle createLayer(java.security.PrivateKey privateKey,String localUser,String localDevice,
            String peerUser,String peerDevice,String peerFingerprint,String ownFingerprint,JSONObject peerJwk,String purpose) throws Exception {
        byte[] bootstrap=SereinDeviceCrypto.ratchetBootstrapSecret(privateKey,localUser,localDevice,peerUser,peerDevice,peerJwk,purpose);
        byte[] session=sessionId(localUser,localDevice,ownFingerprint,peerUser,peerDevice,peerFingerprint,purpose);
        byte[] chains=null;
        try {
            chains=SereinCoreNative.deriveChains(bootstrap,session,0);
            int direction=(localUser+":"+localDevice).compareTo(peerUser+":"+peerDevice)<0?0:1;
            byte[] send=Arrays.copyOfRange(chains,direction==0?0:32,direction==0?32:64);
            byte[] receive=Arrays.copyOfRange(chains,direction==0?32:0,direction==0?64:32);
            try{return SereinCoreNative.createRatchet(session,direction,send,receive);}
            finally{Arrays.fill(send,(byte)0);Arrays.fill(receive,(byte)0);}
        } finally {Arrays.fill(bootstrap,(byte)0);Arrays.fill(session,(byte)0);if(chains!=null)Arrays.fill(chains,(byte)0);}
    }

    private static byte[] sessionId(String userA,String deviceA,String fingerprintA,String userB,String deviceB,String fingerprintB,String purpose) throws Exception {
        String[] parties={userA+":"+deviceA+":"+fingerprintA,userB+":"+deviceB+":"+fingerprintB};Arrays.sort(parties);
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(("Serein/"+purpose+"/live-ratchet-session/v1|"+parties[0]+"|"+parties[1]).getBytes(StandardCharsets.UTF_8));
        byte[] id=Arrays.copyOf(digest,16);if(allZero(id))id[15]=1;Arrays.fill(digest,(byte)0);return id;
    }
    private static boolean allZero(byte[] data){int value=0;for(byte b:data)value|=b;return value==0;}
    private static String stateName(String layer,String localUser,String localDevice,String peerUser,String peerDevice,String ownFingerprint,String peerFingerprint){
        return "live-ratchet-v1:"+layer+":"+localUser+":"+localDevice+":"+peerUser+":"+peerDevice+":"+ownFingerprint+":"+peerFingerprint;
    }

    JSONObject encrypt(byte[] clear,JSONObject route) throws Exception {
        if(clear==null||clear.length>MAX_PLAINTEXT)throw new IllegalArgumentException("Ratchet plaintext exceeds 32 KiB.");
        byte[] inner=null,packed=null,outer=null,nonce1=SereinDeviceCrypto.randomBytes(12),nonce2=SereinDeviceCrypto.randomBytes(12);
        try {
            inner=layer1.encrypt(nonce1,clear,routeAad(route,"layer1"));
            packed=packInner(inner,nonce1);
            outer=layer2.encrypt(nonce2,packed,routeAad(route,"layer2"));
            byte[] header=Arrays.copyOfRange(outer,0,HEADER),cipher=Arrays.copyOfRange(outer,HEADER,outer.length);
            ByteArrayOutputStream complete=new ByteArrayOutputStream(outer.length);complete.write(header);complete.write(cipher);
            return new JSONObject().put("version",3).put("iv",Base64.encodeToString(nonce2,Base64.NO_WRAP)).put("ciphertext",Base64.encodeToString(complete.toByteArray(),Base64.NO_WRAP));
        } finally {wipe(inner);wipe(packed);wipe(outer);wipe(nonce1);wipe(nonce2);}
    }

    byte[] decrypt(String ivBase64,String ciphertextBase64,JSONObject route) throws Exception {
        if(ivBase64==null||ivBase64.length()>24||!ivBase64.matches("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")||ciphertextBase64==null||ciphertextBase64.length()>43_744||!ciphertextBase64.matches("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"))throw new IllegalArgumentException("Ratchet envelope encoding is invalid.");
        byte[] nonce=Base64.decode(ivBase64,Base64.NO_WRAP),complete=Base64.decode(ciphertextBase64,Base64.NO_WRAP),packed=null,inner=null,header=null,cipher=null;
        try {
            if(nonce.length!=12||complete.length<HEADER+16||complete.length>HEADER+MAX_OUTER_CIPHERTEXT)throw new IllegalArgumentException("Malformed Layer 2 ratchet envelope.");
            header=Arrays.copyOfRange(complete,0,HEADER);cipher=Arrays.copyOfRange(complete,HEADER,complete.length);
            packed=layer2.decrypt(header,nonce,cipher,routeAad(route,"layer2"));
            inner=unpackInner(packed);
            byte[] innerHeader=Arrays.copyOfRange(inner,4,4+HEADER),innerNonce=Arrays.copyOfRange(inner,4+HEADER,4+HEADER+12);
            int length=ByteBuffer.wrap(inner,4+HEADER+12,4).order(ByteOrder.BIG_ENDIAN).getInt();
            byte[] innerCipher=Arrays.copyOfRange(inner,4+HEADER+16,4+HEADER+16+length);
            try{return layer1.decrypt(innerHeader,innerNonce,innerCipher,routeAad(route,"layer1"));}
            finally{wipe(innerHeader);wipe(innerNonce);wipe(innerCipher);}
        } finally {wipe(nonce);wipe(complete);wipe(packed);wipe(inner);wipe(header);wipe(cipher);}
    }

    Map<String,byte[]> snapshots() {
        Map<String,byte[]> result=new HashMap<>();result.put(layer1Name,layer1.snapshot());result.put(layer2Name,layer2.snapshot());return result;
    }
    private static byte[] routeAad(JSONObject route,String layer) throws Exception {
        String[] keys={"conversationId","messageId","senderUserId","senderDeviceId","recipientUserId","recipientDeviceId"};
        JSONArray values=new JSONArray().put("serein-message-v3-"+layer);
        for(String key:keys){String value=route.optString(key,"");if(value.isEmpty()||value.length()>128)throw new IllegalArgumentException("Ratchet routing metadata is incomplete.");values.put(value);}
        return values.toString().getBytes(StandardCharsets.UTF_8);
    }
    private static byte[] packInner(byte[] envelope,byte[] nonce) throws Exception {
        if(envelope==null||envelope.length<HEADER+16||nonce.length!=12)throw new IllegalArgumentException("Invalid inner ratchet envelope.");
        byte[] cipher=Arrays.copyOfRange(envelope,HEADER,envelope.length);ByteBuffer buffer=ByteBuffer.allocate(4+HEADER+12+4+cipher.length).order(ByteOrder.BIG_ENDIAN);
        buffer.put(MAGIC).put(envelope,0,HEADER).put(nonce).putInt(cipher.length).put(cipher);wipe(cipher);return buffer.array();
    }
    private static byte[] unpackInner(byte[] packed) {
        if(packed==null||packed.length<4+HEADER+12+4+16||packed.length>4+HEADER+12+4+MAX_CIPHERTEXT)throw new IllegalArgumentException("Nested Layer 1 ratchet envelope is malformed.");
        for(int i=0;i<MAGIC.length;i++)if(packed[i]!=MAGIC[i])throw new IllegalArgumentException("Nested Layer 1 ratchet envelope has a bad magic value.");
        int length=ByteBuffer.wrap(packed,4+HEADER+12,4).order(ByteOrder.BIG_ENDIAN).getInt();
        if(length<16||length>MAX_CIPHERTEXT||packed.length!=4+HEADER+12+4+length)throw new IllegalArgumentException("Nested Layer 1 ratchet ciphertext length is invalid.");
        return packed.clone();
    }
    private static void wipe(byte[] bytes){if(bytes!=null)Arrays.fill(bytes,(byte)0);}
    @Override public void close(){layer1.close();layer2.close();}
}
