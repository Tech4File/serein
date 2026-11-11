package io.serein.chat;

import android.content.Context;
import android.util.Base64;
import org.json.JSONArray;
import org.json.JSONObject;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECFieldFp;
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
    static final int CHUNK_PLAINTEXT_BYTES = CHUNK_CIPHERTEXT_BYTES - 32;
    static final int MAX_CHUNKS = 512;
    static final long MAX_FILE_CIPHERTEXT_BYTES = 64L * 1024L * 1024L;
    private static final String LOCAL_KEY_PREFIX = "device-key-v1:";
    private static final byte[] FINGERPRINT_PREFIX = "Serein ECDH P-256 public key v1\0".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();
    private SereinDeviceCrypto() {}

    static boolean deleteForAccount(Context context,String userId){boolean first=SereinSecureVault.removePrefix(context,LOCAL_KEY_PREFIX+userId+":");boolean second=SereinSecureVault.removePrefix(context,"device-layer2-key-v1:"+userId+":");boolean third=SereinSecureVault.removePrefix(context,"device-signing-key-v1:"+userId+":");boolean retired1=SereinSecureVault.removePrefix(context,"device-retired-key-v1:"+userId+":");boolean retired2=SereinSecureVault.removePrefix(context,"device-retired-layer2-key-v1:"+userId+":");return first&&second&&third&&retired1&&retired2;}
    static KeyPair loadOrCreate(Context context, String userId, String deviceId) throws Exception { return loadOrCreate(context, LOCAL_KEY_PREFIX, userId, deviceId); }
    static KeyPair loadOrCreateLayer2(Context context, String userId, String deviceId) throws Exception { return loadOrCreate(context, "device-layer2-key-v1:", userId, deviceId); }
    static KeyPair loadOrCreateSigning(Context context,String userId,String deviceId) throws Exception { return loadOrCreate(context,"device-signing-key-v1:",userId,deviceId); }
    static String signDeviceKeyRotation(KeyPair signing,String userId,String deviceId,String oldFingerprint,String newFingerprint,long timestamp,long epoch) throws Exception {
        byte[] statement=rotationStatement(userId,deviceId,oldFingerprint,newFingerprint,timestamp,epoch);try{java.security.Signature signature=java.security.Signature.getInstance("SHA256withECDSA");signature.initSign(signing.getPrivate(),RANDOM);signature.update(statement);return base64Url(signature.sign());}finally{Arrays.fill(statement,(byte)0);}
    }
    static boolean verifyDeviceKeyRotation(JSONObject signingJwk,String userId,String deviceId,String oldFingerprint,String newFingerprint,long timestamp,long epoch,String proof) {
        byte[] statement=null,encoded=null;try{if(proof==null||proof.length()>256)return false;statement=rotationStatement(userId,deviceId,oldFingerprint,newFingerprint,timestamp,epoch);encoded=decodeBase64Url(proof);java.security.Signature signature=java.security.Signature.getInstance("SHA256withECDSA");signature.initVerify(publicKey(signingJwk));signature.update(statement);return signature.verify(encoded);}catch(Exception invalid){return false;}finally{if(statement!=null)Arrays.fill(statement,(byte)0);if(encoded!=null)Arrays.fill(encoded,(byte)0);}
    }
    private static byte[] rotationStatement(String userId,String deviceId,String oldFingerprint,String newFingerprint,long timestamp,long epoch){if(timestamp<1||epoch<1||!userId.matches("(?i)[0-9a-f-]{36}")||!deviceId.matches("(?i)[0-9a-f-]{36}")||!newFingerprint.matches("[0-9a-f]{64}")||(!oldFingerprint.isEmpty()&&!oldFingerprint.matches("[0-9a-f]{64}")))throw new IllegalArgumentException("Invalid key-continuity statement fields.");return ("SEREIN-DEVICE-KEY-ROTATION-V1\n"+userId.toLowerCase(java.util.Locale.ROOT)+"\n"+deviceId.toLowerCase(java.util.Locale.ROOT)+"\n"+oldFingerprint+"\n"+newFingerprint+"\n"+timestamp+"\n"+epoch+"\n").getBytes(StandardCharsets.UTF_8);}

    private static KeyPair loadOrCreate(Context context, String prefix, String userId, String deviceId) throws Exception {
        String storeKey = prefix + userId + ":" + deviceId;
        byte[] saved = SereinSecureVault.get(context, storeKey);
        if (saved != null) {
            JSONObject value = new JSONObject(decodeUtf8Strict(saved));
            byte[] pkcs8 = Base64.decode(value.getString("private_pkcs8"), Base64.NO_WRAP);
            PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(pkcs8));
            PublicKey publicKey = publicKey(value.getJSONObject("public_jwk"));
            Arrays.fill(pkcs8, (byte) 0); Arrays.fill(saved, (byte) 0);
            return new KeyPair(publicKey, privateKey);
        }
        KeyPair pair = generateKeyPair();persistKeyPair(context,prefix,userId,deviceId,pair);return pair;
    }
    static KeyPair generateKeyPair() throws Exception {KeyPairGenerator generator=KeyPairGenerator.getInstance("EC");generator.initialize(new ECGenParameterSpec("secp256r1"),RANDOM);return generator.generateKeyPair();}
    static void persistKeyPair(Context context,String prefix,String userId,String deviceId,KeyPair pair)throws Exception{String storeKey=prefix+userId+":"+deviceId;JSONObject savedPair=new JSONObject().put("private_pkcs8",Base64.encodeToString(pair.getPrivate().getEncoded(),Base64.NO_WRAP)).put("public_jwk",publicJwk(pair));SereinSecureVault.put(context,storeKey,savedPair.toString().getBytes(StandardCharsets.UTF_8));}

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
        if (!(ec.getCurve().getField() instanceof ECFieldFp)) throw new IllegalStateException("P-256 provider returned a non-prime field.");
        BigInteger xCoordinate = new BigInteger(1, x), yCoordinate = new BigInteger(1, y);
        BigInteger prime = ((ECFieldFp) ec.getCurve().getField()).getP();
        if (xCoordinate.compareTo(prime) >= 0 || yCoordinate.compareTo(prime) >= 0) throw new IllegalArgumentException("P-256 public point is outside the field.");
        BigInteger lhs = yCoordinate.multiply(yCoordinate).mod(prime);
        BigInteger rhs = xCoordinate.multiply(xCoordinate).multiply(xCoordinate)
                .add(ec.getCurve().getA().multiply(xCoordinate)).add(ec.getCurve().getB()).mod(prime);
        if (!lhs.equals(rhs)) throw new IllegalArgumentException("P-256 public point is not on the curve.");
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new java.security.spec.ECPoint(xCoordinate, yCoordinate), ec));
    }

    static String fingerprint(JSONObject jwk) throws Exception {
        byte[] x = decodeBase64Url(jwk.getString("x")), y = decodeBase64Url(jwk.getString("y"));
        if (x.length != 32 || y.length != 32) throw new IllegalArgumentException("Malformed P-256 key coordinates.");
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); digest.update(FINGERPRINT_PREFIX); digest.update(x); digest.update(y);
        return hex(digest.digest());
    }

    static byte[] deriveHistorySyncKey(PrivateKey localPrivate,String accountId,String localDeviceId,String peerDeviceId,JSONObject peerPublic,String mainDeviceId,String childDeviceId,String requestId,int index,int count) throws Exception {
        if((!localDeviceId.equals(mainDeviceId)&&!localDeviceId.equals(childDeviceId))||(!peerDeviceId.equals(mainDeviceId)&&!peerDeviceId.equals(childDeviceId))||localDeviceId.equals(peerDeviceId)||index<0||count<1||index>=count||count>128)throw new IllegalArgumentException("Invalid history-sync device context.");byte[] secret=null,salt=null;try{PublicKey remote=publicKey(peerPublic);KeyAgreement agreement=KeyAgreement.getInstance("ECDH");agreement.init(localPrivate);agreement.doPhase(remote,true);secret=agreement.generateSecret();String[] devices={mainDeviceId.toLowerCase(java.util.Locale.ROOT),childDeviceId.toLowerCase(java.util.Locale.ROOT)};java.util.Arrays.sort(devices);String scope=accountId.toLowerCase(java.util.Locale.ROOT)+"|"+devices[0]+"|"+devices[1];salt=MessageDigest.getInstance("SHA-256").digest(("serein-history-sync-salt-v1|"+scope).getBytes(StandardCharsets.UTF_8));byte[] info=("serein-history-sync-key-v1|"+scope+"|"+requestId.toLowerCase(java.util.Locale.ROOT)+"|"+index+"|"+count).getBytes(StandardCharsets.UTF_8);return hkdf(secret,salt,info,32);}finally{if(secret!=null)Arrays.fill(secret,(byte)0);if(salt!=null)Arrays.fill(salt,(byte)0);}
    }
    static JSONObject encryptHistorySyncBatch(byte[] key,byte[] clear,String accountId,String mainId,String childId,String requestId,int index,int count)throws Exception{if(clear.length>480*1024)throw new IllegalArgumentException("History-sync clear batch exceeds its limit.");byte[] iv=new byte[12];RANDOM.nextBytes(iv);byte[] aad=historySyncAad(accountId,mainId,childId,requestId,index,count);try{byte[] ciphertext=encrypt(key,clear,aad,iv);return new JSONObject().put("version",1).put("algorithm","AES-256-GCM").put("iv",base64Url(iv)).put("ciphertext",base64Url(ciphertext));}finally{Arrays.fill(aad,(byte)0);Arrays.fill(iv,(byte)0);}}
    static byte[] decryptHistorySyncBatch(byte[] key,JSONObject envelope,String accountId,String mainId,String childId,String requestId,int index,int count)throws Exception{if(envelope.optInt("version")!=1||!"AES-256-GCM".equals(envelope.optString("algorithm")))throw new IllegalArgumentException("Unsupported history-sync envelope.");byte[] iv=decodeBase64Url(envelope.optString("iv")),ciphertext=decodeBase64Url(envelope.optString("ciphertext")),aad=historySyncAad(accountId,mainId,childId,requestId,index,count);try{if(iv.length!=12||ciphertext.length<16||ciphertext.length>512*1024)throw new IllegalArgumentException("Malformed history-sync ciphertext.");return decrypt(key,iv,ciphertext,aad);}finally{Arrays.fill(iv,(byte)0);Arrays.fill(ciphertext,(byte)0);Arrays.fill(aad,(byte)0);}}
    private static byte[] historySyncAad(String accountId,String mainId,String childId,String requestId,int index,int count)throws Exception{String uuid="(?i)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";if(accountId==null||mainId==null||childId==null||requestId==null||!accountId.matches(uuid)||!mainId.matches(uuid)||!childId.matches(uuid)||!requestId.matches(uuid)||mainId.equalsIgnoreCase(childId)||index<0||count<1||index>=count||count>128)throw new IllegalArgumentException("Invalid history-sync batch context.");/* Protocol: compact UTF-8 JSON array; fixed ASCII UUIDs and base-10 integers; field order is normative. */return new JSONArray().put("serein-history-sync-batch-v1").put(accountId.toLowerCase(java.util.Locale.ROOT)).put(mainId.toLowerCase(java.util.Locale.ROOT)).put(childId.toLowerCase(java.util.Locale.ROOT)).put(requestId.toLowerCase(java.util.Locale.ROOT)).put(index).put(count).put(1).toString().getBytes(StandardCharsets.UTF_8);}
    static String sha256Hex(byte[] data)throws Exception{byte[] hash=MessageDigest.getInstance("SHA-256").digest(data);StringBuilder out=new StringBuilder();for(byte value:hash)out.append(String.format(java.util.Locale.ROOT,"%02x",value&255));Arrays.fill(hash,(byte)0);return out.toString();}
    static String canonicalJson(Object value)throws Exception{if(value==null||value==JSONObject.NULL)return"null";if(value instanceof JSONObject){JSONObject object=(JSONObject)value;java.util.ArrayList<String> names=new java.util.ArrayList<>();java.util.Iterator<String> keys=object.keys();while(keys.hasNext())names.add(keys.next());java.util.Collections.sort(names);StringBuilder out=new StringBuilder("{");for(int i=0;i<names.size();i++){if(i>0)out.append(',');String name=names.get(i);out.append(JSONObject.quote(name)).append(':').append(canonicalJson(object.get(name)));}return out.append('}').toString();}if(value instanceof JSONArray){JSONArray array=(JSONArray)value;StringBuilder out=new StringBuilder("[");for(int i=0;i<array.length();i++){if(i>0)out.append(',');out.append(canonicalJson(array.get(i)));}return out.append(']').toString();}if(value instanceof String)return JSONObject.quote((String)value);if(value instanceof Number||value instanceof Boolean)return value.toString();throw new IllegalArgumentException("Unsupported history batch JSON value.");}

    static String fingerprintBundle(JSONObject layer1, JSONObject layer2) throws Exception {
        byte[] first = publicCoordinates(layer1), second = publicCoordinates(layer2);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update("Serein ECDH P-256 device key bundle v2\0".getBytes(StandardCharsets.UTF_8));
        digest.update(first); digest.update(second); return hex(digest.digest());
    }
    private static byte[] publicCoordinates(JSONObject jwk) throws Exception {
        if (!"EC".equals(jwk.optString("kty")) || !"P-256".equals(jwk.optString("crv"))) throw new IllegalArgumentException("Unsupported public key.");
        byte[] x=decodeBase64Url(jwk.getString("x")),y=decodeBase64Url(jwk.getString("y"));
        if(x.length!=32||y.length!=32)throw new IllegalArgumentException("Malformed P-256 public key coordinates.");
        return concat(x,y);
    }

    static byte[] conversationKey(PrivateKey localPrivate, String localUser, String localDevice,
                                 String peerUser, String peerDevice, JSONObject peerJwk) throws Exception {
        return deriveDevicePairKey(localPrivate,localUser,localDevice,peerUser,peerDevice,peerJwk,false);
    }
    static byte[] layer2ConversationKey(PrivateKey localPrivate, String localUser, String localDevice,
                                       String peerUser, String peerDevice, JSONObject peerJwk) throws Exception {
        return deriveDevicePairKey(localPrivate,localUser,localDevice,peerUser,peerDevice,peerJwk,true);
    }
    static byte[] ratchetBootstrapSecret(PrivateKey localPrivate,String localUser,String localDevice,
                                         String peerUser,String peerDevice,JSONObject peerJwk,String purpose) throws Exception {
        if (!"layer1".equals(purpose) && !"layer2".equals(purpose)) throw new IllegalArgumentException("Unknown ratchet bootstrap layer.");
        KeyAgreement agreement=KeyAgreement.getInstance("ECDH");agreement.init(localPrivate);agreement.doPhase(publicKey(peerJwk),true);
        byte[] raw=agreement.generateSecret();String[] parties={localUser+":"+localDevice,peerUser+":"+peerDevice};Arrays.sort(parties);
        String pair=parties[0]+"|"+parties[1],saltLabel="Serein/"+purpose+"/symmetric-ratchet-salt/v1|"+pair,info="Serein/"+purpose+"/symmetric-ratchet-bootstrap/v1|"+pair;
        byte[] salt=MessageDigest.getInstance("SHA-256").digest(saltLabel.getBytes(StandardCharsets.UTF_8));
        try{return hkdf(raw,salt,info.getBytes(StandardCharsets.UTF_8),32);}finally{Arrays.fill(raw,(byte)0);Arrays.fill(salt,(byte)0);}
    }

    private static byte[] deriveDevicePairKey(PrivateKey localPrivate,String localUser,String localDevice,
                                              String peerUser,String peerDevice,JSONObject peerJwk,boolean layer2) throws Exception {
        PublicKey peerPublic = publicKey(peerJwk);
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH"); agreement.init(localPrivate); agreement.doPhase(peerPublic, true);
        byte[] shared = agreement.generateSecret();
        String[] parties = new String[]{localUser + ":" + localDevice, peerUser + ":" + peerDevice};
        Arrays.sort(parties);
        String pair = parties[0] + "|" + parties[1];
        String saltLabel=layer2?"serein-e2ee-layer2-salt-v1":"serein-e2ee-salt-v1";
        String infoLabel=layer2?"serein-e2ee-layer2-session-v1":"serein-e2ee-conversation-v1";
        byte[] salt = MessageDigest.getInstance("SHA-256").digest((saltLabel + "|" + pair).getBytes(StandardCharsets.UTF_8));
        byte[] info = (infoLabel + "|" + pair).getBytes(StandardCharsets.UTF_8);
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
        try { return new JSONObject(decodeUtf8Strict(clear)); }
        finally { Arrays.fill(clear, (byte) 0); }
    }

    static JSONObject encryptLayeredMessage(byte[] layer1Key, byte[] layer2Key, JSONObject content, String conversationId, String messageId,
                                            String senderUserId, String senderDeviceId, String recipientUserId, String recipientDeviceId) throws Exception {
        JSONArray innerFields=messageAad("serein-message-layer1-v2",conversationId,messageId,senderUserId,senderDeviceId,recipientUserId,recipientDeviceId);
        byte[] innerPacked=encrypt(layer1Key,content.toString().getBytes(StandardCharsets.UTF_8),innerFields.toString().getBytes(StandardCharsets.UTF_8),null);
        byte[] innerIv=Arrays.copyOfRange(innerPacked,0,12),innerCipher=Arrays.copyOfRange(innerPacked,12,innerPacked.length);Arrays.fill(innerPacked,(byte)0);
        JSONObject inner=new JSONObject().put("version",1).put("algorithm","AES-256-GCM").put("iv",Base64.encodeToString(innerIv,Base64.NO_WRAP)).put("ciphertext",Base64.encodeToString(innerCipher,Base64.NO_WRAP));
        Arrays.fill(innerIv,(byte)0);Arrays.fill(innerCipher,(byte)0);
        JSONArray outerFields=messageAad("serein-message-layer2-v2",conversationId,messageId,senderUserId,senderDeviceId,recipientUserId,recipientDeviceId);
        byte[] outerPacked=encrypt(layer2Key,inner.toString().getBytes(StandardCharsets.UTF_8),outerFields.toString().getBytes(StandardCharsets.UTF_8),null);
        byte[] outerIv=Arrays.copyOfRange(outerPacked,0,12),outerCipher=Arrays.copyOfRange(outerPacked,12,outerPacked.length);Arrays.fill(outerPacked,(byte)0);
        return new JSONObject().put("version",2).put("algorithm","SEREIN-LAYER2-AES-256-GCM").put("iv",Base64.encodeToString(outerIv,Base64.NO_WRAP)).put("ciphertext",Base64.encodeToString(outerCipher,Base64.NO_WRAP));
    }
    static JSONObject decryptLayeredMessage(byte[] layer1Key,byte[] layer2Key,int cryptoVersion,String ivBase64,String ciphertextBase64,String conversationId,
                                            String messageId,String senderUserId,String senderDeviceId,String recipientUserId,String recipientDeviceId) throws Exception {
        if(cryptoVersion==1)return decryptMessage(layer1Key,ivBase64,ciphertextBase64,conversationId,messageId,senderUserId,senderDeviceId,recipientUserId,recipientDeviceId);
        if(cryptoVersion!=2)throw new IllegalArgumentException("Unsupported encrypted-message version.");
        JSONArray outerFields=messageAad("serein-message-layer2-v2",conversationId,messageId,senderUserId,senderDeviceId,recipientUserId,recipientDeviceId);
        byte[] outer=decrypt(layer2Key,Base64.decode(ivBase64,Base64.DEFAULT),Base64.decode(ciphertextBase64,Base64.DEFAULT),outerFields.toString().getBytes(StandardCharsets.UTF_8));
        try {
            JSONObject inner=new JSONObject(decodeUtf8Strict(outer));
            if(inner.optInt("version")!=1||!"AES-256-GCM".equals(inner.optString("algorithm")))throw new IllegalArgumentException("Malformed inner message envelope.");
            JSONArray innerFields=messageAad("serein-message-layer1-v2",conversationId,messageId,senderUserId,senderDeviceId,recipientUserId,recipientDeviceId);
            byte[] clear=decrypt(layer1Key,Base64.decode(inner.getString("iv"),Base64.DEFAULT),Base64.decode(inner.getString("ciphertext"),Base64.DEFAULT),innerFields.toString().getBytes(StandardCharsets.UTF_8));
            try{return new JSONObject(decodeUtf8Strict(clear));}finally{Arrays.fill(clear,(byte)0);}
        } finally { Arrays.fill(outer,(byte)0); }
    }
    private static JSONArray messageAad(String label,String conversationId,String messageId,String senderUserId,String senderDeviceId,String recipientUserId,String recipientDeviceId){
        return new JSONArray().put(label).put(conversationId).put(messageId).put(senderUserId).put(senderDeviceId).put(recipientUserId).put(recipientDeviceId);
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
        try { return new JSONObject(decodeUtf8Strict(clear)); }
        finally { Arrays.fill(clear, (byte) 0); }
    }
    static JSONObject encryptManifestLayer2(byte[] layer2Key,JSONObject innerEnvelope,String transferId,String senderUserId,String senderDeviceId,String recipientUserId,String recipientDeviceId) throws Exception {
        JSONObject normalized=new JSONObject().put("version",1).put("algorithm","AES-256-GCM").put("iv",innerEnvelope.getString("iv")).put("ciphertext",innerEnvelope.getString("ciphertext"));
        byte[] clear=normalized.toString().getBytes(StandardCharsets.UTF_8);if(clear.length>12_000)throw new IllegalArgumentException("Nested transfer manifest exceeds its size limit.");
        JSONArray fields=new JSONArray().put("serein-transfer-manifest-layer2-v1").put(transferId).put(senderUserId).put(senderDeviceId).put(recipientUserId).put(recipientDeviceId);byte[] iv=randomBytes(12),ciphertext=encrypt(layer2Key,clear,fields.toString().getBytes(StandardCharsets.UTF_8),iv);
        try{return new JSONObject().put("version",2).put("algorithm","AES-256-GCM-LAYER2").put("iv",Base64.encodeToString(iv,Base64.NO_WRAP)).put("ciphertext",Base64.encodeToString(ciphertext,Base64.NO_WRAP));}
        finally{Arrays.fill(clear,(byte)0);Arrays.fill(iv,(byte)0);Arrays.fill(ciphertext,(byte)0);}
    }
    static JSONObject decryptManifestLayer2(byte[] layer2Key,String ivBase64,String ciphertextBase64,String transferId,String senderUserId,String senderDeviceId,String recipientUserId,String recipientDeviceId) throws Exception {
        if(ivBase64.length()>24||ciphertextBase64.length()>16_024)throw new IllegalArgumentException("Layer 2 transfer manifest exceeds its safety limit.");
        JSONArray fields=new JSONArray().put("serein-transfer-manifest-layer2-v1").put(transferId).put(senderUserId).put(senderDeviceId).put(recipientUserId).put(recipientDeviceId);
        byte[] clear=decrypt(layer2Key,Base64.decode(ivBase64,Base64.DEFAULT),Base64.decode(ciphertextBase64,Base64.DEFAULT),fields.toString().getBytes(StandardCharsets.UTF_8));
        try{JSONObject inner=new JSONObject(decodeUtf8Strict(clear));if(inner.optInt("version")!=1||!"AES-256-GCM".equals(inner.optString("algorithm")))throw new IllegalArgumentException("Malformed inner transfer manifest envelope.");return inner;}
        finally{Arrays.fill(clear,(byte)0);}
    }

    static byte[] encryptChunk(byte[] fileKey, byte[] noncePrefix, int index, byte[] plaintext,
                               String transferId, String senderUserId, String senderDeviceId, String recipientUserId, int count) throws Exception {
        return encrypt(fileKey, plaintext, chunkAad(transferId, senderUserId, senderDeviceId, recipientUserId, index, count), chunkIv(noncePrefix, index));
    }

    static byte[] decryptChunk(byte[] fileKey, byte[] noncePrefix, int index, byte[] ciphertext,
                               String transferId, String senderUserId, String senderDeviceId, String recipientUserId, int count) throws Exception {
        return decrypt(fileKey, chunkIv(noncePrefix, index), ciphertext, chunkAad(transferId, senderUserId, senderDeviceId, recipientUserId, index, count));
    }
    static byte[] encryptChunkLayer2(byte[] layer1Key,byte[] layer2Key,byte[] layer1Prefix,byte[] layer2Prefix,int index,byte[] plaintext,
                                     String transferId,String senderUserId,String senderDeviceId,String recipientUserId,int count) throws Exception {
        byte[] inner=encrypt(layer1Key,plaintext,chunkLayerAad("layer1",transferId,senderUserId,senderDeviceId,recipientUserId,index,count),chunkIv(layer1Prefix,index));
        try{return encrypt(layer2Key,inner,chunkLayerAad("layer2",transferId,senderUserId,senderDeviceId,recipientUserId,index,count),chunkIv(layer2Prefix,index));}
        finally{Arrays.fill(inner,(byte)0);}
    }
    static byte[] decryptChunkLayer2(byte[] layer1Key,byte[] layer2Key,byte[] layer1Prefix,byte[] layer2Prefix,int index,byte[] ciphertext,
                                     String transferId,String senderUserId,String senderDeviceId,String recipientUserId,int count) throws Exception {
        byte[] inner=decrypt(layer2Key,chunkIv(layer2Prefix,index),ciphertext,chunkLayerAad("layer2",transferId,senderUserId,senderDeviceId,recipientUserId,index,count));
        try{return decrypt(layer1Key,chunkIv(layer1Prefix,index),inner,chunkLayerAad("layer1",transferId,senderUserId,senderDeviceId,recipientUserId,index,count));}
        finally{Arrays.fill(inner,(byte)0);}
    }
    private static byte[] chunkLayerAad(String layer,String transferId,String senderUserId,String senderDeviceId,String recipientUserId,int index,int count){
        if(!"layer1".equals(layer)&&!"layer2".equals(layer))throw new IllegalArgumentException("Invalid transfer chunk layer.");
        if(index<0||count<1||index>=count)throw new IllegalArgumentException("Invalid transfer chunk position.");
        return new JSONArray().put("serein-transfer-chunk-"+layer+"-v2").put(transferId).put(senderUserId).put(senderDeviceId).put(recipientUserId).put(index).put(count).toString().getBytes(StandardCharsets.UTF_8);
    }

    static byte[] chunkIv(byte[] prefix, int index) {
        if (prefix == null || prefix.length != 4 || index < 0) throw new IllegalArgumentException("Invalid chunk nonce.");
        return ByteBuffer.allocate(12).put(prefix).putInt(0).putInt(index).array();
    }

    static String base64Url(byte[] value) { return Base64.encodeToString(value, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING); }
    static byte[] decodeBase64Url(String value) { return Base64.decode(value, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING); }
    static byte[] randomBytes(int length) { byte[] value = new byte[length]; RANDOM.nextBytes(value); return value; }
    static String hex(byte[] bytes) { StringBuilder out = new StringBuilder(bytes.length * 2); for (byte b : bytes) out.append(String.format(java.util.Locale.ROOT, "%02x", b & 0xff)); return out.toString(); }

    static String decodeUtf8Strict(byte[] value) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value))
                .toString();
    }

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
