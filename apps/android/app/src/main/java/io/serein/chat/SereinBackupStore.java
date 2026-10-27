package io.serein.chat;

import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECPoint;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.UUID;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/** Portable .srbk v3 codec; server-held random backup keys are supplied only in memory. */
final class SereinBackupStore {
    static final String MIME = "application/vnd.serein.backup";
    private static final byte[] MAGIC = "SEREINBK".getBytes(StandardCharsets.US_ASCII);
    private static final String FORMAT = "SEREIN-BACKUP";
    private static final int V3 = 3, V2 = 2, V1 = 1, KDF_VERSION = 1;
    private static final String V3_KDF = "HKDF-SHA256-SERVER-BACKUP-KEY", V2_KDF = "HKDF-SHA256-ACCOUNT-UUID", V1_KDF = "PBKDF2-HMAC-SHA256";
    private static final int V1_ITERATIONS = 600_000;
    private static final int MAX_HEADER = 16 * 1024;
    private static final int MAX_NATIVE_BYTES = 64 * 1024 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();
    private SereinBackupStore() { }

    static final class Info {
        final int version; final String createdAt;
        Info(int version, String createdAt) { this.version=version; this.createdAt=createdAt; }
    }
    static final class EphemeralKeyExchange {
        private KeyPair pair;
        private final JSONObject clientPublicKey;
        private EphemeralKeyExchange(KeyPair pair,JSONObject publicKey){this.pair=pair;this.clientPublicKey=publicKey;}
        JSONObject publicKeyJwk() throws Exception{return new JSONObject(clientPublicKey.toString());}
        byte[] unwrap(String accountId,String deviceId,JSONObject envelope) throws Exception {
            if(pair==null)throw new IOException("The one-use backup key is no longer available.");
            String user=canonicalId(accountId),device=canonicalId(deviceId);
            if(envelope.optInt("key_version")!=1)throw new IOException("Unsupported backup key envelope.");
            JSONObject server=envelope.getJSONObject("server_public_key");if(!"EC".equals(server.optString("kty"))||!"P-256".equals(server.optString("crv")))throw new IOException("Malformed backup key envelope.");
            byte[] x=unb64(server.getString("x"),32),y=unb64(server.getString("y"),32),salt=unb64(envelope.getString("salt"),32),nonce=unb64(envelope.getString("nonce"),12),ciphertext=unb64(envelope.getString("ciphertext"),48),shared=null,wrapKey=null;
            try{
                ECPublicKey own=(ECPublicKey)pair.getPublic();ECPublicKey serverPublic=(ECPublicKey)KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger(1,x),new BigInteger(1,y)),own.getParams()));
                KeyAgreement agreement=KeyAgreement.getInstance("ECDH");agreement.init(pair.getPrivate());agreement.doPhase(serverPublic,true);shared=agreement.generateSecret();if(shared.length!=32)throw new IOException("Invalid ECDH shared secret.");
                String cx=clientPublicKey.getString("x"),cy=clientPublicKey.getString("y"),sx=server.getString("x"),sy=server.getString("y"),saltText=envelope.getString("salt"),nonceText=envelope.getString("nonce");
                byte[] info=array("serein-backup-key-envelope-kdf-v1",user,device,1,cx,cy,sx,sy),aad=array("serein-backup-key-envelope-aad-v1",user,device,1,cx,cy,sx,sy,saltText,nonceText);
                try{wrapKey=hkdf(shared,salt,info);Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(wrapKey,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(aad);byte[] clear=cipher.doFinal(ciphertext);if(clear.length!=32){wipe(clear);throw new IOException("Malformed backup key envelope.");}return clear;}
                finally{wipe(info);wipe(aad);}
            }finally{wipe(x);wipe(y);wipe(salt);wipe(nonce);wipe(ciphertext);wipe(shared);wipe(wrapKey);clear();}
        }
        void clear(){pair=null;}
    }
    static EphemeralKeyExchange newEphemeralKeyExchange() throws Exception {
        KeyPairGenerator generator=KeyPairGenerator.getInstance("EC");generator.initialize(new ECGenParameterSpec("secp256r1"));KeyPair pair=generator.generateKeyPair();ECPublicKey pub=(ECPublicKey)pair.getPublic();
        JSONObject jwk=new JSONObject().put("kty","EC").put("crv","P-256").put("x",b64url(toFixed(pub.getW().getAffineX(),32))).put("y",b64url(toFixed(pub.getW().getAffineY(),32)));
        return new EphemeralKeyExchange(pair,jwk);
    }
    private static byte[] toFixed(BigInteger value,int length) throws Exception { byte[] raw=value.toByteArray(),out=new byte[length];int start=raw.length>length?raw.length-length:0,copy=Math.min(raw.length,length);System.arraycopy(raw,start,out,length-copy,copy);wipe(raw);return out; }
    private static byte[] hkdf(byte[] input,byte[] salt,byte[] info) throws Exception {byte[] prk=null,block=null;try{Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(salt,"HmacSHA256"));prk=mac.doFinal(input);mac.init(new SecretKeySpec(prk,"HmacSHA256"));mac.update(info);mac.update((byte)1);block=mac.doFinal();return Arrays.copyOf(block,32);}finally{wipe(prk);wipe(block);}}

    static Info inspect(byte[] file) throws Exception {
        JSONObject h=unpack(file).header;
        return new Info(h.getInt("version"),h.getString("created_at"));
    }

    static byte[] create(String accountId,String username,byte[] backupKey,JSONObject data) throws Exception {
        String id=canonicalId(accountId); if(username==null)username="";if(backupKey==null||backupKey.length!=32)throw new IOException("The server backup key is unavailable or malformed.");
        byte[] clear=null, compressed=null, key=null, salt=new byte[16], nonce=new byte[12], cipherText=null;
        try {
            JSONObject payload=new JSONObject().put("format",FORMAT).put("version",V3)
                    .put("owner",new JSONObject().put("accountId",id).put("username",username.toLowerCase(java.util.Locale.ROOT)))
                    .put("created_at",timestampNow()).put("snapshot_id",UUID.randomUUID().toString().toLowerCase(java.util.Locale.ROOT)).put("data",data);
            clear=payload.toString().getBytes(StandardCharsets.UTF_8); if(clear.length>MAX_NATIVE_BYTES)throw new IOException("Mobile backup exceeds the 64 MiB local safety limit.");
            WipingByteArrayOutputStream compressedOut=new WipingByteArrayOutputStream();
            try { try(DeflaterOutputStream deflater=new DeflaterOutputStream(compressedOut)){deflater.write(clear);}compressed=compressedOut.toByteArray(); }
            finally { compressedOut.wipe(); }
            String compression="deflate"; if(compressed.length>MAX_NATIVE_BYTES)throw new IOException("Compressed backup exceeds the 64 MiB mobile safety limit.");
            RANDOM.nextBytes(salt);RANDOM.nextBytes(nonce);String created=payload.getString("created_at"),snapshot=payload.getString("snapshot_id"),nonceText=b64url(nonce);
            JSONObject header=new JSONObject().put("format",FORMAT).put("version",V3).put("kdf",V3_KDF).put("key_derivation_version",KDF_VERSION).put("salt",b64url(salt)).put("snapshot_id",snapshot).put("created_at",created).put("compression",compression).put("payload_iv",nonceText);
            key=deriveServerBackupKey(backupKey,id,salt);Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(v3Aad(id,header));cipherText=cipher.doFinal(compressed);
            return pack(header.toString().getBytes(StandardCharsets.UTF_8),cipherText);
        } finally { wipe(clear);wipe(compressed);wipe(key);wipe(salt);wipe(nonce);wipe(cipherText); }
    }

    static JSONObject open(String accountId,String username,String legacyPassword,byte[] backupKey,byte[] file) throws Exception {
        String id=canonicalId(accountId);if(username==null)username="";Parsed parsed=unpack(file);JSONObject h=parsed.header;
        if(h.getInt("version")==V3)return openV3(id,backupKey,parsed);
        if(h.getInt("version")==V2)return openV2(id,parsed);
        if(h.getInt("version")==V1)return openV1(id,username.toLowerCase(java.util.Locale.ROOT),legacyPassword,parsed);
        throw new IOException("Unsupported Serein backup version.");
    }

    private static JSONObject openV3(String id,byte[] backupKey,Parsed p) throws Exception {
        JSONObject h=p.header;if(backupKey==null||backupKey.length!=32)throw new IOException("The account backup key is unavailable.");
        if(!V3_KDF.equals(h.getString("kdf"))||h.getInt("key_derivation_version")!=KDF_VERSION)throw new IOException("Unsupported backup key derivation.");
        byte[] salt=unb64(h.getString("salt"),16),nonce=unb64(h.getString("payload_iv"),12),key=null,clear=null;
        try{key=deriveServerBackupKey(backupKey,id,salt);Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(v3Aad(id,h));clear=cipher.doFinal(p.ciphertext);if(clear.length>MAX_NATIVE_BYTES)throw new IOException("Backup expands beyond the 64 MiB mobile safety limit.");if("deflate".equals(h.getString("compression"))){byte[] zipped=clear;try{clear=inflate(zipped);}finally{wipe(zipped);}}else if(!"none".equals(h.getString("compression")))throw new IOException("Unsupported backup compression.");return validatePayload(clear,id,h);}
        catch(Exception e){throw new IOException("Backup could not be opened for this account or the file is damaged.",e);}finally{wipe(salt);wipe(nonce);wipe(key);wipe(clear);wipe(p.ciphertext);}
    }

    private static JSONObject openV2(String id,Parsed p) throws Exception {
        JSONObject h=p.header;String kdf=h.getString("kdf"),compression=h.getString("compression");if(!V2_KDF.equals(kdf)||h.getInt("key_derivation_version")!=KDF_VERSION)throw new IOException("Unsupported backup key derivation.");
        byte[] nonce=unb64(h.getString("payload_iv"),12),key=null,clear=null;
        try{key=deriveAccountKey(id);Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(v2Aad(id,h));clear=cipher.doFinal(p.ciphertext);if(clear.length>MAX_NATIVE_BYTES)throw new IOException("Backup expands beyond the 64 MiB mobile safety limit.");if("deflate".equals(compression)){byte[] zipped=clear;try{clear=inflate(zipped);}finally{wipe(zipped);}}else if(!"none".equals(compression))throw new IOException("Unsupported backup compression.");return validatePayload(clear,id,h);}
        catch(Exception e){throw new IOException("Backup could not be opened for this account or the file is damaged.",e);}finally{wipe(nonce);wipe(key);wipe(clear);wipe(p.ciphertext);}
    }

    private static JSONObject openV1(String id,String username,String password,Parsed p) throws Exception {
        JSONObject h=p.header;
        if(!V1_KDF.equals(h.getString("kdf"))||h.getInt("iterations")!=V1_ITERATIONS)
            throw new IOException("Unsupported legacy backup parameters.");
        if(password==null||password.isEmpty()) throw new IOException("Enter the original legacy backup password.");
        byte[] passwordUtf8=password.getBytes(StandardCharsets.UTF_8);
        boolean passwordTooLong=passwordUtf8.length>1024;
        wipe(passwordUtf8);
        if(passwordTooLong) throw new IOException("Enter the original legacy backup password.");

        byte[] salt=unb64(h.getString("salt"),16),wrapIv=unb64(h.getString("key_wrap_iv"),12);
        byte[] wrapped=unb64(h.getString("wrapped_key"),48),iv=unb64(h.getString("payload_iv"),12);
        byte[] dataKey=null,passwordKeyBytes=null,clear=null;
        char[] passwordChars=password.toCharArray();
        PBEKeySpec spec=new PBEKeySpec(passwordChars,salt,V1_ITERATIONS,256);
        Arrays.fill(passwordChars,'\0');
        try {
            passwordKeyBytes=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            Cipher unwrap=Cipher.getInstance("AES/GCM/NoPadding");
            unwrap.init(Cipher.DECRYPT_MODE,new SecretKeySpec(passwordKeyBytes,"AES"),new GCMParameterSpec(128,wrapIv));
            unwrap.updateAAD(v1WrapAad(id,username,h));
            dataKey=unwrap.doFinal(wrapped);
            if(dataKey.length!=32)throw new IOException("Legacy backup key is malformed.");
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(dataKey,"AES"),new GCMParameterSpec(128,iv));
            cipher.updateAAD(v1PayloadAad(id,username,h));
            clear=cipher.doFinal(p.ciphertext);
            if(clear.length>MAX_NATIVE_BYTES)throw new IOException("Legacy backup expands beyond the mobile safety limit.");
            if("deflate".equals(h.getString("compression"))){byte[] zipped=clear;try{clear=inflate(zipped);}finally{wipe(zipped);}}
            else if(!"none".equals(h.getString("compression")))throw new IOException("Unsupported legacy backup compression.");
            return validatePayload(clear,id,h);
        } catch(Exception e) {
            throw new IOException("Legacy backup could not be opened. Check the signed-in account, original password, and file.",e);
        } finally {
            spec.clearPassword();Arrays.fill(passwordChars,'\0');
            wipe(salt);wipe(wrapIv);wipe(wrapped);wipe(iv);wipe(dataKey);wipe(passwordKeyBytes);wipe(clear);wipe(p.ciphertext);
        }
    }

    private static JSONObject validatePayload(byte[] clear,String id,JSONObject h) throws Exception {
        JSONObject payload=new JSONObject(new String(clear,StandardCharsets.UTF_8));JSONObject owner=payload.optJSONObject("owner");
        if(!FORMAT.equals(payload.optString("format"))||payload.optInt("version")!=h.optInt("version")||!h.optString("snapshot_id").equals(payload.optString("snapshot_id"))||!h.optString("created_at").equals(payload.optString("created_at"))||owner==null||!id.equals(owner.optString("accountId"))||payload.optJSONObject("data")==null)throw new IOException("Backup account binding or contents are invalid.");
        return payload.getJSONObject("data");
    }

    private static byte[] v2Aad(String id,JSONObject h) throws Exception { return array("serein-backup-payload-v2",FORMAT,V2,id,h.getString("snapshot_id"),h.getString("created_at"),h.getString("compression"),h.getString("kdf"),h.getInt("key_derivation_version"),h.getString("payload_iv")); }
    private static byte[] v3Aad(String id,JSONObject h) throws Exception { return array("serein-backup-payload-v3",FORMAT,V3,id,h.getString("snapshot_id"),h.getString("created_at"),h.getString("compression"),h.getString("kdf"),h.getInt("key_derivation_version"),h.getString("salt"),h.getString("payload_iv")); }
    private static byte[] deriveServerBackupKey(byte[] backupKey,String id,byte[] salt) throws Exception { byte[] info=("Serein backup payload v3|"+id).getBytes(StandardCharsets.UTF_8),prk=null,block=null;try{Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(salt,"HmacSHA256"));prk=mac.doFinal(backupKey);mac.init(new SecretKeySpec(prk,"HmacSHA256"));mac.update(info);mac.update((byte)1);block=mac.doFinal();return Arrays.copyOf(block,32);}finally{wipe(info);wipe(prk);wipe(block);} }
    private static byte[] v1WrapAad(String id,String username,JSONObject h) throws Exception { return array("serein-backup-key-wrap-v1",FORMAT,V1,id,username,h.getString("snapshot_id"),h.getString("kdf"),h.getInt("iterations"),h.getString("salt")); }
    private static byte[] v1PayloadAad(String id,String username,JSONObject h) throws Exception { return array("serein-backup-payload-v1",FORMAT,V1,id,username,h.getString("snapshot_id"),h.getString("created_at"),h.getString("compression"),h.getString("kdf"),h.getInt("iterations"),h.getString("salt"),h.getString("key_wrap_iv"),h.getString("wrapped_key"),h.getString("payload_iv")); }
    private static byte[] array(Object... values) throws Exception { JSONArray a=new JSONArray();for(Object v:values)a.put(v);return a.toString().getBytes(StandardCharsets.UTF_8); }
    private static byte[] deriveAccountKey(String id) throws Exception { byte[] ikm=id.getBytes(StandardCharsets.UTF_8),salt="Serein backup account key v2".getBytes(StandardCharsets.UTF_8),info="Serein backup stable key v1".getBytes(StandardCharsets.UTF_8),prk=null,block=null;try{Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(salt,"HmacSHA256"));prk=mac.doFinal(ikm);mac.init(new SecretKeySpec(prk,"HmacSHA256"));mac.update(info);mac.update((byte)1);block=mac.doFinal();return Arrays.copyOf(block,32);}finally{wipe(ikm);wipe(salt);wipe(info);wipe(prk);wipe(block);} }
    private static byte[] inflate(byte[] input) throws Exception {
        WipingByteArrayOutputStream out=new WipingByteArrayOutputStream();byte[] buf=new byte[8192];
        try(InflaterInputStream inflater=new InflaterInputStream(new ByteArrayInputStream(input))){
            int n;while((n=inflater.read(buf))!=-1){if(out.size()+n>MAX_NATIVE_BYTES)throw new IOException("Decompressed backup exceeds the mobile size limit.");out.write(buf,0,n);}
            return out.toByteArray();
        } finally { wipe(buf);out.wipe(); }
    }
    private static byte[] pack(byte[] header,byte[] cipher) throws Exception {
        long total=(long)MAGIC.length+4L+header.length+cipher.length;
        if(header.length<2||header.length>MAX_HEADER||cipher.length<16||total>MAX_NATIVE_BYTES)throw new IOException("Backup exceeds its safe size limit.");
        ByteBuffer b=ByteBuffer.allocate((int)total).order(ByteOrder.BIG_ENDIAN);
        b.put(MAGIC).putInt(header.length).put(header).put(cipher);
        return b.array();
    }
    private static final class Parsed { final JSONObject header;final byte[] ciphertext;Parsed(JSONObject h,byte[] c){header=h;ciphertext=c;} }
    private static Parsed unpack(byte[] file) throws Exception { if(file==null||file.length<MAGIC.length+4+2+16||file.length>MAX_NATIVE_BYTES)throw new IOException("Backup file is malformed or exceeds the 64 MiB mobile limit.");for(int i=0;i<MAGIC.length;i++)if(file[i]!=MAGIC[i])throw new IOException("This is not a Serein encrypted backup file.");ByteBuffer b=ByteBuffer.wrap(file).order(ByteOrder.BIG_ENDIAN);b.position(MAGIC.length);int len=b.getInt();if(len<2||len>MAX_HEADER||MAGIC.length+4L+len+16>file.length)throw new IOException("Backup header is malformed.");byte[] header=new byte[len];b.get(header);JSONObject h=new JSONObject(new String(header,StandardCharsets.UTF_8));int version=h.optInt("version");Set<String> fields=new HashSet<>();if(version==V3)fields.addAll(Arrays.asList("format","version","kdf","key_derivation_version","salt","snapshot_id","created_at","compression","payload_iv"));else if(version==V2)fields.addAll(Arrays.asList("format","version","kdf","key_derivation_version","snapshot_id","created_at","compression","payload_iv"));else if(version==V1)fields.addAll(Arrays.asList("format","version","kdf","iterations","salt","snapshot_id","created_at","compression","key_wrap_iv","wrapped_key","payload_iv"));else throw new IOException("Unsupported Serein backup version.");Iterator<String> keys=h.keys();while(keys.hasNext())if(!fields.contains(keys.next()))throw new IOException("Backup has unsupported header fields.");if(h.length()!=fields.size()||!FORMAT.equals(h.optString("format"))||!UUID.fromString(h.getString("snapshot_id")).toString().equalsIgnoreCase(h.getString("snapshot_id"))||!validTimestamp(h.getString("created_at"))||!Arrays.asList("deflate","none").contains(h.optString("compression")))throw new IOException("Backup header is malformed.");if(version==V3){if(!V3_KDF.equals(h.optString("kdf"))||h.optInt("key_derivation_version")!=KDF_VERSION)throw new IOException("Unsupported backup key derivation.");unb64(h.getString("salt"),16);}else if(version==V2){if(!V2_KDF.equals(h.optString("kdf"))||h.optInt("key_derivation_version")!=KDF_VERSION)throw new IOException("Unsupported backup key derivation.");}if(version>=V2)unb64(h.getString("payload_iv"),12);byte[] ciphertext=new byte[b.remaining()];b.get(ciphertext);return new Parsed(h,ciphertext); }
    private static String timestampNow(){java.text.SimpleDateFormat format=new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",java.util.Locale.ROOT);format.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));return format.format(new java.util.Date());}
    private static boolean validTimestamp(String value){try{java.time.Instant.parse(value);return true;}catch(Exception ignored){return false;}}
    private static String canonicalId(String account) throws Exception { return UUID.fromString(account).toString().toLowerCase(java.util.Locale.ROOT); }
    private static String b64url(byte[] bytes) { return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    private static byte[] unb64(String value,int exact) throws Exception { if(value==null||!value.matches("[A-Za-z0-9_-]+"))throw new IOException("Backup field is malformed.");byte[] result=java.util.Base64.getUrlDecoder().decode(value);if(result.length!=exact)throw new IOException("Backup field is malformed.");return result; }
    private static final class WipingByteArrayOutputStream extends ByteArrayOutputStream {
        void wipe(){Arrays.fill(buf,(byte)0);reset();}
    }
    private static void wipe(byte[] value){if(value!=null)Arrays.fill(value,(byte)0);}
}
