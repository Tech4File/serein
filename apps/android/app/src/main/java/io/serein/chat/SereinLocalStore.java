package io.serein.chat;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

/** App-private, Keystore-sealed message history and per-device first-use key pins. */
final class SereinLocalStore {
    private final Context context;
    private final String accountId;
    private final String aad;
    private final File file;
    private JSONObject root;

    SereinLocalStore(Context context, String accountId) throws Exception {
        this.context = context.getApplicationContext(); this.accountId = UUID.fromString(accountId).toString();
        this.aad = "message-history-v1:" + this.accountId;
        this.file = new File(this.context.getFilesDir(), "serein-history-" + this.accountId + ".bin");
        load();
    }
    static boolean deleteForAccount(Context context,String accountId){try{String id=UUID.fromString(accountId).toString();File file=new File(context.getApplicationContext().getFilesDir(),"serein-history-"+id+".bin");return !file.exists()||file.delete();}catch(Exception ignored){return false;}}
    private static final long MAX_LOCAL_HISTORY_BYTES = 64L * 1024 * 1024;
    private synchronized void load() throws Exception {
        if (!file.isFile()) { root = new JSONObject().put("version", 1).put("messages", new JSONArray()).put("trust", new JSONObject()).put("ratchets", new JSONObject()).put("meta", new JSONObject()); return; }
        byte[] packed = new byte[(int) Math.min(file.length(), MAX_LOCAL_HISTORY_BYTES)];
        if (file.length() > MAX_LOCAL_HISTORY_BYTES) throw new IllegalStateException("Local message history exceeds its safe size limit.");
        try (FileInputStream in = new FileInputStream(file)) { int at=0,n; while ((n=in.read(packed,at,packed.length-at))>0) at+=n; if(at!=packed.length)throw new java.io.IOException("Local message history was truncated."); }
        byte[] clear = SereinSecureVault.open(aad, packed);
        try { root = new JSONObject(new String(clear, StandardCharsets.UTF_8)); }
        finally { java.util.Arrays.fill(clear,(byte)0); java.util.Arrays.fill(packed,(byte)0); }
        if (root.optInt("version") != 1 || !(root.opt("messages") instanceof JSONArray) || !(root.opt("trust") instanceof JSONObject)) throw new IllegalStateException("Local message history format is unsupported.");
        if (!root.has("ratchets")) root.put("ratchets", new JSONObject());
        else if (!(root.opt("ratchets") instanceof JSONObject)) throw new IllegalStateException("Stored ratchet state format is unsupported; refusing to reset sessions.");
        if (!root.has("meta")) root.put("meta", new JSONObject());
        else if (!(root.opt("meta") instanceof JSONObject)) throw new IllegalStateException("Stored sync metadata is invalid; refusing to reset cursors.");
    }
    synchronized JSONObject meta(String key) throws Exception { JSONObject meta=root.getJSONObject("meta"),value=meta.optJSONObject(key);return value==null?null:new JSONObject(value.toString()); }
    synchronized void putMeta(String key,JSONObject value) throws Exception {if(key==null||key.isEmpty()||key.length()>256||value==null||value.toString().length()>4096)throw new IllegalArgumentException("Invalid sync metadata.");JSONObject previous=new JSONObject(root.toString());try{root.getJSONObject("meta").put(key,new JSONObject(value.toString()));flush();}catch(Exception error){root=previous;throw error;}}
    synchronized JSONArray messages(String conversationId) throws Exception {
        JSONArray result = new JSONArray(), all = root.getJSONArray("messages");
        for(int i=0;i<all.length();i++){JSONObject row=all.optJSONObject(i);if(row!=null&&conversationId.equals(row.optString("conversation_id")))result.put(new JSONObject(row.toString()));}
        return result;
    }
    synchronized boolean containsMessage(String id) throws Exception {
        JSONArray all=root.getJSONArray("messages");for(int i=0;i<all.length();i++){JSONObject row=all.optJSONObject(i);if(row!=null&&id.equals(row.optString("id")))return true;}return false;
    }
    synchronized void saveMessage(JSONObject message) throws Exception {
        JSONArray all=root.getJSONArray("messages"), next=new JSONArray();String id=message.getString("id");
        for(int i=0;i<all.length();i++){JSONObject row=all.optJSONObject(i);if(row!=null&&!id.equals(row.optString("id")))next.put(row);}
        next.put(new JSONObject(message.toString()));
        root.put("messages",next);flush();
    }
    synchronized byte[] ratchetSnapshot(String name) throws Exception {
        if (name == null || name.isEmpty() || name.length() > 512) throw new IllegalArgumentException("Invalid ratchet snapshot key.");
        JSONObject ratchets=root.getJSONObject("ratchets");if(!ratchets.has(name))return null;
        Object raw=ratchets.opt(name);if(!(raw instanceof String)||((String)raw).isEmpty()||((String)raw).length()>1_398_104)throw new IllegalStateException("Stored ratchet snapshot encoding is invalid; refusing to reset the session.");
        String encoded=(String)raw;byte[] snapshot=android.util.Base64.decode(encoded,android.util.Base64.NO_WRAP);
        if(snapshot.length==0||snapshot.length>1024*1024||!android.util.Base64.encodeToString(snapshot,android.util.Base64.NO_WRAP).equals(encoded)){java.util.Arrays.fill(snapshot,(byte)0);throw new IllegalStateException("Stored ratchet snapshot exceeds its safety limit or is non-canonical.");}
        return snapshot;
    }
    synchronized void saveRatchetMessage(JSONObject message, java.util.Map<String, byte[]> snapshots) throws Exception {
        if (snapshots == null || snapshots.size() > 64) throw new IllegalArgumentException("Invalid ratchet snapshot batch.");
        JSONObject previous = new JSONObject(root.toString());
        try {
            JSONArray all = root.getJSONArray("messages"), next = new JSONArray(); String id = message.getString("id");
            for (int i=0;i<all.length();i++) { JSONObject row=all.optJSONObject(i); if(row!=null&&!id.equals(row.optString("id"))) next.put(row); }
            next.put(new JSONObject(message.toString())); root.put("messages", next);
            JSONObject ratchets=root.getJSONObject("ratchets");
            for (java.util.Map.Entry<String,byte[]> item:snapshots.entrySet()) {
                String name=item.getKey();byte[] snapshot=item.getValue();
                if(name==null||name.isEmpty()||name.length()>512||snapshot==null||snapshot.length==0||snapshot.length>1024*1024)throw new IllegalArgumentException("Invalid ratchet snapshot.");
                ratchets.put(name,android.util.Base64.encodeToString(snapshot,android.util.Base64.NO_WRAP));
            }
            flush();
        } catch (Exception error) { root=previous; throw error; }
    }
    synchronized JSONArray backupMessages() throws Exception {
        JSONArray source=root.getJSONArray("messages"), copy=new JSONArray();
        for(int i=0;i<source.length();i++){JSONObject row=source.optJSONObject(i);if(row!=null)copy.put(new JSONObject(row.toString()));}
        return copy;
    }
    synchronized int mergeBackupMessages(JSONArray incoming) throws Exception {
        if(incoming==null||incoming.length()>100000)throw new IllegalArgumentException("Backup contains too many messages for this device.");
        JSONArray current=root.getJSONArray("messages"), merged=new JSONArray();java.util.HashMap<String,JSONObject> byId=new java.util.HashMap<>();java.util.HashSet<String> incomingIds=new java.util.HashSet<>();
        for(int i=0;i<current.length();i++){JSONObject row=current.optJSONObject(i);if(row!=null){String id=row.optString("id","");if(!id.isEmpty()&&!byId.containsKey(id))byId.put(id,row);}}
        int added=0;
        for(int i=0;i<incoming.length();i++){
            JSONObject row=incoming.optJSONObject(i);if(row==null)throw new IllegalArgumentException("Backup contains a malformed message record.");
            Object rawId=row.opt("id"),rawConversation=row.opt("conversation_id"),rawCreated=row.opt("created_at"),rawStatus=row.opt("status");
            if(!(rawId instanceof String)||((String)rawId).isEmpty()||((String)rawId).length()>128||!(rawConversation instanceof String)||((String)rawConversation).isEmpty()||((String)rawConversation).length()>128||!(rawCreated instanceof String)||((String)rawCreated).length()>128||!(rawStatus instanceof String)||!java.util.Arrays.asList("pending","accepted","received").contains(rawStatus))throw new IllegalArgumentException("Backup contains a malformed message record.");
            String id=(String)rawId;try{java.time.Instant.parse((String)rawCreated);}catch(Exception invalidTime){throw new IllegalArgumentException("Backup contains a message with an invalid timestamp.");}
            if(!incomingIds.add(id))throw new IllegalArgumentException("Backup contains duplicate message IDs.");
            if(!byId.containsKey(id)){JSONObject safe=new JSONObject(row.toString());byId.put(id,safe);added++;}
        }
        java.util.ArrayList<JSONObject> rows=new java.util.ArrayList<>(byId.values());
        rows.sort((left,right)->{int time=left.optString("created_at","").compareTo(right.optString("created_at",""));return time!=0?time:left.optString("id","").compareTo(right.optString("id",""));});
        for(JSONObject row:rows)merged.put(row);
        root.put("messages",merged);flush();return added;
    }
    synchronized String trustedFingerprint(String peerUserId,String peerDeviceId) {
        Object value=root.optJSONObject("trust").opt(peerUserId+":"+peerDeviceId);
        return value instanceof JSONObject?((JSONObject)value).optString("fingerprint",""):value instanceof String?(String)value:"";
    }
    synchronized int trustedRatchetVersion(String peerUserId,String peerDeviceId) {
        Object value=root.optJSONObject("trust").opt(peerUserId+":"+peerDeviceId);
        return value instanceof JSONObject?((JSONObject)value).optInt("ratchet_version",2):2;
    }
    synchronized JSONObject trustedDeviceIdentity(String peerUserId,String peerDeviceId) throws Exception {Object value=root.optJSONObject("trust").opt(peerUserId+":"+peerDeviceId);return value instanceof JSONObject?new JSONObject(value.toString()):null;}
    synchronized void trustDeviceIdentity(String peerUserId,String peerDeviceId,String fingerprint,int ratchetVersion,long keyEpoch,JSONObject signingPublicKey) throws Exception {
        if((ratchetVersion!=2&&ratchetVersion!=3)||keyEpoch<1)throw new IllegalArgumentException("Invalid trusted device identity.");JSONObject previous=new JSONObject(root.toString());try{JSONObject trust=new JSONObject().put("fingerprint",fingerprint).put("ratchet_version",ratchetVersion).put("key_epoch",keyEpoch);if(signingPublicKey!=null)trust.put("signing_public_key",new JSONObject(signingPublicKey.toString()));root.getJSONObject("trust").put(peerUserId+":"+peerDeviceId,trust);flush();}catch(Exception error){root=previous;throw error;}
    }
    synchronized void trustFingerprint(String peerUserId,String peerDeviceId,String fingerprint,int ratchetVersion) throws Exception {
        if(ratchetVersion!=2&&ratchetVersion!=3)throw new IllegalArgumentException("Unsupported trusted ratchet capability.");
        JSONObject previous=new JSONObject(root.toString());try{root.getJSONObject("trust").put(peerUserId+":"+peerDeviceId,new JSONObject().put("fingerprint",fingerprint).put("ratchet_version",ratchetVersion));flush();}catch(Exception error){root=previous;throw error;}
    }
    synchronized int mergeHistorySyncMessages(JSONArray incoming)throws Exception{if(incoming==null||incoming.length()>100000)throw new IllegalArgumentException("History sync contains too many records.");JSONObject previous=new JSONObject(root.toString());try{JSONArray current=root.getJSONArray("messages"),next=new JSONArray();java.util.HashMap<String,JSONObject> byId=new java.util.HashMap<>();for(int i=0;i<current.length();i++){JSONObject row=current.optJSONObject(i);if(row!=null){String id=row.optString("id","");if(!id.isEmpty())byId.put(id,row);}}int added=0;java.util.HashSet<String> incomingIds=new java.util.HashSet<>();for(int i=0;i<incoming.length();i++){JSONObject record=incoming.optJSONObject(i);if(record==null)throw new IllegalArgumentException("History batch contains a malformed record.");String id=record.optString("id","");String conversation=record.optString("conversation_id","");String created=record.optString("created_at","");String status=record.optString("status","");JSONObject payload=record.optJSONObject("payload");if(!(id.matches("(?i)[0-9a-f-]{36}")||(payload.optBoolean("system")&&id.matches("[A-Za-z0-9:._-]{1,128}")))||!conversation.matches("(?i)[0-9a-f-]{36}")||id.length()>128||!java.util.Arrays.asList("pending","accepted","sent","delivered","read","received","expired").contains(status)||payload==null)throw new IllegalArgumentException("History record failed schema validation.");try{java.time.Instant.parse(created);}catch(Exception invalid){throw new IllegalArgumentException("History record timestamp is invalid.");}if(!incomingIds.add(id))throw new IllegalArgumentException("History batch contains duplicate message IDs.");JSONObject existing=byId.get(id);if(existing!=null){if(!conversation.equals(existing.optString("conversation_id"))||!created.equals(existing.optString("created_at"))||!payload.optString("text","").equals(existing.optString("text",""))||payload.optBoolean("mine")!=existing.optBoolean("mine")||!payload.optString("sender","").equals(existing.optString("sender","")))throw new IllegalStateException("History conflict for message "+id+"; existing local history was preserved.");continue;}JSONObject row=new JSONObject(payload.toString()).put("id",id).put("conversation_id",conversation).put("created_at",created).put("status",status);byId.put(id,row);added++;}java.util.ArrayList<JSONObject> rows=new java.util.ArrayList<>(byId.values());rows.sort((a,b)->{int time=a.optString("created_at","").compareTo(b.optString("created_at",""));return time!=0?time:a.optString("id","").compareTo(b.optString("id",""));});for(JSONObject row:rows)next.put(row);root.put("messages",next);flush();return added;}catch(Exception error){root=previous;throw error;}}
    private void flush() throws Exception {
        byte[] clear=root.toString().getBytes(StandardCharsets.UTF_8);
        if(clear.length>MAX_LOCAL_HISTORY_BYTES)throw new IllegalStateException("Local history exceeds the 64 MiB device safety limit.");
        byte[] packed=SereinSecureVault.seal(aad,clear);java.util.Arrays.fill(clear,(byte)0);
        File temporary=new File(context.getFilesDir(),".serein-history-"+UUID.randomUUID()+".part");
        try(FileOutputStream out=new FileOutputStream(temporary)){out.write(packed);out.flush();out.getFD().sync();}
        java.util.Arrays.fill(packed,(byte)0);
        try{
            try{Files.move(temporary.toPath(),file.toPath(),StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);}
            catch(java.nio.file.AtomicMoveNotSupportedException unsupported){Files.move(temporary.toPath(),file.toPath(),StandardCopyOption.REPLACE_EXISTING);}
        }catch(Exception error){temporary.delete();throw error;}
    }
}
