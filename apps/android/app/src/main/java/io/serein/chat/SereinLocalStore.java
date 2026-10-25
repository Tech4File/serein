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

/** App-private, Keystore-sealed message history and explicit per-device fingerprint trust. */
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
        if (!file.isFile()) { root = new JSONObject().put("version", 1).put("messages", new JSONArray()).put("trust", new JSONObject()); return; }
        byte[] packed = new byte[(int) Math.min(file.length(), MAX_LOCAL_HISTORY_BYTES)];
        if (file.length() > MAX_LOCAL_HISTORY_BYTES) throw new IllegalStateException("Local message history exceeds its safe size limit.");
        try (FileInputStream in = new FileInputStream(file)) { int at=0,n; while ((n=in.read(packed,at,packed.length-at))>0) at+=n; if(at!=packed.length)throw new java.io.IOException("Local message history was truncated."); }
        byte[] clear = SereinSecureVault.open(aad, packed);
        try { root = new JSONObject(new String(clear, StandardCharsets.UTF_8)); }
        finally { java.util.Arrays.fill(clear,(byte)0); java.util.Arrays.fill(packed,(byte)0); }
        if (root.optInt("version") != 1 || !(root.opt("messages") instanceof JSONArray) || !(root.opt("trust") instanceof JSONObject)) throw new IllegalStateException("Local message history format is unsupported.");
    }
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
        return root.optJSONObject("trust").optString(peerUserId+":"+peerDeviceId,"");
    }
    synchronized void trustFingerprint(String peerUserId,String peerDeviceId,String fingerprint) throws Exception {
        root.getJSONObject("trust").put(peerUserId+":"+peerDeviceId,fingerprint);flush();
    }
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
