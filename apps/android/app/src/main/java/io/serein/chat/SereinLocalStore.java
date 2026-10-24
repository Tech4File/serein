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
    private synchronized void load() throws Exception {
        if (!file.isFile()) { root = new JSONObject().put("version", 1).put("messages", new JSONArray()).put("trust", new JSONObject()); return; }
        byte[] packed = new byte[(int) Math.min(file.length(), 16L * 1024 * 1024)];
        if (file.length() > 16L * 1024 * 1024) throw new IllegalStateException("Local message history exceeds its safe size limit.");
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
        next.put(new JSONObject(message.toString()));while(next.length()>1000){JSONArray trimmed=new JSONArray();for(int i=Math.max(0,next.length()-1000);i<next.length();i++)trimmed.put(next.get(i));next=trimmed;}
        root.put("messages",next);flush();
    }
    synchronized String trustedFingerprint(String peerUserId,String peerDeviceId) {
        return root.optJSONObject("trust").optString(peerUserId+":"+peerDeviceId,"");
    }
    synchronized void trustFingerprint(String peerUserId,String peerDeviceId,String fingerprint) throws Exception {
        root.getJSONObject("trust").put(peerUserId+":"+peerDeviceId,fingerprint);flush();
    }
    private void flush() throws Exception {
        byte[] clear=root.toString().getBytes(StandardCharsets.UTF_8), packed=SereinSecureVault.seal(aad,clear);java.util.Arrays.fill(clear,(byte)0);
        File temporary=new File(context.getFilesDir(),".serein-history-"+UUID.randomUUID()+".part");
        try(FileOutputStream out=new FileOutputStream(temporary)){out.write(packed);out.flush();out.getFD().sync();}
        java.util.Arrays.fill(packed,(byte)0);
        try{
            try{Files.move(temporary.toPath(),file.toPath(),StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);}
            catch(java.nio.file.AtomicMoveNotSupportedException unsupported){Files.move(temporary.toPath(),file.toPath(),StandardCopyOption.REPLACE_EXISTING);}
        }catch(Exception error){temporary.delete();throw error;}
    }
}
