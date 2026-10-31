package io.serein.chat;

import android.content.Context;
import android.net.Uri;
import android.webkit.MimeTypeMap;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/** Foreground native chat/transfer flow. All cleartext is encrypted before API storage. */
final class SereinChatEngine {
    interface Listener { void changed(); }
    static final class Peer {
        final String userId, deviceId, name, fingerprint;
        final JSONObject publicJwk, layer2PublicJwk;
        final byte[] conversationKey, layer2Key;
        final int ratchetVersion;
        final boolean trusted;
        Peer(String userId,String deviceId,String name,String fingerprint,JSONObject publicJwk,JSONObject layer2PublicJwk,byte[] key,byte[] layer2Key,int ratchetVersion,boolean trusted){this.userId=userId;this.deviceId=deviceId;this.name=name;this.fingerprint=fingerprint;this.publicJwk=publicJwk;this.layer2PublicJwk=layer2PublicJwk;this.conversationKey=key;this.layer2Key=layer2Key;this.ratchetVersion=ratchetVersion;this.trusted=trusted;}
    }
    private final Context context;
    private final SereinApi api;
    private final JSONObject user, device, contact;
    private final String userId, deviceId, contactId, contactName, contactUsername;
    private final Listener listener;
    private final Map<String,Peer> peers=new HashMap<>();
    private volatile KeyPair pair, layer2Pair;
    private volatile String ownFingerprint="";
    private volatile SereinLocalStore local;
    private final Object ratchetLock=new Object();
    private volatile String status="Preparing protected device keys…";
    private volatile boolean ready;
    private volatile boolean notificationsArmed;
    private volatile String cursorTime, cursorId;
    private volatile boolean busy;
    private final Set<String> readMarkedIds=new HashSet<>();
    private volatile long lastReceiptRefresh;
    private static final long MAX_CLEAR_BYTES=64L*1024L*1024L;

    SereinChatEngine(Context context,SereinApi api,JSONObject account,JSONObject contact,Listener listener){
        this.context=context.getApplicationContext();this.api=api;this.user=account.optJSONObject("user");this.device=account.optJSONObject("device");this.contact=contact;this.listener=listener;
        userId=user==null?"":user.optString("id");deviceId=device==null?"":device.optString("id");contactId=contact.optString("user_id");contactName=contact.optString("display_name","Contact");contactUsername=contact.optString("username","");
    }
    String status(){return status;}
    boolean ready(){return ready;}
    boolean busy(){return busy;}
    String contactName(){return contactName;}
    String contactId(){return contactId;}
    synchronized List<Peer> peers(){return new ArrayList<>(peers.values());}
    String previousFingerprint(String targetDeviceId){return local==null?"":local.trustedFingerprint(contactId,targetDeviceId);}
    int previousRatchetVersion(String targetDeviceId){return local==null?2:local.trustedRatchetVersion(contactId,targetDeviceId);}
    JSONArray messages() throws Exception { return local==null?new JSONArray():local.messages(contactId); }
    private void notifyUi(){if(listener!=null)listener.changed();}

    CompletableFuture<Void> initialize(){
        if(contact.optBoolean("deleted")){return CompletableFuture.runAsync(()->{try{if(userId.isEmpty()||contactId.isEmpty())throw new IllegalStateException("Archived conversation identity is unavailable.");local=new SereinLocalStore(context,userId);ready=true;status="Archived conversation · this account was deleted · read-only";notifyUi();}catch(Exception error){throw new java.util.concurrent.CompletionException(error);}});}
        return CompletableFuture.supplyAsync(()->{
            try{if(userId.isEmpty()||deviceId.isEmpty())throw new IllegalStateException("Signed-in device identity is unavailable.");SereinAttachmentStore.cleanTemporaryFiles(context);pair=SereinDeviceCrypto.loadOrCreate(context,userId,deviceId);layer2Pair=SereinDeviceCrypto.loadOrCreateLayer2(context,userId,deviceId);ownFingerprint=SereinDeviceCrypto.fingerprintBundle(SereinDeviceCrypto.publicJwk(pair),SereinDeviceCrypto.publicJwk(layer2Pair));local=new SereinLocalStore(context,userId);return null;}
            catch(Exception error){throw new java.util.concurrent.CompletionException(error);}
        }).thenComposeAsync(ignored->{
            try{return api.enrollDeviceKey(SereinDeviceCrypto.publicJwk(pair),SereinDeviceCrypto.publicJwk(layer2Pair),SereinCoreNative.isLoaded()?3:2).thenApplyAsync(reply->{
                try{if(!ownFingerprint.equals(reply.optString("fingerprint")))throw new IllegalStateException("Server fingerprint did not match this device key bundle.");return null;}
                catch(Exception error){throw new java.util.concurrent.CompletionException(error);}
            });}catch(Exception error){return failed(error);}
        }).thenComposeAsync(ignored->refreshPeers()).thenRunAsync(()->{
            try{ready=true;status=peerStatus();notifyUi();retryPending();poll().whenComplete((done,error)->notificationsArmed=true);}
            catch(Exception error){status="Local message history could not be opened.";notifyUi();}
        });
    }

    CompletableFuture<Void> refreshPeers(){
        return api.contactsFuture().thenComposeAsync(value->{
            if(!(value instanceof JSONArray))return failed(new IllegalStateException("The accepted contact list could not be refreshed."));
            try {
                boolean found=false;JSONArray contacts=(JSONArray)value;for(int i=0;i<contacts.length();i++){JSONObject latest=contacts.optJSONObject(i);if(latest!=null&&contactId.equals(latest.optString("user_id"))){if(latest.optBoolean("deleted")){synchronized(contact){contact.put("deleted",true);contact.put("display_name",latest.optString("display_name",contact.optString("display_name")));contact.put("deleted_at",latest.optString("deleted_at",""));contact.put("connected_at",latest.optString("connected_at",""));contact.put("devices",new JSONArray());contact.put("online",false);}synchronized(this){peers.clear();}status="Archived conversation · this account was deleted · read-only";notifyUi();return CompletableFuture.completedFuture(new JSONObject().put("_deleted",true));}synchronized(contact){contact.put("display_name",latest.optString("display_name",contact.optString("display_name")));contact.put("connected_at",latest.optString("connected_at",contact.optString("connected_at","")));contact.remove("devices");contact.remove("online");contact.put("devices",latest.optJSONArray("devices") == null?new JSONArray():latest.optJSONArray("devices"));contact.put("online",latest.optBoolean("online"));}found=true;break;}}
                if(!found)return failed(new IllegalStateException("This contact is no longer active."));
                return api.deviceKeyDirectory(contactId);
            } catch(Exception error) { return failed(error); }
        }).thenAcceptAsync(directory->{
            try{
                if(directory.optBoolean("_deleted"))return;
                if(!contactId.equals(directory.optString("user_id"))||!contactUsername.equals(directory.optString("username")))throw new IllegalStateException("Device-key directory account did not match this contact.");
                JSONArray activeRows=contact.optJSONArray("devices");final JSONArray active=activeRows==null?new JSONArray():activeRows;JSONArray publishedRows=directory.optJSONArray("devices");JSONArray published=publishedRows==null?new JSONArray():publishedRows;
                Map<String,JSONObject> publishedById=new HashMap<>();for(int i=0;i<published.length();i++){JSONObject entry=published.optJSONObject(i);if(entry!=null)publishedById.put(entry.optString("device_id"),entry);}
                Map<String,Peer> next=new HashMap<>();
                for(int i=0;i<active.length();i++){
                    JSONObject d=active.optJSONObject(i);if(d==null)continue;String id=d.optString("id");JSONObject entry=publishedById.get(id);if(entry==null)continue;
                    JSONObject jwk=entry.optJSONObject("public_key"),layer2Jwk=entry.optJSONObject("layer2_public_key");if(jwk==null||layer2Jwk==null||entry.optInt("key_version")!=2||!"ECDH-P256".equals(entry.optString("algorithm")))throw new IllegalStateException("A contact device has not published both E2EE key layers.");
                    String fingerprint=SereinDeviceCrypto.fingerprintBundle(jwk,layer2Jwk);if(!fingerprint.equals(entry.optString("fingerprint")))throw new IllegalStateException("A contact device key-bundle fingerprint is inconsistent.");
                    int ratchetVersion=entry.optInt("ratchet_version",2);if(ratchetVersion!=2&&ratchetVersion!=3)throw new IllegalStateException("A contact device advertises an unsupported ratchet capability.");String trustedFingerprint=local.trustedFingerprint(contactId,id);int pinnedVersion=local.trustedRatchetVersion(contactId,id);boolean firstSeen=trustedFingerprint.isEmpty();if(firstSeen){local.trustFingerprint(contactId,id,fingerprint,ratchetVersion);trustedFingerprint=fingerprint;pinnedVersion=ratchetVersion;}boolean sameFingerprint=fingerprint.equals(trustedFingerprint);boolean capabilityAccepted=(pinnedVersion==2||pinnedVersion==3)&&ratchetVersion>=pinnedVersion;if(sameFingerprint&&capabilityAccepted&&ratchetVersion>pinnedVersion){local.trustFingerprint(contactId,id,fingerprint,ratchetVersion);pinnedVersion=ratchetVersion;}boolean trustedBundle=sameFingerprint&&capabilityAccepted;byte[] key=SereinDeviceCrypto.conversationKey(pair.getPrivate(),userId,deviceId,contactId,id,jwk);byte[] layer2Key=SereinDeviceCrypto.layer2ConversationKey(layer2Pair.getPrivate(),userId,deviceId,contactId,id,layer2Jwk);
                    next.put(id,new Peer(contactId,id,d.optString("name","Device"),fingerprint,jwk,layer2Jwk,key,layer2Key,ratchetVersion,trustedBundle));
                }
                if(publishedById.keySet().stream().anyMatch(id->{for(int i=0;i<active.length();i++)if(id.equals(active.optJSONObject(i)==null?"":active.optJSONObject(i).optString("id")))return false;return true;}))throw new IllegalStateException("The contact device list changed. Refresh Contacts and reopen this chat.");
                synchronized(this){peers.clear();peers.putAll(next);}status=peerStatus();notifyUi();
            }catch(Exception error){throw new java.util.concurrent.CompletionException(error);}
        });
    }
    private String peerStatus(){
        JSONArray active=contact.optJSONArray("devices");int total=active==null?0:active.length(),trusted=0; synchronized(this){for(Peer peer:peers.values())if(peer.trusted)trusted++;}
        if(total==0)return "No active recipient devices are available.";
        if(peers.size()<total)return (total-peers.size())+" active device(s) have not published an E2EE key.";
        return trusted==total?"All "+trusted+" recipient device key bundles are app-checked and locally pinned.":(total-trusted)+" recipient-device key changes or capability downgrades are blocked.";
    }
    CompletableFuture<Void> sendText(String text){return sendMessage(text,null);}
    private CompletableFuture<Void> sendMessage(String text,JSONObject attachment){
        if(!ready)return failed(new IllegalStateException("Protected device setup is not ready."));
        if(text==null||text.trim().isEmpty())return failed(new IllegalArgumentException("Message cannot be empty."));
        if(text.codePointCount(0,text.length())>4000)return failed(new IllegalArgumentException("Messages are limited to 4,000 characters."));
        return CompletableFuture.supplyAsync(()->{
            synchronized(ratchetLock){
                Map<String,byte[]> snapshots=new HashMap<>();List<SereinRatchetSession> opened=new ArrayList<>();
                try{
                    List<Peer> targets=trustedTargets();String messageId=UUID.randomUUID().toString().toLowerCase(Locale.ROOT),createdAt=java.time.Instant.now().toString(),conversation=canonicalConversationId(userId,contactId);JSONArray envelopes=new JSONArray();
                    for(Peer target:targets){JSONObject content=new JSONObject().put("version",1).put("text",text).put("conversation_id",conversation).put("sender_user_id",userId).put("sender_device_id",deviceId).put("recipient_user_id",contactId).put("recipient_device_id",target.deviceId);if(attachment!=null)content.put("attachment",attachment);
                        JSONObject encrypted;int cryptoVersion;
                        if(target.ratchetVersion>=3&&SereinCoreNative.isLoaded()){
                            SereinRatchetSession session=SereinRatchetSession.open(local,pair.getPrivate(),layer2Pair.getPrivate(),userId,deviceId,ownFingerprint,target);opened.add(session);
                            JSONObject route=route(conversation,messageId,userId,deviceId,contactId,target.deviceId);
                            encrypted=session.encrypt(content.toString().getBytes(StandardCharsets.UTF_8),route);cryptoVersion=3;
                            for(Map.Entry<String,byte[]> row:session.snapshots().entrySet())snapshots.put(row.getKey(),row.getValue());
                        }else{encrypted=SereinDeviceCrypto.encryptLayeredMessage(target.conversationKey,target.layer2Key,content,conversation,messageId,userId,deviceId,contactId,target.deviceId);cryptoVersion=2;}
                        envelopes.put(new JSONObject().put("to",target.deviceId).put("crypto_version",cryptoVersion).put("iv",encrypted.getString("iv")).put("ciphertext",encrypted.getString("ciphertext")));
                    }
                    JSONObject localMessage=new JSONObject().put("id",messageId).put("conversation_id",contactId).put("created_at",createdAt).put("text",text).put("mine",true).put("sender",user.optString("display_name","You")).put("status","pending").put("envelopes",envelopes);if(attachment!=null)localMessage.put("attachment",attachment);
                    if(snapshots.isEmpty())local.saveMessage(localMessage);else local.saveRatchetMessage(localMessage,snapshots);notifyUi();return localMessage;
                }catch(Exception error){throw new java.util.concurrent.CompletionException(error);}
                finally{for(byte[] snapshot:snapshots.values())Arrays.fill(snapshot,(byte)0);for(SereinRatchetSession session:opened)session.close();}
            }
        }).thenComposeAsync(message->deliver(message));
    }
    private List<Peer> trustedTargets(){
        List<Peer> targets=new ArrayList<>();JSONArray active=contact.optJSONArray("devices");if(active==null)throw new IllegalStateException("Contact has no active devices.");
        synchronized(this){for(int i=0;i<active.length();i++){JSONObject d=active.optJSONObject(i);if(d==null)continue;Peer peer=peers.get(d.optString("id"));if(peer==null||!peer.trusted)throw new IllegalStateException("A recipient-device key is changed or not locally pinned; sending is blocked.");targets.add(peer);}}
        if(targets.isEmpty())throw new IllegalStateException("No recipient devices are available.");return targets;
    }
    private CompletableFuture<Void> deliver(JSONObject message){
        JSONArray envelopes=message.optJSONArray("envelopes");CompletableFuture<Void> chain=CompletableFuture.completedFuture(null);
        for(int i=0;envelopes!=null&&i<envelopes.length();i++){JSONObject e=envelopes.optJSONObject(i);if(e==null)continue;String id=message.optString("id");chain=chain.thenCompose(ignored->api.sendEnvelopeFuture(id,e.optString("to"),e.optString("iv"),e.optString("ciphertext"),e.optInt("crypto_version",1)).thenApply(value->null));}
        return chain.thenRunAsync(()->{try{message.put("status","accepted");message.remove("envelopes");local.saveMessage(message);status="Encrypted message sent · accepted by all recipient devices.";notifyUi();}catch(Exception error){throw new java.util.concurrent.CompletionException(error);}});
    }
    private void retryPending(){
        try{JSONArray all=local.messages(contactId);for(int i=0;i<all.length();i++){JSONObject row=all.optJSONObject(i);if(row!=null&&row.optBoolean("mine")&&"pending".equals(row.optString("status"))&&row.optJSONArray("envelopes")!=null)deliver(row).exceptionally(error->{status="Pending encrypted message will retry when the connection is available.";notifyUi();return null;});}}
        catch(Exception error){status="Local history could not be opened.";notifyUi();}
    }

    CompletableFuture<Void> poll(){
        if(!ready||busy)return CompletableFuture.completedFuture(null);busy=true;
        return pollPage(40).thenRunAsync(()->{try{markVisibleMessagesRead();long now=System.currentTimeMillis();if(now-lastReceiptRefresh>=12000){refreshOutgoingReceipts();lastReceiptRefresh=now;}}catch(Exception error){status="Read and delivery status will retry when connected.";notifyUi();}}).whenCompleteAsync((ignored,error)->{busy=false;if(error!=null){status="Secure message sync paused; retrying.";notifyUi();}});
    }
    private void markVisibleMessagesRead() throws Exception {
        JSONArray rows=local.messages(contactId),ids=new JSONArray();List<String> newlyMarked=new ArrayList<>();
        for(int i=0;i<rows.length();i++){JSONObject row=rows.optJSONObject(i);if(row==null||row.optBoolean("mine"))continue;String id=row.optString("id","");if(!id.isEmpty()&&!readMarkedIds.contains(id)){ids.put(id);newlyMarked.add(id);if(ids.length()>=200)break;}}
        if(ids.length()>0){api.markMessagesReadFuture(ids).get(20,TimeUnit.SECONDS);readMarkedIds.addAll(newlyMarked);}
    }
    private void refreshOutgoingReceipts() throws Exception {
        JSONArray rows=local.messages(contactId),ids=new JSONArray();Map<String,JSONObject> outgoing=new HashMap<>();
        for(int i=0;i<rows.length();i++){JSONObject row=rows.optJSONObject(i);String state=row==null?"":row.optString("status");if(row!=null&&row.optBoolean("mine")&&("accepted".equals(state)||"delivered".equals(state)||"read".equals(state))&&ids.length()<200){String id=row.optString("id","");if(!id.isEmpty()){ids.put(id);outgoing.put(id,row);}}}
        if(ids.length()==0)return;
        JSONObject payload=(JSONObject)api.messageReceiptsFuture(ids).get(20,TimeUnit.SECONDS);JSONArray receipts=payload.optJSONArray("items");if(receipts==null)return;
        for(int i=0;i<receipts.length();i++){JSONObject receipt=receipts.optJSONObject(i);if(receipt==null)continue;JSONObject row=outgoing.get(receipt.optString("id"));if(row==null)continue;int recipients=receipt.optInt("recipient_count"),delivered=receipt.optInt("delivered_count"),read=receipt.optInt("read_count");String state=read>0?"read":delivered>0?"delivered":"accepted";if(!state.equals(row.optString("status"))||row.optInt("delivered_count",-1)!=delivered||row.optInt("read_count",-1)!=read){row.put("status",state).put("recipient_count",recipients).put("delivered_count",delivered).put("read_count",read);local.saveMessage(row);}}
        notifyUi();
    }
    private CompletableFuture<Void> pollPage(int remainingPages){
        if(remainingPages<=0)return CompletableFuture.completedFuture(null);
        return api.historyPage(cursorTime,cursorId).thenComposeAsync(value->{
            try{
                JSONObject page=(JSONObject)value;JSONArray items=page.optJSONArray("items");if(items==null||items.length()==0)return CompletableFuture.completedFuture(null);
                CompletableFuture<Void> chain=CompletableFuture.completedFuture(null);
                for(int i=0;i<items.length();i++){JSONObject item=items.optJSONObject(i);if(item==null)continue;JSONObject captured=item;chain=chain.thenCompose(ignored->processHistoryItem(captured));}
                return chain.thenCompose(ignored->page.optBoolean("has_more")?pollPage(remainingPages-1):CompletableFuture.completedFuture(null));
            }catch(Exception error){return failed(error);}
        });
    }
    private CompletableFuture<Void> processHistoryItem(JSONObject item){
        return CompletableFuture.runAsync(()->{
            try{
                String created=item.optString("created_at"),id=item.optString("id");JSONObject packet=item.optJSONObject("payload");
                if(packet==null||!"message".equals(packet.optString("type"))) {advance(created,id);return;}
                String senderDevice=packet.optString("from");boolean belongs=false;JSONArray active=contact.optJSONArray("devices");if(active!=null)for(int i=0;i<active.length();i++){JSONObject d=active.optJSONObject(i);if(d!=null&&senderDevice.equals(d.optString("id")))belongs=true;}
                if(!belongs){advance(created,id);return;}
                if(local.containsMessage(id)){api.acknowledgeFuture(id).get(20,TimeUnit.SECONDS);advance(created,id);return;}
                Peer peer; synchronized(this){peer=peers.get(senderDevice);}if(peer==null||!peer.trusted){status=peer==null?"Refresh Contacts: the sender device is not in the accepted contact list.":"Message is held because the sender-device key changed or is not locally pinned.";notifyUi();throw new IllegalStateException(status);}
                JSONObject message=decryptAndStoreIncoming(peer,packet,id,senderDevice,created);
                // Local message and ratchet advancement are durable before ACK deletes the server queue copy.
                api.acknowledgeFuture(id).get(20,TimeUnit.SECONDS);advance(created,id);if(notificationsArmed)SereinNotifications.showIncoming(context,context.getSharedPreferences("serein",Context.MODE_PRIVATE).getBoolean("notification_sound",true));status="Encrypted message received and stored on this device.";notifyUi();
            }catch(Exception error){throw new java.util.concurrent.CompletionException(error);}
        });
    }
    private JSONObject decryptAndStoreIncoming(Peer peer,JSONObject packet,String messageId,String senderDevice,String createdAt) throws Exception {
        String conversation=canonicalConversationId(userId,contactId);int version=packet.optInt("crypto_version",1);JSONObject content;JSONObject message;
        if(version<1||version>3)throw new SecurityException("Encrypted message uses an unsupported protocol version.");
        if(version==3){
            if(peer.ratchetVersion<3)throw new SecurityException("Sender used ratchet v3 without advertising that capability in the trusted device directory.");
            synchronized(ratchetLock){
                SereinRatchetSession session=SereinRatchetSession.open(local,pair.getPrivate(),layer2Pair.getPrivate(),userId,deviceId,ownFingerprint,peer);byte[] clear=null;Map<String,byte[]> snapshots=new HashMap<>();
                try{
                    clear=session.decrypt(packet.optString("iv"),packet.optString("ciphertext"),route(conversation,messageId,contactId,senderDevice,userId,deviceId));
                    content=new JSONObject(SereinDeviceCrypto.decodeUtf8Strict(clear));message=validatedIncomingMessage(content,conversation,messageId,senderDevice,createdAt);
                    for(Map.Entry<String,byte[]> row:session.snapshots().entrySet())snapshots.put(row.getKey(),row.getValue());
                    local.saveRatchetMessage(message,snapshots);
                }finally{if(clear!=null)Arrays.fill(clear,(byte)0);for(byte[] snapshot:snapshots.values())Arrays.fill(snapshot,(byte)0);session.close();}
            }
        }else{
            try{content=SereinDeviceCrypto.decryptLayeredMessage(peer.conversationKey,peer.layer2Key,version,packet.optString("iv"),packet.optString("ciphertext"),conversation,messageId,contactId,senderDevice,userId,deviceId);}
            catch(Exception currentRouteFailure){content=SereinDeviceCrypto.decryptLayeredMessage(peer.conversationKey,peer.layer2Key,version,packet.optString("iv"),packet.optString("ciphertext"),userId,messageId,contactId,senderDevice,userId,deviceId);}
            message=validatedIncomingMessage(content,conversation,messageId,senderDevice,createdAt);local.saveMessage(message);
        }
        return message;
    }
    private JSONObject validatedIncomingMessage(JSONObject content,String conversation,String messageId,String senderDevice,String createdAt) throws Exception {
        if(content.optInt("version")!=1||!(conversation.equals(content.optString("conversation_id"))||userId.equals(content.optString("conversation_id")))||!contactId.equals(content.optString("sender_user_id"))||!senderDevice.equals(content.optString("sender_device_id"))||!userId.equals(content.optString("recipient_user_id"))||!deviceId.equals(content.optString("recipient_device_id")))throw new SecurityException("Encrypted message routing did not match this device.");
        String text=content.optString("text","");if(text.isEmpty()||text.codePointCount(0,text.length())>4000)throw new SecurityException("Encrypted message text exceeded the protocol limit.");
        JSONObject message=new JSONObject().put("id",messageId).put("conversation_id",contactId).put("created_at",createdAt).put("text",text).put("mine",false).put("sender",contactName).put("status","received");
        if(content.has("attachment"))message.put("attachment",validateAttachment(content.getJSONObject("attachment")));return message;
    }
    private static JSONObject route(String conversation,String messageId,String senderUser,String senderDevice,String recipientUser,String recipientDevice) throws Exception {
        return new JSONObject().put("conversationId",conversation).put("messageId",messageId).put("senderUserId",senderUser).put("senderDeviceId",senderDevice).put("recipientUserId",recipientUser).put("recipientDeviceId",recipientDevice);
    }
    private synchronized void advance(String time,String id){if(time!=null&&!time.isEmpty()&&id!=null&&!id.isEmpty()){cursorTime=time;cursorId=id;}}
    private static String canonicalConversationId(String first,String second){String[] pair={first,second};Arrays.sort(pair);return pair[0]+":"+pair[1];}
    private static JSONObject validateAttachment(JSONObject source) throws Exception {
        String id=source.optString("transfer_id"),filename=source.optString("filename"),type=source.optString("content_type");long size=source.optLong("size",-1);
        if(!id.matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")||filename.getBytes(StandardCharsets.UTF_8).length>1024||type.getBytes(StandardCharsets.UTF_8).length>128||size<0||size>MAX_CLEAR_BYTES)throw new SecurityException("Encrypted attachment details are invalid.");
        return new JSONObject().put("transfer_id",id).put("filename",safeFilename(filename)).put("content_type",type).put("size",size);
    }
    private static String safeFilename(String input){StringBuilder out=new StringBuilder();for(int i=0;i<input.length()&&out.length()<150;){int cp=input.codePointAt(i);i+=Character.charCount(cp);out.appendCodePoint(cp=='/'||cp=='\\'||Character.isISOControl(cp)?'_':cp);}String value=out.toString().trim();while(value.startsWith("."))value=value.substring(1);return value.isEmpty()?"attachment":value;}

    CompletableFuture<File> downloadAttachment(JSONObject attachment){
        return CompletableFuture.supplyAsync(()->{
            File temporary=null;byte[] contentKey=null,prefix=null,layer2ContentKey=null,layer2Prefix=null;
            try{
                String transferId=attachment.getString("transfer_id"),filename=attachment.getString("filename");long expected=attachment.getLong("size");
                File existing=SereinAttachmentStore.existing(context,userId,transferId,filename,expected);if(existing!=null)return existing;
                Object listed=api.transfers().join();if(!(listed instanceof JSONArray))throw new IllegalStateException("Encrypted transfer list was unavailable.");
                JSONObject transfer=null;JSONArray rows=(JSONArray)listed;for(int i=0;i<rows.length();i++){JSONObject row=rows.optJSONObject(i);if(row!=null&&transferId.equals(row.optString("id"))){transfer=row;break;}}
                if(transfer==null||transfer.isNull("ready_at"))throw new IllegalStateException("Encrypted transfer is incomplete, expired, or unavailable on this device.");
                String senderUser=transfer.optString("sender_user_id"),senderDevice=transfer.optString("sender_device_id"),recipientUser=transfer.optString("recipient_user_id");
                if(!userId.equals(recipientUser)&&!userId.equals(senderUser))throw new SecurityException("Transfer account binding did not match this session.");
                byte[] manifestKey,manifestLayer2Key;
                if(senderUser.equals(userId)){
                    if(!senderDevice.equals(deviceId))throw new SecurityException("This transfer belongs to another sending device.");
                    manifestKey=SereinDeviceCrypto.conversationKey(pair.getPrivate(),userId,deviceId,userId,deviceId,SereinDeviceCrypto.publicJwk(pair));
                    manifestLayer2Key=SereinDeviceCrypto.layer2ConversationKey(layer2Pair.getPrivate(),userId,deviceId,userId,deviceId,SereinDeviceCrypto.publicJwk(layer2Pair));
                }else{
                    if(!contactId.equals(senderUser))throw new SecurityException("The sender is not the selected contact.");Peer peer; synchronized(this){peer=peers.get(senderDevice);}if(peer==null||!peer.trusted)throw new SecurityException("The sender-device key is not locally pinned or has changed; the file remains locked.");manifestKey=peer.conversationKey;manifestLayer2Key=peer.layer2Key;
                }
                int manifestVersion=transfer.optInt("manifest_crypto_version",1);if(manifestVersion!=1&&manifestVersion!=2)throw new SecurityException("Encrypted transfer uses an unsupported manifest version.");
                JSONObject innerManifestEnvelope=manifestVersion==2?SereinDeviceCrypto.decryptManifestLayer2(manifestLayer2Key,transfer.optString("manifest_iv"),transfer.optString("manifest_ciphertext"),transferId,senderUser,senderDevice,recipientUser,deviceId):new JSONObject().put("version",1).put("algorithm","AES-256-GCM").put("iv",transfer.optString("manifest_iv")).put("ciphertext",transfer.optString("manifest_ciphertext"));
                JSONObject manifest=SereinDeviceCrypto.decryptManifest(manifestKey,innerManifestEnvelope.getString("iv"),innerManifestEnvelope.getString("ciphertext"),transferId,senderUser,senderDevice,recipientUser,deviceId);
                if(expected<0||expected>MAX_CLEAR_BYTES)throw new SecurityException("Attachment size is outside the allowed limit.");
                int chunkCryptoVersion=transfer.optInt("chunk_crypto_version",manifest.optInt("chunk_crypto_version",1));if((chunkCryptoVersion!=1&&chunkCryptoVersion!=2)||manifest.optInt("chunk_crypto_version",1)!=chunkCryptoVersion)throw new SecurityException("Unsupported or inconsistent transfer chunk version.");
                int chunkPlaintextBytes=SereinDeviceCrypto.CHUNK_CIPHERTEXT_BYTES-(chunkCryptoVersion==2?32:16);
                int count=manifest.optInt("chunk_count",-1);int expectedCount=(int)Math.max(1,(expected+chunkPlaintextBytes-1)/chunkPlaintextBytes);
                if(manifest.optInt("version")!=1||!transferId.equals(manifest.optString("transfer_id"))||manifest.optLong("size",-1)!=expected||count<1||count>SereinDeviceCrypto.MAX_CHUNKS||count!=expectedCount||count!=transfer.optInt("chunk_count")||!filename.equals(manifest.optString("filename"))||!attachment.optString("content_type").equals(manifest.optString("content_type")))throw new SecurityException("Authenticated file manifest did not match the chat notice or transfer limits.");
                int tagBytes=chunkCryptoVersion==2?32:16;if(transfer.optLong("total_ciphertext_bytes",-1)!=expected+(long)count*tagBytes)throw new SecurityException("Encrypted transfer byte count did not match its manifest.");
                contentKey=android.util.Base64.decode(manifest.getString("content_key"),android.util.Base64.DEFAULT);prefix=android.util.Base64.decode(manifest.getString("nonce_prefix"),android.util.Base64.DEFAULT);if(contentKey.length!=32||prefix.length!=4)throw new SecurityException("Encrypted transfer key material is malformed.");
                if(chunkCryptoVersion==2){layer2ContentKey=android.util.Base64.decode(manifest.getString("layer2_content_key"),android.util.Base64.DEFAULT);layer2Prefix=android.util.Base64.decode(manifest.getString("layer2_nonce_prefix"),android.util.Base64.DEFAULT);if(layer2ContentKey.length!=32||layer2Prefix.length!=4)throw new SecurityException("Layer 2 transfer chunk key material is malformed.");}
                temporary=File.createTempFile("serein-clear-",".part",context.getCacheDir());long clearBytes=0;
                try(FileOutputStream output=new FileOutputStream(temporary,false)){
                    for(int index=0;index<count;index++){
                        SereinApi.BinaryReply reply=api.transferChunk("GET",transferId,index,null,null).join();byte[] encrypted=reply.bytes;
                        if(reply.sha256==null||!SereinDeviceCrypto.sha256Hex(encrypted).equalsIgnoreCase(reply.sha256))throw new SecurityException("Encrypted chunk checksum did not match the server response.");
                        byte[] clear=chunkCryptoVersion==2?SereinDeviceCrypto.decryptChunkLayer2(contentKey,layer2ContentKey,prefix,layer2Prefix,index,encrypted,transferId,senderUser,senderDevice,recipientUser,count):SereinDeviceCrypto.decryptChunk(contentKey,prefix,index,encrypted,transferId,senderUser,senderDevice,recipientUser,count);
                        try{clearBytes+=clear.length;if(clearBytes>expected)throw new SecurityException("Decrypted attachment exceeded its authenticated size.");output.write(clear);}finally{Arrays.fill(clear,(byte)0);Arrays.fill(encrypted,(byte)0);}
                    }
                    output.flush();output.getFD().sync();
                }
                if(clearBytes!=expected||temporary.length()!=expected)throw new SecurityException("Decrypted attachment size did not match its authenticated manifest.");
                File saved;try(InputStream input=new FileInputStream(temporary)){saved=SereinAttachmentStore.save(context,userId,transferId,filename,input,expected);}
                api.acknowledgeTransfer(transferId).join();status="Download saved. Tap Open to hand it to a compatible app.";notifyUi();return saved;
            }catch(Throwable error){throw new java.util.concurrent.CompletionException(unwrap(error));}
            finally{if(contentKey!=null)Arrays.fill(contentKey,(byte)0);if(prefix!=null)Arrays.fill(prefix,(byte)0);if(layer2ContentKey!=null)Arrays.fill(layer2ContentKey,(byte)0);if(layer2Prefix!=null)Arrays.fill(layer2Prefix,(byte)0);if(temporary!=null)temporary.delete();}
        });
    }

    CompletableFuture<Void> uploadAttachment(File source,String filename,String contentType){
        final String selectedName=filename==null?"attachment":filename;
        final String selectedType=contentType==null?"application/octet-stream":contentType;
        return CompletableFuture.runAsync(()->{
            byte[] contentKey=SereinDeviceCrypto.randomBytes(32),prefix=SereinDeviceCrypto.randomBytes(4),layer2ContentKey=SereinDeviceCrypto.randomBytes(32),layer2Prefix=SereinDeviceCrypto.randomBytes(4);String transferId=UUID.randomUUID().toString().toLowerCase(Locale.ROOT);boolean created=false,uploaded=false;
            try{
                long size=source.length();if(size<0||size>MAX_CLEAR_BYTES)throw new IllegalArgumentException("This file exceeds the 64 MiB transfer limit.");
                String cleanFilename=safeFilename(selectedName),safeContentType=selectedType.isEmpty()||selectedType.length()>128?"application/octet-stream":selectedType;
                int count=(int)Math.max(1,(size+SereinDeviceCrypto.CHUNK_PLAINTEXT_BYTES-1)/SereinDeviceCrypto.CHUNK_PLAINTEXT_BYTES);long cipherBytes=size+count*32L;
                if(count>SereinDeviceCrypto.MAX_CHUNKS||cipherBytes>SereinDeviceCrypto.MAX_FILE_CIPHERTEXT_BYTES)throw new IllegalArgumentException("This file exceeds the encrypted-transfer limit.");
                List<Peer> targets=trustedTargets();JSONObject manifest=new JSONObject().put("version",1).put("chunk_crypto_version",2).put("transfer_id",transferId).put("filename",cleanFilename).put("content_type",safeContentType).put("size",size).put("chunk_count",count).put("content_key",android.util.Base64.encodeToString(contentKey,android.util.Base64.NO_WRAP)).put("nonce_prefix",android.util.Base64.encodeToString(prefix,android.util.Base64.NO_WRAP)).put("layer2_content_key",android.util.Base64.encodeToString(layer2ContentKey,android.util.Base64.NO_WRAP)).put("layer2_nonce_prefix",android.util.Base64.encodeToString(layer2Prefix,android.util.Base64.NO_WRAP));
                JSONArray envelopes=new JSONArray();JSONObject selfJwk=SereinDeviceCrypto.publicJwk(pair),selfLayer2Jwk=SereinDeviceCrypto.publicJwk(layer2Pair);byte[] selfKey=SereinDeviceCrypto.conversationKey(pair.getPrivate(),userId,deviceId,userId,deviceId,selfJwk),selfLayer2Key=SereinDeviceCrypto.layer2ConversationKey(layer2Pair.getPrivate(),userId,deviceId,userId,deviceId,selfLayer2Jwk);
                JSONObject ownInner=SereinDeviceCrypto.encryptManifest(selfKey,manifest,transferId,userId,deviceId,contactId,deviceId),own=SereinDeviceCrypto.encryptManifestLayer2(selfLayer2Key,ownInner,transferId,userId,deviceId,contactId,deviceId);envelopes.put(new JSONObject().put("device_id",deviceId).put("crypto_version",2).put("iv",own.getString("iv")).put("ciphertext",own.getString("ciphertext")));Arrays.fill(selfKey,(byte)0);Arrays.fill(selfLayer2Key,(byte)0);
                for(Peer target:targets){JSONObject inner=SereinDeviceCrypto.encryptManifest(target.conversationKey,manifest,transferId,userId,deviceId,contactId,target.deviceId),wrapped=SereinDeviceCrypto.encryptManifestLayer2(target.layer2Key,inner,transferId,userId,deviceId,contactId,target.deviceId);envelopes.put(new JSONObject().put("device_id",target.deviceId).put("crypto_version",2).put("iv",wrapped.getString("iv")).put("ciphertext",wrapped.getString("ciphertext")));}
                JSONObject request=new JSONObject().put("id",transferId).put("recipient_user_id",contactId).put("chunk_count",count).put("chunk_crypto_version",2).put("total_ciphertext_bytes",cipherBytes).put("device_envelopes",envelopes);
                api.createTransfer(request).join();created=true;
                byte[] buffer=new byte[SereinDeviceCrypto.CHUNK_PLAINTEXT_BYTES];
                try(RandomAccessFile input=new RandomAccessFile(source,"r")){
                    for(int index=0;index<count;index++){
                        int wanted=(int)Math.min(buffer.length,size-(long)index*buffer.length),read=0;while(read<wanted){int n=input.read(buffer,read,wanted-read);if(n<0)throw new java.io.IOException("Selected file changed while being encrypted.");read+=n;}
                        byte[] clear=Arrays.copyOf(buffer,wanted),encrypted;try{encrypted=SereinDeviceCrypto.encryptChunkLayer2(contentKey,layer2ContentKey,prefix,layer2Prefix,index,clear,transferId,userId,deviceId,contactId,count);}finally{Arrays.fill(clear,(byte)0);}
                        String hash=SereinDeviceCrypto.sha256Hex(encrypted);try{api.transferChunk("PUT",transferId,index,encrypted,hash).join();}finally{Arrays.fill(encrypted,(byte)0);}
                    }
                    if(input.read()!=-1)throw new java.io.IOException("Selected file changed while being encrypted.");
                }finally{Arrays.fill(buffer,(byte)0);}
                uploaded=true;JSONObject attachment=new JSONObject().put("transfer_id",transferId).put("filename",cleanFilename).put("content_type",safeContentType).put("size",size);sendMessage("📎 "+cleanFilename,attachment).join();
            }catch(Throwable error){if(created&&!uploaded)try{api.abortTransfer(transferId).join();}catch(Throwable ignored){}throw new java.util.concurrent.CompletionException(unwrap(error));}
            finally{Arrays.fill(contentKey,(byte)0);Arrays.fill(prefix,(byte)0);Arrays.fill(layer2ContentKey,(byte)0);Arrays.fill(layer2Prefix,(byte)0);}
        });
    }

    static String mimeType(Context context,Uri uri,String filename){String type=context.getContentResolver().getType(uri);if(type!=null&&!type.isEmpty())return type;String extension=MimeTypeMap.getFileExtensionFromUrl(filename);String guess=MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension==null?"":extension.toLowerCase(Locale.ROOT));return guess==null?"application/octet-stream":guess;}
    private static Throwable unwrap(Throwable error){while(error instanceof java.util.concurrent.CompletionException&&error.getCause()!=null)error=error.getCause();return error;}
    private static <T> CompletableFuture<T> failed(Throwable error){CompletableFuture<T> result=new CompletableFuture<>();result.completeExceptionally(error);return result;}
}
