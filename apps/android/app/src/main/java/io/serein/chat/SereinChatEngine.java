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
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/** Foreground native chat/transfer flow. All cleartext is encrypted before API storage. */
final class SereinChatEngine {
    interface Listener { void changed(); }
    static final class Peer {
        final String userId, deviceId, name, fingerprint;
        final JSONObject publicJwk;
        final byte[] conversationKey;
        final boolean trusted;
        Peer(String userId,String deviceId,String name,String fingerprint,JSONObject publicJwk,byte[] key,boolean trusted){this.userId=userId;this.deviceId=deviceId;this.name=name;this.fingerprint=fingerprint;this.publicJwk=publicJwk;this.conversationKey=key;this.trusted=trusted;}
    }
    private final Context context;
    private final SereinApi api;
    private final JSONObject user, device, contact;
    private final String userId, deviceId, contactId, contactName, contactUsername;
    private final Listener listener;
    private final Map<String,Peer> peers=new HashMap<>();
    private volatile KeyPair pair;
    private volatile SereinLocalStore local;
    private volatile String status="Preparing protected device keys…";
    private volatile boolean ready;
    private volatile String cursorTime, cursorId;
    private volatile boolean busy;
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
    JSONArray messages() throws Exception { return local==null?new JSONArray():local.messages(contactId); }
    private void notifyUi(){if(listener!=null)listener.changed();}

    CompletableFuture<Void> initialize(){
        return CompletableFuture.supplyAsync(()->{
            try{if(userId.isEmpty()||deviceId.isEmpty())throw new IllegalStateException("Signed-in device identity is unavailable.");SereinAttachmentStore.cleanTemporaryFiles(context);pair=SereinDeviceCrypto.loadOrCreate(context,userId,deviceId);local=new SereinLocalStore(context,userId);return null;}
            catch(Exception error){throw new java.util.concurrent.CompletionException(error);}
        }).thenComposeAsync(ignored->{
            try{return api.enrollDeviceKey(SereinDeviceCrypto.publicJwk(pair)).thenApplyAsync(reply->{
                try{String fp=SereinDeviceCrypto.fingerprint(SereinDeviceCrypto.publicJwk(pair));if(!fp.equals(reply.optString("fingerprint")))throw new IllegalStateException("Server fingerprint did not match this device key.");return null;}
                catch(Exception error){throw new java.util.concurrent.CompletionException(error);}
            });}catch(Exception error){return failed(error);}
        }).thenComposeAsync(ignored->refreshPeers()).thenRunAsync(()->{
            try{ready=true;status=peerStatus();notifyUi();retryPending();poll();}
            catch(Exception error){status="Local message history could not be opened.";notifyUi();}
        });
    }

    CompletableFuture<Void> refreshPeers(){
        return api.contactsFuture().thenComposeAsync(value->{
            if(!(value instanceof JSONArray))return failed(new IllegalStateException("The accepted contact list could not be refreshed."));
            try {
                boolean found=false;JSONArray contacts=(JSONArray)value;for(int i=0;i<contacts.length();i++){JSONObject latest=contacts.optJSONObject(i);if(latest!=null&&contactId.equals(latest.optString("user_id"))){synchronized(contact){contact.remove("devices");contact.remove("online");contact.put("devices",latest.optJSONArray("devices") == null?new JSONArray():latest.optJSONArray("devices"));contact.put("online",latest.optBoolean("online"));}found=true;break;}}
                if(!found)return failed(new IllegalStateException("This contact is no longer active."));
                return api.deviceKeyDirectory(contactId);
            } catch(Exception error) { return failed(error); }
        }).thenAcceptAsync(directory->{
            try{
                if(!contactId.equals(directory.optString("user_id"))||!contactUsername.equals(directory.optString("username")))throw new IllegalStateException("Device-key directory account did not match this contact.");
                JSONArray activeRows=contact.optJSONArray("devices");final JSONArray active=activeRows==null?new JSONArray():activeRows;JSONArray publishedRows=directory.optJSONArray("devices");JSONArray published=publishedRows==null?new JSONArray():publishedRows;
                Map<String,JSONObject> publishedById=new HashMap<>();for(int i=0;i<published.length();i++){JSONObject entry=published.optJSONObject(i);if(entry!=null)publishedById.put(entry.optString("device_id"),entry);}
                Map<String,Peer> next=new HashMap<>();
                for(int i=0;i<active.length();i++){
                    JSONObject d=active.optJSONObject(i);if(d==null)continue;String id=d.optString("id");JSONObject entry=publishedById.get(id);if(entry==null)continue;
                    JSONObject jwk=entry.optJSONObject("public_key");if(jwk==null||!"ECDH-P256".equals(entry.optString("algorithm")))throw new IllegalStateException("A contact device published an unsupported key.");
                    String fingerprint=SereinDeviceCrypto.fingerprint(jwk);if(!fingerprint.equals(entry.optString("fingerprint")))throw new IllegalStateException("A contact device fingerprint is inconsistent.");
                    String trusted=local.trustedFingerprint(contactId,id);byte[] key=SereinDeviceCrypto.conversationKey(pair.getPrivate(),userId,deviceId,contactId,id,jwk);
                    next.put(id,new Peer(contactId,id,d.optString("name","Device"),fingerprint,jwk,key,fingerprint.equals(trusted)));
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
        return trusted==total?"All "+trusted+" recipient-device fingerprints are verified on this device.":"Verify "+(total-trusted)+" recipient-device fingerprint(s) before sending.";
    }
    CompletableFuture<Void> trust(String targetDeviceId){
        return CompletableFuture.runAsync(()->{
            try{Peer peer; synchronized(this){peer=peers.get(targetDeviceId);}if(peer==null)throw new IllegalStateException("Device key is no longer available.");local.trustFingerprint(contactId,targetDeviceId,peer.fingerprint);synchronized(this){peers.put(targetDeviceId,new Peer(peer.userId,peer.deviceId,peer.name,peer.fingerprint,peer.publicJwk,peer.conversationKey,true));}status=peerStatus();notifyUi();}
            catch(Exception error){throw new java.util.concurrent.CompletionException(error);}
        });
    }

    CompletableFuture<Void> sendText(String text){return sendMessage(text,null);}
    private CompletableFuture<Void> sendMessage(String text,JSONObject attachment){
        if(!ready)return failed(new IllegalStateException("Protected device setup is not ready."));
        if(text==null||text.trim().isEmpty())return failed(new IllegalArgumentException("Message cannot be empty."));
        if(text.codePointCount(0,text.length())>4000)return failed(new IllegalArgumentException("Messages are limited to 4,000 characters."));
        return CompletableFuture.supplyAsync(()->{
            try{
                List<Peer> targets=trustedTargets();String messageId=UUID.randomUUID().toString().toLowerCase(Locale.ROOT),createdAt=java.time.Instant.now().toString();JSONArray envelopes=new JSONArray();
                for(Peer target:targets){JSONObject content=new JSONObject().put("version",1).put("text",text).put("conversation_id",contactId).put("sender_user_id",userId).put("sender_device_id",deviceId).put("recipient_user_id",contactId).put("recipient_device_id",target.deviceId);if(attachment!=null)content.put("attachment",attachment);
                    JSONObject encrypted=SereinDeviceCrypto.encryptMessage(target.conversationKey,content,contactId,messageId,userId,deviceId,contactId,target.deviceId);
                    envelopes.put(new JSONObject().put("to",target.deviceId).put("iv",encrypted.getString("iv")).put("ciphertext",encrypted.getString("ciphertext")));
                }
                JSONObject localMessage=new JSONObject().put("id",messageId).put("conversation_id",contactId).put("created_at",createdAt).put("text",text).put("mine",true).put("sender",user.optString("display_name","You")).put("status","pending").put("envelopes",envelopes);if(attachment!=null)localMessage.put("attachment",attachment);
                local.saveMessage(localMessage);notifyUi();return localMessage;
            }catch(Exception error){throw new java.util.concurrent.CompletionException(error);}
        }).thenComposeAsync(message->deliver(message));
    }
    private List<Peer> trustedTargets(){
        List<Peer> targets=new ArrayList<>();JSONArray active=contact.optJSONArray("devices");if(active==null)throw new IllegalStateException("Contact has no active devices.");
        synchronized(this){for(int i=0;i<active.length();i++){JSONObject d=active.optJSONObject(i);if(d==null)continue;Peer peer=peers.get(d.optString("id"));if(peer==null||!peer.trusted)throw new IllegalStateException("Verify every current recipient-device fingerprint before sending.");targets.add(peer);}}
        if(targets.isEmpty())throw new IllegalStateException("No recipient devices are available.");return targets;
    }
    private CompletableFuture<Void> deliver(JSONObject message){
        JSONArray envelopes=message.optJSONArray("envelopes");CompletableFuture<Void> chain=CompletableFuture.completedFuture(null);
        for(int i=0;envelopes!=null&&i<envelopes.length();i++){JSONObject e=envelopes.optJSONObject(i);if(e==null)continue;String id=message.optString("id");chain=chain.thenCompose(ignored->api.sendEnvelopeFuture(id,e.optString("to"),e.optString("iv"),e.optString("ciphertext")).thenApply(value->null));}
        return chain.thenRunAsync(()->{try{message.put("status","accepted");message.remove("envelopes");local.saveMessage(message);status="Encrypted message accepted by all recipient devices.";notifyUi();}catch(Exception error){throw new java.util.concurrent.CompletionException(error);}});
    }
    private void retryPending(){
        try{JSONArray all=local.messages(contactId);for(int i=0;i<all.length();i++){JSONObject row=all.optJSONObject(i);if(row!=null&&row.optBoolean("mine")&&"pending".equals(row.optString("status"))&&row.optJSONArray("envelopes")!=null)deliver(row).exceptionally(error->{status="Pending encrypted message will retry when the connection is available.";notifyUi();return null;});}}
        catch(Exception error){status="Local history could not be opened.";notifyUi();}
    }

    CompletableFuture<Void> poll(){
        if(!ready||busy)return CompletableFuture.completedFuture(null);busy=true;
        return pollPage(40).whenCompleteAsync((ignored,error)->{busy=false;if(error!=null){status="Secure message sync paused; retrying.";notifyUi();}});
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
                if(local.containsMessage(id)){api.acknowledgeFuture(id);advance(created,id);return;}
                Peer peer; synchronized(this){peer=peers.get(senderDevice);}if(peer==null||!peer.trusted){status=peer==null?"Refresh Contacts: the sender device is not in the accepted contact list.":"Message is held until you verify the sender-device fingerprint.";notifyUi();throw new IllegalStateException(status);}
                JSONObject content=SereinDeviceCrypto.decryptMessage(peer.conversationKey,packet.optString("iv"),packet.optString("ciphertext"),contactId,id,contactId,senderDevice,userId,deviceId);
                if(content.optInt("version")!=1||!contactId.equals(content.optString("conversation_id"))||!contactId.equals(content.optString("sender_user_id"))||!senderDevice.equals(content.optString("sender_device_id"))||!userId.equals(content.optString("recipient_user_id"))||!deviceId.equals(content.optString("recipient_device_id")))throw new SecurityException("Encrypted message routing did not match this device.");
                String text=content.optString("text","");if(text.isEmpty()||text.codePointCount(0,text.length())>4000)throw new SecurityException("Encrypted message text exceeded the protocol limit.");
                JSONObject message=new JSONObject().put("id",id).put("conversation_id",contactId).put("created_at",created).put("text",text).put("mine",false).put("sender",contactName).put("status","received");
                if(content.has("attachment")){JSONObject attachment=validateAttachment(content.getJSONObject("attachment"));message.put("attachment",attachment);}
                local.saveMessage(message);api.acknowledgeFuture(id);advance(created,id);status="Encrypted message received and stored on this device.";notifyUi();
            }catch(Exception error){throw new java.util.concurrent.CompletionException(error);}
        });
    }
    private synchronized void advance(String time,String id){if(time!=null&&!time.isEmpty()&&id!=null&&!id.isEmpty()){cursorTime=time;cursorId=id;}}
    private static JSONObject validateAttachment(JSONObject source) throws Exception {
        String id=source.optString("transfer_id"),filename=source.optString("filename"),type=source.optString("content_type");long size=source.optLong("size",-1);
        if(!id.matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")||filename.getBytes(StandardCharsets.UTF_8).length>1024||type.getBytes(StandardCharsets.UTF_8).length>128||size<0||size>MAX_CLEAR_BYTES)throw new SecurityException("Encrypted attachment details are invalid.");
        return new JSONObject().put("transfer_id",id).put("filename",safeFilename(filename)).put("content_type",type).put("size",size);
    }
    private static String safeFilename(String input){StringBuilder out=new StringBuilder();for(int i=0;i<input.length()&&out.length()<150;){int cp=input.codePointAt(i);i+=Character.charCount(cp);out.appendCodePoint(cp=='/'||cp=='\\'||Character.isISOControl(cp)?'_':cp);}String value=out.toString().trim();while(value.startsWith("."))value=value.substring(1);return value.isEmpty()?"attachment":value;}

    CompletableFuture<File> downloadAttachment(JSONObject attachment){
        return CompletableFuture.supplyAsync(()->{
            File temporary=null;byte[] contentKey=null,prefix=null;
            try{
                String transferId=attachment.getString("transfer_id"),filename=attachment.getString("filename");long expected=attachment.getLong("size");
                File existing=SereinAttachmentStore.existing(context,transferId,filename,expected);if(existing!=null)return existing;
                Object listed=api.transfers().join();if(!(listed instanceof JSONArray))throw new IllegalStateException("Encrypted transfer list was unavailable.");
                JSONObject transfer=null;JSONArray rows=(JSONArray)listed;for(int i=0;i<rows.length();i++){JSONObject row=rows.optJSONObject(i);if(row!=null&&transferId.equals(row.optString("id"))){transfer=row;break;}}
                if(transfer==null||transfer.isNull("ready_at"))throw new IllegalStateException("Encrypted transfer is incomplete, expired, or unavailable on this device.");
                String senderUser=transfer.optString("sender_user_id"),senderDevice=transfer.optString("sender_device_id"),recipientUser=transfer.optString("recipient_user_id");
                if(!userId.equals(recipientUser)&&!userId.equals(senderUser))throw new SecurityException("Transfer account binding did not match this session.");
                byte[] manifestKey;
                if(senderUser.equals(userId)){
                    if(!senderDevice.equals(deviceId))throw new SecurityException("This transfer belongs to another sending device.");
                    manifestKey=SereinDeviceCrypto.conversationKey(pair.getPrivate(),userId,deviceId,userId,deviceId,SereinDeviceCrypto.publicJwk(pair));
                }else{
                    if(!contactId.equals(senderUser))throw new SecurityException("The sender is not the selected contact.");Peer peer; synchronized(this){peer=peers.get(senderDevice);}if(peer==null||!peer.trusted)throw new SecurityException("Verify the sender-device fingerprint before downloading.");manifestKey=peer.conversationKey;
                }
                JSONObject manifest=SereinDeviceCrypto.decryptManifest(manifestKey,transfer.optString("manifest_iv"),transfer.optString("manifest_ciphertext"),transferId,senderUser,senderDevice,recipientUser,deviceId);
                if(expected<0||expected>MAX_CLEAR_BYTES)throw new SecurityException("Attachment size is outside the allowed limit.");
                int count=manifest.optInt("chunk_count",-1);int expectedCount=(int)Math.max(1,(expected+SereinDeviceCrypto.CHUNK_PLAINTEXT_BYTES-1)/SereinDeviceCrypto.CHUNK_PLAINTEXT_BYTES);
                if(manifest.optInt("version")!=1||!transferId.equals(manifest.optString("transfer_id"))||manifest.optLong("size",-1)!=expected||count<1||count>SereinDeviceCrypto.MAX_CHUNKS||count!=expectedCount||count!=transfer.optInt("chunk_count")||!filename.equals(manifest.optString("filename"))||!attachment.optString("content_type").equals(manifest.optString("content_type")))throw new SecurityException("Authenticated file manifest did not match the chat notice or transfer limits.");
                if(transfer.optLong("total_ciphertext_bytes",-1)!=expected+(long)count*16)throw new SecurityException("Encrypted transfer byte count did not match its manifest.");
                contentKey=android.util.Base64.decode(manifest.getString("content_key"),android.util.Base64.DEFAULT);prefix=android.util.Base64.decode(manifest.getString("nonce_prefix"),android.util.Base64.DEFAULT);if(contentKey.length!=32||prefix.length!=4)throw new SecurityException("Encrypted transfer key material is malformed.");
                temporary=File.createTempFile("serein-clear-",".part",context.getCacheDir());long clearBytes=0;
                try(FileOutputStream output=new FileOutputStream(temporary,false)){
                    for(int index=0;index<count;index++){
                        SereinApi.BinaryReply reply=api.transferChunk("GET",transferId,index,null,null).join();byte[] encrypted=reply.bytes;
                        if(reply.sha256==null||!SereinDeviceCrypto.sha256Hex(encrypted).equalsIgnoreCase(reply.sha256))throw new SecurityException("Encrypted chunk checksum did not match the server response.");
                        byte[] clear=SereinDeviceCrypto.decryptChunk(contentKey,prefix,index,encrypted,transferId,senderUser,senderDevice,recipientUser,count);
                        try{clearBytes+=clear.length;if(clearBytes>expected)throw new SecurityException("Decrypted attachment exceeded its authenticated size.");output.write(clear);}finally{Arrays.fill(clear,(byte)0);Arrays.fill(encrypted,(byte)0);}
                    }
                    output.flush();output.getFD().sync();
                }
                if(clearBytes!=expected||temporary.length()!=expected)throw new SecurityException("Decrypted attachment size did not match its authenticated manifest.");
                File saved;try(InputStream input=new FileInputStream(temporary)){saved=SereinAttachmentStore.save(context,transferId,filename,input,expected);}
                api.acknowledgeTransfer(transferId).join();status="Download saved. Tap Open to hand it to a compatible app.";notifyUi();return saved;
            }catch(Throwable error){throw new java.util.concurrent.CompletionException(unwrap(error));}
            finally{if(contentKey!=null)Arrays.fill(contentKey,(byte)0);if(prefix!=null)Arrays.fill(prefix,(byte)0);if(temporary!=null)temporary.delete();}
        });
    }

    CompletableFuture<Void> uploadAttachment(File source,String filename,String contentType){
        final String selectedName=filename==null?"attachment":filename;
        final String selectedType=contentType==null?"application/octet-stream":contentType;
        return CompletableFuture.runAsync(()->{
            byte[] contentKey=SereinDeviceCrypto.randomBytes(32),prefix=SereinDeviceCrypto.randomBytes(4);String transferId=UUID.randomUUID().toString().toLowerCase(Locale.ROOT);boolean created=false,uploaded=false;
            try{
                long size=source.length();if(size<0||size>MAX_CLEAR_BYTES)throw new IllegalArgumentException("This file exceeds the 64 MiB transfer limit.");
                String cleanFilename=safeFilename(selectedName),safeContentType=selectedType.isEmpty()||selectedType.length()>128?"application/octet-stream":selectedType;
                int count=(int)Math.max(1,(size+SereinDeviceCrypto.CHUNK_PLAINTEXT_BYTES-1)/SereinDeviceCrypto.CHUNK_PLAINTEXT_BYTES);long cipherBytes=size+count*16L;
                if(count>SereinDeviceCrypto.MAX_CHUNKS||cipherBytes>SereinDeviceCrypto.MAX_FILE_CIPHERTEXT_BYTES)throw new IllegalArgumentException("This file exceeds the encrypted-transfer limit.");
                List<Peer> targets=trustedTargets();JSONObject manifest=new JSONObject().put("version",1).put("transfer_id",transferId).put("filename",cleanFilename).put("content_type",safeContentType).put("size",size).put("chunk_count",count).put("content_key",android.util.Base64.encodeToString(contentKey,android.util.Base64.NO_WRAP)).put("nonce_prefix",android.util.Base64.encodeToString(prefix,android.util.Base64.NO_WRAP));
                JSONArray envelopes=new JSONArray();JSONObject selfJwk=SereinDeviceCrypto.publicJwk(pair);byte[] selfKey=SereinDeviceCrypto.conversationKey(pair.getPrivate(),userId,deviceId,userId,deviceId,selfJwk);
                JSONObject own=SereinDeviceCrypto.encryptManifest(selfKey,manifest,transferId,userId,deviceId,contactId,deviceId);envelopes.put(new JSONObject().put("device_id",deviceId).put("iv",own.getString("iv")).put("ciphertext",own.getString("ciphertext")));Arrays.fill(selfKey,(byte)0);
                for(Peer target:targets){JSONObject wrapped=SereinDeviceCrypto.encryptManifest(target.conversationKey,manifest,transferId,userId,deviceId,contactId,target.deviceId);envelopes.put(new JSONObject().put("device_id",target.deviceId).put("iv",wrapped.getString("iv")).put("ciphertext",wrapped.getString("ciphertext")));}
                JSONObject request=new JSONObject().put("id",transferId).put("recipient_user_id",contactId).put("chunk_count",count).put("total_ciphertext_bytes",cipherBytes).put("device_envelopes",envelopes);
                api.createTransfer(request).join();created=true;
                byte[] buffer=new byte[SereinDeviceCrypto.CHUNK_PLAINTEXT_BYTES];
                try(RandomAccessFile input=new RandomAccessFile(source,"r")){
                    for(int index=0;index<count;index++){
                        int wanted=(int)Math.min(buffer.length,size-(long)index*buffer.length),read=0;while(read<wanted){int n=input.read(buffer,read,wanted-read);if(n<0)throw new java.io.IOException("Selected file changed while being encrypted.");read+=n;}
                        byte[] clear=Arrays.copyOf(buffer,wanted);byte[] encrypted=SereinDeviceCrypto.encryptChunk(contentKey,prefix,index,clear,transferId,userId,deviceId,contactId,count);Arrays.fill(clear,(byte)0);
                        String hash=SereinDeviceCrypto.sha256Hex(encrypted);api.transferChunk("PUT",transferId,index,encrypted,hash).join();Arrays.fill(encrypted,(byte)0);
                    }
                    if(input.read()!=-1)throw new java.io.IOException("Selected file changed while being encrypted.");
                }
                uploaded=true;JSONObject attachment=new JSONObject().put("transfer_id",transferId).put("filename",cleanFilename).put("content_type",safeContentType).put("size",size);sendMessage("📎 "+cleanFilename,attachment).join();
            }catch(Throwable error){if(created&&!uploaded)try{api.abortTransfer(transferId).join();}catch(Throwable ignored){}throw new java.util.concurrent.CompletionException(unwrap(error));}
            finally{Arrays.fill(contentKey,(byte)0);Arrays.fill(prefix,(byte)0);}
        });
    }

    static String mimeType(Context context,Uri uri,String filename){String type=context.getContentResolver().getType(uri);if(type!=null&&!type.isEmpty())return type;String extension=MimeTypeMap.getFileExtensionFromUrl(filename);String guess=MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension==null?"":extension.toLowerCase(Locale.ROOT));return guess==null?"application/octet-stream":guess;}
    private static Throwable unwrap(Throwable error){while(error instanceof java.util.concurrent.CompletionException&&error.getCause()!=null)error=error.getCause();return error;}
    private static <T> CompletableFuture<T> failed(Throwable error){CompletableFuture<T> result=new CompletableFuture<>();result.completeExceptionally(error);return result;}
}
