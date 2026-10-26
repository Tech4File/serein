package io.serein.chat;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.view.Gravity;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputConnectionWrapper;
import android.view.inputmethod.InputContentInfo;
import android.text.Editable;
import android.text.Selection;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/** Foreground encrypted conversation with authenticated per-device keys and file transfers. */
public final class SereinConversationActivity extends Activity {
    private static final int PICK_FILE = 7412;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private SereinApi api;
    private SereinChatEngine engine;
    private JSONObject contact;
    private String accountId="";
    private LinearLayout messages, root;
    private ScrollView messageScroll;
    private TextView status;
    private EditText composer;
    private Button send, attach, emojiToggle;
    private LinearLayout emojiPanel;
    private boolean emojiPanelVisible;
    private boolean started;
    private int pollCounter;
    private int defaultWindowAnimations;
    private final Runnable pollTask = new Runnable() { @Override public void run() { if(engine!=null&&engine.ready()){engine.poll();if(++pollCounter%12==0)engine.refreshPeers();}if(started)handler.postDelayed(this,5000); } };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        defaultWindowAnimations=getWindow().getAttributes().windowAnimations;
        boolean reduced=getSharedPreferences("serein",MODE_PRIVATE).getBoolean("reduce_motion",false);
        getWindow().setWindowAnimations(reduced?0:defaultWindowAnimations);
        try {
            JSONObject account = new JSONObject(getIntent().getStringExtra("account"));
            accountId=account.optJSONObject("user")==null?"":account.optJSONObject("user").optString("id","");
            contact = new JSONObject(getIntent().getStringExtra("contact"));
            api = new SereinApi(this);
            String configured = getSharedPreferences("serein", MODE_PRIVATE).getString("api_base", "https://api.example.invalid"); api.setBaseUrl(configured);
            buildUi();
            engine = new SereinChatEngine(this, api, account, contact, this::render);
            setTitle(contact.optString("display_name", "Conversation"));
            engine.initialize().whenComplete((ignored,error)->runOnUiThread(()->{
                status.setText(error==null?engine.status():safeError(error));
                if(error==null){boolean writable=!contact.optBoolean("deleted");composer.setEnabled(writable);send.setEnabled(writable);attach.setEnabled(writable);emojiToggle.setEnabled(writable);render();if(writable)pollTask.run();}else{composer.setEnabled(false);send.setEnabled(false);attach.setEnabled(false);emojiToggle.setEnabled(false);}
            }));
        } catch (Exception error) { finish(); Toast.makeText(this,"This conversation could not be opened.",Toast.LENGTH_LONG).show(); }
    }

    private int dp(float value){return (int)(value*getResources().getDisplayMetrics().density+0.5f);}
    private void buildUi(){
        root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setBackgroundColor(SereinUi.chatBackground(this));
        LinearLayout top=SereinUi.row(this);top.setPadding(dp(8),dp(6),dp(8),dp(6));top.setBackgroundColor(SereinUi.surface(this));
        Button back=SereinUi.button(this,"←",false);back.setContentDescription("Back to chats");back.setTextSize(22);back.setPadding(0,0,0,0);back.setBackgroundColor(android.graphics.Color.TRANSPARENT);top.addView(back,new LinearLayout.LayoutParams(dp(40),dp(48)));back.setOnClickListener(v->finish());
        String displayName=contact.optString("display_name","Conversation");String initial=displayName.isEmpty()?"S":displayName.substring(0,1).toUpperCase(java.util.Locale.getDefault());TextView avatar=SereinUi.avatar(this,initial,42);avatar.setBackground(SereinUi.shape(this,SereinUi.accent(this),21));LinearLayout.LayoutParams avatarParams=SereinUi.margin(this,42,42,1,0,10,0);top.addView(avatar,avatarParams);
        LinearLayout titleBox=SereinUi.column(this);TextView title=SereinUi.text(this,displayName,17,SereinUi.text(this),true);title.setMaxLines(1);titleBox.addView(title);status=SereinUi.text(this,"Preparing secure messaging…",11,SereinUi.muted(this),false);status.setMaxLines(1);status.setEllipsize(android.text.TextUtils.TruncateAt.END);titleBox.addView(status);top.addView(titleBox,new LinearLayout.LayoutParams(0,-2,1));
        Button keys=SereinUi.button(this,"Keys",false);keys.setContentDescription("View and verify device keys");top.addView(keys,new LinearLayout.LayoutParams(-2,dp(42)));keys.setOnClickListener(v->showPeerKeys());root.addView(top);
        TextView notice=SereinUi.text(this,"🔒  Messages are encrypted for verified devices. Verify fingerprints before sending.",11,SereinUi.isDark(this)?SereinTokens.NOTICE_TEXT_DARK:SereinTokens.NOTICE_TEXT_LIGHT,false);notice.setPadding(dp(12),dp(9),dp(12),dp(9));notice.setBackgroundColor(SereinUi.isDark(this)?SereinTokens.NOTICE_DARK:SereinTokens.NOTICE_LIGHT);root.addView(notice,new LinearLayout.LayoutParams(-1,-2));
        messageScroll=new ScrollView(this);messageScroll.setFillViewport(false);messageScroll.setBackground(new SereinChatWallpaper(this));messages=new LinearLayout(this);messages.setOrientation(LinearLayout.VERTICAL);messages.setPadding(dp(10),dp(8),dp(10),dp(8));messageScroll.addView(messages);root.addView(messageScroll,new LinearLayout.LayoutParams(-1,0,1));
        emojiPanel=buildEmojiPanel();emojiPanel.setVisibility(View.GONE);root.addView(emojiPanel,new LinearLayout.LayoutParams(-1,-2));
        LinearLayout composerRow=new LinearLayout(this);composerRow.setGravity(Gravity.CENTER_VERTICAL);composerRow.setPadding(dp(5),dp(3),dp(5),dp(3));composerRow.setBackground(SereinUi.shape(this,SereinUi.surface(this),24));LinearLayout.LayoutParams composerParams=SereinUi.margin(this,-1,-2,8,6,8,7);
        emojiToggle=SereinUi.button(this,"☺",false);emojiToggle.setContentDescription("Choose an emoji");emojiToggle.setTextSize(22);emojiToggle.setBackgroundColor(android.graphics.Color.TRANSPARENT);composerRow.addView(emojiToggle,new LinearLayout.LayoutParams(dp(40),dp(44)));emojiToggle.setOnClickListener(v->toggleEmojiPanel());
        attach=SereinUi.button(this,"＋",false);attach.setContentDescription("Attach a file, GIF, or image");attach.setTextSize(22);attach.setBackgroundColor(android.graphics.Color.TRANSPARENT);composerRow.addView(attach,new LinearLayout.LayoutParams(dp(38),dp(44)));attach.setOnClickListener(v->pickFile());
        composer=new RichContentEditText(this,(content,mime,permission)->receiveKeyboardContent(content,mime,permission));composer.setHint("Write a message…");composer.setTextSize(SereinUi.fontSize(this,16));composer.setMinLines(1);composer.setMaxLines(4);composer.setPadding(dp(8),dp(8),dp(8),dp(8));composer.setBackgroundColor(android.graphics.Color.TRANSPARENT);composerRow.addView(composer,new LinearLayout.LayoutParams(0,-2,1));
        send=SereinUi.button(this,"↑",true);send.setContentDescription("Send encrypted message");send.setTextSize(21);send.setPadding(0,0,0,0);composerRow.addView(send,new LinearLayout.LayoutParams(dp(42),dp(42)));send.setOnClickListener(v->sendText());root.addView(composerRow,composerParams);composer.setEnabled(false);send.setEnabled(false);attach.setEnabled(false);emojiToggle.setEnabled(false);setContentView(root);
    }
    private void sendText(){if(contact!=null&&contact.optBoolean("deleted")){toast("This archived conversation is read-only.");return;}String text=composer.getText().toString().trim();if(text.isEmpty())return;send.setEnabled(false);status.setText("Encrypting separately for verified recipient devices…");engine.sendText(text).whenComplete((ignored,error)->runOnUiThread(()->{send.setEnabled(!contact.optBoolean("deleted"));if(error!=null)status.setText(safeError(error));else{composer.setText("");status.setText(engine.status());}render();}));}
    private void pickFile(){if(contact!=null&&contact.optBoolean("deleted")){toast("This archived conversation is read-only.");return;}if(engine==null||!engine.ready()){toast("Secure messaging is still starting.");return;}Intent pick=new Intent(Intent.ACTION_OPEN_DOCUMENT);pick.addCategory(Intent.CATEGORY_OPENABLE);pick.setType("*/*");pickFileIntent(pick);}
    private void pickFileIntent(Intent intent){try{startActivityForResult(intent,PICK_FILE);}catch(Exception error){toast("No file picker is available on this device.");}}
    @Override protected void onActivityResult(int requestCode,int resultCode,Intent data){super.onActivityResult(requestCode,resultCode,data);if(requestCode!=PICK_FILE||resultCode!=RESULT_OK||data==null||data.getData()==null)return;Uri uri=data.getData();String name=displayName(uri);String type=SereinChatEngine.mimeType(this,uri,name);stageAndUploadAttachment(uri,name,type,null);}
    private void receiveKeyboardContent(InputContentInfo content,String mime,boolean permissionGranted){runOnUiThread(()->{if(contact==null||contact.optBoolean("deleted")||engine==null||!engine.ready()){if(permissionGranted)try{content.releasePermission();}catch(Exception ignored){}toast("Secure messaging is not ready for this GIF or image.");return;}String name=displayName(content.getContentUri());if(name==null||name.trim().isEmpty()||"attachment".equals(name))name="image/gif".equalsIgnoreCase(mime)?"keyboard.gif":"keyboard-image";stageAndUploadAttachment(content.getContentUri(),name,mime,permissionGranted?content:null);});}
    private void stageAndUploadAttachment(Uri uri,String name,String type,InputContentInfo permission){if(engine==null||!engine.ready()){toast("Secure messaging is still starting.");if(permission!=null)try{permission.releasePermission();}catch(Exception ignored){}return;}status.setText("Preparing encrypted file transfer…");attach.setEnabled(false);
        CompletableFuture.supplyAsync(()->{File staged=null;try{staged=File.createTempFile("serein-upload-",".bin",getCacheDir());long copied=0;try(InputStream in=getContentResolver().openInputStream(uri);FileOutputStream out=new FileOutputStream(staged)){if(in==null)throw new java.io.IOException("Selected file could not be opened.");byte[] buffer=new byte[64*1024];int n;while((n=in.read(buffer))!=-1){copied+=n;if(copied>SereinDeviceCrypto.MAX_FILE_CIPHERTEXT_BYTES)throw new java.io.IOException("Selected file exceeds the 64 MiB encrypted-transfer limit.");out.write(buffer,0,n);}out.flush();out.getFD().sync();}return staged;}catch(Exception error){if(staged!=null)staged.delete();throw new java.util.concurrent.CompletionException(error);}finally{if(permission!=null)try{permission.releasePermission();}catch(Exception ignored){}}}).thenCompose(file->engine.uploadAttachment(file,name,type).whenComplete((ignored,error)->file.delete())).whenComplete((ignored,error)->runOnUiThread(()->{attach.setEnabled(!contact.optBoolean("deleted"));status.setText(error==null?engine.status():safeError(error));render();}));
    }
    private LinearLayout buildEmojiPanel(){LinearLayout panel=new LinearLayout(this);panel.setOrientation(LinearLayout.VERTICAL);panel.setPadding(dp(7),dp(6),dp(7),dp(6));panel.setBackgroundColor(SereinUi.surface(this));Button gif=SereinUi.button(this,"Choose GIF or image",false);gif.setOnClickListener(v->pickFile());panel.addView(gif,new LinearLayout.LayoutParams(-1,dp(40)));String[] emojis={"😀","😃","😄","😁","😆","😅","😂","🙂","🙃","😉","😊","😍","🥰","😘","😋","😎","🤔","🥳","😴","😭","😡","🤗","🤩","🤝","👋","🙌","👏","👍","👎","👌","✌️","🤞","🙏","💪","❤️","🧡","💛","💚","💙","💜","🖤","🤍","💔","💕","💖","💯","🔥","✨","🎉","🎂","☕","🍕","🌈","🌻","🐱","🐶","🦋","🌍","🚀","🎵"};ScrollView scroll=new ScrollView(this);LinearLayout rows=new LinearLayout(this);rows.setOrientation(LinearLayout.VERTICAL);for(int offset=0;offset<emojis.length;offset+=8){LinearLayout row=new LinearLayout(this);for(int i=offset;i<Math.min(offset+8,emojis.length);i++){final String emoji=emojis[i];Button option=SereinUi.button(this,emoji,false);option.setTextSize(23);option.setPadding(0,0,0,0);option.setContentDescription("Insert "+emoji);option.setOnClickListener(v->insertEmoji(emoji));row.addView(option,new LinearLayout.LayoutParams(0,dp(42),1));}rows.addView(row,new LinearLayout.LayoutParams(-1,-2));}scroll.addView(rows);LinearLayout.LayoutParams scrollParams=new LinearLayout.LayoutParams(-1,dp(132));scrollParams.topMargin=dp(4);panel.addView(scroll,scrollParams);return panel;}
    private void toggleEmojiPanel(){emojiPanelVisible=!emojiPanelVisible;emojiPanel.setVisibility(emojiPanelVisible?View.VISIBLE:View.GONE);emojiToggle.setText(emojiPanelVisible?"×":"☺");}
    private void insertEmoji(String emoji){if(composer==null||!composer.isEnabled())return;Editable value=composer.getText();int start=Selection.getSelectionStart(value),end=Selection.getSelectionEnd(value);if(start<0)start=value.length();if(end<0)end=start;value.replace(Math.min(start,end),Math.max(start,end),emoji);int cursor=Math.min(start,end)+emoji.length();composer.setSelection(Math.min(cursor,value.length()));composer.requestFocus();}
    private static final class RichContentEditText extends EditText{
        interface Receiver{void receive(InputContentInfo content,String mime,boolean permissionGranted);}
        private final Receiver receiver;
        RichContentEditText(Context context,Receiver receiver){super(context);this.receiver=receiver;setInputType(android.text.InputType.TYPE_CLASS_TEXT|android.text.InputType.TYPE_TEXT_FLAG_CAP_SENTENCES|android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE);}
        @Override public InputConnection onCreateInputConnection(EditorInfo attrs){InputConnection base=super.onCreateInputConnection(attrs);if(base==null)return null;attrs.contentMimeTypes=new String[]{"image/gif","image/*"};return new InputConnectionWrapper(base,false){@Override public boolean commitContent(InputContentInfo content,int flags,Bundle opts){String mime=null;android.content.ClipDescription description=content.getDescription();for(int i=0;i<description.getMimeTypeCount();i++){String candidate=description.getMimeType(i);if(candidate!=null&&candidate.toLowerCase(java.util.Locale.ROOT).startsWith("image/")){mime=candidate;break;}}if(mime==null)return super.commitContent(content,flags,opts);boolean granted=false;if((flags&InputConnection.INPUT_CONTENT_GRANT_READ_URI_PERMISSION)!=0){try{content.requestPermission();granted=true;}catch(Exception error){return false;}}receiver.receive(content,mime,granted);return true;}};}
    }
    private String displayName(Uri uri){try(Cursor cursor=getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){if(cursor!=null&&cursor.moveToFirst())return cursor.getString(0);}catch(Exception ignored){}return "attachment";}
    private void render(){if(!started||messages==null)return;runOnUiThread(()->{try{status.setText(engine.status());if(contact.optBoolean("deleted")){String name=contact.optString("display_name","Conversation");setTitle(name);composer.setEnabled(false);send.setEnabled(false);attach.setEnabled(false);}JSONArray rows=engine.messages();messages.removeAllViews();String connected=contact.optString("connected_at","");if(!connected.isEmpty())renderSystemEvent("You and "+contact.optString("display_name","this person").replaceFirst("\\s+\\(Deleted User\\)$","")+" are now friends.",connected);for(int i=0;i<rows.length();i++){JSONObject row=rows.optJSONObject(i);if(row!=null)renderMessage(row);}if(contact.optBoolean("deleted")){String name=contact.optString("display_name","This person").replaceFirst("\\s+\\(Deleted User\\)$","");renderSystemEvent(name+" deleted his account. No new messages are allowed.",contact.optString("deleted_at",""));}messageScroll.post(()->messageScroll.fullScroll(View.FOCUS_DOWN));}catch(Exception error){status.setText("Encrypted local history could not be displayed.");}});}
    private void renderSystemEvent(String text,String timestamp){LinearLayout event=new LinearLayout(this);event.setOrientation(LinearLayout.VERTICAL);event.setGravity(Gravity.CENTER);event.setPadding(dp(12),dp(9),dp(12),dp(9));event.setBackgroundColor(0x122b7664);TextView label=SereinUi.text(this,text,11,SereinUi.muted(this),false);label.setGravity(Gravity.CENTER);event.addView(label);if(timestamp!=null&&!timestamp.isEmpty()){TextView date=SereinUi.text(this,formatEventDate(timestamp),9,SereinUi.muted(this),false);date.setGravity(Gravity.CENTER);event.addView(date);}messages.addView(event,SereinUi.margin(this,-2,-2,0,12,0,12));}
    private String formatEventDate(String timestamp){try{return java.time.Instant.parse(timestamp).atZone(java.time.ZoneId.systemDefault()).format(java.time.format.DateTimeFormatter.ofPattern("MMM d, yyyy · h:mm a",java.util.Locale.getDefault()));}catch(Exception ignored){return timestamp;}}
    private void renderMessage(JSONObject row){
        boolean mine=row.optBoolean("mine");
        LinearLayout line=new LinearLayout(this);line.setGravity(mine?Gravity.END:Gravity.START);
        LinearLayout bubble=new LinearLayout(this);bubble.setOrientation(LinearLayout.VERTICAL);bubble.setPadding(dp(12),dp(8),dp(12),dp(7));bubble.setBackground(SereinUi.chatBubble(this,mine));
        int maximum=Math.max(dp(180),getResources().getDisplayMetrics().widthPixels-dp(72));bubble.setMaxWidth((int)(maximum*.84f));
        LinearLayout.LayoutParams bubbleParams=new LinearLayout.LayoutParams(-2,-2);line.addView(bubble,bubbleParams);messages.addView(line,SereinUi.margin(this,-1,-2,0,4,0,5));
        TextView body=SereinUi.text(this,row.optString("text"),16,SereinUi.chatBubbleText(this,mine),false);body.setTextIsSelectable(true);bubble.addView(body);
        JSONObject attachment=row.optJSONObject("attachment");if(attachment!=null){String filename=attachment.optString("filename","attachment"),mime=attachment.optString("content_type","application/octet-stream");long size=attachment.optLong("size",0);TextView details=SereinUi.text(this,mime+" · "+formatBytes(size),10,SereinUi.muted(this),false);bubble.addView(details);File saved=SereinAttachmentStore.existing(this,accountId,attachment.optString("transfer_id"),filename,size);Button action=SereinUi.button(this,saved==null?"Download":"Open",false);bubble.addView(action,SereinUi.margin(this,-1,40,0,8,0,0));action.setOnClickListener(v->{if(saved!=null){try{SereinAttachmentStore.open(this,saved,mime);}catch(Exception error){toast(error.getMessage());}return;}action.setEnabled(false);action.setText("Decrypting…");engine.downloadAttachment(attachment).whenComplete((file,error)->runOnUiThread(()->{action.setEnabled(true);if(error!=null){action.setText("Download");toast(safeError(error));}else{action.setText("Open");try{SereinAttachmentStore.open(this,file,mime);}catch(Exception openError){toast(openError.getMessage());}}render();}));});}
        TextView meta=SereinUi.text(this,row.optString("created_at"),10,mine&&SereinUi.isDark(this)?0xFFB9D9D0:SereinUi.muted(this),false);meta.setGravity(Gravity.END);bubble.addView(meta);
    }
    private String formatBytes(long value){if(value<1024)return value+" B";if(value<1024*1024)return String.format(java.util.Locale.ROOT,"%.1f KB",value/1024.0);return String.format(java.util.Locale.ROOT,"%.1f MB",value/1048576.0);}
    private void showPeerKeys(){if(engine==null)return;List<SereinChatEngine.Peer> peers=engine.peers();if(peers.isEmpty()){new AlertDialog.Builder(this).setTitle("Device fingerprints").setMessage(engine.status()).setPositiveButton("OK",null).show();return;}
        LinearLayout list=new LinearLayout(this);list.setOrientation(LinearLayout.VERTICAL);list.setPadding(dp(12),dp(8),dp(12),dp(8));
        for(SereinChatEngine.Peer peer:peers){TextView label=SereinUi.text(this,peer.name+"\nMessage capability: "+(peer.ratchetVersion>=3?"experimental ratchet v3":"two-layer static v2")+"\n"+peer.fingerprint.replaceAll("(.{4})","$1 ").trim()+"\n"+(peer.trusted?"Verified on this device":"Not verified — compare through a separate trusted channel"),11,SereinUi.text(this),false);label.setTextIsSelectable(true);list.addView(label);if(!peer.trusted){Button trust=SereinUi.button(this,"I compared this fingerprint and capability",false);list.addView(trust,SereinUi.margin(this,-1,40,0,8,0,14));trust.setOnClickListener(v->{String previous=engine.previousFingerprint(peer.deviceId);int previousVersion=engine.previousRatchetVersion(peer.deviceId);String detail="Compare the complete fingerprint and reported ratchet capability with "+contact.optString("display_name","your contact")+" through a separate trusted channel.\n\nReported capability: "+(peer.ratchetVersion>=3?"experimental ratchet v3":"two-layer static v2")+"\n\n"+peer.fingerprint.replaceAll("(.{4})","$1 ").trim()+(previous.isEmpty()?"":"\n\nPreviously trusted key: "+previous)+(previous.isEmpty()||previous.equals(peer.fingerprint)?"":"\n\nThis key changed. Verify the new fingerprint directly before trusting it.")+(previousVersion==peer.ratchetVersion?"":"\n\nThe peer ratchet capability changed. Re-verify before trusting it.");new AlertDialog.Builder(this).setTitle("Verify device key").setMessage(detail).setNegativeButton("Cancel",null).setPositiveButton("Trust this key",(d,w)->engine.trust(peer.deviceId).whenComplete((ignored,error)->runOnUiThread(()->{if(error!=null)toast(safeError(error));else{toast("Device fingerprint trusted on this device.");showPeerKeys();}}))).show();});}}
        ScrollView scroll=new ScrollView(this);scroll.addView(list);new AlertDialog.Builder(this).setTitle("End-to-end encryption keys").setView(scroll).setPositiveButton("Done",null).show();
    }
    private String safeError(Throwable error){Throwable value=error;while(value.getCause()!=null&&(value instanceof java.util.concurrent.CompletionException||value instanceof java.util.concurrent.ExecutionException))value=value.getCause();String message=value.getMessage();return message==null?"Encrypted operation failed; no cleartext was sent.":message;}
    private void toast(String value){Toast.makeText(this,value==null?"Operation failed.":value,Toast.LENGTH_LONG).show();}
    @Override protected void onResume(){super.onResume();started=true;if(engine!=null&&engine.ready())pollTask.run();}
    @Override protected void onPause(){started=false;handler.removeCallbacks(pollTask);super.onPause();}
}
