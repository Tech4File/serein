package io.serein.chat;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.view.Gravity;
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
import java.util.ArrayList;
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
    private Button send, attach;
    private boolean started;
    private int pollCounter;
    private final Runnable pollTask = new Runnable() { @Override public void run() { if(engine!=null&&engine.ready()){engine.poll();if(++pollCounter%12==0)engine.refreshPeers();}if(started)handler.postDelayed(this,5000); } };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
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
                if(error==null){boolean writable=!contact.optBoolean("deleted");composer.setEnabled(writable);send.setEnabled(writable);attach.setEnabled(writable);render();if(writable)pollTask.run();}else{composer.setEnabled(false);send.setEnabled(false);attach.setEnabled(false);}
            }));
        } catch (Exception error) { finish(); Toast.makeText(this,"This conversation could not be opened.",Toast.LENGTH_LONG).show(); }
    }

    private int dp(float value){return (int)(value*getResources().getDisplayMetrics().density+0.5f);}
    private void buildUi(){
        root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setBackgroundColor(SereinUi.bg(this));root.setPadding(dp(14),dp(10),dp(14),dp(8));
        LinearLayout top=new LinearLayout(this);top.setGravity(Gravity.CENTER_VERTICAL);TextView title=SereinUi.text(this,contact.optString("display_name","Conversation"),18,SereinUi.text(this),true);top.addView(title,new LinearLayout.LayoutParams(0,dp(44),1));Button keys=SereinUi.button(this,"Device keys",false);top.addView(keys);keys.setOnClickListener(v->showPeerKeys());root.addView(top);
        status=SereinUi.text(this,"Preparing secure messaging…",10,SereinUi.muted(this),false);status.setPadding(0,dp(5),0,dp(8));root.addView(status);
        messageScroll=new ScrollView(this);messageScroll.setFillViewport(false);messages=new LinearLayout(this);messages.setOrientation(LinearLayout.VERTICAL);messageScroll.addView(messages);root.addView(messageScroll,new LinearLayout.LayoutParams(-1,0,1));
        LinearLayout composerRow=new LinearLayout(this);composerRow.setGravity(Gravity.BOTTOM);attach=SereinUi.button(this,"＋",false);composerRow.addView(attach,new LinearLayout.LayoutParams(dp(44),dp(46)));attach.setOnClickListener(v->pickFile());
        composer=new EditText(this);composer.setHint("Write an encrypted message…");composer.setTextSize(16);composer.setMinLines(1);composer.setMaxLines(4);composer.setPadding(dp(10),dp(8),dp(10),dp(8));composer.setBackgroundColor(SereinUi.surface(this));composerRow.addView(composer,new LinearLayout.LayoutParams(0,-2,1));
        send=SereinUi.button(this,"Send",true);composerRow.addView(send,new LinearLayout.LayoutParams(dp(64),dp(46)));send.setOnClickListener(v->sendText());root.addView(composerRow);composer.setEnabled(false);send.setEnabled(false);attach.setEnabled(false);setContentView(root);
    }
    private void sendText(){if(contact!=null&&contact.optBoolean("deleted")){toast("This archived conversation is read-only.");return;}String text=composer.getText().toString().trim();if(text.isEmpty())return;send.setEnabled(false);status.setText("Encrypting separately for verified recipient devices…");engine.sendText(text).whenComplete((ignored,error)->runOnUiThread(()->{send.setEnabled(!contact.optBoolean("deleted"));if(error!=null)status.setText(safeError(error));else{composer.setText("");status.setText(engine.status());}render();}));}
    private void pickFile(){if(contact!=null&&contact.optBoolean("deleted")){toast("This archived conversation is read-only.");return;}if(engine==null||!engine.ready()){toast("Secure messaging is still starting.");return;}Intent pick=new Intent(Intent.ACTION_OPEN_DOCUMENT);pick.addCategory(Intent.CATEGORY_OPENABLE);pick.setType("*/*");pickFileIntent(pick);}
    private void pickFileIntent(Intent intent){try{startActivityForResult(intent,PICK_FILE);}catch(Exception error){toast("No file picker is available on this device.");}}
    @Override protected void onActivityResult(int requestCode,int resultCode,Intent data){super.onActivityResult(requestCode,resultCode,data);if(requestCode!=PICK_FILE||resultCode!=RESULT_OK||data==null||data.getData()==null)return;Uri uri=data.getData();String name=displayName(uri);String type=SereinChatEngine.mimeType(this,uri,name);status.setText("Preparing encrypted file transfer…");attach.setEnabled(false);
        CompletableFuture.supplyAsync(()->{File staged=null;try{staged=File.createTempFile("serein-upload-",".bin",getCacheDir());long copied=0;try(InputStream in=getContentResolver().openInputStream(uri);FileOutputStream out=new FileOutputStream(staged)){if(in==null)throw new java.io.IOException("Selected file could not be opened.");byte[] buffer=new byte[64*1024];int n;while((n=in.read(buffer))!=-1){copied+=n;if(copied>SereinDeviceCrypto.MAX_FILE_CIPHERTEXT_BYTES)throw new java.io.IOException("Selected file exceeds the 64 MiB encrypted-transfer limit.");out.write(buffer,0,n);}out.flush();out.getFD().sync();}return staged;}catch(Exception error){if(staged!=null)staged.delete();throw new java.util.concurrent.CompletionException(error);}}).thenCompose(file->engine.uploadAttachment(file,name,type).whenComplete((ignored,error)->file.delete())).whenComplete((ignored,error)->runOnUiThread(()->{attach.setEnabled(!contact.optBoolean("deleted"));status.setText(error==null?engine.status():safeError(error));render();}));
    }
    private String displayName(Uri uri){try(Cursor cursor=getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){if(cursor!=null&&cursor.moveToFirst())return cursor.getString(0);}catch(Exception ignored){}return "attachment";}
    private void render(){if(!started||messages==null)return;runOnUiThread(()->{try{status.setText(engine.status());if(contact.optBoolean("deleted")){String name=contact.optString("display_name","Conversation");setTitle(name);composer.setEnabled(false);send.setEnabled(false);attach.setEnabled(false);}JSONArray rows=engine.messages();messages.removeAllViews();String connected=contact.optString("connected_at","");if(!connected.isEmpty())renderSystemEvent("You and "+contact.optString("display_name","this person").replaceFirst("\\s+\\(Deleted User\\)$","")+" are now friends.",connected);for(int i=0;i<rows.length();i++){JSONObject row=rows.optJSONObject(i);if(row!=null)renderMessage(row);}if(contact.optBoolean("deleted")){String name=contact.optString("display_name","This person").replaceFirst("\\s+\\(Deleted User\\)$","");renderSystemEvent(name+" deleted his account. No new messages are allowed.",contact.optString("deleted_at",""));}messageScroll.post(()->messageScroll.fullScroll(View.FOCUS_DOWN));}catch(Exception error){status.setText("Encrypted local history could not be displayed.");}});}
    private void renderSystemEvent(String text,String timestamp){LinearLayout event=new LinearLayout(this);event.setOrientation(LinearLayout.VERTICAL);event.setGravity(Gravity.CENTER);event.setPadding(dp(12),dp(9),dp(12),dp(9));event.setBackgroundColor(0x122b7664);TextView label=SereinUi.text(this,text,11,SereinUi.muted(this),false);label.setGravity(Gravity.CENTER);event.addView(label);if(timestamp!=null&&!timestamp.isEmpty()){TextView date=SereinUi.text(this,formatEventDate(timestamp),9,SereinUi.muted(this),false);date.setGravity(Gravity.CENTER);event.addView(date);}messages.addView(event,SereinUi.margin(this,-2,-2,0,12,0,12));}
    private String formatEventDate(String timestamp){try{return java.time.Instant.parse(timestamp).atZone(java.time.ZoneId.systemDefault()).format(java.time.format.DateTimeFormatter.ofPattern("MMM d, yyyy · h:mm a",java.util.Locale.getDefault()));}catch(Exception ignored){return timestamp;}}
    private void renderMessage(JSONObject row){
        LinearLayout bubble=new LinearLayout(this);bubble.setOrientation(LinearLayout.VERTICAL);bubble.setPadding(dp(12),dp(9),dp(12),dp(9));bubble.setBackgroundColor(SereinUi.surface(this));LinearLayout.LayoutParams params=SereinUi.margin(this,-1,-2,0,4,0,6);messages.addView(bubble,params);
        TextView body=SereinUi.text(this,row.optString("text"),14,SereinUi.text(this),false);body.setTextIsSelectable(true);bubble.addView(body);
        JSONObject attachment=row.optJSONObject("attachment");if(attachment!=null){String filename=attachment.optString("filename","attachment"),mime=attachment.optString("content_type","application/octet-stream");long size=attachment.optLong("size",0);TextView details=SereinUi.text(this,mime+" · "+formatBytes(size),10,SereinUi.muted(this),false);bubble.addView(details);File saved=SereinAttachmentStore.existing(this,accountId,attachment.optString("transfer_id"),filename,size);Button action=SereinUi.button(this,saved==null?"Download":"Open",false);bubble.addView(action,SereinUi.margin(this,-1,40,0,8,0,0));action.setOnClickListener(v->{if(saved!=null){try{SereinAttachmentStore.open(this,saved,mime);}catch(Exception error){toast(error.getMessage());}return;}action.setEnabled(false);action.setText("Decrypting…");engine.downloadAttachment(attachment).whenComplete((file,error)->runOnUiThread(()->{action.setEnabled(true);if(error!=null){action.setText("Download");toast(safeError(error));}else{action.setText("Open");try{SereinAttachmentStore.open(this,file,mime);}catch(Exception openError){toast(openError.getMessage());}}render();}));});}
        TextView meta=SereinUi.text(this,(row.optBoolean("mine")?"You":""+row.optString("sender"))+" · "+row.optString("created_at"),10,SereinUi.muted(this),false);bubble.addView(meta);
    }
    private String formatBytes(long value){if(value<1024)return value+" B";if(value<1024*1024)return String.format(java.util.Locale.ROOT,"%.1f KB",value/1024.0);return String.format(java.util.Locale.ROOT,"%.1f MB",value/1048576.0);}
    private void showPeerKeys(){if(engine==null)return;List<SereinChatEngine.Peer> peers=engine.peers();if(peers.isEmpty()){new AlertDialog.Builder(this).setTitle("Device fingerprints").setMessage(engine.status()).setPositiveButton("OK",null).show();return;}
        LinearLayout list=new LinearLayout(this);list.setOrientation(LinearLayout.VERTICAL);list.setPadding(dp(12),dp(8),dp(12),dp(8));
        for(SereinChatEngine.Peer peer:peers){TextView label=SereinUi.text(this,peer.name+"\n"+peer.fingerprint.replaceAll("(.{4})","$1 ").trim()+"\n"+(peer.trusted?"Verified on this device":"Not verified — compare through a separate trusted channel"),11,SereinUi.text(this),false);label.setTextIsSelectable(true);list.addView(label);if(!peer.trusted){Button trust=SereinUi.button(this,"I compared this fingerprint",false);list.addView(trust,SereinUi.margin(this,-1,40,0,8,0,14));trust.setOnClickListener(v->{String previous=engine.previousFingerprint(peer.deviceId);String detail="Compare the complete fingerprint with "+contact.optString("display_name","your contact")+" through a separate trusted channel.\n\n"+peer.fingerprint.replaceAll("(.{4})","$1 ").trim()+(previous.isEmpty()?"":"\n\nPreviously trusted key: "+previous)+(previous.isEmpty()||previous.equals(peer.fingerprint)?"":"\n\nThis key changed. Verify the new fingerprint directly before trusting it.");new AlertDialog.Builder(this).setTitle("Verify device key").setMessage(detail).setNegativeButton("Cancel",null).setPositiveButton("Trust this key",(d,w)->engine.trust(peer.deviceId).whenComplete((ignored,error)->runOnUiThread(()->{if(error!=null)toast(safeError(error));else{toast("Device fingerprint trusted on this device.");showPeerKeys();}}))).show();});}}
        ScrollView scroll=new ScrollView(this);scroll.addView(list);new AlertDialog.Builder(this).setTitle("End-to-end encryption keys").setView(scroll).setPositiveButton("Done",null).show();
    }
    private String safeError(Throwable error){Throwable value=error;while(value.getCause()!=null&&(value instanceof java.util.concurrent.CompletionException||value instanceof java.util.concurrent.ExecutionException))value=value.getCause();String message=value.getMessage();return message==null?"Encrypted operation failed; no cleartext was sent.":message;}
    private void toast(String value){Toast.makeText(this,value==null?"Operation failed.":value,Toast.LENGTH_LONG).show();}
    @Override protected void onResume(){super.onResume();started=true;if(engine!=null&&engine.ready())pollTask.run();}
    @Override protected void onPause(){started=false;handler.removeCallbacks(pollTask);super.onPause();}
}
