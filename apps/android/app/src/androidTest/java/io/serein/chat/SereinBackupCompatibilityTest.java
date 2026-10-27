package io.serein.chat;

import android.test.AndroidTestCase;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.UUID;

/** Instrumented compatibility checks run on the minimum and current Android emulator APIs. */
public final class SereinBackupCompatibilityTest extends AndroidTestCase {
    public void testV3RoundTripAndAccountBinding() throws Exception {
        String accountId=UUID.randomUUID().toString().toLowerCase(java.util.Locale.ROOT);
        String username="backup_test";
        JSONObject message=new JSONObject().put("id",UUID.randomUUID().toString()).put("conversation_id",UUID.randomUUID().toString())
                .put("created_at","2026-10-25T10:11:12.123Z").put("text","older Android fixture")
                .put("mine",true).put("sender","Backup Test").put("status","accepted");
        JSONObject snapshot=new JSONObject().put("snapshot_version",1).put("created_at","2026-10-25T10:11:12.123Z")
                .put("messages",new JSONArray().put(message)).put("media",new JSONObject().put("included",false).put("policy","references-only"));
        byte[] backupKey=new byte[32];for(int i=0;i<backupKey.length;i++)backupKey[i]=(byte)(i+1);
        byte[] file=SereinBackupStore.create(accountId,username,backupKey,snapshot);
        SereinBackupStore.Info info=SereinBackupStore.inspect(file);
        assertEquals(3,info.version);
        assertTrue(info.createdAt.contains("T"));
        JSONObject opened=SereinBackupStore.open(accountId,username,"",backupKey,file);
        assertEquals(1,opened.getJSONArray("messages").length());
        assertEquals("older Android fixture",opened.getJSONArray("messages").getJSONObject(0).getString("text"));
        try {
            SereinBackupStore.open(UUID.randomUUID().toString(),username,"",backupKey,file);
            fail("A different account ID must not decrypt this backup.");
        } catch (Exception expected) { }
        java.util.Arrays.fill(backupKey,(byte)0);
    }

    public void testLocalRestoreMergeIsIdempotentAndKeepsExistingRows() throws Exception {
        String accountId=UUID.randomUUID().toString().toLowerCase(java.util.Locale.ROOT);
        try {
            SereinLocalStore store=new SereinLocalStore(getContext(),accountId);
            String id=UUID.randomUUID().toString(),conversation=UUID.randomUUID().toString();
            JSONObject original=new JSONObject().put("id",id).put("conversation_id",conversation)
                    .put("created_at","2026-10-25T10:11:12.123Z").put("text","existing")
                    .put("mine",true).put("sender","A").put("status","accepted");
            assertEquals(1,store.mergeBackupMessages(new JSONArray().put(original)));
            JSONObject altered= new JSONObject(original.toString()).put("text","must not overwrite");
            assertEquals(0,store.mergeBackupMessages(new JSONArray().put(altered)));
            JSONArray rows=store.backupMessages();
            assertEquals(1,rows.length());
            assertEquals("existing",rows.getJSONObject(0).getString("text"));
        } finally {
            SereinLocalStore.deleteForAccount(getContext(),accountId);
        }
    }

    public void testMalformedTimestampAndDuplicateBackupIdsAreRejected() throws Exception {
        String accountId=UUID.randomUUID().toString().toLowerCase(java.util.Locale.ROOT);
        try {
            SereinLocalStore store=new SereinLocalStore(getContext(),accountId);
            String id=UUID.randomUUID().toString(),conversation=UUID.randomUUID().toString();
            JSONObject row=new JSONObject().put("id",id).put("conversation_id",conversation)
                    .put("created_at","not-a-time").put("text","invalid").put("status","received");
            try { store.mergeBackupMessages(new JSONArray().put(row)); fail("Malformed timestamps must be rejected."); }
            catch (IllegalArgumentException expected) { }
            row.put("created_at","2026-10-25T10:11:12.123Z");
            try { store.mergeBackupMessages(new JSONArray().put(row).put(new JSONObject(row.toString()))); fail("Duplicate IDs within a snapshot must be rejected."); }
            catch (IllegalArgumentException expected) { }
            assertEquals(0,store.backupMessages().length());
        } finally {
            SereinLocalStore.deleteForAccount(getContext(),accountId);
        }
    }
}
