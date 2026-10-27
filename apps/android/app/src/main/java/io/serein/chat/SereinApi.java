package io.serein.chat;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** First-party REST client using Android/JDK networking only. No third-party runtime packages. */
final class SereinApi {
    interface Callback { void complete(Object result, String error); }
    private final Context context;
    private final ExecutorService worker = Executors.newFixedThreadPool(2);
    private final Handler main = new Handler(Looper.getMainLooper());
    private final SessionVault sessionVault;
    private volatile String baseUrl;

    SereinApi(Context context) {
        this.context = context.getApplicationContext();
        this.sessionVault = new SessionVault(this.context);
        this.baseUrl = this.context.getSharedPreferences("serein", Context.MODE_PRIVATE)
                .getString("api_base", "https://api.example.invalid");
    }
    String baseUrl() { return baseUrl; }
    String normalizeBaseUrl(String value) {
        String clean = value == null ? "" : value.trim().replaceAll("/+$", "");
        try { URL parsed = new URL(clean); if (!"https".equalsIgnoreCase(parsed.getProtocol()) || parsed.getHost().isEmpty() || parsed.getUserInfo()!=null || (parsed.getPath()!=null&&!parsed.getPath().isEmpty()&&!parsed.getPath().equals("/")) || parsed.getQuery()!=null || parsed.getRef()!=null) throw new IllegalArgumentException("Use an HTTPS server origin without a path, credentials, or query values."); }
        catch (java.net.MalformedURLException invalid) { throw new IllegalArgumentException("Enter a valid HTTPS server origin."); }
        return clean;
    }
    void setBaseUrl(String value) {
        String clean=normalizeBaseUrl(value);baseUrl=clean;
        context.getSharedPreferences("serein", Context.MODE_PRIVATE).edit().putString("api_base", clean).apply();
    }
    void testConnection(String candidate, Callback cb) {
        final String origin;
        try { origin=normalizeBaseUrl(candidate); } catch (Exception e) { cb.complete(null,e.getMessage());return; }
        worker.execute(() -> {
            Object result=null;String error=null;HttpURLConnection connection=null;
            try {
                connection=(HttpURLConnection)new URL(origin+"/healthz").openConnection();connection.setRequestMethod("GET");connection.setConnectTimeout(8000);connection.setReadTimeout(10000);connection.setInstanceFollowRedirects(false);connection.setRequestProperty("Accept","application/json");
                int code=connection.getResponseCode();InputStream stream=code>=200&&code<400?connection.getInputStream():connection.getErrorStream();String body=stream==null?"{}":readFully(stream);result=body.isEmpty()?new JSONObject():new org.json.JSONTokener(body).nextValue();
                if((code<200||code>=300)&&code!=503)error="Server returned HTTP "+code+".";
            } catch(Exception e) { error="Could not reach the server over HTTPS."; }
            finally { if(connection!=null)connection.disconnect(); }
            Object finalResult=result;String finalError=error;main.post(()->cb.complete(finalResult,finalError));
        });
    }
    String stableDeviceId() {
        android.content.SharedPreferences p = context.getSharedPreferences("serein", Context.MODE_PRIVATE);
        String id = p.getString("device_id", null);
        if (id == null) { id = UUID.randomUUID().toString(); p.edit().putString("device_id", id).apply(); }
        return id;
    }
    void register(String username, String email, String displayName, String password, Callback cb) {
        JSONObject body = json("username", username, "email", email, "display_name", displayName,
                "password", password);
        request("POST", "/api/v1/auth/register", body, cb);
    }
    void login(String identity, String password, Callback cb) {
        request("POST", "/api/v1/auth/login", json("identity", identity, "password", password), cb);
    }
    void verifyEmail(String email, String code, Callback cb) {
        request("POST", "/api/v1/auth/verify-email", json("email", email, "code", code,
                "device_name", "Serein Android", "device_id", stableDeviceId()), cb);
    }
    void verifyLogin(String identity, String password, String code, Callback cb) {
        request("POST", "/api/v1/auth/verify-login", json("identity", identity, "password", password,
                "code", code, "device_name", "Serein Android", "device_id", stableDeviceId()), cb);
    }
    void resendVerification(String identity, Callback cb) {
        request("POST", "/api/v1/auth/resend-verification", json("identity", identity), cb);
    }
    void me(Callback cb) { request("GET", "/api/v1/me", null, cb); }
    void contacts(Callback cb) { request("GET", "/api/v1/contacts", null, cb); }
    void devices(Callback cb) { request("GET", "/api/v1/devices", null, cb); }
    void settings(Callback cb) { request("GET", "/api/v1/settings", null, cb); }
    void messageHistory(String afterCreatedAt, String afterId, Callback cb) {
        String path="/api/v1/messages?limit=100";
        if(afterCreatedAt!=null&&afterId!=null)try{path+="&after_created_at="+java.net.URLEncoder.encode(afterCreatedAt,"UTF-8")+"&after_id="+java.net.URLEncoder.encode(afterId,"UTF-8");}catch(Exception ignored){}
        request("GET", path, null, cb);
    }
    void acknowledgeMessage(String id, Callback cb) { request("POST", "/api/v1/messages/" + id + "/ack", new JSONObject(), cb); }
    void sendEncryptedEnvelope(String id, String deviceId, String iv, String ciphertext, Callback cb) {
        request("POST", "/api/v1/messages", json("id", id, "to", deviceId, "iv", iv, "ciphertext", ciphertext), cb);
    }

    CompletableFuture<Object> future(String method, String path, JSONObject body) {
        CompletableFuture<Object> result = new CompletableFuture<>();
        request(method, path, body, (value, error) -> {
            if (error != null) result.completeExceptionally(new java.io.IOException(error));
            else result.complete(value);
        });
        return result;
    }
    CompletableFuture<Object> contactsFuture() { return future("GET", "/api/v1/contacts", null); }
    CompletableFuture<JSONObject> deviceKeyDirectory(String contactId) {
        return future("GET", "/api/v1/contacts/" + contactId + "/device-keys", null).thenApply(value -> (JSONObject) value);
    }
    CompletableFuture<JSONObject> enrollDeviceKey(JSONObject publicKey, JSONObject layer2PublicKey, int ratchetVersion) {
        if (ratchetVersion != 2 && ratchetVersion != 3) throw new IllegalArgumentException("Unsupported ratchet capability.");
        JSONObject body = json("algorithm", "ECDH-P256");
        try { body.put("public_key", publicKey); body.put("layer2_public_key", layer2PublicKey); body.put("ratchet_version", ratchetVersion); } catch (Exception ignored) { }
        return future("PUT", "/api/v1/device-key", body).thenApply(value -> (JSONObject) value);
    }
    CompletableFuture<Object> historyPage(String afterCreatedAt, String afterId) {
        String path="/api/v1/messages?limit=100";
        if(afterCreatedAt!=null&&afterId!=null)try{path+="&after_created_at="+java.net.URLEncoder.encode(afterCreatedAt,"UTF-8")+"&after_id="+java.net.URLEncoder.encode(afterId,"UTF-8");}catch(Exception ignored){}
        return future("GET", path, null);
    }
    CompletableFuture<Object> sendEnvelopeFuture(String id, String deviceId, String iv, String ciphertext, int cryptoVersion) {
        JSONObject body = json("id", id, "to", deviceId, "iv", iv, "ciphertext", ciphertext);
        try { body.put("crypto_version", cryptoVersion); } catch (Exception ignored) { }
        return future("POST", "/api/v1/messages", body);
    }
    CompletableFuture<Object> acknowledgeFuture(String id) { return future("POST", "/api/v1/messages/" + id + "/ack", new JSONObject()); }
    CompletableFuture<JSONObject> backupKeyEnvelope(JSONObject clientPublicKey) throws org.json.JSONException {
        JSONObject body=new JSONObject().put("client_public_key",clientPublicKey);
        return future("POST","/api/v1/backups/key-envelope",body).thenApply(value -> (JSONObject)value);
    }
    CompletableFuture<Object> transfers() { return future("GET", "/api/v1/transfers", null); }
    CompletableFuture<Object> createTransfer(JSONObject body) { return future("POST", "/api/v1/transfers", body); }
    CompletableFuture<Object> acknowledgeTransfer(String id) { return future("POST", "/api/v1/transfers/" + id + "/ack", new JSONObject()); }
    CompletableFuture<Object> abortTransfer(String id) { return future("DELETE", "/api/v1/transfers/" + id, null); }

    static final class BinaryReply {
        final byte[] bytes; final String sha256;
        BinaryReply(byte[] bytes, String sha256) { this.bytes = bytes; this.sha256 = sha256; }
    }
    CompletableFuture<BinaryReply> transferChunk(String method, String transferId, int index, byte[] body, String digest) {
        CompletableFuture<BinaryReply> result = new CompletableFuture<>();
        worker.execute(() -> {
            HttpURLConnection connection = null;
            try {
                URL url = new URL(baseUrl + "/api/v1/transfers/" + transferId + "/chunks/" + index);
                if (!"https".equalsIgnoreCase(url.getProtocol())) throw new SecurityException("Refusing a non-HTTPS transfer request.");
                connection = (HttpURLConnection) url.openConnection(); connection.setInstanceFollowRedirects(false);
                connection.setRequestMethod(method); connection.setConnectTimeout(15000); connection.setReadTimeout(30000);
                connection.setRequestProperty("Accept", "application/octet-stream");
                String sessionToken = sessionVault.load(origin(url));
                if (sessionToken != null && !sessionToken.isEmpty()) connection.setRequestProperty("Cookie", "serein_session=" + sessionToken);
                if ("PUT".equals(method)) {
                    connection.setDoOutput(true); connection.setRequestProperty("Content-Type", "application/octet-stream");
                    connection.setRequestProperty("X-Chunk-SHA256", digest == null ? "" : digest);
                    try (OutputStream out = connection.getOutputStream()) { out.write(body); }
                }
                int code = connection.getResponseCode();
                if (code == 401) sessionVault.clear(); saveSessionCookie(connection.getHeaderField("Set-Cookie"), origin(url));
                InputStream stream = code >= 200 && code < 300 ? connection.getInputStream() : connection.getErrorStream();
                byte[] bytes = stream == null ? new byte[0] : readBytes(stream, 512 * 1024);
                if (code < 200 || code >= 300) {
                    String message = "Transfer request failed (" + code + ").";
                    try { message = new JSONObject(new String(bytes, StandardCharsets.UTF_8)).optString("error", message); } catch (Exception ignored) { }
                    throw new java.io.IOException(message);
                }
                result.complete(new BinaryReply(bytes, connection.getHeaderField("X-Chunk-SHA256")));
            } catch (Exception error) {
                result.completeExceptionally(new java.io.IOException(error.getMessage() == null ? "Could not complete the encrypted transfer." : error.getMessage()));
            } finally { if (connection != null) connection.disconnect(); }
        });
        return result;
    }
    private static byte[] readBytes(InputStream stream, int maximum) throws Exception {
        try (InputStream in = stream; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[16 * 1024]; int read;
            while ((read = in.read(buffer)) != -1) { if (out.size() + read > maximum) throw new java.io.IOException("Transfer response exceeds the chunk size limit."); out.write(buffer, 0, read); }
            return out.toByteArray();
        }
    }
    void saveSettings(JSONObject patch, Callback cb) { request("PUT", "/api/v1/settings", patch, cb); }
    void addContact(String identity, Callback cb) { request("POST", "/api/v1/contact-requests", json("identity", identity), cb); }
    void contactRequests(Callback cb) { request("GET", "/api/v1/contact-requests", null, cb); }
    void acceptContactRequest(String id, Callback cb) { request("POST", "/api/v1/contact-requests/" + id + "/accept", new JSONObject(), cb); }
    void dismissContactRequest(String id, Callback cb) { request("DELETE", "/api/v1/contact-requests/" + id, null, cb); }
    void blocks(Callback cb) { request("GET", "/api/v1/blocks", null, cb); }
    void blockUser(String id, Callback cb) { request("PUT", "/api/v1/blocks/" + id, new JSONObject(), cb); }
    void unblockUser(String id, Callback cb) { request("DELETE", "/api/v1/blocks/" + id, null, cb); }
    void removeContact(String id, Callback cb) { request("DELETE", "/api/v1/contacts/" + id, null, cb); }
    void revokeDevice(String id, Callback cb) { request("DELETE", "/api/v1/devices/" + id, null, cb); }
    void revokeOthers(Callback cb) { request("POST", "/api/v1/devices/revoke-others", new JSONObject(), cb); }
    void deleteAccount(String password, Callback cb) { request("DELETE", "/api/v1/me", json("password", password), (result,error)->{if(error==null)sessionVault.clear();cb.complete(result,error);}); }
    void logout(Callback cb) { request("POST", "/api/v1/auth/logout", new JSONObject(), (result,error)->{sessionVault.clear();cb.complete(result,error);}); }

    private static JSONObject json(String... pairs) {
        JSONObject value = new JSONObject();
        try { for (int i=0; i+1<pairs.length; i+=2) value.put(pairs[i], pairs[i+1]); }
        catch (Exception ignored) { }
        return value;
    }
    private void request(String method, String path, JSONObject body, Callback callback) {
        worker.execute(() -> {
            Object result = null; String error = null; HttpURLConnection connection = null;
            try {
                URL url = new URL(baseUrl + path); if (!"https".equalsIgnoreCase(url.getProtocol())) throw new SecurityException("Refusing a non-HTTPS API request.");
                connection = (HttpURLConnection) url.openConnection(); connection.setInstanceFollowRedirects(false);
                connection.setRequestMethod(method); connection.setConnectTimeout(12000); connection.setReadTimeout(15000);
                connection.setRequestProperty("Accept", "application/json");
                String sessionToken = sessionVault.load(origin(url));
                if (sessionToken != null && !sessionToken.isEmpty()) connection.setRequestProperty("Cookie", "serein_session=" + sessionToken);
                if (body != null) {
                    connection.setDoOutput(true); connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                    byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
                    try (OutputStream out = connection.getOutputStream()) { out.write(bytes); }
                }
                int code = connection.getResponseCode();
                if (code == 401) sessionVault.clear();
                saveSessionCookie(connection.getHeaderField("Set-Cookie"), origin(url));
                InputStream stream = code >= 200 && code < 400 ? connection.getInputStream() : connection.getErrorStream();
                String text = stream == null ? "{}" : readFully(stream);
                Object parsed = text.isEmpty() ? new JSONObject() : new org.json.JSONTokener(text).nextValue();
                result = parsed;
                if (code < 200 || code >= 300) error = parsed instanceof JSONObject ? ((JSONObject) parsed).optString("error", "API request failed (" + code + ")") : "API request failed (" + code + ")";
            } catch (Exception e) { error = e.getMessage() == null ? "Could not reach the Serein API." : e.getMessage(); }
            finally { if (connection != null) connection.disconnect(); }
            Object finalResult = result; String finalError = error;
            main.post(() -> callback.complete(finalResult, finalError));
        });
    }
    private static String origin(URL url) { int port=url.getPort()>=0?url.getPort():url.getDefaultPort();return url.getProtocol().toLowerCase(java.util.Locale.ROOT)+"://"+url.getHost().toLowerCase(java.util.Locale.ROOT)+":"+port; }
    private void saveSessionCookie(String setCookie, String requestOrigin) throws Exception {
        if (setCookie == null || !setCookie.startsWith("serein_session=")) return;
        String first = setCookie.split(";", 2)[0];
        String value = first.substring("serein_session=".length());
        if (value.isEmpty()) sessionVault.clear(); else sessionVault.save(value, requestOrigin);
    }
    private static String readFully(InputStream stream) throws Exception {
        try (InputStream in = stream; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096]; int read; while ((read = in.read(buffer)) != -1) { if(out.size()+read>12*1024*1024)throw new java.io.IOException("API response exceeds the client size limit."); out.write(buffer, 0, read); }
            return out.toString(StandardCharsets.UTF_8.name());
        }
    }
}
