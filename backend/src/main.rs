use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use hkdf::Hkdf;
use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use axum::{body::{Body, Bytes}, extract::{ws::{Message, WebSocket, WebSocketUpgrade}, Path, Query, Request, State}, http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode}, middleware::{self, Next}, response::{IntoResponse, Response}, routing::{delete, get, post, put}, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sha2_11::Sha256 as HkdfSha256;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{collections::{BTreeSet, HashMap}, env, net::SocketAddr, sync::Arc, time::Duration};
use zeroize::{Zeroize, Zeroizing};
use tokio::sync::mpsc;
use tower_http::{cors::{AllowOrigin, CorsLayer}, services::ServeDir, trace::TraceLayer};
use tracing::{info, warn};
use uuid::Uuid;

mod mail;

const COOKIE_NAME: &str = "serein_session";
const SESSION_SECONDS: i64 = 60 * 60 * 24 * 30;
const OTP_RESEND_COOLDOWN_SECONDS: u64 = 60;
const MAX_CIPHERTEXT_CHARS: usize = serein_core::MAX_CIPHERTEXT_CHARS;
const MAX_LIVE_CONNECTIONS: usize = 20_000;
const MAX_QUEUED_PER_DEVICE: i64 = 5_000;
const MAX_TRANSFER_CHUNK_BYTES: usize = 256 * 1024;
const MAX_TRANSFER_CHUNKS: i32 = 512;
const MAX_TRANSFER_BYTES: i64 = 64 * 1024 * 1024;
const MAX_ACTIVE_TRANSFER_BYTES_PER_ACCOUNT: i64 = 256 * 1024 * 1024;
const MAX_ACTIVE_TRANSFERS_PER_ACCOUNT: i64 = 100;
const MAX_TRANSFER_DEVICES: usize = 32;
const TRANSFER_TTL_DAYS: i64 = 7;
// The web client sends only per-recipient-device AES-GCM ciphertext after local fingerprint confirmation.
// Native clients remain unsupported, and this web implementation has not been independently reviewed.
const MESSAGING_ENABLED: bool = true;

type PeerMap = DashMap<Uuid, Peer>;
#[derive(Clone)] struct AppState { peers: Arc<PeerMap>, db: PgPool, mailer: Arc<mail::Mailer>, cookie_secure: bool, allowed_origins: Arc<Vec<String>>, backup_key_kek: Option<[u8;32]> }
#[derive(Clone)] struct Peer { connection_id: Uuid, tx: mpsc::Sender<String> }
#[derive(Clone)] struct AuthContext { user_id: Uuid, username: String, email: String, display_name: String, email_verified: bool, device_id: Uuid, device_name: String, session_hash: Vec<u8> }
#[derive(Deserialize)] struct RegisterInput { username: String, email: String, display_name: String, password: String }
#[derive(Deserialize)] #[serde(deny_unknown_fields)] struct BackupKeyEnvelopeRequest { client_public_key: P256PublicJwk }
#[derive(Deserialize)] #[serde(deny_unknown_fields)] struct DeleteAccountInput { password: String }
#[derive(Deserialize)] #[serde(deny_unknown_fields)] struct LoginInput { identity: String, password: String }
#[derive(Deserialize)] struct VerifyEmailInput { email: String, code: String, device_name: Option<String>, device_id: Option<Uuid> }
#[derive(Deserialize)] struct VerifyLoginInput { identity: String, password: String, code: String, device_name: Option<String>, device_id: Option<Uuid> }
#[derive(Deserialize)] struct ResendVerificationInput { identity: String }
#[derive(Deserialize)] #[serde(deny_unknown_fields)] struct AddContactInput { identity: Option<String>, username: Option<String>, email: Option<String> }
#[derive(Deserialize,Serialize,Default)] #[serde(deny_unknown_fields)] struct SettingsPatch { #[serde(skip_serializing_if="Option::is_none")] theme: Option<String>, #[serde(skip_serializing_if="Option::is_none")] font_scale: Option<String>, #[serde(skip_serializing_if="Option::is_none")] reduce_motion: Option<bool>, #[serde(skip_serializing_if="Option::is_none")] notifications: Option<bool>, #[serde(skip_serializing_if="Option::is_none")] presence_visibility: Option<String>, #[serde(skip_serializing_if="Option::is_none")] allow_contact_requests: Option<bool>, #[serde(skip_serializing_if="Option::is_none")] discoverable_by_email: Option<bool> }
#[derive(Serialize)] struct ErrorBody { error: String }
#[derive(Deserialize)] #[serde(deny_unknown_fields)] struct DevicePublicKeyInput { algorithm: String, public_key: P256PublicJwk, layer2_public_key: P256PublicJwk, #[serde(default)] ratchet_version: Option<u8> }
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)] #[serde(deny_unknown_fields)] struct P256PublicJwk { kty: String, crv: String, x: String, y: String }
#[derive(Serialize)] struct ContactRequestReply { id: Uuid, username: String, display_name: String, created_at: String, direction: String }
#[derive(Serialize)] struct BlockReply { user_id: Uuid, username: String, display_name: String, created_at: String }
#[derive(Serialize)] struct AuthReply { user: UserReply, device: DeviceReply }
#[derive(Serialize)] struct UserReply { id: Uuid, username: String, email: String, display_name: String, email_verified: bool }
#[derive(Serialize, Clone)] struct DeviceReply { id: Uuid, name: String }
#[derive(Serialize, Clone)] struct ContactReply { user_id: Uuid, username: String, display_name: String, email_verified: bool, online: bool, devices: Vec<DeviceReply>, connected_at: String, deleted: bool, deleted_at: Option<String> }
#[derive(Serialize)] struct DeviceSessionReply { id: Uuid, name: String, created_at: String, last_seen_at: String, current: bool, online: bool }
#[derive(Deserialize)] #[serde(tag = "type", rename_all = "snake_case")] enum ClientFrame { Message { id: Uuid, to: Uuid, iv: String, ciphertext: String, crypto_version: Option<u8> }, Ack { id: Uuid }, Heartbeat }
#[derive(Deserialize)] struct HistoryQuery { after_created_at: Option<String>, after_id: Option<Uuid>, limit: Option<i64> }
#[derive(Deserialize)] #[serde(deny_unknown_fields)] struct MessageReceiptsQuery { ids: Vec<Uuid> }
#[derive(Deserialize)] struct SendEnvelopeInput { id: Uuid, to: Uuid, iv: String, ciphertext: String, crypto_version: Option<u8> }
#[derive(Deserialize)] struct CreateTransferInput { id: Uuid, recipient_user_id: Uuid, chunk_count: i32, total_ciphertext_bytes: i64, #[serde(default = "legacy_transfer_crypto_version")] chunk_crypto_version: u8, device_envelopes: Vec<TransferDeviceEnvelope> }
#[derive(Deserialize)] struct TransferDeviceEnvelope { device_id: Uuid, #[serde(default = "legacy_transfer_crypto_version")] crypto_version: u8, iv: String, ciphertext: String }
fn legacy_transfer_crypto_version() -> u8 { 1 }
#[derive(Serialize)] struct TransferReply { id: Uuid, sender_user_id: Uuid, recipient_user_id: Uuid, sender_device_id: Uuid, chunk_count: i32, chunk_crypto_version: u8, total_ciphertext_bytes: i64, received_chunks: i64, ready_at: Option<String>, expires_at: String, manifest_iv: String, manifest_ciphertext: String, manifest_crypto_version: u8, acknowledged: bool }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "serein_api=info,tower_http=info".into())).init();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL is required");
    let db = PgPoolOptions::new().max_connections(20).connect(&database_url).await?;
    initialize_schema(&db).await?;
    let cookie_secure = env::var("COOKIE_SECURE").map(|v| v != "false").unwrap_or(true);
    let allowed_origins = parse_web_origins(&env::var("ALLOWED_WEB_ORIGINS").unwrap_or_else(|_| "http://localhost:8080".into()))
        .map_err(std::io::Error::other)?;
    let cors_origins = allowed_origins.iter().map(|origin|HeaderValue::try_from(origin.as_str()))
        .collect::<Result<Vec<_>,_>>()?;
    let cors = CorsLayer::new().allow_origin(AllowOrigin::list(cors_origins)).allow_methods([Method::GET,Method::POST,Method::PUT,Method::DELETE,Method::OPTIONS]).allow_headers([header::CONTENT_TYPE,HeaderName::from_static("x-chunk-sha256")]).expose_headers([header::RETRY_AFTER,HeaderName::from_static("x-chunk-sha256")]).allow_credentials(true);
    let mailer = Arc::new(mail::Mailer::from_env().map_err(std::io::Error::other)?);
    info!(provider=mailer.provider_name(),"email delivery configuration loaded");
    let backup_key_kek = parse_backup_key_encryption_key().map_err(std::io::Error::other)?;
    if backup_key_kek.is_none() { warn!("SEREIN_BACKUP_KEY_ENCRYPTION_KEY is not configured; portable backup key access is disabled"); }
    let cleanup_db=db.clone();
    tokio::spawn(async move {
        let mut interval=tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            match sqlx::query("DELETE FROM encrypted_transfers WHERE id IN (SELECT id FROM encrypted_transfers WHERE expires_at<=now() ORDER BY expires_at LIMIT 1)").execute(&cleanup_db).await {
                Ok(result) if result.rows_affected()>0=>info!(deleted=result.rows_affected(),"expired encrypted transfer purged"),
                Ok(_)=>{},
                Err(_)=>warn!("encrypted transfer cleanup failed"),
            }
            match sqlx::query("DELETE FROM contact_requests WHERE id IN (SELECT id FROM contact_requests WHERE expires_at<=now() ORDER BY expires_at LIMIT 50)").execute(&cleanup_db).await {
                Ok(result) if result.rows_affected()>0=>info!(deleted=result.rows_affected(),"expired contact requests purged"),
                Ok(_)=>{},
                Err(_)=>warn!("contact request cleanup failed"),
            }
            match sqlx::query("DELETE FROM queued_ciphertexts WHERE (recipient_device_id,id) IN (SELECT recipient_device_id,id FROM queued_ciphertexts WHERE delivered_at IS NOT NULL ORDER BY delivered_at,recipient_device_id,id LIMIT 500)").execute(&cleanup_db).await {
                Ok(result) if result.rows_affected()>0=>info!(deleted=result.rows_affected(),"legacy acknowledged ciphertext packets purged"),
                Ok(_)=>{},
                Err(_)=>warn!("acknowledged ciphertext cleanup failed"),
            }
            match sqlx::query("DELETE FROM queued_ciphertexts WHERE (recipient_device_id,id) IN (SELECT recipient_device_id,id FROM queued_ciphertexts WHERE delivered_at IS NULL AND created_at<=now()-interval '30 days' ORDER BY created_at,recipient_device_id,id LIMIT 500)").execute(&cleanup_db).await {
                Ok(result) if result.rows_affected()>0=>info!(deleted=result.rows_affected(),"expired ciphertext packets purged"),
                Ok(_)=>{},
                Err(_)=>warn!("expired ciphertext cleanup failed"),
            }
        }
    });
    let state = AppState { peers: Arc::new(PeerMap::new()), db, mailer, cookie_secure, allowed_origins: Arc::new(allowed_origins), backup_key_kek };
    let app = Router::new()
        .route("/healthz", get(healthz)).route("/api/v1/security/capabilities", get(security_capabilities)).route("/status", get(|| async { axum::response::Html(include_str!("../../frontend/web/status.html")) }))
        .route("/api/v1/auth/register", post(register)).route("/api/v1/auth/verify-email", post(verify_email)).route("/api/v1/auth/resend-verification", post(resend_verification)).route("/api/v1/auth/login", post(login)).route("/api/v1/auth/verify-login", post(verify_login)).route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/me", get(me).delete(delete_account)).route("/api/v1/backups/key-envelope", post(get_backup_key_envelope)).route("/api/v1/device-key", put(register_device_public_key)).route("/api/v1/contacts/:contact_id/device-keys", get(list_contact_device_public_keys)).route("/api/v1/messages", get(list_messages).post(send_message_api)).route("/api/v1/messages/receipts", post(list_message_receipts)).route("/api/v1/messages/read", post(mark_messages_read_api)).route("/api/v1/messages/:id/ack", post(ack_message_api)).route("/api/v1/messages/:id/read", post(mark_message_read_api)).route("/api/v1/settings", get(get_settings).put(put_settings)).route("/api/v1/contacts", get(list_contacts).post(create_contact_request))
        .route("/api/v1/contact-requests", get(list_contact_requests).post(create_contact_request)).route("/api/v1/contact-requests/:request_id/accept", post(accept_contact_request)).route("/api/v1/contact-requests/:request_id", delete(delete_contact_request))
        .route("/api/v1/blocks", get(list_blocks)).route("/api/v1/blocks/:user_id", put(block_user).delete(unblock_user))
        .route("/api/v1/contacts/:contact_id", delete(remove_contact)).route("/api/v1/devices", get(list_devices))
        .route("/api/v1/devices/:device_id", delete(revoke_device)).route("/api/v1/devices/revoke-others", post(revoke_other_devices))
        .route("/api/v1/transfers", get(list_encrypted_transfers).post(create_encrypted_transfer))
        .route("/api/v1/transfers/:transfer_id/chunks/:index", put(upload_transfer_chunk).get(download_transfer_chunk))
        .route("/api/v1/transfers/:transfer_id/ack", post(ack_encrypted_transfer)).route("/api/v1/transfers/:transfer_id", delete(abort_encrypted_transfer))
        .route("/v1/ws", get(ws_handler)).fallback_service(ServeDir::new("../frontend/web").append_index_html_on_directories(true))
        .layer(TraceLayer::new_for_http()).layer(middleware::from_fn_with_state(state.clone(),security_headers)).layer(cors).with_state(state);
    let listen_addr = env::var("LISTEN_ADDR").or_else(|_| env::var("PORT").map(|port| format!("0.0.0.0:{port}"))).unwrap_or_else(|_| "0.0.0.0:8080".into());
    let addr: SocketAddr = listen_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "Serein API and development relay listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz(State(state):State<AppState>)->Response{
    let database_ready=matches!(tokio::time::timeout(Duration::from_secs(2),sqlx::query("SELECT 1").execute(&state.db)).await,Ok(Ok(_)));
    let frontend_ready=["../frontend/web/index.html","../frontend/web/app.js","../frontend/web/style.css"]
        .iter().all(|path|std::path::Path::new(*path).is_file());
    let ready=database_ready&&frontend_ready;
    let health=serde_json::json!({
        "status":if ready{"ready"}else{"degraded"},
        "service":"Serein",
        "components":{
            "api":"ready",
            "database":if database_ready{"ready"}else{"unavailable"},
            "frontend":if frontend_ready{"available"}else{"unavailable"},
            "email_delivery":if state.mailer.is_enabled(){"configured"}else{"disabled"}
        }
    });
    let status=if ready{StatusCode::OK}else{StatusCode::SERVICE_UNAVAILABLE};
    (status,Json(health)).into_response()
}

async fn security_capabilities() -> Json<Value> {
    Json(serde_json::json!({
        "messaging_enabled": MESSAGING_ENABLED,
        "shared_core": {
            "backend": true,
            "web_wasm": true,
            "android_native": false,
            "ios_native": false,
            "status": "partial"
        },
        "e2ee": {
            "protocol": "independent_device_bound_layer2_v2",
            "protocol_status": "in_development_unreviewed",
            "device_key_registry": "dual_public_key_source_implemented_unverified",
            "web_device_key_enrollment": "web_android_ios_source_implemented_unverified",
            "web_conversation_key_derivation": "independent_layer1_layer2_key_pairs_source_implemented_unverified",
            "authenticated_key_exchange": "manual_combined_fingerprint_verification",
            "key_change_verification": "manual_reverification_required",
            "forward_secrecy": "not_implemented",
            "client_encrypt_decrypt": "web_android_ios_source_implemented_unverified",
            "message_delivery": if MESSAGING_ENABLED { "enabled" } else { "disabled" },
            "independent_review": "not_started"
        },
        "file_transfers": {
            "server_chunk_store": "source_implemented_unverified",
            "web_client": "source_implemented_unverified",
            "native_clients": "source_implemented_unverified",
            "media_preview": "browser_native_supported_codecs_only",
            "independent_review": "not_started"
        },
        "calls": {
            "quic_media_transport": "not_implemented",
            "session_signaling": "not_implemented",
            "device_session_coordination": "not_implemented"
        }
    }))
}

async fn initialize_schema(db: &PgPool) -> Result<(), sqlx::Error> {
    let statements = [
        "CREATE TABLE IF NOT EXISTS accounts (id UUID PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, password_hash TEXT NOT NULL, email_verified BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        "CREATE TABLE IF NOT EXISTS devices (id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, label TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(), revoked_at TIMESTAMPTZ NULL)",
        "CREATE INDEX IF NOT EXISTS devices_by_user ON devices(user_id, created_at DESC)",
        "CREATE TABLE IF NOT EXISTS device_public_keys (device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE, user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, algorithm TEXT NOT NULL CHECK(algorithm='ECDH-P256'), public_key JSONB NOT NULL, layer2_public_key JSONB, fingerprint TEXT NOT NULL, key_version INTEGER NOT NULL DEFAULT 1 CHECK(key_version IN (1,2)), ratchet_version SMALLINT NOT NULL DEFAULT 2 CHECK(ratchet_version IN (2,3)), registered_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        "ALTER TABLE device_public_keys ADD COLUMN IF NOT EXISTS layer2_public_key JSONB",
        "ALTER TABLE device_public_keys ADD COLUMN IF NOT EXISTS ratchet_version SMALLINT NOT NULL DEFAULT 2",
        "ALTER TABLE device_public_keys DROP CONSTRAINT IF EXISTS device_public_keys_ratchet_version_check",
        "ALTER TABLE device_public_keys ADD CONSTRAINT device_public_keys_ratchet_version_check CHECK(ratchet_version IN (2,3))",
        "ALTER TABLE device_public_keys DROP CONSTRAINT IF EXISTS device_public_keys_key_version_check",
        "ALTER TABLE device_public_keys ADD CONSTRAINT device_public_keys_key_version_check CHECK(key_version IN (1,2))",
        "CREATE INDEX IF NOT EXISTS device_public_keys_by_user ON device_public_keys(user_id,registered_at)",
        "CREATE TABLE IF NOT EXISTS auth_sessions (token_hash BYTEA PRIMARY KEY, user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL)",
        "CREATE TABLE IF NOT EXISTS account_backup_keys (user_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE, key_version SMALLINT NOT NULL DEFAULT 1 CHECK(key_version=1), at_rest_version SMALLINT NOT NULL DEFAULT 1 CHECK(at_rest_version=1), nonce BYTEA NOT NULL CHECK(octet_length(nonce)=12), ciphertext BYTEA NOT NULL CHECK(octet_length(ciphertext)=48), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        "DELETE FROM auth_sessions s USING accounts a WHERE s.user_id=a.id AND a.email_verified=FALSE",
        "CREATE TABLE IF NOT EXISTS email_verification_challenges (user_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE, code_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, resend_after TIMESTAMPTZ NOT NULL, attempt_count SMALLINT NOT NULL DEFAULT 0, send_count SMALLINT NOT NULL DEFAULT 1, window_started_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        "CREATE INDEX IF NOT EXISTS auth_sessions_by_user ON auth_sessions(user_id, expires_at)",
        "CREATE TABLE IF NOT EXISTS contacts (owner_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, contact_id UUID NOT NULL, contact_display_name TEXT NOT NULL DEFAULT 'Deleted User', deleted_at TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(owner_id, contact_id), CHECK(owner_id <> contact_id))",
        "ALTER TABLE contacts DROP CONSTRAINT IF EXISTS contacts_contact_id_fkey",
        "ALTER TABLE contacts ADD COLUMN IF NOT EXISTS contact_display_name TEXT",
        "ALTER TABLE contacts ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL",
        "UPDATE contacts c SET contact_display_name=a.display_name FROM accounts a WHERE a.id=c.contact_id AND c.contact_display_name IS NULL",
        "UPDATE contacts SET contact_display_name='Deleted User' WHERE contact_display_name IS NULL",
        "ALTER TABLE contacts ALTER COLUMN contact_display_name SET DEFAULT 'Deleted User'",
        "ALTER TABLE contacts ALTER COLUMN contact_display_name SET NOT NULL",
        "CREATE INDEX IF NOT EXISTS contacts_by_deleted_peer ON contacts(owner_id,contact_id,deleted_at)",
        "CREATE TABLE IF NOT EXISTS contact_requests (id UUID PRIMARY KEY, sender_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, recipient_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL DEFAULT (now()+interval '30 days'), UNIQUE(sender_id,recipient_id), CHECK(sender_id<>recipient_id))",
        "ALTER TABLE contact_requests ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT (now()+interval '30 days')",
        "CREATE INDEX IF NOT EXISTS contact_requests_incoming_expiry ON contact_requests(recipient_id,expires_at,created_at DESC)",
        "CREATE TABLE IF NOT EXISTS account_action_limits (user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, action TEXT NOT NULL, window_started_at TIMESTAMPTZ NOT NULL DEFAULT now(), attempt_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(user_id,action))",
        "CREATE TABLE IF NOT EXISTS user_blocks (owner_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, blocked_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(owner_id,blocked_user_id), CHECK(owner_id<>blocked_user_id))",
        "CREATE TABLE IF NOT EXISTS user_settings (user_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE, settings JSONB NOT NULL DEFAULT '{}'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        "CREATE TABLE IF NOT EXISTS queued_ciphertexts (id UUID NOT NULL, sender_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE, recipient_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE, payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), delivered_at TIMESTAMPTZ NULL, PRIMARY KEY(recipient_device_id, id))",
        "ALTER TABLE queued_ciphertexts ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ NULL",
        "CREATE INDEX IF NOT EXISTS queued_ciphertexts_delivery ON queued_ciphertexts(recipient_device_id, delivered_at, created_at, id)",
        "CREATE INDEX IF NOT EXISTS queued_ciphertexts_created_at ON queued_ciphertexts(created_at)",
        "CREATE INDEX IF NOT EXISTS queued_ciphertexts_delivered_cleanup ON queued_ciphertexts(delivered_at,recipient_device_id,id) WHERE delivered_at IS NOT NULL",
        "CREATE TABLE IF NOT EXISTS message_receipts (message_id UUID NOT NULL, sender_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, sender_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE, recipient_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, recipient_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE, accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(), delivered_at TIMESTAMPTZ NULL, read_at TIMESTAMPTZ NULL, PRIMARY KEY(message_id,recipient_device_id), CHECK(read_at IS NULL OR delivered_at IS NOT NULL))",
        "CREATE INDEX IF NOT EXISTS message_receipts_sender_message ON message_receipts(sender_user_id,message_id)",
        "CREATE INDEX IF NOT EXISTS message_receipts_recipient_message ON message_receipts(recipient_user_id,message_id)",
        "INSERT INTO message_receipts(message_id,sender_user_id,sender_device_id,recipient_user_id,recipient_device_id,accepted_at,delivered_at) SELECT q.id,sd.user_id,q.sender_device_id,rd.user_id,q.recipient_device_id,q.created_at,q.delivered_at FROM queued_ciphertexts q JOIN devices sd ON sd.id=q.sender_device_id JOIN devices rd ON rd.id=q.recipient_device_id ON CONFLICT(message_id,recipient_device_id) DO NOTHING",
        "CREATE TABLE IF NOT EXISTS encrypted_transfers (id UUID PRIMARY KEY, sender_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, sender_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE, recipient_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 1 AND 512), chunk_crypto_version SMALLINT NOT NULL DEFAULT 1 CHECK(chunk_crypto_version IN (1,2)), total_ciphertext_bytes BIGINT NOT NULL CHECK(total_ciphertext_bytes BETWEEN 1 AND 67108864), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL, ready_at TIMESTAMPTZ NULL)",
        "ALTER TABLE encrypted_transfers ADD COLUMN IF NOT EXISTS chunk_crypto_version SMALLINT NOT NULL DEFAULT 1",
        "ALTER TABLE encrypted_transfers DROP CONSTRAINT IF EXISTS encrypted_transfers_chunk_crypto_version_check",
        "ALTER TABLE encrypted_transfers ADD CONSTRAINT encrypted_transfers_chunk_crypto_version_check CHECK(chunk_crypto_version IN (1,2))",
        "CREATE TABLE IF NOT EXISTS encrypted_transfer_device_envelopes (transfer_id UUID NOT NULL REFERENCES encrypted_transfers(id) ON DELETE CASCADE, target_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE, target_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, iv TEXT NOT NULL, ciphertext TEXT NOT NULL, crypto_version SMALLINT NOT NULL DEFAULT 1, acknowledged_at TIMESTAMPTZ NULL, PRIMARY KEY(transfer_id,target_device_id))",
        "ALTER TABLE encrypted_transfer_device_envelopes ADD COLUMN IF NOT EXISTS crypto_version SMALLINT NOT NULL DEFAULT 1",
        "CREATE TABLE IF NOT EXISTS encrypted_transfer_chunks (transfer_id UUID NOT NULL REFERENCES encrypted_transfers(id) ON DELETE CASCADE, chunk_index INTEGER NOT NULL CHECK(chunk_index >= 0), ciphertext BYTEA NOT NULL, sha256 BYTEA NOT NULL CHECK(octet_length(sha256)=32), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(transfer_id,chunk_index))",
        "CREATE INDEX IF NOT EXISTS encrypted_transfers_sender_expiry ON encrypted_transfers(sender_user_id,expires_at)",
        "CREATE INDEX IF NOT EXISTS encrypted_transfers_recipient_expiry ON encrypted_transfers(recipient_user_id,expires_at)",
        "CREATE INDEX IF NOT EXISTS encrypted_transfers_expiry ON encrypted_transfers(expires_at)",
        "CREATE INDEX IF NOT EXISTS encrypted_transfers_sender_device ON encrypted_transfers(sender_device_id,expires_at)",

        "CREATE INDEX IF NOT EXISTS encrypted_transfer_envelopes_device ON encrypted_transfer_device_envelopes(target_device_id,transfer_id)",
        "CREATE INDEX IF NOT EXISTS encrypted_transfer_chunks_by_transfer ON encrypted_transfer_chunks(transfer_id,chunk_index)",
    ];
    for statement in statements { sqlx::query(statement).execute(db).await?; }
    Ok(())
}
fn normalize_web_origin(raw:&str)->Result<String,String>{
    let url=reqwest::Url::parse(raw.trim()).map_err(|_|"ALLOWED_WEB_ORIGINS entries must be valid origins".to_owned())?;
    let host=url.host_str().ok_or_else(||"ALLOWED_WEB_ORIGINS entries must include a host".to_owned())?;
    let local_http=url.scheme()=="http"&&matches!(host,"localhost"|"127.0.0.1"|"[::1]"|"::1");
    if !(url.scheme()=="https"||local_http)||!url.username().is_empty()||url.password().is_some()
        ||url.path()!="/"||url.query().is_some()||url.fragment().is_some(){
        return Err("ALLOWED_WEB_ORIGINS must contain HTTPS origins (HTTP only for localhost), without paths or credentials".into());
    }
    Ok(url.origin().ascii_serialization())
}

fn parse_web_origins(raw:&str)->Result<Vec<String>,String>{
    let origins=raw.split(',').map(str::trim).filter(|value|!value.is_empty())
        .map(normalize_web_origin).collect::<Result<Vec<_>,_>>()?;
    if origins.is_empty(){return Err("ALLOWED_WEB_ORIGINS must contain at least one trusted origin".into());}
    let mut unique=Vec::with_capacity(origins.len());
    for origin in origins{if !unique.contains(&origin){unique.push(origin);}}
    Ok(unique)
}

async fn security_headers(State(state):State<AppState>,request:Request,next:Next)->Response{
    if let Some(origin)=request.headers().get(header::ORIGIN){
        let allowed=origin.to_str().ok().and_then(|value|normalize_web_origin(value).ok())
            .is_some_and(|origin|state.allowed_origins.iter().any(|allowed|allowed==&origin));
        if !allowed{
            warn!(origin=%origin.to_str().unwrap_or("<invalid>"),"rejected request from an origin not listed in ALLOWED_WEB_ORIGINS");
            return api_error(StatusCode::FORBIDDEN,"request origin is not allowed");
        }
    }
    let mut response=next.run(request).await;
    let headers=response.headers_mut();
    headers.insert("content-security-policy",HeaderValue::from_static("default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https://nekos.best; font-src 'self' data:; connect-src 'self' https: wss:; media-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"));
    headers.insert("x-content-type-options",HeaderValue::from_static("nosniff"));
    headers.insert("x-frame-options",HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy",HeaderValue::from_static("no-referrer"));
    headers.insert("permissions-policy",HeaderValue::from_static("camera=(self), microphone=(self), geolocation=()"));
    if state.cookie_secure{headers.insert("strict-transport-security",HeaderValue::from_static("max-age=31536000"));}
    response
}
fn api_error(status: StatusCode, message: &'static str) -> Response { (status, Json(ErrorBody { error: message.into() })).into_response() }
fn verification_response(status:StatusCode,email:&str,message:&'static str,delivery:&'static str)->Response{
    (status,Json(serde_json::json!({"error":message,"verification":{"required":true,"verified":false,"email":email,"delivery":delivery,"purpose":"email"}}))).into_response()
}
fn verification_login_response(email:&str,message:&'static str,delivery:&'static str)->Response{
    (StatusCode::FORBIDDEN,Json(serde_json::json!({"error":message,"verification":{"required":true,"verified":false,"email":email,"delivery":delivery,"purpose":"login"}}))).into_response()
}
fn resend_cooldown_response(seconds:u64)->Response{
    let retry=seconds.clamp(1,OTP_RESEND_COOLDOWN_SECONDS);
    let mut response=(StatusCode::TOO_MANY_REQUESTS,Json(serde_json::json!({"error":"please wait before requesting another code","retry_after_seconds":retry}))).into_response();
    if let Ok(value)=HeaderValue::try_from(retry.to_string()){response.headers_mut().insert(header::RETRY_AFTER,value);}
    response
}
fn resend_accepted_response()->Response{
    let retry=OTP_RESEND_COOLDOWN_SECONDS;
    let mut response=(StatusCode::ACCEPTED,Json(serde_json::json!({"message":"If the account exists, a code may be sent.","retry_after_seconds":retry}))).into_response();
    if let Ok(value)=HeaderValue::try_from(retry.to_string()){response.headers_mut().insert(header::RETRY_AFTER,value);}
    response
}
fn account_unique_conflict(constraint: Option<&str>) -> Option<&'static str> {
    match constraint {
        Some("accounts_username_key") => Some("That username is already taken. Choose another username."),
        Some("accounts_email_key") => Some("That email address is already registered. Sign in or use another email."),
        _ => None,
    }
}
fn normalise_username(value: &str) -> String { serein_core::normalize_username(value) }
fn history_page_limit(requested: Option<i64>) -> i64 { serein_core::history_page_limit(requested) }
fn valid_ciphertext_parts(iv:&str,ciphertext:&str)->bool{serein_core::valid_ciphertext_parts(iv,ciphertext)}
fn valid_theme(value:&str)->bool{serein_core::valid_theme(value)}
fn valid_font_scale(value:&str)->bool{serein_core::valid_font_scale(value)}
fn valid_username(value: &str) -> bool { serein_core::valid_username(value) }
fn valid_email(value: &str) -> bool { serein_core::valid_email(value) }
fn registration_password_requirements(password:&str)->[bool;5]{serein_core::registration_password_requirements(password)}
fn cookie_value(headers:&HeaderMap)->Option<String>{let raw=headers.get(header::COOKIE)?.to_str().ok()?;raw.split(';').filter_map(|p|p.trim().split_once('=')).find_map(|(k,v)|(k==COOKIE_NAME&&!v.is_empty()).then(||v.to_string()))}
fn token_hash(token:&str)->Vec<u8>{Sha256::digest(token.as_bytes()).to_vec()}
fn new_token()->String{let mut bytes=[0u8;32];OsRng.fill_bytes(&mut bytes);URL_SAFE_NO_PAD.encode(bytes)}
fn parse_backup_key_encryption_key()->Result<Option<[u8;32]>,String>{
    let Ok(value)=env::var("SEREIN_BACKUP_KEY_ENCRYPTION_KEY")else{return Ok(None)};
    if value.trim().is_empty(){return Ok(None)};
    let decoded=URL_SAFE_NO_PAD.decode(value.trim()).map_err(|_|"SEREIN_BACKUP_KEY_ENCRYPTION_KEY must be a 32-byte base64url value".to_owned())?;
    if decoded.len()!=32{return Err("SEREIN_BACKUP_KEY_ENCRYPTION_KEY must decode to exactly 32 bytes".into());}
    let mut key=[0u8;32];key.copy_from_slice(&decoded);Ok(Some(key))
}
fn append_cookie(response:&mut Response,cookie:String){if let Ok(value)=HeaderValue::from_bytes(cookie.as_bytes()){response.headers_mut().append(header::SET_COOKIE,value);}}
fn attach_session_cookie(response:&mut Response,token:&str,secure:bool){let s=if secure{"; Secure"}else{""};append_cookie(response,format!("{COOKIE_NAME}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}{s}",SESSION_SECONDS));}
fn clear_session_cookie(response:&mut Response,secure:bool){let s=if secure{"; Secure"}else{""};append_cookie(response,format!("{COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{s}"));}
async fn authenticate(db:&PgPool,headers:&HeaderMap)->Result<Option<AuthContext>,sqlx::Error>{
    let Some(token)=cookie_value(headers) else{return Ok(None)};let hash=token_hash(&token);
    let row=sqlx::query_as::<_,(Uuid,String,String,String,bool,Uuid,String,Vec<u8>)>("SELECT a.id,a.username,a.email,a.display_name,a.email_verified,d.id,d.label,s.token_hash FROM auth_sessions s JOIN accounts a ON a.id=s.user_id JOIN devices d ON d.id=s.device_id WHERE s.token_hash=$1 AND s.expires_at>now() AND d.revoked_at IS NULL AND a.email_verified=TRUE").bind(&hash).fetch_optional(db).await?;
    Ok(row.map(|(user_id,username,email,display_name,email_verified,device_id,device_name,session_hash)|AuthContext{user_id,username,email,display_name,email_verified,device_id,device_name,session_hash}))
}
fn auth_reply(ctx:&AuthContext)->AuthReply{AuthReply{user:UserReply{id:ctx.user_id,username:ctx.username.clone(),email:ctx.email.clone(),display_name:ctx.display_name.clone(),email_verified:ctx.email_verified},device:DeviceReply{id:ctx.device_id,name:ctx.device_name.clone()}}}
async fn create_device_session(db:&PgPool,user_id:Uuid,device_name:&str,requested_device_id:Option<Uuid>)->Result<(Uuid,String),sqlx::Error>{
    let mut tx=db.begin().await?;
    let mut device_id=requested_device_id.unwrap_or_else(Uuid::new_v4);
    let existing=sqlx::query_as::<_,(Uuid,bool)>("SELECT user_id,revoked_at IS NOT NULL FROM devices WHERE id=$1").bind(device_id).fetch_optional(&mut *tx).await?;
    match existing {
        Some((owner,false)) if owner==user_id=>{sqlx::query("UPDATE devices SET label=$2,last_seen_at=now() WHERE id=$1").bind(device_id).bind(device_name).execute(&mut *tx).await?;},
        Some(_)=>{device_id=Uuid::new_v4();sqlx::query("INSERT INTO devices(id,user_id,label) VALUES($1,$2,$3)").bind(device_id).bind(user_id).bind(device_name).execute(&mut *tx).await?;},
        None=>{sqlx::query("INSERT INTO devices(id,user_id,label) VALUES($1,$2,$3)").bind(device_id).bind(user_id).bind(device_name).execute(&mut *tx).await?;}
    }
    let token=new_token();let hash=token_hash(&token);sqlx::query("INSERT INTO auth_sessions(token_hash,user_id,device_id,expires_at) VALUES($1,$2,$3,now()+make_interval(secs => $4::double precision))").bind(&hash).bind(user_id).bind(device_id).bind(SESSION_SECONDS as f64).execute(&mut *tx).await?;tx.commit().await?;Ok((device_id,token))
}
async fn register(State(state):State<AppState>,Json(input):Json<RegisterInput>)->Response{
    let username=normalise_username(&input.username);
    let email=input.email.trim().to_ascii_lowercase();
    let display=input.display_name.trim();
    if !valid_username(&username){return api_error(StatusCode::BAD_REQUEST,"username must be 3–32 lowercase letters, digits, dots, dashes, or underscores");}
    if !valid_email(&email){return api_error(StatusCode::BAD_REQUEST,"enter a valid email address");}
    if !(2..=48).contains(&display.chars().count()){return api_error(StatusCode::BAD_REQUEST,"display name must be 2–48 characters");}

    let existing=match sqlx::query_as::<_,(Uuid,String,String,String,bool)>(
        "SELECT id,username,email,password_hash,email_verified FROM accounts WHERE username=$1 OR email=$2 ORDER BY id"
    ).bind(&username).bind(&email).fetch_all(&state.db).await{
        Ok(rows)=>rows,
        Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"account registration is temporarily unavailable"),
    };
    if !existing.is_empty(){
        if existing.len()==1{
            let (user_id,stored_username,stored_email,password_hash,verified)=&existing[0];
            let same_account=stored_username==&username&&stored_email==&email;
            let password_matches=PasswordHash::new(password_hash).ok()
                .is_some_and(|parsed|Argon2::default().verify_password(input.password.as_bytes(),&parsed).is_ok());
            if same_account&&!verified&&password_matches{
                match ensure_verification_challenge(&state.db,&state.mailer,*user_id,stored_email).await{
                    Ok(())=>return verification_response(StatusCode::ACCEPTED,stored_email,"This account needs email verification. Check your inbox or resend the code after the short wait.","email"),
                    Err(error) if cooldown_seconds(&error).is_some()||error=="send_limit"=>return verification_response(StatusCode::ACCEPTED,stored_email,"This account needs email verification. Check your inbox or wait briefly before requesting another code.","email"),
                    Err(error)=>{
                        warn!(provider=state.mailer.provider_name(),failure=otp_failure_kind(&error),provider_status=otp_provider_status(&error),"verification delivery could not be prepared for an existing unverified account");
                        return verification_response(StatusCode::SERVICE_UNAVAILABLE,stored_email,"Your account is saved but a verification code is not currently available. Try again shortly.","unavailable");
                    }
                }
            }
        }
        let message=if existing.iter().any(|row|row.1==username){
            account_unique_conflict(Some("accounts_username_key")).unwrap()
        }else{
            account_unique_conflict(Some("accounts_email_key")).unwrap()
        };
        return api_error(StatusCode::CONFLICT,message);
    }

    if !state.mailer.is_enabled(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"email verification is not configured");}
    let [pw_length,pw_upper,pw_lower,pw_digit,pw_bytes]=registration_password_requirements(&input.password);
    if !pw_length{return api_error(StatusCode::BAD_REQUEST,"password must contain at least 8 characters");}
    if !pw_bytes{return api_error(StatusCode::BAD_REQUEST,"password must be no more than 1024 UTF-8 bytes");}
    if !(pw_upper&&pw_lower&&pw_digit){return api_error(StatusCode::BAD_REQUEST,"password must include an uppercase letter, a lowercase letter, and a number");}
    let salt=SaltString::generate(&mut OsRng);
    let password_hash=match Argon2::default().hash_password(input.password.as_bytes(),&salt){
        Ok(hash)=>hash.to_string(),
        Err(_)=>return api_error(StatusCode::INTERNAL_SERVER_ERROR,"could not create account"),
    };
    let user_id=Uuid::new_v4();
    if let Err(error)=sqlx::query("INSERT INTO accounts(id,username,email,display_name,password_hash,email_verified) VALUES($1,$2,$3,$4,$5,FALSE)")
        .bind(user_id).bind(&username).bind(&email).bind(display).bind(password_hash).execute(&state.db).await{
        if let Some(message)=account_unique_conflict(error.as_database_error().and_then(|db_error|db_error.constraint())){return api_error(StatusCode::CONFLICT,message);}
        warn!("account registration insert failed");
        return api_error(StatusCode::SERVICE_UNAVAILABLE,"account registration is temporarily unavailable");
    }
    if let Some(kek)=state.backup_key_kek.as_ref(){
        match ensure_account_backup_key(&state.db,user_id,kek).await{Ok(mut key)=>key.zeroize(),Err(_)=>warn!("backup key will be provisioned lazily after account registration")}
    }
    if let Err(error)=issue_verification_code(&state.db,&state.mailer,user_id,&email,false).await{
        warn!(provider=state.mailer.provider_name(),failure=otp_failure_kind(&error),provider_status=otp_provider_status(&error),"verification email delivery failed after account creation");
        return verification_response(StatusCode::SERVICE_UNAVAILABLE,&email,"Your account is saved but the verification code could not be sent. Try resending shortly.","unavailable");
    }
    (StatusCode::ACCEPTED,Json(serde_json::json!({"verification":{"required":true,"verified":false,"delivery":"email","email":email},"message":"Check your email for a verification code."}))).into_response()
}

async fn verify_email(State(state):State<AppState>,Json(input):Json<VerifyEmailInput>)->Response{
    let email=input.email.trim().to_ascii_lowercase();
    if !valid_email(&email)||input.code.len()!=6||!input.code.bytes().all(|b|b.is_ascii_digit()){
        return api_error(StatusCode::BAD_REQUEST,"enter a valid email and six-digit verification code");
    }
    let user_id=match sqlx::query_scalar::<_,Uuid>("SELECT id FROM accounts WHERE email=$1 AND email_verified=FALSE").bind(&email).fetch_optional(&state.db).await{
        Ok(Some(id))=>id,Ok(None)=>return api_error(StatusCode::BAD_REQUEST,"verification code is invalid or expired"),Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"verification service unavailable")
    };
    let mut tx=match state.db.begin().await{Ok(tx)=>tx,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"verification service unavailable")};
    let challenge=sqlx::query_as::<_,(String,bool,i16)>("SELECT code_hash,expires_at>now(),attempt_count FROM email_verification_challenges WHERE user_id=$1 FOR UPDATE").bind(user_id).fetch_optional(&mut *tx).await;
    let challenge=match challenge{Ok(Some(value))=>value,Ok(None)=>{let _=tx.rollback().await;return api_error(StatusCode::BAD_REQUEST,"verification code is invalid or expired")},Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"verification service unavailable")}};
    let (code_hash,not_expired,attempts)=challenge;
    if !not_expired||attempts>=5{let _=tx.rollback().await;return api_error(StatusCode::BAD_REQUEST,"verification code is invalid or expired");}
    let parsed=match PasswordHash::new(&code_hash){Ok(v)=>v,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::INTERNAL_SERVER_ERROR,"verification could not be completed")}};
    if Argon2::default().verify_password(input.code.as_bytes(),&parsed).is_err(){
        if sqlx::query("UPDATE email_verification_challenges SET attempt_count=attempt_count+1 WHERE user_id=$1").bind(user_id).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"verification service unavailable");}
        if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"verification service unavailable");}
        return api_error(StatusCode::BAD_REQUEST,"verification code is invalid or expired");
    }
    let updated=match sqlx::query("UPDATE accounts SET email_verified=TRUE WHERE id=$1 AND email_verified=FALSE").bind(user_id).execute(&mut *tx).await{Ok(result)=>result.rows_affected(),Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"verification service unavailable")}};
    if updated!=1{let _=tx.rollback().await;return api_error(StatusCode::BAD_REQUEST,"verification code is invalid or expired");}
    if sqlx::query("DELETE FROM email_verification_challenges WHERE user_id=$1").bind(user_id).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"verification service unavailable");}
    if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"verification service unavailable");}
    let device_name=input.device_name.as_deref().unwrap_or("Web browser").trim();let device_name=if device_name.is_empty(){"Web browser"}else{device_name};
    let(device_id,token)=match create_device_session(&state.db,user_id,device_name,input.device_id).await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"email verified; sign in to create a session")};
    let ctx=match sqlx::query_as::<_,(String,String,String)>("SELECT username,email,display_name FROM accounts WHERE id=$1").bind(user_id).fetch_one(&state.db).await{Ok((username,email,display_name))=>AuthContext{user_id,username,email,display_name,email_verified:true,device_id,device_name:device_name.into(),session_hash:token_hash(&token)},Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"email verified; sign in to continue")};
    let mut response=Json(serde_json::json!({"account":auth_reply(&ctx),"verification":{"required":false,"verified":true}})).into_response();attach_session_cookie(&mut response,&token,state.cookie_secure);response
}

async fn resend_verification(State(state):State<AppState>,Json(input):Json<ResendVerificationInput>)->Response{
    let identity=input.identity.trim().to_ascii_lowercase();
    if identity.is_empty(){return api_error(StatusCode::BAD_REQUEST,"enter your email or username");}
    if !state.mailer.is_enabled(){warn!("verification resend blocked because email delivery is disabled");return api_error(StatusCode::SERVICE_UNAVAILABLE,"email verification is not configured");}
    let account=match sqlx::query_as::<_,(Uuid,bool,String)>("SELECT id,email_verified,email FROM accounts WHERE email=$1 OR username=$1").bind(&identity).fetch_optional(&state.db).await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"verification service unavailable")};
    if let Some((user_id,_,email))=account{
        if let Err(error)=issue_verification_code(&state.db,&state.mailer,user_id,&email,true).await{
            warn!(provider=state.mailer.provider_name(),failure=otp_failure_kind(&error),provider_status=otp_provider_status(&error),"verification resend failed");
            if let Some(seconds)=cooldown_seconds(&error){return resend_cooldown_response(seconds);}
            if error=="send_limit"{return api_error(StatusCode::TOO_MANY_REQUESTS,"daily verification-code send limit reached; try again later");}
            return api_error(StatusCode::SERVICE_UNAVAILABLE,"verification email could not be sent");
        }
    }
    resend_accepted_response()
}

async fn issue_verification_code(db:&PgPool,mailer:&mail::Mailer,user_id:Uuid,email:&str,resend:bool)->Result<(),String>{
    if !mailer.is_enabled(){return Err("email delivery is not configured".into());}
    let mut raw=[0u8;4];OsRng.fill_bytes(&mut raw);let code=format!("{:06}",u32::from_be_bytes(raw)%1_000_000);
    let salt=SaltString::generate(&mut OsRng);let code_hash=Argon2::default().hash_password(code.as_bytes(),&salt).map_err(|e|format!("OTP hash failed: {e}"))?.to_string();
    let mut tx=db.begin().await.map_err(|e|format!("OTP transaction failed: {e}"))?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1::text),hashtext('email-verification'))").bind(user_id.to_string()).execute(&mut *tx).await.map_err(|e|format!("OTP lock failed: {e}"))?;
    let old=sqlx::query_as::<_,(i16,bool,bool,i64)>("SELECT send_count,window_started_at>now()-interval '24 hours',resend_after>now(),GREATEST(1,CEIL(EXTRACT(EPOCH FROM (resend_after-now()))))::BIGINT FROM email_verification_challenges WHERE user_id=$1 FOR UPDATE").bind(user_id).fetch_optional(&mut *tx).await.map_err(|e|format!("OTP lookup failed: {e}"))?;
    let send_count=match old{
        None=>1,
        Some((count,active,waiting,retry_after))=>{
            if resend&&waiting{return Err(format!("cooldown:{retry_after}"));}
            if resend&&active&&count>=5{return Err("send_limit".into());}
            if active{count.saturating_add(1)}else{1}
        }
    };
    sqlx::query("INSERT INTO email_verification_challenges(user_id,code_hash,expires_at,resend_after,attempt_count,send_count,window_started_at) VALUES($1,$2,now()+interval '10 minutes',now()+interval '60 seconds',0,$3,now()) ON CONFLICT(user_id) DO UPDATE SET code_hash=EXCLUDED.code_hash,expires_at=EXCLUDED.expires_at,resend_after=EXCLUDED.resend_after,attempt_count=0,send_count=$3,window_started_at=CASE WHEN email_verification_challenges.window_started_at<=now()-interval '24 hours' THEN now() ELSE email_verification_challenges.window_started_at END").bind(user_id).bind(code_hash).bind(send_count).execute(&mut *tx).await.map_err(|e|format!("OTP save failed: {e}"))?;
    tx.commit().await.map_err(|e|format!("OTP commit failed: {e}"))?;
    mailer.send_otp(email,&code).await?;
    info!(provider=mailer.provider_name(),"verification email accepted by configured provider");
    Ok(())
}

async fn ensure_verification_challenge(db:&PgPool,mailer:&mail::Mailer,user_id:Uuid,email:&str)->Result<(),String>{
    let (exists,active)=sqlx::query_as::<_,(bool,bool)>("SELECT EXISTS(SELECT 1 FROM email_verification_challenges WHERE user_id=$1),EXISTS(SELECT 1 FROM email_verification_challenges WHERE user_id=$1 AND expires_at>now())")
        .bind(user_id).fetch_one(db).await.map_err(|_|"verification challenge lookup failed".to_owned())?;
    if active{return Ok(());}
    issue_verification_code(db,mailer,user_id,email,exists).await
}

fn cooldown_seconds(error:&str)->Option<u64>{error.strip_prefix("cooldown:").and_then(|value|value.parse().ok()).or_else(||(error=="cooldown").then_some(60))}
fn otp_provider_status(error:&str)->Option<u16>{error.strip_prefix("mail API returned HTTP ").and_then(|value|value.split_whitespace().next()).and_then(|value|value.parse().ok())}

fn otp_failure_kind(error:&str)->&'static str{
    if cooldown_seconds(error).is_some(){"cooldown"}
    else if error=="send_limit"{"send_limit"}
    else if error.starts_with("mail API")||error=="SMTP delivery failed"||error=="Email delivery is not configured"||error=="email delivery is not configured"{"provider_delivery"}
    else if error.starts_with("OTP hash"){"challenge_hash_generation"}
    else if error.starts_with("OTP transaction"){"challenge_db_begin"}
    else if error.starts_with("OTP lock"){"challenge_db_lock"}
    else if error.starts_with("OTP lookup")||error.starts_with("verification challenge lookup"){"challenge_db_lookup"}
    else if error.starts_with("OTP save"){"challenge_db_write"}
    else if error.starts_with("OTP commit"){"challenge_db_commit"}
    else{"challenge_generation_or_delivery"}
}

async fn login(State(state):State<AppState>,Json(input):Json<LoginInput>)->Response{
    let identity=input.identity.trim().to_ascii_lowercase();if identity.is_empty()||input.password.is_empty(){return api_error(StatusCode::BAD_REQUEST,"enter your username/email and password");}
    let row=match sqlx::query_as::<_,(Uuid,String,String,bool)>("SELECT id,email,password_hash,email_verified FROM accounts WHERE username=$1 OR email=$1").bind(&identity).fetch_optional(&state.db).await{Ok(row)=>row,Err(_)=>{warn!("login lookup failed");return api_error(StatusCode::SERVICE_UNAVAILABLE,"account service unavailable");}};
    let Some((user_id,email,password_hash,email_verified))=row else{return api_error(StatusCode::UNAUTHORIZED,"invalid username/email or password")};let parsed=match PasswordHash::new(&password_hash){Ok(p)=>p,Err(_)=>return api_error(StatusCode::INTERNAL_SERVER_ERROR,"stored credential could not be verified")};if Argon2::default().verify_password(input.password.as_bytes(),&parsed).is_err(){return api_error(StatusCode::UNAUTHORIZED,"invalid username/email or password");}if !email_verified{
        let (message,delivery)=match ensure_verification_challenge(&state.db,&state.mailer,user_id,&email).await{
            Ok(())=>("Email verification is required. Check your inbox for the code.","email"),
            Err(error) if cooldown_seconds(&error).is_some()=>("Email verification is required. A code was recently requested; wait briefly before resending.","email"),
            Err(error) if error=="send_limit"=>("Email verification is required. The resend limit was reached; try again later.","limited"),
            Err(error)=>{warn!(provider=state.mailer.provider_name(),failure=otp_failure_kind(&error),provider_status=otp_provider_status(&error),"verification email could not be prepared after unverified sign-in");("Email verification is required, but code delivery is currently unavailable. Try again shortly.","unavailable")}
        };
        return verification_response(StatusCode::FORBIDDEN,&email,message,delivery);
    }
    let (message,delivery)=match ensure_verification_challenge(&state.db,&state.mailer,user_id,&email).await{
        Ok(())=>("A sign-in code was sent to your verified email. Enter it to finish signing in.","email"),
        Err(error) if cooldown_seconds(&error).is_some()=>("A sign-in code was recently requested. Check your inbox or wait briefly before resending.","email"),
        Err(error) if error=="send_limit"=>("The sign-in code limit was reached. Try again later.","limited"),
        Err(error)=>{warn!(provider=state.mailer.provider_name(),failure=otp_failure_kind(&error),provider_status=otp_provider_status(&error),"login OTP could not be prepared");("Sign-in code delivery is currently unavailable. Try again shortly.","unavailable")}
    };
    verification_login_response(&email,message,delivery)
}
async fn verify_login(State(state):State<AppState>,Json(input):Json<VerifyLoginInput>)->Response{
    let identity=input.identity.trim().to_ascii_lowercase();
    if identity.is_empty()||input.password.is_empty()||input.code.len()!=6||!input.code.bytes().all(|b|b.is_ascii_digit()){
        return api_error(StatusCode::BAD_REQUEST,"enter your sign-in credentials and six-digit code");
    }
    let account=match sqlx::query_as::<_,(Uuid,String,String,String,String,bool)>("SELECT id,username,email,display_name,password_hash,email_verified FROM accounts WHERE username=$1 OR email=$1").bind(&identity).fetch_optional(&state.db).await{
        Ok(Some(value))=>value,Ok(None)=>return api_error(StatusCode::UNAUTHORIZED,"invalid sign-in credentials or code"),Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"sign-in service unavailable")
    };
    let (user_id,username,email,display_name,password_hash,email_verified)=account;
    if !email_verified{return api_error(StatusCode::UNAUTHORIZED,"invalid sign-in credentials or code");}
    let parsed=match PasswordHash::new(&password_hash){Ok(value)=>value,Err(_)=>return api_error(StatusCode::INTERNAL_SERVER_ERROR,"stored credential could not be verified")};
    if Argon2::default().verify_password(input.password.as_bytes(),&parsed).is_err(){return api_error(StatusCode::UNAUTHORIZED,"invalid sign-in credentials or code");}
    let mut tx=match state.db.begin().await{Ok(tx)=>tx,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"sign-in service unavailable")};
    let challenge=sqlx::query_as::<_,(String,bool,i16)>("SELECT code_hash,expires_at>now(),attempt_count FROM email_verification_challenges WHERE user_id=$1 FOR UPDATE").bind(user_id).fetch_optional(&mut *tx).await;
    let (code_hash,not_expired,attempts)=match challenge{Ok(Some(value))=>value,Ok(None)=>{let _=tx.rollback().await;return api_error(StatusCode::BAD_REQUEST,"sign-in code is invalid or expired")},Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"sign-in service unavailable")}};
    if !not_expired||attempts>=5{let _=tx.rollback().await;return api_error(StatusCode::BAD_REQUEST,"sign-in code is invalid or expired");}
    let parsed=match PasswordHash::new(&code_hash){Ok(value)=>value,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::INTERNAL_SERVER_ERROR,"sign-in could not be completed")}};
    if Argon2::default().verify_password(input.code.as_bytes(),&parsed).is_err(){
        if sqlx::query("UPDATE email_verification_challenges SET attempt_count=attempt_count+1 WHERE user_id=$1").bind(user_id).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"sign-in service unavailable");}
        if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"sign-in service unavailable");}
        return api_error(StatusCode::BAD_REQUEST,"sign-in code is invalid or expired");
    }
    if sqlx::query("UPDATE email_verification_challenges SET expires_at=now(),resend_after=now(),attempt_count=5 WHERE user_id=$1").bind(user_id).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"sign-in service unavailable");}
    if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"sign-in service unavailable");}
    let label=input.device_name.as_deref().unwrap_or("Web browser").trim();let label=if label.is_empty(){"Web browser"}else{label};let(device_id,token)=match create_device_session(&state.db,user_id,label,input.device_id).await{Ok(value)=>value,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not create session")};
    let ctx=AuthContext{user_id,username,email,display_name,email_verified:true,device_id,device_name:label.into(),session_hash:token_hash(&token)};
    let mut response=Json(serde_json::json!({"account":auth_reply(&ctx),"verification":{"required":false,"verified":true}})).into_response();attach_session_cookie(&mut response,&token,state.cookie_secure);response
}
async fn logout(State(state):State<AppState>,headers:HeaderMap)->Response{
    if let Some(token)=cookie_value(&headers){
        let hash=token_hash(&token);
        let device_id=match sqlx::query_scalar::<_,Uuid>("SELECT device_id FROM auth_sessions WHERE token_hash=$1").bind(&hash).fetch_optional(&state.db).await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not end session")};
        if sqlx::query("DELETE FROM auth_sessions WHERE token_hash=$1").bind(hash).execute(&state.db).await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not end session");}
        if let Some(device_id)=device_id{let other_session=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM auth_sessions WHERE device_id=$1 AND expires_at>now())").bind(device_id).fetch_one(&state.db).await.unwrap_or(true);if !other_session{state.peers.remove(&device_id);}}
    }
    let mut response=Json(serde_json::json!({"ok":true})).into_response();clear_session_cookie(&mut response,state.cookie_secure);response
}
async fn me(State(state):State<AppState>,headers:HeaderMap)->Response{match authenticate(&state.db,&headers).await{Ok(Some(ctx))=>Json(auth_reply(&ctx)).into_response(),Ok(None)=>api_error(StatusCode::UNAUTHORIZED,"sign in required"),Err(_)=>api_error(StatusCode::SERVICE_UNAVAILABLE,"account service unavailable")}}

async fn delete_account(State(state):State<AppState>,headers:HeaderMap,Json(input):Json<DeleteAccountInput>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    if input.password.is_empty()||input.password.len()>4096{return api_error(StatusCode::BAD_REQUEST,"enter your current password to confirm account deletion");}
    let mut tx=match state.db.begin().await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"account deletion is temporarily unavailable")};
    let account=match sqlx::query_as::<_,(String,String,String)>("SELECT username,display_name,password_hash FROM accounts WHERE id=$1 FOR UPDATE").bind(ctx.user_id).fetch_optional(&mut *tx).await{
        Ok(Some(value))=>value,Ok(None)=>{let _=tx.rollback().await;return api_error(StatusCode::UNAUTHORIZED,"sign in required");},Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"account deletion is temporarily unavailable");}
    };
    let (username,display_name,password_hash)=account;
    let parsed=match PasswordHash::new(&password_hash){Ok(value)=>value,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"account deletion could not be verified");}};
    if Argon2::default().verify_password(input.password.as_bytes(),&parsed).is_err(){let _=tx.rollback().await;return api_error(StatusCode::FORBIDDEN,"current password is incorrect; the account was not deleted");}
    let devices=match sqlx::query_scalar::<_,Uuid>("SELECT id FROM devices WHERE user_id=$1 FOR UPDATE").bind(ctx.user_id).fetch_all(&mut *tx).await{Ok(value)=>value,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"account deletion is temporarily unavailable");}};
    if sqlx::query("UPDATE contacts SET contact_display_name=COALESCE(NULLIF(btrim($2),''),contact_display_name),deleted_at=COALESCE(deleted_at,now()) WHERE contact_id=$1 AND owner_id<>$1 AND deleted_at IS NULL").bind(ctx.user_id).bind(&display_name).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"account deletion is temporarily unavailable");}
    let account_id=ctx.user_id.to_string();
    let has_legacy_messages=match sqlx::query_scalar::<_,bool>("SELECT to_regclass('public.offline_messages') IS NOT NULL").fetch_one(&mut *tx).await{Ok(value)=>value,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"account deletion is temporarily unavailable");}};
    if has_legacy_messages&&sqlx::query("DELETE FROM offline_messages WHERE sender IN ($1,$2) OR recipient IN ($1,$2)").bind(&account_id).bind(&username).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"account deletion is temporarily unavailable");}
    if sqlx::query("DELETE FROM accounts WHERE id=$1").bind(ctx.user_id).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"account deletion is temporarily unavailable");}
    if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"account deletion did not complete; retry after checking the account state");}
    for device_id in devices{state.peers.remove(&device_id);}
    let mut response=Json(serde_json::json!({"ok":true,"account_deleted":true,"username_released":true,"peer_history_retained_locally":true,"recreated_username_is_new_identity":true})).into_response();
    clear_session_cookie(&mut response,state.cookie_secure);response
}
fn decode_p256_coordinate(value:&str)->Option<[u8;32]>{let bytes=URL_SAFE_NO_PAD.decode(value).ok()?;if bytes.len()!=32{return None;}let mut coordinate=[0u8;32];coordinate.copy_from_slice(&bytes);Some(coordinate)}
fn p256_public_key_fingerprint(key:&P256PublicJwk)->Option<[u8;64]>{
    if key.kty!="EC"||key.crv!="P-256"{return None;}
    let x=decode_p256_coordinate(&key.x)?;let y=decode_p256_coordinate(&key.y)?;let mut coordinates=[0u8;64];coordinates[..32].copy_from_slice(&x);coordinates[32..].copy_from_slice(&y);Some(coordinates)
}
fn p256_key_bundle_fingerprint(layer1:&P256PublicJwk,layer2:&P256PublicJwk)->Option<String>{
    let first=p256_public_key_fingerprint(layer1)?;let second=p256_public_key_fingerprint(layer2)?;
    let mut material=Vec::with_capacity(64+128);material.extend_from_slice(b"Serein ECDH P-256 device key bundle v2\0");material.extend_from_slice(&first);material.extend_from_slice(&second);Some(hex_lower(&Sha256::digest(material)))
}

fn backup_key_at_rest_aad(user_id:Uuid)->Result<Vec<u8>,String>{
    serde_json::to_vec(&serde_json::json!(["serein-account-backup-key-at-rest-v1",user_id.to_string(),1]))
        .map_err(|_|"backup key metadata could not be encoded".into())
}
fn seal_account_backup_key(user_id:Uuid,key:&[u8;32],kek:&[u8;32])->Result<([u8;12],Vec<u8>),String>{
    let cipher=Aes256Gcm::new_from_slice(kek).map_err(|_|"backup key encryption is unavailable".to_owned())?;
    let mut nonce=[0u8;12];OsRng.fill_bytes(&mut nonce);
    let aad=backup_key_at_rest_aad(user_id)?;
    let encrypted=cipher.encrypt(Nonce::from_slice(&nonce),Payload{msg:key,aad:&aad})
        .map_err(|_|"backup key encryption is unavailable".to_owned())?;
    Ok((nonce,encrypted))
}
fn open_account_backup_key(user_id:Uuid,nonce:&[u8],ciphertext:&[u8],kek:&[u8;32])->Result<[u8;32],String>{
    if nonce.len()!=12||ciphertext.len()!=48{return Err("stored backup key has an invalid format".into());}
    let cipher=Aes256Gcm::new_from_slice(kek).map_err(|_|"backup key encryption is unavailable".to_owned())?;
    let aad=backup_key_at_rest_aad(user_id)?;
    let mut clear=cipher.decrypt(Nonce::from_slice(nonce),Payload{msg:ciphertext,aad:&aad})
        .map_err(|_|"stored backup key could not be opened".to_owned())?;
    if clear.len()!=32{clear.zeroize();return Err("stored backup key has an invalid length".into());}
    let mut key=[0u8;32];key.copy_from_slice(&clear);clear.zeroize();Ok(key)
}
async fn ensure_account_backup_key(db:&PgPool,user_id:Uuid,kek:&[u8;32])->Result<[u8;32],String>{
    let query="SELECT key_version,at_rest_version,nonce,ciphertext FROM account_backup_keys WHERE user_id=$1";
    if let Some(row)=sqlx::query_as::<_,(i16,i16,Vec<u8>,Vec<u8>)>(query).bind(user_id).fetch_optional(db).await.map_err(|_|"backup key storage is unavailable".to_owned())?{
        if row.0!=1||row.1!=1{return Err("stored backup key version is unsupported".into());}
        return open_account_backup_key(user_id,&row.2,&row.3,kek);
    }
    let mut candidate=[0u8;32];OsRng.fill_bytes(&mut candidate);
    let sealed=seal_account_backup_key(user_id,&candidate,kek);candidate.zeroize();
    let (nonce,ciphertext)=sealed?;
    sqlx::query("INSERT INTO account_backup_keys(user_id,key_version,at_rest_version,nonce,ciphertext) VALUES($1,1,1,$2,$3) ON CONFLICT(user_id) DO NOTHING")
        .bind(user_id).bind(nonce.as_slice()).bind(&ciphertext).execute(db).await.map_err(|_|"backup key storage is unavailable".to_owned())?;
    let row=sqlx::query_as::<_,(i16,i16,Vec<u8>,Vec<u8>)>(query)
        .bind(user_id).fetch_optional(db).await.map_err(|_|"backup key storage is unavailable".to_owned())?
        .ok_or_else(||"backup key storage is unavailable".to_owned())?;
    if row.0!=1||row.1!=1{return Err("stored backup key version is unsupported".into());}
    open_account_backup_key(user_id,&row.2,&row.3,kek)
}
fn parse_p256_public_jwk(jwk:&P256PublicJwk)->Option<PublicKey>{
    let coords=p256_public_key_fingerprint(jwk)?;
    let mut sec1=[0u8;65];sec1[0]=4;sec1[1..].copy_from_slice(&coords);
    PublicKey::from_sec1_bytes(&sec1).ok()
}
async fn get_backup_key_envelope(State(state):State<AppState>,headers:HeaderMap,Json(input):Json<BackupKeyEnvelopeRequest>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(value)=>value,Err(response)=>return response};
    let Some(kek)=state.backup_key_kek else{return api_error(StatusCode::SERVICE_UNAVAILABLE,"portable backup keys are not configured on this server")};
    match enforce_action_limit(&state.db,ctx.user_id,"backup-key-envelope",10).await{
        Ok(true)=>{},Ok(false)=>return api_error(StatusCode::TOO_MANY_REQUESTS,"backup-key access limit reached; try later"),
        Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"backup key access is temporarily unavailable"),
    }
    let Some(client_public)=parse_p256_public_jwk(&input.client_public_key)else{return api_error(StatusCode::BAD_REQUEST,"invalid ephemeral P-256 public key")};
    let backup_key=match ensure_account_backup_key(&state.db,ctx.user_id,&kek).await{Ok(value)=>Zeroizing::new(value),Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"backup key is temporarily unavailable")};
    let server_secret=SecretKey::random(&mut OsRng);let server_public=server_secret.public_key();let shared=diffie_hellman(server_secret.to_nonzero_scalar(),client_public.as_affine());
    let point=server_public.to_encoded_point(false);let Some(server_x)=point.x()else{return api_error(StatusCode::INTERNAL_SERVER_ERROR,"backup key wrapping failed")};let Some(server_y)=point.y()else{return api_error(StatusCode::INTERNAL_SERVER_ERROR,"backup key wrapping failed")};
    let server_public_jwk=P256PublicJwk{kty:"EC".into(),crv:"P-256".into(),x:URL_SAFE_NO_PAD.encode(server_x),y:URL_SAFE_NO_PAD.encode(server_y)};
    let mut salt=[0u8;32];OsRng.fill_bytes(&mut salt);let mut nonce=[0u8;12];OsRng.fill_bytes(&mut nonce);
    let user=ctx.user_id.to_string();let device=ctx.device_id.to_string();let client_x=input.client_public_key.x.clone();let client_y=input.client_public_key.y.clone();let server_x_text=server_public_jwk.x.clone();let server_y_text=server_public_jwk.y.clone();let salt_text=URL_SAFE_NO_PAD.encode(salt);let nonce_text=URL_SAFE_NO_PAD.encode(nonce);
    let info=serde_json::to_vec(&serde_json::json!(["serein-backup-key-envelope-kdf-v1",user,device,1,client_x,client_y,server_x_text,server_y_text])).expect("backup envelope metadata is JSON-serializable");
    let aad=serde_json::to_vec(&serde_json::json!(["serein-backup-key-envelope-aad-v1",user,device,1,client_x,client_y,server_x_text,server_y_text,salt_text,nonce_text])).expect("backup envelope metadata is JSON-serializable");
    let mut wrap_key=Zeroizing::new([0u8;32]);if Hkdf::<HkdfSha256>::new(Some(&salt),shared.raw_secret_bytes().as_slice()).expand(&info,&mut *wrap_key).is_err(){return api_error(StatusCode::INTERNAL_SERVER_ERROR,"backup key wrapping failed");}
    let cipher=match Aes256Gcm::new_from_slice(&*wrap_key){Ok(value)=>value,Err(_)=>return api_error(StatusCode::INTERNAL_SERVER_ERROR,"backup key wrapping failed")};
    let ciphertext=match cipher.encrypt(Nonce::from_slice(&nonce),Payload{msg:&backup_key[..],aad:&aad}){Ok(value)=>value,Err(_)=>return api_error(StatusCode::INTERNAL_SERVER_ERROR,"backup key wrapping failed")};
    Json(serde_json::json!({"key_version":1,"server_public_key":server_public_jwk,"salt":salt_text,"nonce":nonce_text,"ciphertext":URL_SAFE_NO_PAD.encode(ciphertext)})).into_response()
}

async fn register_device_public_key(State(state):State<AppState>,headers:HeaderMap,Json(input):Json<DevicePublicKeyInput>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    if input.algorithm!="ECDH-P256"{return api_error(StatusCode::BAD_REQUEST,"unsupported device key algorithm");}
    let ratchet_version=input.ratchet_version.unwrap_or(2);if !matches!(ratchet_version,2..=3){return api_error(StatusCode::BAD_REQUEST,"unsupported device ratchet version");}
    let Some(fingerprint)=p256_key_bundle_fingerprint(&input.public_key,&input.layer2_public_key)else{return api_error(StatusCode::BAD_REQUEST,"invalid public device key bundle");};
    let public_key=match serde_json::to_value(&input.public_key){Ok(v)=>v,Err(_)=>return api_error(StatusCode::BAD_REQUEST,"invalid public device key")};
    let layer2_public_key=match serde_json::to_value(&input.layer2_public_key){Ok(v)=>v,Err(_)=>return api_error(StatusCode::BAD_REQUEST,"invalid layer-2 public device key")};
    let inserted=sqlx::query("INSERT INTO device_public_keys(device_id,user_id,algorithm,public_key,layer2_public_key,fingerprint,key_version,ratchet_version) SELECT d.id,d.user_id,'ECDH-P256',$3,$4,$5,2,$6 FROM devices d WHERE d.id=$1 AND d.user_id=$2 AND d.revoked_at IS NULL ON CONFLICT(device_id) DO UPDATE SET layer2_public_key=EXCLUDED.layer2_public_key,fingerprint=EXCLUDED.fingerprint,key_version=2,ratchet_version=EXCLUDED.ratchet_version WHERE device_public_keys.user_id=EXCLUDED.user_id AND device_public_keys.public_key=EXCLUDED.public_key AND (device_public_keys.layer2_public_key IS NULL OR device_public_keys.layer2_public_key=EXCLUDED.layer2_public_key)")
        .bind(ctx.device_id).bind(ctx.user_id).bind(public_key).bind(layer2_public_key).bind(&fingerprint).bind(ratchet_version as i16).execute(&state.db).await;
    if inserted.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"device key could not be registered");}
    let stored=sqlx::query_as::<_,(Value,Option<Value>,String,i32,i16)>("SELECT public_key,layer2_public_key,fingerprint,key_version,ratchet_version FROM device_public_keys WHERE device_id=$1 AND user_id=$2")
        .bind(ctx.device_id).bind(ctx.user_id).fetch_optional(&state.db).await;
    match stored{
        Ok(Some((stored_key,Some(stored_layer2),stored_fingerprint,2,stored_ratchet_version))) if stored_ratchet_version==ratchet_version as i16&&stored_key==serde_json::to_value(&input.public_key).unwrap_or(Value::Null)&&stored_layer2==serde_json::to_value(&input.layer2_public_key).unwrap_or(Value::Null)&&stored_fingerprint==fingerprint=>Json(serde_json::json!({"registered":true,"algorithm":"ECDH-P256","fingerprint":fingerprint,"key_version":2,"ratchet_version":ratchet_version})).into_response(),
        Ok(Some(_))=>api_error(StatusCode::CONFLICT,"a different key is already registered for this device; key rotation requires verification"),
        Ok(None)=>api_error(StatusCode::FORBIDDEN,"active device session required"),
        Err(_)=>api_error(StatusCode::SERVICE_UNAVAILABLE,"device key status unavailable"),
    }
}
async fn list_contact_device_public_keys(State(state):State<AppState>,headers:HeaderMap,Path(contact_id):Path<Uuid>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    let allowed=sqlx::query_scalar::<_,bool>("SELECT $1=$2 OR (EXISTS(SELECT 1 FROM contacts WHERE owner_id=$1 AND contact_id=$2 AND deleted_at IS NULL) AND NOT EXISTS(SELECT 1 FROM user_blocks WHERE (owner_id=$1 AND blocked_user_id=$2) OR (owner_id=$2 AND blocked_user_id=$1)))")
        .bind(ctx.user_id).bind(contact_id).fetch_one(&state.db).await;
    if !matches!(allowed,Ok(true)){return api_error(StatusCode::NOT_FOUND,"contact key directory unavailable");}
    let username=match sqlx::query_scalar::<_,String>("SELECT username FROM accounts WHERE id=$1").bind(contact_id).fetch_optional(&state.db).await{Ok(Some(value))=>value,Ok(None)=>return api_error(StatusCode::NOT_FOUND,"contact key directory unavailable"),Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact key directory unavailable")};
    let rows=sqlx::query_as::<_,(Uuid,Value,Option<Value>,String,String,i32,i16)>("SELECT k.device_id,k.public_key,k.layer2_public_key,k.fingerprint,k.algorithm,k.key_version,k.ratchet_version FROM device_public_keys k JOIN devices d ON d.id=k.device_id AND d.revoked_at IS NULL WHERE k.user_id=$1 ORDER BY d.created_at ASC,d.id ASC")
        .bind(contact_id).fetch_all(&state.db).await;
    match rows{Ok(devices)=>Json(serde_json::json!({"user_id":contact_id,"username":username,"devices":devices.into_iter().map(|(device_id,public_key,layer2_public_key,fingerprint,algorithm,key_version,ratchet_version)|serde_json::json!({"device_id":device_id,"public_key":public_key,"layer2_public_key":layer2_public_key,"fingerprint":fingerprint,"algorithm":algorithm,"key_version":key_version,"ratchet_version":ratchet_version})).collect::<Vec<_>>()})).into_response(),Err(_)=>api_error(StatusCode::SERVICE_UNAVAILABLE,"contact key directory unavailable")}
}
async fn require_user(state:&AppState,headers:&HeaderMap)->Result<AuthContext,Response>{match authenticate(&state.db,headers).await{Ok(Some(ctx))=>Ok(ctx),Ok(None)=>Err(api_error(StatusCode::UNAUTHORIZED,"sign in required")),Err(_)=>{warn!("session validation failed");Err(api_error(StatusCode::SERVICE_UNAVAILABLE,"account service unavailable"))}}}
async fn session_is_active(db:&PgPool,ctx:&AuthContext)->bool{sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM auth_sessions s JOIN devices d ON d.id=s.device_id JOIN accounts a ON a.id=s.user_id AND a.email_verified=TRUE WHERE s.token_hash=$1 AND s.device_id=$2 AND s.user_id=$3 AND s.expires_at>now() AND d.revoked_at IS NULL)").bind(&ctx.session_hash).bind(ctx.device_id).bind(ctx.user_id).fetch_one(db).await.unwrap_or(false)}
async fn list_contacts(State(state):State<AppState>,headers:HeaderMap)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    let rows=match sqlx::query_as::<_,(Uuid,String,String,bool,Option<Uuid>,Option<String>,Option<bool>,bool,String,bool,Option<String>)>(
        "SELECT c.contact_id,COALESCE(a.username,''),CASE WHEN c.deleted_at IS NOT NULL THEN c.contact_display_name||' (Deleted User)' ELSE COALESCE(a.display_name,c.contact_display_name) END,COALESCE(a.email_verified,FALSE),d.id,d.label,(d.last_seen_at>now()-interval '90 seconds'),COALESCE(us.settings->>'presence_visibility','contacts')<>'nobody',to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),c.deleted_at IS NOT NULL,CASE WHEN c.deleted_at IS NULL THEN NULL ELSE to_char(c.deleted_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') END FROM contacts c LEFT JOIN accounts a ON a.id=c.contact_id LEFT JOIN user_settings us ON us.user_id=a.id LEFT JOIN devices d ON c.deleted_at IS NULL AND d.user_id=a.id AND d.revoked_at IS NULL WHERE c.owner_id=$1 AND (a.id IS NOT NULL OR c.deleted_at IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM user_blocks b WHERE (b.owner_id=c.owner_id AND b.blocked_user_id=c.contact_id) OR (b.owner_id=c.contact_id AND b.blocked_user_id=c.owner_id)) ORDER BY c.deleted_at NULLS FIRST,lower(COALESCE(a.username,c.contact_display_name)),d.created_at ASC,d.id ASC"
    ).bind(ctx.user_id).fetch_all(&state.db).await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"contacts unavailable")};
    let mut grouped:HashMap<Uuid,ContactReply>=HashMap::new();
    for(user_id,username,display_name,email_verified,device_id,device_name,recently_active,presence_visible,connected_at,deleted,deleted_at)in rows{
        let contact=grouped.entry(user_id).or_insert_with(||ContactReply{user_id,username,display_name,email_verified,online:false,devices:Vec::new(),connected_at:connected_at.clone(),deleted,deleted_at:deleted_at.clone()});
        if let Some(device_id)=device_id{contact.online|=presence_visible&&recently_active.unwrap_or(false)&&state.peers.contains_key(&device_id);contact.devices.push(DeviceReply{id:device_id,name:device_name.unwrap_or_else(||"Device".into())});}
    }
    let mut result=grouped.into_values().collect::<Vec<_>>();result.sort_by(|a,b|a.deleted.cmp(&b.deleted).then_with(||a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase())));Json(result).into_response()
}
async fn get_settings(State(state):State<AppState>,headers:HeaderMap)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    match sqlx::query_scalar::<_,Value>("SELECT settings FROM user_settings WHERE user_id=$1").bind(ctx.user_id).fetch_optional(&state.db).await{Ok(Some(mut value))=>{if let Some(object)=value.as_object_mut(){object.entry("presence_visibility").or_insert_with(||serde_json::json!("contacts"));object.entry("allow_contact_requests").or_insert_with(||serde_json::json!(true));object.entry("discoverable_by_email").or_insert_with(||serde_json::json!(false));Json(value).into_response()}else{api_error(StatusCode::SERVICE_UNAVAILABLE,"settings are invalid")}},Ok(None)=>Json(serde_json::json!({"theme":"system","font_scale":"system","reduce_motion":false,"notifications":false,"presence_visibility":"contacts","allow_contact_requests":true,"discoverable_by_email":false})).into_response(),Err(_)=>api_error(StatusCode::SERVICE_UNAVAILABLE,"settings unavailable")}
}
async fn put_settings(State(state):State<AppState>,headers:HeaderMap,Json(patch):Json<SettingsPatch>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    if patch.theme.as_deref().is_some_and(|v|!valid_theme(v)){return api_error(StatusCode::BAD_REQUEST,"invalid theme setting");}
    if patch.font_scale.as_deref().is_some_and(|v|!valid_font_scale(v)){return api_error(StatusCode::BAD_REQUEST,"invalid font scale");}
    if patch.presence_visibility.as_deref().is_some_and(|v|!matches!(v,"contacts"|"nobody")){return api_error(StatusCode::BAD_REQUEST,"presence visibility must be contacts or nobody");}
    let value=match serde_json::to_value(patch){Ok(v)=>v,Err(_)=>return api_error(StatusCode::BAD_REQUEST,"invalid settings")};
    let mut tx=match state.db.begin().await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not save settings")};
    if sqlx::query("SELECT id FROM accounts WHERE id=$1 FOR UPDATE").bind(ctx.user_id).fetch_optional(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not save settings");}
    if sqlx::query("INSERT INTO user_settings(user_id,settings) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET settings=user_settings.settings || EXCLUDED.settings,updated_at=now()").bind(ctx.user_id).bind(value).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not save settings");}
    if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not save settings");}
    Json(serde_json::json!({"ok":true})).into_response()
}
async fn list_messages(State(state):State<AppState>,headers:HeaderMap,Query(query):Query<HistoryQuery>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    let limit=history_page_limit(query.limit);let after_time=query.after_created_at.as_deref();let after_id=query.after_id;
    if after_time.is_some()!=after_id.is_some(){return api_error(StatusCode::BAD_REQUEST,"history cursor requires both timestamp and message id");}
    let rows=match sqlx::query_as::<_,(Uuid,Value,String)>("SELECT id,payload,created_at::text FROM queued_ciphertexts WHERE recipient_device_id=$1 AND delivered_at IS NULL AND ($2::timestamptz IS NULL OR (created_at,id)>($2::timestamptz,$3::uuid)) ORDER BY created_at,id LIMIT $4").bind(ctx.device_id).bind(after_time).bind(after_id).bind(limit+1).fetch_all(&state.db).await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"message history unavailable")};
    let mut rows=rows;let has_more=rows.len() as i64>limit;if has_more{rows.pop();}
    let mut items=Vec::with_capacity(rows.len());let mut next=None;for(id,payload,created_at)in rows{next=Some(serde_json::json!({"after_created_at":created_at,"after_id":id}));items.push(serde_json::json!({"id":id,"payload":payload,"created_at":created_at}));}
    Json(serde_json::json!({"items":items,"next":next,"has_more":has_more})).into_response()
}
async fn ack_message_api(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<Uuid>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    // Persist device delivery status before deleting this device's queued ciphertext copy.
    if sqlx::query("UPDATE message_receipts SET delivered_at=COALESCE(delivered_at,now()) WHERE message_id=$1 AND recipient_user_id=$2 AND recipient_device_id=$3").bind(id).bind(ctx.user_id).bind(ctx.device_id).execute(&state.db).await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"message delivery receipt unavailable");}
    match sqlx::query("DELETE FROM queued_ciphertexts WHERE recipient_device_id=$1 AND id=$2").bind(ctx.device_id).bind(id).execute(&state.db).await{
        Ok(_)=>Json(serde_json::json!({"ok":true})).into_response(),
        Err(_)=>api_error(StatusCode::SERVICE_UNAVAILABLE,"message acknowledgement unavailable")
    }
}
async fn list_message_receipts(State(state):State<AppState>,headers:HeaderMap,Json(query):Json<MessageReceiptsQuery>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    if query.ids.len()>200{return api_error(StatusCode::BAD_REQUEST,"at most 200 message IDs may be queried at once");}
    let mut ids=query.ids;ids.sort_unstable();ids.dedup();if ids.is_empty(){return Json(serde_json::json!({"items":[]})).into_response();}
    let rows=match sqlx::query_as::<_,(Uuid,i64,i64,i64)>("SELECT message_id,COUNT(*)::bigint,COUNT(delivered_at)::bigint,COUNT(read_at)::bigint FROM message_receipts WHERE sender_user_id=$1 AND message_id=ANY($2) GROUP BY message_id").bind(ctx.user_id).bind(ids).fetch_all(&state.db).await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"message receipt status unavailable")};
    let items=rows.into_iter().map(|(id,recipients,delivered,read)|serde_json::json!({"id":id,"recipient_count":recipients,"delivered_count":delivered,"read_count":read})).collect::<Vec<_>>();
    Json(serde_json::json!({"items":items})).into_response()
}
async fn mark_messages_read_api(State(state):State<AppState>,headers:HeaderMap,Json(query):Json<MessageReceiptsQuery>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    if query.ids.len()>200{return api_error(StatusCode::BAD_REQUEST,"at most 200 message IDs may be marked read at once");}
    let mut ids=query.ids;ids.sort_unstable();ids.dedup();if ids.is_empty(){return Json(serde_json::json!({"ok":true,"updated":0})).into_response();}
    match sqlx::query("UPDATE message_receipts SET delivered_at=COALESCE(delivered_at,now()),read_at=COALESCE(read_at,now()) WHERE message_id=ANY($1) AND recipient_user_id=$2 AND recipient_device_id=$3").bind(ids).bind(ctx.user_id).bind(ctx.device_id).execute(&state.db).await{
        Ok(result)=>Json(serde_json::json!({"ok":true,"updated":result.rows_affected()})).into_response(),
        Err(_)=>api_error(StatusCode::SERVICE_UNAVAILABLE,"read receipts could not be saved")
    }
}
async fn mark_message_read_api(State(state):State<AppState>,headers:HeaderMap,Path(id):Path<Uuid>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    match sqlx::query("UPDATE message_receipts SET delivered_at=COALESCE(delivered_at,now()),read_at=COALESCE(read_at,now()) WHERE message_id=$1 AND recipient_user_id=$2 AND recipient_device_id=$3").bind(id).bind(ctx.user_id).bind(ctx.device_id).execute(&state.db).await{
        Ok(_)=>Json(serde_json::json!({"ok":true})).into_response(),
        Err(_)=>api_error(StatusCode::SERVICE_UNAVAILABLE,"read receipt could not be saved")
    }
}
async fn send_message_api(State(state):State<AppState>,headers:HeaderMap,Json(input):Json<SendEnvelopeInput>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    let crypto_version=input.crypto_version.unwrap_or(1);
    if !matches!(crypto_version,1..=3)||input.to==ctx.device_id||!valid_ciphertext_parts(&input.iv,&input.ciphertext){return api_error(StatusCode::BAD_REQUEST,"invalid encrypted envelope");}
    let target_user=match sqlx::query_scalar::<_,Uuid>("SELECT user_id FROM devices WHERE id=$1 AND revoked_at IS NULL").bind(input.to).fetch_optional(&state.db).await{Ok(Some(v))=>v,Ok(None)=>return api_error(StatusCode::NOT_FOUND,"recipient device not found"),Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"message service unavailable")};
    let allowed=match sqlx::query_scalar::<_,bool>("SELECT ($1=$2 OR EXISTS(SELECT 1 FROM contacts WHERE owner_id=$1 AND contact_id=$2 AND deleted_at IS NULL)) AND NOT EXISTS(SELECT 1 FROM user_blocks WHERE (owner_id=$1 AND blocked_user_id=$2) OR (owner_id=$2 AND blocked_user_id=$1))").bind(ctx.user_id).bind(target_user).fetch_one(&state.db).await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"message authorization unavailable")};
    if !allowed{return api_error(StatusCode::FORBIDDEN,"recipient is not a contact");}
    let payload=serde_json::json!({"type":"message","id":input.id,"from":ctx.device_id,"crypto_version":crypto_version,"iv":input.iv,"ciphertext":input.ciphertext});
    let mut tx=match state.db.begin().await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"message service unavailable")};
    let locked=sqlx::query_scalar::<_,Uuid>("SELECT id FROM accounts WHERE id IN ($1,$2) ORDER BY id FOR SHARE").bind(ctx.user_id).bind(target_user).fetch_all(&mut *tx).await;
    let expected_locks=if ctx.user_id==target_user{1}else{2};
    if !locked.as_ref().is_ok_and(|ids|ids.len()==expected_locks){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"message authorization unavailable");}
    let still_allowed=sqlx::query_scalar::<_,bool>("SELECT ($1=$2 OR EXISTS(SELECT 1 FROM contacts WHERE owner_id=$1 AND contact_id=$2 AND deleted_at IS NULL)) AND NOT EXISTS(SELECT 1 FROM user_blocks WHERE (owner_id=$1 AND blocked_user_id=$2) OR (owner_id=$2 AND blocked_user_id=$1))").bind(ctx.user_id).bind(target_user).fetch_one(&mut *tx).await;
    if !matches!(still_allowed,Ok(true)){let _=tx.rollback().await;return api_error(StatusCode::FORBIDDEN,"recipient is not a contact");}
    if sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1::text),hashtext($2::text))").bind(input.to).bind("recipient-queue").execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"message queue unavailable");}
    let queued=match sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM queued_ciphertexts WHERE recipient_device_id=$1 AND delivered_at IS NULL AND id<>$2").bind(input.to).bind(input.id).fetch_one(&mut *tx).await{Ok(v)=>v,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"message queue unavailable");}};
    if queued>=MAX_QUEUED_PER_DEVICE{let _=tx.rollback().await;return api_error(StatusCode::TOO_MANY_REQUESTS,"recipient offline queue is full");}
    let inserted=match sqlx::query("INSERT INTO queued_ciphertexts(id,sender_device_id,recipient_device_id,payload) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(input.id).bind(ctx.device_id).bind(input.to).bind(&payload).execute(&mut *tx).await{Ok(v)=>v.rows_affected()>0,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"message could not be durably stored");}};
    if !inserted{let existing=match sqlx::query_as::<_,(Uuid,Value)>("SELECT sender_device_id,payload FROM queued_ciphertexts WHERE recipient_device_id=$1 AND id=$2").bind(input.to).bind(input.id).fetch_optional(&mut *tx).await{Ok(v)=>v,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"message retry could not be checked");}};if !matches!(existing,Some((sender,stored)) if sender==ctx.device_id && stored==payload){let _=tx.rollback().await;return api_error(StatusCode::CONFLICT,"message ID was already used with different content");}}
    let receipt=sqlx::query("INSERT INTO message_receipts(message_id,sender_user_id,sender_device_id,recipient_user_id,recipient_device_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT(message_id,recipient_device_id) DO UPDATE SET accepted_at=message_receipts.accepted_at WHERE message_receipts.sender_user_id=EXCLUDED.sender_user_id AND message_receipts.sender_device_id=EXCLUDED.sender_device_id AND message_receipts.recipient_user_id=EXCLUDED.recipient_user_id").bind(input.id).bind(ctx.user_id).bind(ctx.device_id).bind(target_user).bind(input.to).execute(&mut *tx).await;
    if !matches!(receipt,Ok(ref result) if result.rows_affected()==1){let _=tx.rollback().await;return api_error(StatusCode::CONFLICT,"message ID conflicts with an existing delivery record");}
    if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"message commit failed");}
    if inserted{let peer_tx=state.peers.get(&input.to).map(|peer|peer.tx.clone());if let Some(tx)=peer_tx{let live_payload=payload.to_string();tokio::spawn(async move{let _=tx.send(live_payload).await;});}}
    let _=sqlx::query("UPDATE devices SET last_seen_at=now() WHERE id=$1 AND user_id=$2").bind(ctx.device_id).bind(ctx.user_id).execute(&state.db).await;
    Json(serde_json::json!({"type":"accepted","id":input.id,"to":input.to})).into_response()
}
fn transfer_no_store(mut response:Response)->Response{
    response.headers_mut().insert(header::CACHE_CONTROL,HeaderValue::from_static("no-store"));
    response.headers_mut().insert(header::PRAGMA,HeaderValue::from_static("no-cache"));
    response
}

fn hex_lower(bytes:&[u8])->String{
    const HEX:&[u8]=b"0123456789abcdef";
    let mut result=String::with_capacity(bytes.len()*2);
    for byte in bytes{result.push(HEX[(byte>>4) as usize] as char);result.push(HEX[(byte&0x0f) as usize] as char);}
    result
}

async fn create_encrypted_transfer(State(state):State<AppState>,headers:HeaderMap,Json(input):Json<CreateTransferInput>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    let minimum_tag_bytes=match input.chunk_crypto_version{1=>16,2=>32,_=>return api_error(StatusCode::BAD_REQUEST,"unsupported encrypted-transfer chunk version")};
    if input.id.is_nil()||input.recipient_user_id.is_nil()||input.chunk_count<1||input.chunk_count>MAX_TRANSFER_CHUNKS
        ||input.total_ciphertext_bytes<1||input.total_ciphertext_bytes>MAX_TRANSFER_BYTES
        ||input.total_ciphertext_bytes>i64::from(input.chunk_count)*MAX_TRANSFER_CHUNK_BYTES as i64
        ||input.total_ciphertext_bytes<i64::from(input.chunk_count)*minimum_tag_bytes
        ||input.device_envelopes.is_empty()||input.device_envelopes.len()>MAX_TRANSFER_DEVICES{
        return api_error(StatusCode::BAD_REQUEST,"invalid encrypted transfer manifest or size limits");
    }
    let mut supplied=BTreeSet::new();
    for envelope in &input.device_envelopes{
        if envelope.device_id.is_nil()||!supplied.insert(envelope.device_id)||!matches!(envelope.crypto_version,1..=2)
            ||envelope.ciphertext.len()>16_384||!valid_ciphertext_parts(&envelope.iv,&envelope.ciphertext){
            return api_error(StatusCode::BAD_REQUEST,"invalid or duplicate per-device encrypted manifest");
        }
    }
    let mut tx=match state.db.begin().await{Ok(tx)=>tx,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer service unavailable")};
    // Serialize quota accounting for both participants, in a stable lock order.
    let mut quota_users=vec![ctx.user_id,input.recipient_user_id];quota_users.sort_unstable();quota_users.dedup();
    for user_id in quota_users{
        if sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1::text),hashtext('encrypted-transfer-quota'))").bind(user_id.to_string()).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer quota check unavailable");}
    }
    let recipient_verified=match sqlx::query_scalar::<_,bool>("SELECT email_verified FROM accounts WHERE id=$1").bind(input.recipient_user_id).fetch_optional(&mut *tx).await{Ok(Some(value))=>value,Ok(None)=>{let _=tx.rollback().await;return api_error(StatusCode::NOT_FOUND,"recipient account not found");},Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer service unavailable");}};
    if !recipient_verified{let _=tx.rollback().await;return api_error(StatusCode::FORBIDDEN,"recipient account is not verified");}
    let user_locks=sqlx::query_scalar::<_,Uuid>("SELECT id FROM accounts WHERE id IN ($1,$2) ORDER BY id FOR SHARE").bind(ctx.user_id).bind(input.recipient_user_id).fetch_all(&mut *tx).await;
    let expected_user_locks=if ctx.user_id==input.recipient_user_id{1}else{2};
    if !user_locks.is_ok_and(|ids|ids.len()==expected_user_locks){let _=tx.rollback().await;return api_error(StatusCode::NOT_FOUND,"recipient account not found");}
    if input.recipient_user_id!=ctx.user_id{
        let contact=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM contacts WHERE owner_id=$1 AND contact_id=$2 AND deleted_at IS NULL) AND NOT EXISTS(SELECT 1 FROM user_blocks WHERE (owner_id=$1 AND blocked_user_id=$2) OR (owner_id=$2 AND blocked_user_id=$1))").bind(ctx.user_id).bind(input.recipient_user_id).fetch_optional(&mut *tx).await;
        if !matches!(contact,Ok(Some(true))){let _=tx.rollback().await;return api_error(StatusCode::FORBIDDEN,"recipient must be an accepted contact");}
    }
    let mut active_devices=match sqlx::query_as::<_,(Uuid,Uuid)>("SELECT id,user_id FROM devices WHERE user_id IN ($1,$2) AND revoked_at IS NULL ORDER BY id FOR SHARE").bind(ctx.user_id).bind(input.recipient_user_id).fetch_all(&mut *tx).await{Ok(rows)=>rows,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer devices unavailable");}};
    // Transfer manifests are scoped to the sending session plus every active recipient device.
    // Other sender devices cannot silently inherit an in-progress transfer.
    active_devices.retain(|(device_id,user_id)|*user_id!=ctx.user_id||*device_id==ctx.device_id);
    let recipient_device_count=active_devices.iter().filter(|device|device.1==input.recipient_user_id).count();
    if recipient_device_count==0||active_devices.len()>MAX_TRANSFER_DEVICES{
        let _=tx.rollback().await;return api_error(StatusCode::CONFLICT,"no recipient device is available or the device limit was exceeded");
    }
    let expected=active_devices.iter().map(|(id,_)|*id).collect::<BTreeSet<_>>();
    if supplied!=expected{let _=tx.rollback().await;return api_error(StatusCode::BAD_REQUEST,"manifest must include the sending session and every active recipient device");}
    let usage=sqlx::query_as::<_,(i64,i64,i64,i64)>("SELECT (SELECT COALESCE(SUM(total_ciphertext_bytes),0) FROM encrypted_transfers WHERE expires_at>now() AND (sender_user_id=$1 OR recipient_user_id=$1)),(SELECT COALESCE(SUM(total_ciphertext_bytes),0) FROM encrypted_transfers WHERE expires_at>now() AND (sender_user_id=$2 OR recipient_user_id=$2)),(SELECT COUNT(*) FROM encrypted_transfers WHERE expires_at>now() AND (sender_user_id=$1 OR recipient_user_id=$1)),(SELECT COUNT(*) FROM encrypted_transfers WHERE expires_at>now() AND (sender_user_id=$2 OR recipient_user_id=$2))").bind(ctx.user_id).bind(input.recipient_user_id).fetch_one(&mut *tx).await;
    let(usage_sender,usage_recipient,count_sender,count_recipient)=match usage{Ok(value)=>value,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer quota check unavailable");}};
    if usage_sender.saturating_add(input.total_ciphertext_bytes)>MAX_ACTIVE_TRANSFER_BYTES_PER_ACCOUNT
        ||usage_recipient.saturating_add(input.total_ciphertext_bytes)>MAX_ACTIVE_TRANSFER_BYTES_PER_ACCOUNT
        ||count_sender>=MAX_ACTIVE_TRANSFERS_PER_ACCOUNT||count_recipient>=MAX_ACTIVE_TRANSFERS_PER_ACCOUNT{
        let _=tx.rollback().await;return api_error(StatusCode::INSUFFICIENT_STORAGE,"active encrypted-transfer quota exceeded");
    }
    let expires_days=TRANSFER_TTL_DAYS as i32;
    if let Err(error)=sqlx::query("INSERT INTO encrypted_transfers(id,sender_user_id,sender_device_id,recipient_user_id,chunk_count,chunk_crypto_version,total_ciphertext_bytes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()+make_interval(days => $8))").bind(input.id).bind(ctx.user_id).bind(ctx.device_id).bind(input.recipient_user_id).bind(input.chunk_count).bind(input.chunk_crypto_version as i16).bind(input.total_ciphertext_bytes).bind(expires_days).execute(&mut *tx).await{
        let _=tx.rollback().await;
        if error.as_database_error().is_some_and(|e|e.is_unique_violation()){return api_error(StatusCode::CONFLICT,"transfer ID already exists");}
        warn!("encrypted transfer creation failed");return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer could not be created");
    }
    for envelope in &input.device_envelopes{
        let Some(target_user)=active_devices.iter().find(|pair|pair.0==envelope.device_id).map(|pair|pair.1) else {let _=tx.rollback().await;return api_error(StatusCode::BAD_REQUEST,"manifest references an unavailable device");};
        if sqlx::query("INSERT INTO encrypted_transfer_device_envelopes(transfer_id,target_device_id,target_user_id,iv,ciphertext,crypto_version) VALUES($1,$2,$3,$4,$5,$6)").bind(input.id).bind(envelope.device_id).bind(target_user).bind(&envelope.iv).bind(&envelope.ciphertext).bind(envelope.crypto_version as i16).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"per-device transfer envelopes could not be saved");}
    }
    if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer could not be committed");}
    transfer_no_store((StatusCode::CREATED,Json(serde_json::json!({"id":input.id,"chunk_count":input.chunk_count,"chunk_crypto_version":input.chunk_crypto_version,"total_ciphertext_bytes":input.total_ciphertext_bytes,"expires_in_days":TRANSFER_TTL_DAYS,"state":"uploading","server_can_decrypt":false}))).into_response())
}

async fn upload_transfer_chunk(State(state):State<AppState>,headers:HeaderMap,Path((transfer_id,index)):Path<(Uuid,i32)>,body:Bytes)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    let content_type=headers.get(header::CONTENT_TYPE).and_then(|v|v.to_str().ok()).unwrap_or("").split(';').next().unwrap_or("").trim();
    if content_type!="application/octet-stream"||index<0||body.is_empty()||body.len()>MAX_TRANSFER_CHUNK_BYTES{return api_error(StatusCode::BAD_REQUEST,"chunk must be non-empty octet-stream data within the size limit");}
    let provided_hash=headers.get("x-chunk-sha256").and_then(|v|v.to_str().ok()).unwrap_or("");
    let hash=Sha256::digest(body.as_ref()).to_vec();if provided_hash.len()!=64||!provided_hash.eq_ignore_ascii_case(&hex_lower(&hash)){return api_error(StatusCode::BAD_REQUEST,"chunk SHA-256 does not match body");}
    let mut tx=match state.db.begin().await{Ok(tx)=>tx,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer service unavailable")};
    if sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1::text),hashtext('encrypted-transfer-upload'))").bind(transfer_id.to_string()).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer upload lock unavailable");}
    let meta=sqlx::query_as::<_,(Uuid,i32,i64,bool,bool)>("SELECT sender_device_id,chunk_count,total_ciphertext_bytes,ready_at IS NOT NULL,expires_at>now() FROM encrypted_transfers WHERE id=$1 FOR UPDATE").bind(transfer_id).fetch_optional(&mut *tx).await;
    let(sender_device,chunk_count,total_bytes,ready,not_expired)=match meta{Ok(Some(value))=>value,Ok(None)=>{let _=tx.rollback().await;return api_error(StatusCode::NOT_FOUND,"transfer not found");},Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer unavailable");}};
    if sender_device!=ctx.device_id{let _=tx.rollback().await;return api_error(StatusCode::FORBIDDEN,"only the originating device can upload transfer chunks");}
    if !not_expired{let _=tx.rollback().await;return api_error(StatusCode::GONE,"transfer expired");}
    if index>=chunk_count{let _=tx.rollback().await;return api_error(StatusCode::BAD_REQUEST,"chunk index is outside the declared manifest");}
    let existing=sqlx::query_scalar::<_,Vec<u8>>("SELECT sha256 FROM encrypted_transfer_chunks WHERE transfer_id=$1 AND chunk_index=$2").bind(transfer_id).bind(index).fetch_optional(&mut *tx).await;
    match existing{
        Ok(Some(saved_hash)) if saved_hash==hash=>{if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"chunk acknowledgement failed");}return Json(serde_json::json!({"ok":true,"duplicate":true,"sha256":hex_lower(&hash)})).into_response();}
        Ok(Some(_))=>{let _=tx.rollback().await;return api_error(StatusCode::CONFLICT,"chunk index already contains different ciphertext");}
        Ok(None)=>{}
        Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"chunk state unavailable");}
    }
    if ready{let _=tx.rollback().await;return api_error(StatusCode::CONFLICT,"transfer is already complete");}
    let current_bytes=match sqlx::query_scalar::<_,i64>("SELECT COALESCE(SUM(octet_length(ciphertext)),0) FROM encrypted_transfer_chunks WHERE transfer_id=$1").bind(transfer_id).fetch_one(&mut *tx).await{Ok(value)=>value,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer quota unavailable");}};
    if current_bytes.saturating_add(body.len() as i64)>total_bytes{let _=tx.rollback().await;return api_error(StatusCode::BAD_REQUEST,"chunk exceeds declared total size");}
    if sqlx::query("INSERT INTO encrypted_transfer_chunks(transfer_id,chunk_index,ciphertext,sha256) VALUES($1,$2,$3,$4)").bind(transfer_id).bind(index).bind(body.to_vec()).bind(&hash).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"chunk could not be stored");}
    let progress=match sqlx::query_as::<_,(i64,i64)>("SELECT COUNT(*),COALESCE(SUM(octet_length(ciphertext)),0) FROM encrypted_transfer_chunks WHERE transfer_id=$1").bind(transfer_id).fetch_one(&mut *tx).await{Ok(value)=>value,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer progress unavailable");}};
    let(count,received_bytes)=progress;
    let completed=count==i64::from(chunk_count);
    if completed&&received_bytes!=total_bytes{let _=tx.rollback().await;return api_error(StatusCode::BAD_REQUEST,"final chunk does not match declared total size");}
    if completed&&sqlx::query("UPDATE encrypted_transfers SET ready_at=now() WHERE id=$1 AND ready_at IS NULL").bind(transfer_id).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer could not be finalized");}
    if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"chunk could not be committed");}
    Json(serde_json::json!({"ok":true,"chunk_index":index,"received_chunks":count,"received_bytes":received_bytes,"complete":completed,"sha256":hex_lower(&hash)})).into_response()
}

async fn list_encrypted_transfers(State(state):State<AppState>,headers:HeaderMap)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    let rows=match sqlx::query_as::<_,(Uuid,Uuid,Uuid,Uuid,i32,i16,i64,i64,Option<String>,String,String,String,i16,bool)>("SELECT f.id,f.sender_user_id,f.recipient_user_id,f.sender_device_id,f.chunk_count,f.chunk_crypto_version,f.total_ciphertext_bytes,(SELECT COUNT(*) FROM encrypted_transfer_chunks c WHERE c.transfer_id=f.id),f.ready_at::text,f.expires_at::text,e.iv,e.ciphertext,e.crypto_version,e.acknowledged_at IS NOT NULL FROM encrypted_transfers f JOIN encrypted_transfer_device_envelopes e ON e.transfer_id=f.id JOIN devices d ON d.id=e.target_device_id JOIN accounts a ON a.id=e.target_user_id WHERE e.target_device_id=$1 AND d.revoked_at IS NULL AND a.email_verified=TRUE AND f.expires_at>now() AND (f.sender_device_id=$1 OR f.ready_at IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM user_blocks b WHERE (b.owner_id=f.sender_user_id AND b.blocked_user_id=f.recipient_user_id) OR (b.owner_id=f.recipient_user_id AND b.blocked_user_id=f.sender_user_id)) ORDER BY f.created_at DESC LIMIT 50").bind(ctx.device_id).fetch_all(&state.db).await{Ok(rows)=>rows,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer list unavailable")};
    transfer_no_store(Json(rows.into_iter().map(|(id,sender_user_id,recipient_user_id,sender_device_id,chunk_count,chunk_crypto_version,total_ciphertext_bytes,received_chunks,ready_at,expires_at,manifest_iv,manifest_ciphertext,manifest_crypto_version,acknowledged)|TransferReply{id,sender_user_id,recipient_user_id,sender_device_id,chunk_count,chunk_crypto_version:chunk_crypto_version as u8,total_ciphertext_bytes,received_chunks,ready_at,expires_at,manifest_iv,manifest_ciphertext,manifest_crypto_version:manifest_crypto_version as u8,acknowledged}).collect::<Vec<_>>()).into_response())
}

async fn download_transfer_chunk(State(state):State<AppState>,headers:HeaderMap,Path((transfer_id,index)):Path<(Uuid,i32)>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};if index<0{return api_error(StatusCode::BAD_REQUEST,"invalid chunk index");}
    let row=sqlx::query_as::<_,(Vec<u8>,Vec<u8>)>("SELECT c.ciphertext,c.sha256 FROM encrypted_transfer_chunks c JOIN encrypted_transfers f ON f.id=c.transfer_id JOIN encrypted_transfer_device_envelopes e ON e.transfer_id=f.id JOIN devices d ON d.id=e.target_device_id JOIN accounts a ON a.id=e.target_user_id WHERE c.transfer_id=$1 AND c.chunk_index=$2 AND f.ready_at IS NOT NULL AND f.expires_at>now() AND e.target_device_id=$3 AND d.revoked_at IS NULL AND a.email_verified=TRUE AND NOT EXISTS(SELECT 1 FROM user_blocks b WHERE (b.owner_id=f.sender_user_id AND b.blocked_user_id=f.recipient_user_id) OR (b.owner_id=f.recipient_user_id AND b.blocked_user_id=f.sender_user_id))").bind(transfer_id).bind(index).bind(ctx.device_id).fetch_optional(&state.db).await;
    let(bytes,digest)=match row{Ok(Some(value))=>value,Ok(None)=>return api_error(StatusCode::NOT_FOUND,"complete transfer chunk not found"),Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer chunk unavailable")};
    let mut response=Body::from(bytes).into_response();response.headers_mut().insert(header::CONTENT_TYPE,HeaderValue::from_static("application/octet-stream"));response.headers_mut().insert(header::CACHE_CONTROL,HeaderValue::from_static("no-store"));
    let digest_hex=hex_lower(&digest);if let Ok(value)=HeaderValue::try_from(digest_hex.as_str()){response.headers_mut().insert("x-chunk-sha256",value);}response
}

async fn ack_encrypted_transfer(State(state):State<AppState>,headers:HeaderMap,Path(transfer_id):Path<Uuid>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    match sqlx::query("UPDATE encrypted_transfer_device_envelopes e SET acknowledged_at=COALESCE(e.acknowledged_at,now()) WHERE e.transfer_id=$1 AND e.target_device_id=$2 AND EXISTS(SELECT 1 FROM encrypted_transfers f JOIN devices d ON d.id=e.target_device_id JOIN accounts a ON a.id=e.target_user_id WHERE f.id=e.transfer_id AND d.revoked_at IS NULL AND a.email_verified=TRUE AND f.ready_at IS NOT NULL AND f.expires_at>now())").bind(transfer_id).bind(ctx.device_id).execute(&state.db).await{
        Ok(result) if result.rows_affected()==1=>Json(serde_json::json!({"ok":true})).into_response(),
        Ok(_)=>api_error(StatusCode::NOT_FOUND,"complete transfer not found"),Err(_)=>api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer acknowledgement unavailable")
    }
}

async fn abort_encrypted_transfer(State(state):State<AppState>,headers:HeaderMap,Path(transfer_id):Path<Uuid>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    match sqlx::query("DELETE FROM encrypted_transfers WHERE id=$1 AND sender_device_id=$2").bind(transfer_id).bind(ctx.device_id).execute(&state.db).await{
        Ok(result) if result.rows_affected()==1=>Json(serde_json::json!({"ok":true})).into_response(),
        Ok(_)=>api_error(StatusCode::NOT_FOUND,"transfer not found"),Err(_)=>api_error(StatusCode::SERVICE_UNAVAILABLE,"transfer could not be deleted")
    }
}

async fn enforce_action_limit(db:&PgPool,user_id:Uuid,action:&str,limit:i32)->Result<bool,sqlx::Error>{
    let attempts=sqlx::query_scalar::<_,i32>("INSERT INTO account_action_limits(user_id,action,window_started_at,attempt_count) VALUES($1,$2,now(),1) ON CONFLICT(user_id,action) DO UPDATE SET window_started_at=CASE WHEN account_action_limits.window_started_at<now()-interval '1 hour' THEN now() ELSE account_action_limits.window_started_at END,attempt_count=CASE WHEN account_action_limits.window_started_at<now()-interval '1 hour' THEN 1 ELSE LEAST(account_action_limits.attempt_count+1,11) END RETURNING attempt_count").bind(user_id).bind(action).fetch_one(db).await?;
    Ok(attempts<=limit)
}

async fn create_contact_request(State(state):State<AppState>,headers:HeaderMap,Json(input):Json<AddContactInput>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    let supplied=[input.identity,input.username,input.email].into_iter().flatten().collect::<Vec<_>>();
    if supplied.len()!=1{return api_error(StatusCode::BAD_REQUEST,"provide exactly one username or email address");}
    let identity=supplied.into_iter().next().unwrap_or_default().trim().to_ascii_lowercase();
    let by_email=identity.contains('@');
    if (by_email&&!valid_email(&identity))||(!by_email&&!valid_username(&normalise_username(&identity))){return api_error(StatusCode::BAD_REQUEST,"enter a valid username or email address");}
    match enforce_action_limit(&state.db,ctx.user_id,"contact-discovery",10).await{
        Ok(true)=>{},Ok(false)=>return api_error(StatusCode::TOO_MANY_REQUESTS,"too many contact searches; try again later"),Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable")
    }
    let mut tx=match state.db.begin().await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable")};
    let candidate=if by_email{
        sqlx::query_as::<_,(Uuid,bool,bool)>("SELECT a.id,a.email_verified,COALESCE(s.settings->>'allow_contact_requests','true')<>'false' AND COALESCE(s.settings->>'discoverable_by_email','false')<>'false' FROM accounts a LEFT JOIN user_settings s ON s.user_id=a.id WHERE a.email=$1").bind(&identity).fetch_optional(&mut *tx).await
    }else{
        let username=normalise_username(&identity);
        sqlx::query_as::<_,(Uuid,bool,bool)>("SELECT a.id,a.email_verified,COALESCE(s.settings->>'allow_contact_requests','true')<>'false' FROM accounts a LEFT JOIN user_settings s ON s.user_id=a.id WHERE a.username=$1").bind(&username).fetch_optional(&mut *tx).await
    };
    let candidate=match candidate{Ok(row)=>row,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable");}};
    if let Some((target_id,verified,accepting_requests))=candidate{
        if target_id!=ctx.user_id&&verified&&accepting_requests{
            let locked=sqlx::query_scalar::<_,Uuid>("SELECT id FROM accounts WHERE id IN ($1,$2) ORDER BY id FOR SHARE").bind(ctx.user_id).bind(target_id).fetch_all(&mut *tx).await;
            if !locked.is_ok_and(|ids|ids.len()==2){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable");}
            let accepting_now=if by_email{
                sqlx::query_scalar::<_,bool>("SELECT COALESCE(settings->>'allow_contact_requests','true')<>'false' AND COALESCE(settings->>'discoverable_by_email','false')<>'false' FROM user_settings WHERE user_id=$1").bind(target_id).fetch_optional(&mut *tx).await
            }else{
                sqlx::query_scalar::<_,bool>("SELECT COALESCE(settings->>'allow_contact_requests','true')<>'false' FROM user_settings WHERE user_id=$1").bind(target_id).fetch_optional(&mut *tx).await
            };
            let accepting_now=match accepting_now{Ok(value)=>value.unwrap_or(true),Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable");}};
            if accepting_now{
                let mut lock_users=vec![ctx.user_id,target_id];lock_users.sort_unstable();lock_users.dedup();
                for user_id in lock_users{if sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1::text),hashtext('contact-request-quota'))").bind(user_id.to_string()).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable");}}
                let has_capacity=sqlx::query_scalar::<_,bool>("SELECT (SELECT COUNT(*) FROM contact_requests WHERE sender_id=$1 AND expires_at>now())<50 AND (SELECT COUNT(*) FROM contact_requests WHERE recipient_id=$2 AND expires_at>now())<100").bind(ctx.user_id).bind(target_id).fetch_one(&mut *tx).await;
                match has_capacity{Ok(true)=>{},Ok(false)=>{if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable");}return (StatusCode::ACCEPTED,Json(serde_json::json!({"ok":true,"message":"If the account is eligible, it will receive a connection request. This response does not reveal eligibility; sent requests appear in your pending list."}))).into_response();},Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable");}}
                let eligible=sqlx::query_scalar::<_,bool>("SELECT NOT EXISTS(SELECT 1 FROM contacts WHERE owner_id=$1 AND contact_id=$2 AND deleted_at IS NULL) AND NOT EXISTS(SELECT 1 FROM user_blocks WHERE (owner_id=$1 AND blocked_user_id=$2) OR (owner_id=$2 AND blocked_user_id=$1))").bind(ctx.user_id).bind(target_id).fetch_one(&mut *tx).await;
                match eligible{
                    Ok(true)=>{if sqlx::query("INSERT INTO contact_requests(id,sender_id,recipient_id) VALUES($1,$2,$3) ON CONFLICT(sender_id,recipient_id) DO NOTHING").bind(Uuid::new_v4()).bind(ctx.user_id).bind(target_id).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable");}},
                    Ok(false)=>{},Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable");}
                }
            }
        }
    }
    if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable");}
    (StatusCode::ACCEPTED,Json(serde_json::json!({"ok":true,"message":"If the account is eligible, it will receive a connection request. This response does not reveal eligibility; sent requests appear in your pending list."}))).into_response()
}

async fn list_contact_requests(State(state):State<AppState>,headers:HeaderMap)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    let rows=match sqlx::query_as::<_,(Uuid,String,String,String,String)>("(SELECT r.id,a.username,a.display_name,to_char(r.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),'incoming'::text FROM contact_requests r JOIN accounts a ON a.id=r.sender_id WHERE r.recipient_id=$1 AND r.expires_at>now()) UNION ALL (SELECT r.id,a.username,a.display_name,to_char(r.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),'sent'::text FROM contact_requests r JOIN accounts a ON a.id=r.recipient_id WHERE r.sender_id=$1 AND r.expires_at>now()) ORDER BY 4 DESC").bind(ctx.user_id).fetch_all(&state.db).await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact requests unavailable")};
    Json(rows.into_iter().map(|(id,username,display_name,created_at,direction)|ContactRequestReply{id,username,display_name,created_at,direction}).collect::<Vec<_>>()).into_response()
}

async fn accept_contact_request(State(state):State<AppState>,headers:HeaderMap,Path(request_id):Path<Uuid>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    let mut tx=match state.db.begin().await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable")};
    let possible_sender=match sqlx::query_scalar::<_,Uuid>("SELECT sender_id FROM contact_requests WHERE id=$1 AND recipient_id=$2 AND expires_at>now()").bind(request_id).bind(ctx.user_id).fetch_optional(&mut *tx).await{Ok(Some(v))=>v,Ok(None)=>{let _=tx.rollback().await;return api_error(StatusCode::NOT_FOUND,"pending request not found");},Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable");}};
    let locked=sqlx::query_scalar::<_,Uuid>("SELECT id FROM accounts WHERE id IN ($1,$2) ORDER BY id FOR SHARE").bind(ctx.user_id).bind(possible_sender).fetch_all(&mut *tx).await;
    if !locked.is_ok_and(|ids|ids.len()==2){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable");}
    let sender=match sqlx::query_scalar::<_,Uuid>("SELECT sender_id FROM contact_requests WHERE id=$1 AND recipient_id=$2 AND expires_at>now() FOR UPDATE").bind(request_id).bind(ctx.user_id).fetch_optional(&mut *tx).await{Ok(Some(v))=>v,Ok(None)=>{let _=tx.rollback().await;return api_error(StatusCode::NOT_FOUND,"pending request not found");},Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable");}};
    let blocked=match sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM user_blocks WHERE (owner_id=$1 AND blocked_user_id=$2) OR (owner_id=$2 AND blocked_user_id=$1))").bind(ctx.user_id).bind(sender).fetch_one(&mut *tx).await{Ok(v)=>v,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable");}};
    if blocked{let _=sqlx::query("DELETE FROM contact_requests WHERE id=$1").bind(request_id).execute(&mut *tx).await;let _=tx.commit().await;return api_error(StatusCode::NOT_FOUND,"pending request not found");}
    let sender_name=match sqlx::query_scalar::<_,String>("SELECT display_name FROM accounts WHERE id=$1").bind(sender).fetch_optional(&mut *tx).await{Ok(Some(value))=>value,Ok(None)=>{let _=tx.rollback().await;return api_error(StatusCode::NOT_FOUND,"pending request not found");},Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not accept contact request");}};
    for(owner,contact,label)in[(ctx.user_id,sender,sender_name.as_str()),(sender,ctx.user_id,ctx.display_name.as_str())]{
        if sqlx::query("INSERT INTO contacts(owner_id,contact_id,contact_display_name) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(owner).bind(contact).bind(label).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not accept contact request");}
    }
    if sqlx::query("DELETE FROM contact_requests WHERE (sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1)").bind(ctx.user_id).bind(sender).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not accept contact request");}
    if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not accept contact request");}
    Json(serde_json::json!({"ok":true,"contact_id":sender})).into_response()
}

async fn delete_contact_request(State(state):State<AppState>,headers:HeaderMap,Path(request_id):Path<Uuid>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    match sqlx::query("DELETE FROM contact_requests WHERE id=$1 AND (sender_id=$2 OR recipient_id=$2)").bind(request_id).bind(ctx.user_id).execute(&state.db).await{
        Ok(result) if result.rows_affected()==1=>Json(serde_json::json!({"ok":true})).into_response(),
        Ok(_)=>api_error(StatusCode::NOT_FOUND,"pending request not found"),Err(_)=>api_error(StatusCode::SERVICE_UNAVAILABLE,"contact request service unavailable")
    }
}

async fn list_blocks(State(state):State<AppState>,headers:HeaderMap)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    let rows=match sqlx::query_as::<_,(Uuid,String,String,String)>("SELECT b.blocked_user_id,a.username,a.display_name,b.created_at::text FROM user_blocks b JOIN accounts a ON a.id=b.blocked_user_id WHERE b.owner_id=$1 ORDER BY a.username").bind(ctx.user_id).fetch_all(&state.db).await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"blocked users unavailable")};
    Json(rows.into_iter().map(|(user_id,username,display_name,created_at)|BlockReply{user_id,username,display_name,created_at}).collect::<Vec<_>>()).into_response()
}

async fn block_user(State(state):State<AppState>,headers:HeaderMap,Path(user_id):Path<Uuid>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    if user_id==ctx.user_id{return api_error(StatusCode::BAD_REQUEST,"you cannot block yourself");}
    let mut tx=match state.db.begin().await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"block service unavailable")};
    let locked=sqlx::query_scalar::<_,Uuid>("SELECT id FROM accounts WHERE id IN ($1,$2) ORDER BY id FOR UPDATE").bind(ctx.user_id).bind(user_id).fetch_all(&mut *tx).await;
    if !locked.is_ok_and(|ids|ids.len()==2){let _=tx.rollback().await;return api_error(StatusCode::NOT_FOUND,"user not found");}
    let inserted=match sqlx::query("INSERT INTO user_blocks(owner_id,blocked_user_id) SELECT $1,id FROM accounts WHERE id=$2 ON CONFLICT DO NOTHING").bind(ctx.user_id).bind(user_id).execute(&mut *tx).await{Ok(v)=>v,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"block service unavailable");}};
    let exists=if inserted.rows_affected()==1{true}else{sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM user_blocks WHERE owner_id=$1 AND blocked_user_id=$2)").bind(ctx.user_id).bind(user_id).fetch_one(&mut *tx).await.unwrap_or(false)};
    if !exists{let _=tx.rollback().await;return api_error(StatusCode::NOT_FOUND,"user not found");}
    if sqlx::query("DELETE FROM contacts WHERE (owner_id=$1 AND contact_id=$2) OR (owner_id=$2 AND contact_id=$1)").bind(ctx.user_id).bind(user_id).execute(&mut *tx).await.is_err()||sqlx::query("DELETE FROM contact_requests WHERE (sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1)").bind(ctx.user_id).bind(user_id).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"block service unavailable");}
    if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"block service unavailable");}
    Json(serde_json::json!({"ok":true,"contact_removed":true,"history_retained":true})).into_response()
}

async fn unblock_user(State(state):State<AppState>,headers:HeaderMap,Path(user_id):Path<Uuid>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    match sqlx::query("DELETE FROM user_blocks WHERE owner_id=$1 AND blocked_user_id=$2").bind(ctx.user_id).bind(user_id).execute(&state.db).await{
        Ok(result) if result.rows_affected()==1=>Json(serde_json::json!({"ok":true})).into_response(),
        Ok(_)=>api_error(StatusCode::NOT_FOUND,"blocked user not found"),Err(_)=>api_error(StatusCode::SERVICE_UNAVAILABLE,"block service unavailable")
    }
}
async fn remove_contact(State(state):State<AppState>,headers:HeaderMap,Path(contact_id):Path<Uuid>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    let mut tx=match state.db.begin().await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"contacts unavailable")};
    if sqlx::query("DELETE FROM contacts WHERE (owner_id=$1 AND contact_id=$2) OR (owner_id=$2 AND contact_id=$1)").bind(ctx.user_id).bind(contact_id).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not remove contact");}
    if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not remove contact");}
    Json(serde_json::json!({"ok":true,"history_retained":true})).into_response()
}
async fn list_devices(State(state):State<AppState>,headers:HeaderMap)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};let rows=match sqlx::query_as::<_,(Uuid,String,String,String,bool,bool)>("SELECT d.id,d.label,to_char(d.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),to_char(d.last_seen_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),d.id=$2,(d.last_seen_at>now()-interval '90 seconds') FROM devices d WHERE d.user_id=$1 AND d.revoked_at IS NULL ORDER BY d.last_seen_at DESC").bind(ctx.user_id).bind(ctx.device_id).fetch_all(&state.db).await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"device sessions unavailable")};Json(rows.into_iter().map(|(id,name,created_at,last_seen_at,current,recently_active)|DeviceSessionReply{id,name,created_at,last_seen_at,current,online:recently_active&&state.peers.contains_key(&id)}).collect::<Vec<_>>()).into_response()
}
async fn revoke_device(State(state):State<AppState>,headers:HeaderMap,Path(device_id):Path<Uuid>)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    if device_id==ctx.device_id{return api_error(StatusCode::BAD_REQUEST,"use sign out to end this device session");}
    let mut tx=match state.db.begin().await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"device sessions unavailable")};
    let updated=match sqlx::query("UPDATE devices SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL").bind(device_id).bind(ctx.user_id).execute(&mut *tx).await{Ok(v)=>v.rows_affected(),Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not revoke device");}};
    if updated==0{let _=tx.rollback().await;return api_error(StatusCode::NOT_FOUND,"device session not found");}
    if sqlx::query("DELETE FROM auth_sessions WHERE device_id=$1 AND user_id=$2").bind(device_id).bind(ctx.user_id).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not revoke device");}
    if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not revoke device");}
    state.peers.remove(&device_id);Json(serde_json::json!({"ok":true,"history_retained":true})).into_response()
}
async fn revoke_other_devices(State(state):State<AppState>,headers:HeaderMap)->Response{
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    let mut tx=match state.db.begin().await{Ok(v)=>v,Err(_)=>return api_error(StatusCode::SERVICE_UNAVAILABLE,"device sessions unavailable")};
    let ids=match sqlx::query_scalar::<_,Uuid>("SELECT id FROM devices WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL").bind(ctx.user_id).bind(ctx.device_id).fetch_all(&mut *tx).await{Ok(v)=>v,Err(_)=>{let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not list devices");}};
    if sqlx::query("UPDATE devices SET revoked_at=now() WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL").bind(ctx.user_id).bind(ctx.device_id).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not revoke devices");}
    if sqlx::query("DELETE FROM auth_sessions WHERE user_id=$1 AND device_id<>$2").bind(ctx.user_id).bind(ctx.device_id).execute(&mut *tx).await.is_err(){let _=tx.rollback().await;return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not revoke devices");}
    if tx.commit().await.is_err(){return api_error(StatusCode::SERVICE_UNAVAILABLE,"could not revoke devices");}
    for id in ids{state.peers.remove(&id);}
    Json(serde_json::json!({"ok":true,"history_retained":true})).into_response()
}
async fn ws_handler(State(state):State<AppState>,headers:HeaderMap,ws:WebSocketUpgrade)->Response{
    if let Some(origin)=headers.get(header::ORIGIN).and_then(|v|v.to_str().ok()){
        let allowed=normalize_web_origin(origin).ok().is_some_and(|value|state.allowed_origins.iter().any(|item|item==&value));
        if !allowed{warn!(origin=%origin,"rejected websocket origin not listed in ALLOWED_WEB_ORIGINS");return api_error(StatusCode::FORBIDDEN,"web origin is not allowed");}
    }
    let ctx=match require_user(&state,&headers).await{Ok(v)=>v,Err(r)=>return r};
    ws.max_message_size(100*1024).max_frame_size(100*1024).on_upgrade(move|socket|handle_socket(socket,state,ctx)).into_response()
}
async fn handle_socket(socket:WebSocket,state:AppState,ctx:AuthContext){
    if state.peers.len()>=MAX_LIVE_CONNECTIONS&&!state.peers.contains_key(&ctx.device_id){warn!("live connection cap reached");return;}let(mut ws_tx,mut ws_rx)=socket.split();let(out_tx,mut out_rx)=mpsc::channel::<String>(128);let connection_id=Uuid::new_v4();state.peers.insert(ctx.device_id,Peer{connection_id,tx:out_tx.clone()});let _=sqlx::query("UPDATE devices SET last_seen_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL").bind(ctx.device_id).bind(ctx.user_id).execute(&state.db).await;
    // Replay in bounded keyset pages on a producer task. The socket loop starts immediately,
    // so the bounded channel is always drained while a large offline backlog is replayed.
    {let db=state.db.clone();let tx=out_tx.clone();let device_id=ctx.device_id;tokio::spawn(async move{
        let mut cursor_time:Option<String>=None;let mut cursor_id:Option<Uuid>=None;
        loop {
            let rows=sqlx::query_as::<_,(Uuid,Value,String)>("SELECT id,payload,created_at::text FROM queued_ciphertexts WHERE recipient_device_id=$1 AND delivered_at IS NULL AND ($2::timestamptz IS NULL OR (created_at,id)>($2::timestamptz,$3::uuid)) ORDER BY created_at,id LIMIT 100").bind(device_id).bind(cursor_time.as_deref()).bind(cursor_id).fetch_all(&db).await;
            let Ok(rows)=rows else{break;};if rows.is_empty(){break;}let count=rows.len();
            for(id,payload,created_at)in rows{cursor_time=Some(created_at);cursor_id=Some(id);if tx.send(payload.to_string()).await.is_err(){return;}}
            if count<100{break;}
        }
    });}
    let mut session_check=tokio::time::interval(Duration::from_secs(20));loop{tokio::select!{
        _=session_check.tick()=>{if !session_is_active(&state.db,&ctx).await{let _=ws_tx.send(Message::Close(None)).await;break;}},
        outgoing=out_rx.recv()=>match outgoing{Some(text)=>{if !session_is_active(&state.db,&ctx).await{let _=ws_tx.send(Message::Close(None)).await;break;}if ws_tx.send(Message::Text(text.into())).await.is_err(){break}},None=>break},
        incoming=ws_rx.next()=>match incoming{Some(Ok(Message::Text(text)))=>{
            if !session_is_active(&state.db,&ctx).await{let _=ws_tx.send(Message::Close(None)).await;break;}if text.len()>MAX_CIPHERTEXT_CHARS+1024{continue;}let Ok(frame)=serde_json::from_str::<ClientFrame>(&text)else{continue;};
            match frame{ClientFrame::Message{id,to,iv,ciphertext,crypto_version}=>{
                let crypto_version=crypto_version.unwrap_or(1);if !matches!(crypto_version,1..=3)||to==ctx.device_id||!valid_ciphertext_parts(&iv,&ciphertext){continue;}let target_user=sqlx::query_scalar::<_,Uuid>("SELECT d.user_id FROM devices d WHERE d.id=$1 AND d.revoked_at IS NULL").bind(to).fetch_optional(&state.db).await.ok().flatten();let Some(target_user)=target_user else{let _=ws_tx.send(Message::Text(serde_json::json!({"type":"error","id":id,"to":to,"message":"recipient device is unavailable"}).to_string().into())).await;continue;};let allowed=sqlx::query_scalar::<_,bool>("SELECT ($1=$2 OR EXISTS(SELECT 1 FROM contacts WHERE owner_id=$1 AND contact_id=$2 AND deleted_at IS NULL)) AND NOT EXISTS(SELECT 1 FROM user_blocks WHERE (owner_id=$1 AND blocked_user_id=$2) OR (owner_id=$2 AND blocked_user_id=$1))").bind(ctx.user_id).bind(target_user).fetch_one(&state.db).await.unwrap_or(false);if !allowed{let _=ws_tx.send(Message::Text(serde_json::json!({"type":"error","id":id,"message":"recipient is not a contact"}).to_string().into())).await;continue;}
                let payload=serde_json::json!({"type":"message","id":id,"from":ctx.device_id,"crypto_version":crypto_version,"iv":iv,"ciphertext":ciphertext});
                let mut tx=match state.db.begin().await{Ok(tx)=>tx,Err(_)=>{let _=ws_tx.send(Message::Text(serde_json::json!({"type":"error","id":id,"to":to,"message":"message service unavailable"}).to_string().into())).await;continue;}};
                let account_locks=sqlx::query_scalar::<_,Uuid>("SELECT id FROM accounts WHERE id IN ($1,$2) ORDER BY id FOR SHARE").bind(ctx.user_id).bind(target_user).fetch_all(&mut *tx).await;let expected_locks=if ctx.user_id==target_user{1}else{2};if !account_locks.is_ok_and(|ids|ids.len()==expected_locks){let _=tx.rollback().await;continue;}
                let still_allowed=sqlx::query_scalar::<_,bool>("SELECT ($1=$2 OR EXISTS(SELECT 1 FROM contacts WHERE owner_id=$1 AND contact_id=$2 AND deleted_at IS NULL)) AND NOT EXISTS(SELECT 1 FROM user_blocks WHERE (owner_id=$1 AND blocked_user_id=$2) OR (owner_id=$2 AND blocked_user_id=$1))").bind(ctx.user_id).bind(target_user).fetch_one(&mut *tx).await;if !matches!(still_allowed,Ok(true)){let _=tx.rollback().await;let _=ws_tx.send(Message::Text(serde_json::json!({"type":"error","id":id,"message":"recipient is not a contact"}).to_string().into())).await;continue;}
                let _=sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1::text),hashtext($2::text))").bind(to).bind("recipient-queue").execute(&mut *tx).await;
                let queued=sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM queued_ciphertexts WHERE recipient_device_id=$1 AND delivered_at IS NULL AND id<>$2").bind(to).bind(id).fetch_one(&mut *tx).await.unwrap_or(MAX_QUEUED_PER_DEVICE);
                if queued>=MAX_QUEUED_PER_DEVICE{let _=tx.rollback().await;let _=ws_tx.send(Message::Text(serde_json::json!({"type":"error","id":id,"to":to,"message":"recipient offline queue is full"}).to_string().into())).await;continue;}
                let inserted=match sqlx::query("INSERT INTO queued_ciphertexts(id,sender_device_id,recipient_device_id,payload) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(id).bind(ctx.device_id).bind(to).bind(&payload).execute(&mut *tx).await{Ok(r)=>r.rows_affected()>0,Err(_)=>{warn!("ciphertext insert failed");let _=tx.rollback().await;let _=ws_tx.send(Message::Text(serde_json::json!({"type":"error","id":id,"to":to,"message":"message could not be durably stored"}).to_string().into())).await;continue;}};
                if !inserted{let existing=sqlx::query_as::<_,(Uuid,Value)>("SELECT sender_device_id,payload FROM queued_ciphertexts WHERE recipient_device_id=$1 AND id=$2").bind(to).bind(id).fetch_optional(&mut *tx).await.ok().flatten();if !matches!(existing,Some((sender,stored)) if sender==ctx.device_id && stored==payload){let _=tx.rollback().await;let _=ws_tx.send(Message::Text(serde_json::json!({"type":"error","id":id,"to":to,"message":"message ID was already used with different content"}).to_string().into())).await;continue;}}
                let receipt=sqlx::query("INSERT INTO message_receipts(message_id,sender_user_id,sender_device_id,recipient_user_id,recipient_device_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT(message_id,recipient_device_id) DO UPDATE SET accepted_at=message_receipts.accepted_at WHERE message_receipts.sender_user_id=EXCLUDED.sender_user_id AND message_receipts.sender_device_id=EXCLUDED.sender_device_id AND message_receipts.recipient_user_id=EXCLUDED.recipient_user_id").bind(id).bind(ctx.user_id).bind(ctx.device_id).bind(target_user).bind(to).execute(&mut *tx).await;
                if !matches!(receipt,Ok(ref result) if result.rows_affected()==1){let _=tx.rollback().await;let _=ws_tx.send(Message::Text(serde_json::json!({"type":"error","id":id,"to":to,"message":"message ID conflicts with an existing delivery record"}).to_string().into())).await;continue;}
                if tx.commit().await.is_err(){let _=ws_tx.send(Message::Text(serde_json::json!({"type":"error","id":id,"to":to,"message":"message commit failed"}).to_string().into())).await;continue;}
                if inserted{let peer_tx=state.peers.get(&to).map(|peer|peer.tx.clone());if let Some(tx)=peer_tx{let live_payload=payload.to_string();tokio::spawn(async move{let _=tx.send(live_payload).await;});}}let _=sqlx::query("UPDATE devices SET last_seen_at=now() WHERE id=$1").bind(ctx.device_id).execute(&state.db).await;let _=ws_tx.send(Message::Text(serde_json::json!({"type":"accepted","id":id,"to":to}).to_string().into())).await;
            },ClientFrame::Ack{id}=>{let _=sqlx::query("UPDATE message_receipts SET delivered_at=COALESCE(delivered_at,now()) WHERE message_id=$1 AND recipient_user_id=$2 AND recipient_device_id=$3").bind(id).bind(ctx.user_id).bind(ctx.device_id).execute(&state.db).await;let _=sqlx::query("UPDATE queued_ciphertexts SET delivered_at=COALESCE(delivered_at,now()) WHERE recipient_device_id=$1 AND id=$2").bind(ctx.device_id).bind(id).execute(&state.db).await;},ClientFrame::Heartbeat=>{let _=sqlx::query("UPDATE devices SET last_seen_at=now() WHERE id=$1 AND revoked_at IS NULL").bind(ctx.device_id).execute(&state.db).await;}}
        },Some(Ok(Message::Close(_)))|None|Some(Err(_))=>break,_=>{}}
    }}if state.peers.get(&ctx.device_id).is_some_and(|p|p.connection_id==connection_id){state.peers.remove(&ctx.device_id);}
}

#[cfg(test)]
mod tests {
    use super::{account_unique_conflict, cooldown_seconds, history_page_limit, normalise_username, normalize_web_origin, parse_web_origins, p256_key_bundle_fingerprint, registration_password_requirements, token_hash, valid_ciphertext_parts, valid_email, valid_font_scale, valid_theme, valid_username, LoginInput, VerifyLoginInput, P256PublicJwk, TransferDeviceEnvelope, DevicePublicKeyInput, CreateTransferInput, seal_account_backup_key, open_account_backup_key, backup_key_at_rest_aad};
    use uuid::Uuid;
    use zeroize::Zeroize;
    use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use hkdf::Hkdf;
    use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint, SecretKey};
    use rand_core::OsRng;
    use sha2_11::Sha256 as HkdfSha256;
    #[test] fn backup_master_key_is_aead_protected_at_rest_and_bound_to_account(){let account=Uuid::new_v4();let other=Uuid::new_v4();let mut backup=[7u8;32];let kek=[9u8;32];let(nonce,ciphertext)=seal_account_backup_key(account,&backup,&kek).unwrap();assert_eq!(ciphertext.len(),48);assert_eq!(open_account_backup_key(account,&nonce,&ciphertext,&kek).unwrap(),backup);assert!(open_account_backup_key(other,&nonce,&ciphertext,&kek).is_err());backup.zeroize();}
    #[test] fn ephemeral_p256_backup_key_envelope_round_trips_with_client_exchange(){let server_secret=SecretKey::random(&mut OsRng);let client_secret=SecretKey::random(&mut OsRng);let server_public=server_secret.public_key();let client_public=client_secret.public_key();let server_shared=diffie_hellman(server_secret.to_nonzero_scalar(),client_public.as_affine());let client_shared=diffie_hellman(client_secret.to_nonzero_scalar(),server_public.as_affine());assert_eq!(server_shared.raw_secret_bytes(),client_shared.raw_secret_bytes());let client_point=client_public.to_encoded_point(false);let server_point=server_public.to_encoded_point(false);let cx=URL_SAFE_NO_PAD.encode(client_point.x().unwrap());let cy=URL_SAFE_NO_PAD.encode(client_point.y().unwrap());let sx=URL_SAFE_NO_PAD.encode(server_point.x().unwrap());let sy=URL_SAFE_NO_PAD.encode(server_point.y().unwrap());let user=Uuid::new_v4().to_string();let device=Uuid::new_v4().to_string();let salt=[4u8;32];let nonce=[6u8;12];let salt_text=URL_SAFE_NO_PAD.encode(salt);let nonce_text=URL_SAFE_NO_PAD.encode(nonce);let info=serde_json::to_vec(&serde_json::json!(["serein-backup-key-envelope-kdf-v1",user,device,1,cx,cy,sx,sy])).unwrap();let aad=serde_json::to_vec(&serde_json::json!(["serein-backup-key-envelope-aad-v1",user,device,1,cx,cy,sx,sy,salt_text,nonce_text])).unwrap();let mut key=[0u8;32];Hkdf::<HkdfSha256>::new(Some(&salt),server_shared.raw_secret_bytes().as_slice()).expand(&info,&mut key).unwrap();let backup=[11u8;32];let cipher=Aes256Gcm::new_from_slice(&key).unwrap();let ciphertext=cipher.encrypt(Nonce::from_slice(&nonce),Payload{msg:&backup,aad:&aad}).unwrap();let mut client_key=[0u8;32];Hkdf::<HkdfSha256>::new(Some(&salt),client_shared.raw_secret_bytes().as_slice()).expand(&info,&mut client_key).unwrap();let client_cipher=Aes256Gcm::new_from_slice(&client_key).unwrap();let opened=client_cipher.decrypt(Nonce::from_slice(&nonce),Payload{msg:&ciphertext,aad:&aad}).unwrap();assert_eq!(opened,backup);key.zeroize();client_key.zeroize();}
    #[test] fn backup_at_rest_aad_is_compact_json_with_stable_binding_fields(){let aad=backup_key_at_rest_aad(Uuid::parse_str("8ac15a50-267e-4d62-8e16-b0854d1c722d").unwrap()).unwrap();assert_eq!(String::from_utf8(aad).unwrap(),r#"["serein-account-backup-key-at-rest-v1","8ac15a50-267e-4d62-8e16-b0854d1c722d",1]"#);}
    #[test] fn duplicate_username_and_email_return_distinct_safe_messages(){assert!(account_unique_conflict(Some("accounts_username_key")).unwrap().contains("username"));assert!(account_unique_conflict(Some("accounts_email_key")).unwrap().contains("email"));assert!(account_unique_conflict(Some("unrelated_constraint")).is_none());}
    #[test] fn username_normalisation_is_ascii_lowercase(){assert_eq!(normalise_username("  Alice_7 "),"alice_7");}
    #[test] fn username_validation_rejects_short_and_unsafe_values(){assert!(valid_username("alice.7"));assert!(!valid_username("ab"));assert!(!valid_username("bad name"));assert!(!valid_username("Upper"));}
    #[test] fn email_validation_rejects_obvious_invalid_values(){assert!(valid_email("user@example.org"));assert!(!valid_email("no-at-sign"));assert!(!valid_email("user@localhost"));}
    #[test] fn session_tokens_are_stored_as_fixed_length_hashes(){let a=token_hash("opaque-random-session");assert_eq!(a.len(),32);assert_eq!(a,token_hash("opaque-random-session"));assert_ne!(a,token_hash("different-session"));}
    #[test] fn history_page_size_is_defaulted_and_bounded(){assert_eq!(history_page_limit(None),100);assert_eq!(history_page_limit(Some(0)),1);assert_eq!(history_page_limit(Some(500)),200);}
    #[test] fn account_setting_values_are_allowlisted(){assert!(valid_theme("dark"));assert!(!valid_theme("ultraviolet"));assert!(valid_font_scale("system"));assert!(valid_font_scale("large"));assert!(valid_font_scale("extra_large"));assert!(!valid_font_scale("huge"));}
    #[test] fn ciphertext_envelopes_require_gcm_iv_and_tag(){assert!(valid_ciphertext_parts("AAAAAAAAAAAAAAAA","AAAAAAAAAAAAAAAAAAAAAA=="));assert!(!valid_ciphertext_parts("short","AAAAAAAAAAAAAAAAAAAAAA=="));assert!(!valid_ciphertext_parts("AAAAAAAAAAAAAAAA","AA=="));}
    #[test] fn device_ratchet_capability_defaults_to_legacy_static_and_accepts_web_v3(){let public=r#"{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}"#;let legacy:DevicePublicKeyInput=serde_json::from_str(&format!(r#"{{"algorithm":"ECDH-P256","public_key":{public},"layer2_public_key":{public}}}"#)).unwrap();assert_eq!(legacy.ratchet_version,None);let web:DevicePublicKeyInput=serde_json::from_str(&format!(r#"{{"algorithm":"ECDH-P256","public_key":{public},"layer2_public_key":{public},"ratchet_version":3}}"#)).unwrap();assert_eq!(web.ratchet_version,Some(3));}
    #[test] fn transfer_manifest_crypto_version_is_explicit_and_legacy_defaults_to_one(){let legacy:TransferDeviceEnvelope=serde_json::from_str(r#"{"device_id":"11111111-1111-4111-8111-111111111111","iv":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA=="}"#).unwrap();assert_eq!(legacy.crypto_version,1);let layered:TransferDeviceEnvelope=serde_json::from_str(r#"{"device_id":"11111111-1111-4111-8111-111111111111","crypto_version":2,"iv":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA=="}"#).unwrap();assert_eq!(layered.crypto_version,2);}
    #[test] fn transfer_chunk_crypto_version_defaults_legacy_and_accepts_nested_v2(){let base=r#"{"id":"11111111-1111-4111-8111-111111111111","recipient_user_id":"22222222-2222-4222-8222-222222222222","chunk_count":1,"total_ciphertext_bytes":32,"device_envelopes":[]}"#;let legacy:CreateTransferInput=serde_json::from_str(base).unwrap();assert_eq!(legacy.chunk_crypto_version,1);let v2:CreateTransferInput=serde_json::from_str(&base.replace("\"total_ciphertext_bytes\":32","\"chunk_crypto_version\":2,\"total_ciphertext_bytes\":32")).unwrap();assert_eq!(v2.chunk_crypto_version,2);}
    #[test] fn layer2_fingerprint_binds_both_ordered_device_public_keys(){let first=P256PublicJwk{kty:"EC".into(),crv:"P-256".into(),x:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),y:"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into()};let second=P256PublicJwk{kty:"EC".into(),crv:"P-256".into(),x:"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".into(),y:"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM".into()};let ab=p256_key_bundle_fingerprint(&first,&second).unwrap();let ba=p256_key_bundle_fingerprint(&second,&first).unwrap();assert_eq!(ab.len(),64);assert_ne!(ab,ba);}
    #[test] fn registration_password_policy_requires_length_case_digit_and_byte_limit(){assert_eq!(registration_password_requirements("Serein123"),[true,true,true,true,true]);assert_eq!(registration_password_requirements("password1"),[true,false,true,true,true]);assert_eq!(registration_password_requirements("PASSWORD1"),[true,true,false,true,true]);assert_eq!(registration_password_requirements("Password"),[true,true,true,false,true]);assert_eq!(registration_password_requirements("Abc123"),[false,true,true,true,true]);assert!(!registration_password_requirements(&format!("{}Aa1", "x".repeat(1022)))[4]);}
    #[test] fn resend_cooldown_seconds_are_parsed_and_bounded_by_response(){assert_eq!(cooldown_seconds("cooldown:59"),Some(59));assert_eq!(cooldown_seconds("cooldown"),Some(60));assert_eq!(cooldown_seconds("send_limit"),None);}
    #[test] fn login_payload_is_strict_and_login_otp_requires_all_credentials(){
        assert!(serde_json::from_str::<LoginInput>(r#"{"identity":"person@example.test","password":"correct horse battery staple"}"#).is_ok());
        assert!(serde_json::from_str::<LoginInput>(r#"{"identity":"person@example.test","password":"secret","device_name":"Android"}"#).is_err());
        assert!(serde_json::from_str::<VerifyLoginInput>(r#"{"identity":"person@example.test","password":"secret","code":"123456"}"#).is_ok());
        assert!(serde_json::from_str::<VerifyLoginInput>(r#"{"identity":"person@example.test","password":"secret"}"#).is_err());
    }
    #[test] fn web_origins_are_exact_https_origins_and_local_http_only(){assert_eq!(normalize_web_origin("https://web.example.org/" ).unwrap(),"https://web.example.org");assert_eq!(normalize_web_origin("https://web.example.org:8443").unwrap(),"https://web.example.org:8443");assert!(normalize_web_origin("https://web.example.org/path").is_err());assert!(normalize_web_origin("http://web.example.org").is_err());assert_eq!(normalize_web_origin("http://localhost:8080").unwrap(),"http://localhost:8080");}
    #[test] fn comma_separated_web_origins_accept_multiple_exact_origins_and_reject_bad_entries(){assert_eq!(parse_web_origins("https://app.example.org, https://preview.example.org:8443, https://app.example.org").unwrap(),vec!["https://app.example.org","https://preview.example.org:8443"]);assert!(parse_web_origins("https://app.example.org,https://evil.example.org/path").is_err());assert!(parse_web_origins(" , ").is_err());}
}
