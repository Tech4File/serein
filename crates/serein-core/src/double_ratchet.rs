//! Serein development Double Ratchet core, implemented over X25519, HKDF-SHA256,
//! HMAC-SHA256, and AES-256-GCM.
//!
//! The initializer consumes a caller-authenticated bootstrap secret and the
//! first DH public/private pair. X3DH/signed-prekey directory handling, identity
//! signatures, app integration, independent review, and migration of existing
//! static-P256 message history are separate unfinished layers. Local snapshots
//! contain private keys and live chain/message keys and must be AEAD-sealed by
//! the platform local store before persistence.

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit as AesKeyInit, Nonce,
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::ratchet::{
    derive_root_step, RatchetError, MAX_RATCHET_AAD_BYTES, MAX_RATCHET_PLAINTEXT_BYTES,
    MAX_SKIPPED_PER_CHAIN, MAX_SKIPPED_PER_SESSION,
};

pub const DOUBLE_RATCHET_VERSION: u8 = 1;
pub const DOUBLE_RATCHET_HEADER_LEN: usize = 58;
const SNAPSHOT_FIXED_LEN: usize = 230;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DoubleRatchetHeader {
    pub session_id: [u8; 16],
    pub direction: u8,
    pub dh_public: [u8; 32],
    pub previous_chain_length: u32,
    pub message_number: u32,
}

impl DoubleRatchetHeader {
    pub fn encode(self) -> [u8; DOUBLE_RATCHET_HEADER_LEN] {
        let mut out = [0u8; DOUBLE_RATCHET_HEADER_LEN];
        out[0] = DOUBLE_RATCHET_VERSION;
        out[1..17].copy_from_slice(&self.session_id);
        out[17] = self.direction;
        out[18..50].copy_from_slice(&self.dh_public);
        out[50..54].copy_from_slice(&self.previous_chain_length.to_be_bytes());
        out[54..58].copy_from_slice(&self.message_number.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DoubleRatchetError> {
        if bytes.len() != DOUBLE_RATCHET_HEADER_LEN || bytes[0] != DOUBLE_RATCHET_VERSION {
            return Err(DoubleRatchetError::MalformedHeader);
        }
        let session_id: [u8; 16] = bytes[1..17]
            .try_into()
            .map_err(|_| DoubleRatchetError::MalformedHeader)?;
        let direction = bytes[17];
        let dh_public: [u8; 32] = bytes[18..50]
            .try_into()
            .map_err(|_| DoubleRatchetError::MalformedHeader)?;
        if session_id.iter().all(|b| *b == 0) || direction > 1 || dh_public.iter().all(|b| *b == 0)
        {
            return Err(DoubleRatchetError::MalformedHeader);
        }
        Ok(Self {
            session_id,
            direction,
            dh_public,
            previous_chain_length: u32::from_be_bytes(
                bytes[50..54]
                    .try_into()
                    .map_err(|_| DoubleRatchetError::MalformedHeader)?,
            ),
            message_number: u32::from_be_bytes(
                bytes[54..58]
                    .try_into()
                    .map_err(|_| DoubleRatchetError::MalformedHeader)?,
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DoubleRatchetError {
    InvalidSessionId,
    InvalidDirection,
    InvalidBootstrapSecret,
    InvalidDhKey,
    MalformedHeader,
    WrongSession,
    WrongDirection,
    MissingSendingChain,
    MissingReceivingChain,
    MissingLocalDhForReply,
    CounterExhausted,
    ExcessiveGap { gap: usize, maximum: usize },
    SkippedKeyLimit,
    DuplicateOrExpired,
    AuthenticationFailed,
    EncryptionFailed,
    InvalidInputLength,
    InvalidSnapshot,
    KdfFailure,
}

impl From<RatchetError> for DoubleRatchetError {
    fn from(value: RatchetError) -> Self {
        match value {
            RatchetError::InvalidSessionId => Self::InvalidSessionId,
            RatchetError::InvalidBootstrapSecret | RatchetError::InvalidChainKey => {
                Self::InvalidBootstrapSecret
            }
            RatchetError::InvalidDhOutput => Self::InvalidDhKey,
            RatchetError::InvalidDirection => Self::InvalidDirection,
            RatchetError::CounterExhausted => Self::CounterExhausted,
            RatchetError::ExcessiveGap { gap, maximum } => Self::ExcessiveGap { gap, maximum },
            RatchetError::SkippedKeyLimit => Self::SkippedKeyLimit,
            RatchetError::AuthenticationFailed => Self::AuthenticationFailed,
            RatchetError::EncryptionFailed => Self::EncryptionFailed,
            RatchetError::InvalidInputLength => Self::InvalidInputLength,
            RatchetError::MalformedHeader => Self::MalformedHeader,
            RatchetError::InvalidSnapshot => Self::InvalidSnapshot,
            RatchetError::KdfFailure => Self::KdfFailure,
            RatchetError::WrongSession => Self::WrongSession,
            RatchetError::WrongDirection => Self::WrongDirection,
            RatchetError::DuplicateOrExpired => Self::DuplicateOrExpired,
            RatchetError::StaleSendTicket | RatchetError::StaleReceiveTicket => {
                Self::DuplicateOrExpired
            }
        }
    }
}

#[derive(Clone)]
struct DhKeyPair {
    private: [u8; 32],
    public: [u8; 32],
}

impl DhKeyPair {
    fn from_private(mut private: [u8; 32]) -> Result<Self, DoubleRatchetError> {
        if private.iter().all(|byte| *byte == 0) {
            private.zeroize();
            return Err(DoubleRatchetError::InvalidDhKey);
        }
        let secret = StaticSecret::from(private);
        private.zeroize();
        let public = PublicKey::from(&secret).to_bytes();
        let private = Zeroizing::new(secret.to_bytes());
        if public.iter().all(|byte| *byte == 0) {
            return Err(DoubleRatchetError::InvalidDhKey);
        }
        Ok(Self {
            private: *private,
            public,
        })
    }
}

impl Drop for DhKeyPair {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

fn dh_shared(local: &DhKeyPair, remote_public: &[u8; 32]) -> Result<[u8; 32], DoubleRatchetError> {
    if remote_public.iter().all(|b| *b == 0) {
        return Err(DoubleRatchetError::InvalidDhKey);
    }
    let secret = StaticSecret::from(local.private);
    let public = PublicKey::from(*remote_public);
    let shared = secret.diffie_hellman(&public);
    if !shared.was_contributory() {
        return Err(DoubleRatchetError::InvalidDhKey);
    }
    let output = shared.to_bytes();
    if output.iter().all(|b| *b == 0) {
        return Err(DoubleRatchetError::InvalidDhKey);
    }
    Ok(output)
}

#[derive(Clone)]
pub struct DoubleRatchet {
    session_id: [u8; 16],
    send_direction: u8,
    root_key: [u8; 32],
    local_dh: DhKeyPair,
    remote_dh: [u8; 32],
    send_chain_key: Option<[u8; 32]>,
    receive_chain_key: Option<[u8; 32]>,
    send_number: u32,
    receive_number: u32,
    previous_send_count: u32,
    skipped: BTreeMap<([u8; 32], u32), [u8; 32]>,
}

impl DoubleRatchet {
    /// Initialize the initiator side after an authenticated bootstrap. The
    /// initial DH agreement creates the first sending chain; the responder
    /// initializes the matching receiving chain with `new_responder`.
    pub fn new_initiator(
        session_id: [u8; 16],
        send_direction: u8,
        bootstrap_secret: [u8; 32],
        local_dh_private: [u8; 32],
        remote_dh_public: [u8; 32],
    ) -> Result<Self, DoubleRatchetError> {
        let bootstrap_secret = Zeroizing::new(bootstrap_secret);
        let local_dh_private = Zeroizing::new(local_dh_private);
        validate_init(session_id, send_direction, &bootstrap_secret)?;
        let local_dh = DhKeyPair::from_private(*local_dh_private)?;
        let dh = Zeroizing::new(dh_shared(&local_dh, &remote_dh_public)?);
        let (root_key, send_chain_key) = derive_root_step(&bootstrap_secret, &dh)?;
        Ok(Self {
            session_id,
            send_direction,
            root_key,
            local_dh,
            remote_dh: remote_dh_public,
            send_chain_key: Some(send_chain_key),
            receive_chain_key: None,
            send_number: 0,
            receive_number: 0,
            previous_send_count: 0,
            skipped: BTreeMap::new(),
        })
    }

    /// Initialize the responder side. Its initial receive chain matches the
    /// initiator's first send chain. It must generate a fresh local DH private
    /// key on its first reply, supplied to `encrypt`.
    pub fn new_responder(
        session_id: [u8; 16],
        send_direction: u8,
        bootstrap_secret: [u8; 32],
        local_dh_private: [u8; 32],
        remote_dh_public: [u8; 32],
    ) -> Result<Self, DoubleRatchetError> {
        let bootstrap_secret = Zeroizing::new(bootstrap_secret);
        let local_dh_private = Zeroizing::new(local_dh_private);
        validate_init(session_id, send_direction, &bootstrap_secret)?;
        let local_dh = DhKeyPair::from_private(*local_dh_private)?;
        let dh = Zeroizing::new(dh_shared(&local_dh, &remote_dh_public)?);
        let (root_key, receive_chain_key) = derive_root_step(&bootstrap_secret, &dh)?;
        Ok(Self {
            session_id,
            send_direction,
            root_key,
            local_dh,
            remote_dh: remote_dh_public,
            send_chain_key: None,
            receive_chain_key: Some(receive_chain_key),
            send_number: 0,
            receive_number: 0,
            previous_send_count: 0,
            skipped: BTreeMap::new(),
        })
    }

    /// Encrypt one message. `new_local_dh_private` is required only for the
    /// responder's first outgoing message; after a remote DH turn, this method
    /// has already generated a new sending chain during successful decrypt.
    pub fn encrypt(
        &mut self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        external_aad: &[u8],
        new_local_dh_private: Option<[u8; 32]>,
    ) -> Result<(DoubleRatchetHeader, Vec<u8>), DoubleRatchetError> {
        let mut new_local_dh_private = new_local_dh_private.map(Zeroizing::new);
        validate_message_lengths(plaintext.len(), external_aad.len())?;
        let mut candidate = self.clone();
        if candidate.send_chain_key.is_none() {
            let private = new_local_dh_private
                .take()
                .ok_or(DoubleRatchetError::MissingLocalDhForReply)?;
            candidate.rotate_sending_chain(*private)?;
        }
        let chain_key = candidate
            .send_chain_key
            .as_ref()
            .ok_or(DoubleRatchetError::MissingSendingChain)?;
        let next_send_number = candidate
            .send_number
            .checked_add(1)
            .ok_or(DoubleRatchetError::CounterExhausted)?;
        let header = DoubleRatchetHeader {
            session_id: candidate.session_id,
            direction: candidate.send_direction,
            dh_public: candidate.local_dh.public,
            previous_chain_length: candidate.previous_send_count,
            message_number: candidate.send_number,
        };
        let (message_key, next_chain_key) = chain_step(chain_key);
        let message_key = Zeroizing::new(message_key);
        let next_chain_key = Zeroizing::new(next_chain_key);
        let cipher = <Aes256Gcm as AesKeyInit>::new_from_slice(&message_key[..])
            .map_err(|_| DoubleRatchetError::EncryptionFailed)?;
        let aad = Zeroizing::new(build_aad(&header, external_aad));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| DoubleRatchetError::EncryptionFailed)?;
        if let Some(old) = candidate.send_chain_key.as_mut() {
            old.zeroize();
        }
        candidate.send_chain_key = Some(*next_chain_key);
        candidate.send_number = next_send_number;
        *self = candidate;
        Ok((header, ciphertext))
    }

    /// Decrypt transactionally. All DH/root/chain transitions occur on a
    /// temporary state copy and commit only after the GCM tag is verified.
    /// Pass fresh CSPRNG bytes for `new_local_dh_private`; they are used only if
    /// the authenticated header starts a new remote DH chain.
    pub fn decrypt(
        &mut self,
        header: DoubleRatchetHeader,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        external_aad: &[u8],
        new_local_dh_private: [u8; 32],
    ) -> Result<Vec<u8>, DoubleRatchetError> {
        let mut new_local_dh_private = Zeroizing::new(new_local_dh_private);
        if ciphertext.len() < 16
            || ciphertext.len() > MAX_RATCHET_PLAINTEXT_BYTES + 16
            || external_aad.len() > MAX_RATCHET_AAD_BYTES
        {
            return Err(DoubleRatchetError::InvalidInputLength);
        }
        header
            .message_number
            .checked_add(1)
            .ok_or(DoubleRatchetError::CounterExhausted)?;
        let mut candidate = self.clone();
        let message_key =
            Zeroizing::new(candidate.prepare_receive(header, &mut new_local_dh_private)?);
        let cipher = <Aes256Gcm as AesKeyInit>::new_from_slice(&message_key[..])
            .map_err(|_| DoubleRatchetError::AuthenticationFailed)?;
        let aad = Zeroizing::new(build_aad(&header, external_aad));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| DoubleRatchetError::AuthenticationFailed)?;
        *self = candidate;
        Ok(plaintext)
    }

    fn prepare_receive(
        &mut self,
        header: DoubleRatchetHeader,
        new_local_private: &mut [u8; 32],
    ) -> Result<[u8; 32], DoubleRatchetError> {
        if header.session_id != self.session_id {
            return Err(DoubleRatchetError::WrongSession);
        }
        if header.direction > 1 || header.direction == self.send_direction {
            return Err(DoubleRatchetError::WrongDirection);
        }
        if header.dh_public.iter().all(|b| *b == 0) {
            return Err(DoubleRatchetError::InvalidDhKey);
        }

        if let Some(key) = self
            .skipped
            .remove(&(header.dh_public, header.message_number))
        {
            return Ok(key);
        }
        let next_number = header
            .message_number
            .checked_add(1)
            .ok_or(DoubleRatchetError::CounterExhausted)?;
        if header.dh_public != self.remote_dh {
            let old_gap = if self.receive_chain_key.is_some() {
                if header.previous_chain_length < self.receive_number {
                    return Err(DoubleRatchetError::DuplicateOrExpired);
                }
                (header.previous_chain_length - self.receive_number) as usize
            } else {
                if header.previous_chain_length != 0 {
                    return Err(DoubleRatchetError::DuplicateOrExpired);
                }
                0
            };
            let new_gap = header.message_number as usize;
            preflight_gap(self, self.remote_dh, old_gap)?;
            preflight_gap(self, header.dh_public, new_gap)?;
            if new_gap > MAX_SKIPPED_PER_CHAIN {
                return Err(DoubleRatchetError::ExcessiveGap {
                    gap: new_gap,
                    maximum: MAX_SKIPPED_PER_CHAIN,
                });
            }
            if self
                .skipped
                .len()
                .saturating_add(old_gap)
                .saturating_add(new_gap)
                > MAX_SKIPPED_PER_SESSION
            {
                return Err(DoubleRatchetError::SkippedKeyLimit);
            }

            self.skip_until(header.previous_chain_length, self.remote_dh)?;
            let dh_receive = Zeroizing::new(dh_shared(&self.local_dh, &header.dh_public)?);
            let (next_root, receive_chain) = derive_root_step(&self.root_key, &dh_receive)?;
            let next_root = Zeroizing::new(next_root);
            let receive_chain = Zeroizing::new(receive_chain);
            self.root_key.zeroize();
            self.root_key = *next_root;
            if let Some(old) = self.receive_chain_key.as_mut() {
                old.zeroize();
            }
            self.receive_chain_key = Some(*receive_chain);
            self.remote_dh = header.dh_public;
            self.previous_send_count = self.send_number;
            self.send_number = 0;
            self.receive_number = 0;

            let new_local = DhKeyPair::from_private(*new_local_private)?;
            new_local_private.zeroize();
            let dh_send = Zeroizing::new(dh_shared(&new_local, &self.remote_dh)?);
            let (send_root, send_chain) = derive_root_step(&self.root_key, &dh_send)?;
            let send_root = Zeroizing::new(send_root);
            let send_chain = Zeroizing::new(send_chain);
            self.root_key.zeroize();
            self.root_key = *send_root;
            if let Some(old) = self.send_chain_key.as_mut() {
                old.zeroize();
            }
            self.send_chain_key = Some(*send_chain);
            self.local_dh = new_local;
        } else {
            new_local_private.zeroize();
        }

        if header.message_number < self.receive_number {
            return Err(DoubleRatchetError::DuplicateOrExpired);
        }
        let gap = (header.message_number - self.receive_number) as usize;
        preflight_gap(self, self.remote_dh, gap)?;
        self.skip_until(header.message_number, self.remote_dh)?;
        let chain_key = self
            .receive_chain_key
            .as_ref()
            .ok_or(DoubleRatchetError::MissingReceivingChain)?;
        let (message_key, next_chain_key) = chain_step(chain_key);
        if let Some(old) = self.receive_chain_key.as_mut() {
            old.zeroize();
        }
        self.receive_chain_key = Some(next_chain_key);
        self.receive_number = next_number;
        Ok(message_key)
    }

    fn rotate_sending_chain(&mut self, private: [u8; 32]) -> Result<(), DoubleRatchetError> {
        self.previous_send_count = self.send_number;
        self.send_number = 0;
        let next_local = DhKeyPair::from_private(private)?;
        let dh = Zeroizing::new(dh_shared(&next_local, &self.remote_dh)?);
        let (next_root, next_chain) = derive_root_step(&self.root_key, &dh)?;
        let next_root = Zeroizing::new(next_root);
        let next_chain = Zeroizing::new(next_chain);
        self.root_key.zeroize();
        self.root_key = *next_root;
        if let Some(old) = self.send_chain_key.as_mut() {
            old.zeroize();
        }
        self.send_chain_key = Some(*next_chain);
        self.local_dh = next_local;
        Ok(())
    }

    fn skip_until(&mut self, target: u32, dh_public: [u8; 32]) -> Result<(), DoubleRatchetError> {
        if target < self.receive_number {
            return Err(DoubleRatchetError::DuplicateOrExpired);
        }
        let gap = (target - self.receive_number) as usize;
        preflight_gap(self, dh_public, gap)?;
        if gap > 0 && self.receive_chain_key.is_none() {
            return Err(DoubleRatchetError::MissingReceivingChain);
        }
        while self.receive_number < target {
            let chain = self
                .receive_chain_key
                .as_ref()
                .ok_or(DoubleRatchetError::MissingReceivingChain)?;
            let (key, next_chain) = chain_step(chain);
            if let Some(old) = self.receive_chain_key.as_mut() {
                old.zeroize();
            }
            self.receive_chain_key = Some(next_chain);
            self.skipped.insert((dh_public, self.receive_number), key);
            self.receive_number = self
                .receive_number
                .checked_add(1)
                .ok_or(DoubleRatchetError::CounterExhausted)?;
        }
        Ok(())
    }

    pub fn skipped_key_count(&self) -> usize {
        self.skipped.len()
    }
    pub fn next_send_number(&self) -> u32 {
        self.send_number
    }
    pub fn next_receive_number(&self) -> u32 {
        self.receive_number
    }
    pub fn remote_dh_public(&self) -> [u8; 32] {
        self.remote_dh
    }
    pub fn local_dh_public(&self) -> [u8; 32] {
        self.local_dh.public
    }

    /// Raw secret snapshot. Locally AEAD-seal and zeroize the returned bytes.
    pub fn snapshot(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SNAPSHOT_FIXED_LEN + self.skipped.len() * 68);
        out.extend_from_slice(b"SDR1");
        out.push(DOUBLE_RATCHET_VERSION);
        out.extend_from_slice(&self.session_id);
        out.push(self.send_direction);
        out.extend_from_slice(&self.root_key);
        out.extend_from_slice(&self.local_dh.private);
        out.extend_from_slice(&self.local_dh.public);
        out.extend_from_slice(&self.remote_dh);
        match self.send_chain_key {
            Some(key) => {
                out.push(1);
                out.extend_from_slice(&key);
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0; 32]);
            }
        }
        match self.receive_chain_key {
            Some(key) => {
                out.push(1);
                out.extend_from_slice(&key);
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0; 32]);
            }
        }
        out.extend_from_slice(&self.send_number.to_be_bytes());
        out.extend_from_slice(&self.receive_number.to_be_bytes());
        out.extend_from_slice(&self.previous_send_count.to_be_bytes());
        out.extend_from_slice(&(self.skipped.len() as u16).to_be_bytes());
        for ((dh, number), key) in &self.skipped {
            out.extend_from_slice(dh);
            out.extend_from_slice(&number.to_be_bytes());
            out.extend_from_slice(key);
        }
        out
    }

    pub fn restore_snapshot(bytes: &[u8]) -> Result<Self, DoubleRatchetError> {
        if bytes.len() < SNAPSHOT_FIXED_LEN
            || &bytes[..4] != b"SDR1"
            || bytes[4] != DOUBLE_RATCHET_VERSION
        {
            return Err(DoubleRatchetError::InvalidSnapshot);
        }
        let session_id: [u8; 16] = bytes[5..21]
            .try_into()
            .map_err(|_| DoubleRatchetError::InvalidSnapshot)?;
        let send_direction = bytes[21];
        let root_key = Zeroizing::new(
            <[u8; 32]>::try_from(&bytes[22..54])
                .map_err(|_| DoubleRatchetError::InvalidSnapshot)?,
        );
        let local_private = Zeroizing::new(
            <[u8; 32]>::try_from(&bytes[54..86])
                .map_err(|_| DoubleRatchetError::InvalidSnapshot)?,
        );
        let local_public: [u8; 32] = bytes[86..118]
            .try_into()
            .map_err(|_| DoubleRatchetError::InvalidSnapshot)?;
        let remote_dh: [u8; 32] = bytes[118..150]
            .try_into()
            .map_err(|_| DoubleRatchetError::InvalidSnapshot)?;
        let send_present = bytes[150];
        let send_bytes = Zeroizing::new(
            <[u8; 32]>::try_from(&bytes[151..183])
                .map_err(|_| DoubleRatchetError::InvalidSnapshot)?,
        );
        let receive_present = bytes[183];
        let receive_bytes = Zeroizing::new(
            <[u8; 32]>::try_from(&bytes[184..216])
                .map_err(|_| DoubleRatchetError::InvalidSnapshot)?,
        );
        let send_number = u32::from_be_bytes(
            bytes[216..220]
                .try_into()
                .map_err(|_| DoubleRatchetError::InvalidSnapshot)?,
        );
        let receive_number = u32::from_be_bytes(
            bytes[220..224]
                .try_into()
                .map_err(|_| DoubleRatchetError::InvalidSnapshot)?,
        );
        let previous_send_count = u32::from_be_bytes(
            bytes[224..228]
                .try_into()
                .map_err(|_| DoubleRatchetError::InvalidSnapshot)?,
        );
        let count = u16::from_be_bytes(
            bytes[228..230]
                .try_into()
                .map_err(|_| DoubleRatchetError::InvalidSnapshot)?,
        ) as usize;
        if session_id.iter().all(|b| *b == 0)
            || send_direction > 1
            || root_key.iter().all(|b| *b == 0)
            || remote_dh.iter().all(|b| *b == 0)
            || count > MAX_SKIPPED_PER_SESSION
            || bytes.len() != SNAPSHOT_FIXED_LEN + count * 68
            || send_present > 1
            || receive_present > 1
            || (send_present == 0 && (send_bytes.iter().any(|b| *b != 0) || send_number != 0))
            || (receive_present == 0
                && (receive_bytes.iter().any(|b| *b != 0) || receive_number != 0))
            || (send_present == 1 && send_bytes.iter().all(|b| *b == 0))
            || (receive_present == 1 && receive_bytes.iter().all(|b| *b == 0))
        {
            return Err(DoubleRatchetError::InvalidSnapshot);
        }
        let local_dh = DhKeyPair::from_private(*local_private)
            .map_err(|_| DoubleRatchetError::InvalidSnapshot)?;
        if local_dh.public != local_public {
            return Err(DoubleRatchetError::InvalidSnapshot);
        }
        let mut skipped: BTreeMap<([u8; 32], u32), [u8; 32]> = BTreeMap::new();
        for entry in bytes[SNAPSHOT_FIXED_LEN..].as_chunks::<68>().0 {
            let dh: [u8; 32] = entry[..32]
                .try_into()
                .map_err(|_| DoubleRatchetError::InvalidSnapshot)?;
            let number = u32::from_be_bytes(
                entry[32..36]
                    .try_into()
                    .map_err(|_| DoubleRatchetError::InvalidSnapshot)?,
            );
            let mut key: [u8; 32] = entry[36..]
                .try_into()
                .map_err(|_| DoubleRatchetError::InvalidSnapshot)?;
            if dh.iter().all(|b| *b == 0)
                || key.iter().all(|b| *b == 0)
                || skipped.contains_key(&(dh, number))
            {
                key.zeroize();
                for value in skipped.values_mut() {
                    value.zeroize();
                }
                return Err(DoubleRatchetError::InvalidSnapshot);
            }
            skipped.insert((dh, number), key);
        }
        let mut per_chain = BTreeMap::<[u8; 32], usize>::new();
        for (dh, _) in skipped.keys() {
            *per_chain.entry(*dh).or_default() += 1;
        }
        if per_chain.values().any(|n| *n > MAX_SKIPPED_PER_CHAIN) {
            for value in skipped.values_mut() {
                value.zeroize();
            }
            return Err(DoubleRatchetError::InvalidSnapshot);
        }
        Ok(Self {
            session_id,
            send_direction,
            root_key: *root_key,
            local_dh,
            remote_dh,
            send_chain_key: (send_present == 1).then_some(*send_bytes),
            receive_chain_key: (receive_present == 1).then_some(*receive_bytes),
            send_number,
            receive_number,
            previous_send_count,
            skipped,
        })
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.remote_dh.zeroize();
        if let Some(key) = self.send_chain_key.as_mut() {
            key.zeroize();
        }
        if let Some(key) = self.receive_chain_key.as_mut() {
            key.zeroize();
        }
        for key in self.skipped.values_mut() {
            key.zeroize();
        }
    }
}

fn validate_init(
    session_id: [u8; 16],
    direction: u8,
    bootstrap: &[u8; 32],
) -> Result<(), DoubleRatchetError> {
    if session_id.iter().all(|b| *b == 0) {
        return Err(DoubleRatchetError::InvalidSessionId);
    }
    if direction > 1 {
        return Err(DoubleRatchetError::InvalidDirection);
    }
    if bootstrap.iter().all(|b| *b == 0) {
        return Err(DoubleRatchetError::InvalidBootstrapSecret);
    }
    Ok(())
}

fn validate_message_lengths(
    plaintext_len: usize,
    aad_len: usize,
) -> Result<(), DoubleRatchetError> {
    if plaintext_len > MAX_RATCHET_PLAINTEXT_BYTES || aad_len > MAX_RATCHET_AAD_BYTES {
        Err(DoubleRatchetError::InvalidInputLength)
    } else {
        Ok(())
    }
}

fn preflight_gap(
    state: &DoubleRatchet,
    dh: [u8; 32],
    gap: usize,
) -> Result<(), DoubleRatchetError> {
    if gap > MAX_SKIPPED_PER_CHAIN {
        return Err(DoubleRatchetError::ExcessiveGap {
            gap,
            maximum: MAX_SKIPPED_PER_CHAIN,
        });
    }
    if state.skipped.len().saturating_add(gap) > MAX_SKIPPED_PER_SESSION {
        return Err(DoubleRatchetError::SkippedKeyLimit);
    }
    let chain_count = state.skipped.range((dh, 0)..=(dh, u32::MAX)).count();
    if chain_count.saturating_add(gap) > MAX_SKIPPED_PER_CHAIN {
        return Err(DoubleRatchetError::ExcessiveGap {
            gap: chain_count.saturating_add(gap),
            maximum: MAX_SKIPPED_PER_CHAIN,
        });
    }
    Ok(())
}

fn chain_step(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (
        hmac_label(chain_key, b"Serein/DR/v1/message-key"),
        hmac_label(chain_key, b"Serein/DR/v1/next-chain-key"),
    )
}

fn hmac_label(key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(label);
    let mut output = mac.finalize().into_bytes();
    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(&output);
    output.zeroize();
    *result
}

fn build_aad(header: &DoubleRatchetHeader, external: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOUBLE_RATCHET_HEADER_LEN + external.len());
    aad.extend_from_slice(&header.encode());
    aad.extend_from_slice(external);
    aad
}

const FFI_INVALID_ARGUMENT: isize = -1;
const FFI_INVALID_STATE: isize = -2;
const FFI_SESSION_OR_REPLAY: isize = -4;
const FFI_AUTHENTICATION: isize = -5;
const FFI_COUNTER_OR_KDF: isize = -6;
const FFI_SKIPPED_KEY_LIMIT: isize = -7;
const MAX_SNAPSHOT_LEN: usize = SNAPSHOT_FIXED_LEN + MAX_SKIPPED_PER_SESSION * 68;

fn ffi_error_code(error: DoubleRatchetError) -> isize {
    match error {
        DoubleRatchetError::WrongSession
        | DoubleRatchetError::WrongDirection
        | DoubleRatchetError::DuplicateOrExpired => FFI_SESSION_OR_REPLAY,
        DoubleRatchetError::AuthenticationFailed => FFI_AUTHENTICATION,
        DoubleRatchetError::CounterExhausted | DoubleRatchetError::KdfFailure => FFI_COUNTER_OR_KDF,
        DoubleRatchetError::SkippedKeyLimit | DoubleRatchetError::ExcessiveGap { .. } => {
            FFI_SKIPPED_KEY_LIMIT
        }
        DoubleRatchetError::InvalidSessionId
        | DoubleRatchetError::InvalidDirection
        | DoubleRatchetError::InvalidBootstrapSecret
        | DoubleRatchetError::InvalidDhKey
        | DoubleRatchetError::MalformedHeader
        | DoubleRatchetError::MissingSendingChain
        | DoubleRatchetError::MissingReceivingChain
        | DoubleRatchetError::MissingLocalDhForReply
        | DoubleRatchetError::EncryptionFailed
        | DoubleRatchetError::InvalidInputLength
        | DoubleRatchetError::InvalidSnapshot => FFI_INVALID_STATE,
    }
}

unsafe fn ffi_read_array<const N: usize>(ptr: *const u8) -> [u8; N] {
    unsafe { std::slice::from_raw_parts(ptr, N) }
        .try_into()
        .expect("fixed-length FFI input")
}

fn ffi_ranges_overlap(a: *const u8, a_len: usize, b: *const u8, b_len: usize) -> bool {
    if a_len == 0 || b_len == 0 {
        return false;
    }
    let (a_start, b_start) = (a as usize, b as usize);
    let (Some(a_end), Some(b_end)) = (a_start.checked_add(a_len), b_start.checked_add(b_len))
    else {
        return true;
    };
    a_start < b_end && b_start < a_end
}

/// Derive an X25519 public key from private bytes held by the caller.
/// Returns 1 on success, 0 for an invalid private key, or -1 for invalid pointers/ranges.
/// # Safety
/// `private` must be readable for 32 bytes and `public_out` writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn serein_core_double_ratchet_public_from_private(
    private: *const u8,
    public_out: *mut u8,
) -> i32 {
    if private.is_null() || public_out.is_null() || ffi_ranges_overlap(private, 32, public_out, 32)
    {
        return -1;
    }
    let private = Zeroizing::new(unsafe { ffi_read_array::<32>(private) });
    match DhKeyPair::from_private(*private) {
        Ok(pair) => {
            unsafe { std::slice::from_raw_parts_mut(public_out, 32) }.copy_from_slice(&pair.public);
            1
        }
        Err(_) => 0,
    }
}

/// Create an initiator ratchet after the application has authenticated the
/// bootstrap secret and remote DH key. Returns null for invalid inputs.
/// # Safety
/// Each pointer must be readable for its documented fixed length.
#[no_mangle]
pub unsafe extern "C" fn serein_core_double_ratchet_new_initiator(
    session_id: *const u8,
    send_direction: u8,
    bootstrap_secret: *const u8,
    local_dh_private: *const u8,
    remote_dh_public: *const u8,
) -> *mut DoubleRatchet {
    if session_id.is_null()
        || bootstrap_secret.is_null()
        || local_dh_private.is_null()
        || remote_dh_public.is_null()
    {
        return std::ptr::null_mut();
    }
    let session_id = unsafe { ffi_read_array::<16>(session_id) };
    let bootstrap_secret = Zeroizing::new(unsafe { ffi_read_array::<32>(bootstrap_secret) });
    let local_dh_private = Zeroizing::new(unsafe { ffi_read_array::<32>(local_dh_private) });
    let remote_dh_public = unsafe { ffi_read_array::<32>(remote_dh_public) };
    match DoubleRatchet::new_initiator(
        session_id,
        send_direction,
        *bootstrap_secret,
        *local_dh_private,
        remote_dh_public,
    ) {
        Ok(ratchet) => Box::into_raw(Box::new(ratchet)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create a responder ratchet after authenticating the initiator's DH key.
/// Returns null for invalid inputs.
/// # Safety
/// Each pointer must be readable for its documented fixed length.
#[no_mangle]
pub unsafe extern "C" fn serein_core_double_ratchet_new_responder(
    session_id: *const u8,
    send_direction: u8,
    bootstrap_secret: *const u8,
    local_dh_private: *const u8,
    remote_dh_public: *const u8,
) -> *mut DoubleRatchet {
    if session_id.is_null()
        || bootstrap_secret.is_null()
        || local_dh_private.is_null()
        || remote_dh_public.is_null()
    {
        return std::ptr::null_mut();
    }
    let session_id = unsafe { ffi_read_array::<16>(session_id) };
    let bootstrap_secret = Zeroizing::new(unsafe { ffi_read_array::<32>(bootstrap_secret) });
    let local_dh_private = Zeroizing::new(unsafe { ffi_read_array::<32>(local_dh_private) });
    let remote_dh_public = unsafe { ffi_read_array::<32>(remote_dh_public) };
    match DoubleRatchet::new_responder(
        session_id,
        send_direction,
        *bootstrap_secret,
        *local_dh_private,
        remote_dh_public,
    ) {
        Ok(ratchet) => Box::into_raw(Box::new(ratchet)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Destroy a live double-ratchet handle and zeroize its secret state.
/// # Safety
/// A non-null pointer must be a live handle returned by this library.
#[no_mangle]
pub unsafe extern "C" fn serein_core_double_ratchet_free(handle: *mut DoubleRatchet) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// Return the raw snapshot length, or zero for a null handle.
/// # Safety
/// A non-null pointer must be a live handle returned by this library.
#[no_mangle]
pub unsafe extern "C" fn serein_core_double_ratchet_snapshot_len(
    handle: *const DoubleRatchet,
) -> usize {
    if handle.is_null() {
        return 0;
    }
    SNAPSHOT_FIXED_LEN + unsafe { &*handle }.skipped.len() * 68
}

/// Copy the raw secret snapshot to caller memory; locally AEAD-seal it before persistence.
/// Returns bytes written, or a negative error code.
/// # Safety
/// `handle` must be live and `out` writable for `capacity` bytes, with no overlap.
#[no_mangle]
pub unsafe extern "C" fn serein_core_double_ratchet_snapshot(
    handle: *const DoubleRatchet,
    out: *mut u8,
    capacity: usize,
) -> isize {
    if handle.is_null() || out.is_null() {
        return FFI_INVALID_ARGUMENT;
    }
    let mut snapshot = unsafe { &*handle }.snapshot();
    if snapshot.len() > capacity
        || ffi_ranges_overlap(
            handle.cast(),
            std::mem::size_of::<DoubleRatchet>(),
            out,
            snapshot.len(),
        )
    {
        snapshot.zeroize();
        return FFI_INVALID_ARGUMENT;
    }
    unsafe { std::slice::from_raw_parts_mut(out, snapshot.len()) }.copy_from_slice(&snapshot);
    let len = snapshot.len() as isize;
    snapshot.zeroize();
    len
}

/// Restore a snapshot only after authenticating it with the local storage key.
/// Returns null on malformed state. The input bytes are not modified.
/// # Safety
/// `snapshot` must be readable for `snapshot_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn serein_core_double_ratchet_restore(
    snapshot: *const u8,
    snapshot_len: usize,
) -> *mut DoubleRatchet {
    if snapshot.is_null() || !(SNAPSHOT_FIXED_LEN..=MAX_SNAPSHOT_LEN).contains(&snapshot_len) {
        return std::ptr::null_mut();
    }
    let bytes = unsafe { std::slice::from_raw_parts(snapshot, snapshot_len) };
    match DoubleRatchet::restore_snapshot(bytes) {
        Ok(ratchet) => Box::into_raw(Box::new(ratchet)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Encrypt and advance one message. Returns ciphertext length or a negative code.
/// `new_local_dh_private` may be null except when a responder starts its first
/// sending chain. Nonce freshness is the caller's responsibility.
/// # Safety
/// Input and output ranges must be valid; outputs may not overlap each other,
/// the handle, nonce, plaintext, AAD, or optional private-key input.
#[no_mangle]
pub unsafe extern "C" fn serein_core_double_ratchet_encrypt(
    handle: *mut DoubleRatchet,
    nonce: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
    aad: *const u8,
    aad_len: usize,
    new_local_dh_private: *const u8,
    header_out: *mut u8,
    header_capacity: usize,
    ciphertext_out: *mut u8,
    ciphertext_capacity: usize,
) -> isize {
    if handle.is_null()
        || nonce.is_null()
        || header_out.is_null()
        || ciphertext_out.is_null()
        || (plaintext_len > 0 && plaintext.is_null())
        || (aad_len > 0 && aad.is_null())
        || plaintext_len > MAX_RATCHET_PLAINTEXT_BYTES
        || aad_len > MAX_RATCHET_AAD_BYTES
        || header_capacity < DOUBLE_RATCHET_HEADER_LEN
        || ciphertext_capacity < plaintext_len.saturating_add(16)
    {
        return FFI_INVALID_ARGUMENT;
    }
    let header_len = DOUBLE_RATCHET_HEADER_LEN;
    let ciphertext_len = plaintext_len + 16;
    let handle_ptr = handle.cast::<u8>();
    let handle_len = std::mem::size_of::<DoubleRatchet>();
    if ffi_ranges_overlap(header_out, header_len, ciphertext_out, ciphertext_len)
        || ffi_ranges_overlap(header_out, header_len, plaintext, plaintext_len)
        || ffi_ranges_overlap(header_out, header_len, aad, aad_len)
        || ffi_ranges_overlap(ciphertext_out, ciphertext_len, plaintext, plaintext_len)
        || ffi_ranges_overlap(ciphertext_out, ciphertext_len, aad, aad_len)
        || ffi_ranges_overlap(header_out, header_len, nonce, 12)
        || ffi_ranges_overlap(ciphertext_out, ciphertext_len, nonce, 12)
        || ffi_ranges_overlap(handle_ptr, handle_len, header_out, header_len)
        || ffi_ranges_overlap(handle_ptr, handle_len, ciphertext_out, ciphertext_len)
        || ffi_ranges_overlap(handle_ptr, handle_len, nonce, 12)
        || ffi_ranges_overlap(handle_ptr, handle_len, plaintext, plaintext_len)
        || ffi_ranges_overlap(handle_ptr, handle_len, aad, aad_len)
        || (!new_local_dh_private.is_null()
            && (ffi_ranges_overlap(header_out, header_len, new_local_dh_private, 32)
                || ffi_ranges_overlap(ciphertext_out, ciphertext_len, new_local_dh_private, 32)
                || ffi_ranges_overlap(handle_ptr, handle_len, new_local_dh_private, 32)))
    {
        return FFI_INVALID_ARGUMENT;
    }
    let nonce = unsafe { ffi_read_array::<12>(nonce) };
    let plaintext = if plaintext_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) }
    };
    let aad = if aad_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(aad, aad_len) }
    };
    let new_private = if new_local_dh_private.is_null() {
        None
    } else {
        Some(unsafe { ffi_read_array::<32>(new_local_dh_private) })
    };
    match unsafe { &mut *handle }.encrypt(&nonce, plaintext, aad, new_private) {
        Ok((header, ciphertext)) => {
            unsafe { std::slice::from_raw_parts_mut(header_out, header_len) }
                .copy_from_slice(&header.encode());
            unsafe { std::slice::from_raw_parts_mut(ciphertext_out, ciphertext.len()) }
                .copy_from_slice(&ciphertext);
            ciphertext.len() as isize
        }
        Err(error) => ffi_error_code(error),
    }
}

/// Authenticate and decrypt a message; state advances only after GCM succeeds.
/// Caller must supply fresh CSPRNG private bytes for a possible DH turn.
/// Returns plaintext length or a negative error code.
/// # Safety
/// Input ranges must be readable, output writable, and `handle` live. Output
/// must not overlap the handle, inputs, or authenticated header.
#[no_mangle]
pub unsafe extern "C" fn serein_core_double_ratchet_decrypt(
    handle: *mut DoubleRatchet,
    header: *const u8,
    nonce: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    aad: *const u8,
    aad_len: usize,
    new_local_dh_private: *const u8,
    plaintext_out: *mut u8,
    plaintext_capacity: usize,
) -> isize {
    if handle.is_null()
        || header.is_null()
        || nonce.is_null()
        || ciphertext.is_null()
        || new_local_dh_private.is_null()
        || plaintext_out.is_null()
        || (aad_len > 0 && aad.is_null())
        || !(16..=MAX_RATCHET_PLAINTEXT_BYTES + 16).contains(&ciphertext_len)
        || aad_len > MAX_RATCHET_AAD_BYTES
        || plaintext_capacity < ciphertext_len - 16
    {
        return FFI_INVALID_ARGUMENT;
    }
    let plaintext_len = ciphertext_len - 16;
    let output_len = plaintext_len.max(1);
    let handle_ptr = handle.cast::<u8>();
    let handle_len = std::mem::size_of::<DoubleRatchet>();
    if ffi_ranges_overlap(plaintext_out, output_len, handle_ptr, handle_len)
        || ffi_ranges_overlap(plaintext_out, output_len, header, DOUBLE_RATCHET_HEADER_LEN)
        || ffi_ranges_overlap(plaintext_out, output_len, nonce, 12)
        || ffi_ranges_overlap(plaintext_out, output_len, ciphertext, ciphertext_len)
        || ffi_ranges_overlap(plaintext_out, output_len, aad, aad_len)
        || ffi_ranges_overlap(plaintext_out, output_len, new_local_dh_private, 32)
        || ffi_ranges_overlap(handle_ptr, handle_len, header, DOUBLE_RATCHET_HEADER_LEN)
        || ffi_ranges_overlap(handle_ptr, handle_len, nonce, 12)
        || ffi_ranges_overlap(handle_ptr, handle_len, ciphertext, ciphertext_len)
        || ffi_ranges_overlap(handle_ptr, handle_len, aad, aad_len)
        || ffi_ranges_overlap(handle_ptr, handle_len, new_local_dh_private, 32)
    {
        return FFI_INVALID_ARGUMENT;
    }
    let parsed_header = match DoubleRatchetHeader::decode(unsafe {
        std::slice::from_raw_parts(header, DOUBLE_RATCHET_HEADER_LEN)
    }) {
        Ok(value) => value,
        Err(error) => return ffi_error_code(error),
    };
    let nonce = unsafe { ffi_read_array::<12>(nonce) };
    let new_private = unsafe { ffi_read_array::<32>(new_local_dh_private) };
    let ciphertext = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };
    let aad = if aad_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(aad, aad_len) }
    };
    match unsafe { &mut *handle }.decrypt(parsed_header, &nonce, ciphertext, aad, new_private) {
        Ok(mut plaintext) => {
            unsafe { std::slice::from_raw_parts_mut(plaintext_out, plaintext.len()) }
                .copy_from_slice(&plaintext);
            let len = plaintext.len() as isize;
            plaintext.zeroize();
            len
        }
        Err(error) => ffi_error_code(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_abi_double_ratchet_round_trip_rotation_and_snapshot_restore() {
        let session = [0x27; 16];
        let bootstrap = [0x61; 32];
        let alice_private = [0x32; 32];
        let bob_private = [0x73; 32];
        let mut alice_public = [0u8; 32];
        let mut bob_public = [0u8; 32];
        assert_eq!(
            unsafe {
                serein_core_double_ratchet_public_from_private(
                    alice_private.as_ptr(),
                    alice_public.as_mut_ptr(),
                )
            },
            1
        );
        assert_eq!(
            unsafe {
                serein_core_double_ratchet_public_from_private(
                    bob_private.as_ptr(),
                    bob_public.as_mut_ptr(),
                )
            },
            1
        );
        let alice = unsafe {
            serein_core_double_ratchet_new_initiator(
                session.as_ptr(),
                0,
                bootstrap.as_ptr(),
                alice_private.as_ptr(),
                bob_public.as_ptr(),
            )
        };
        let bob = unsafe {
            serein_core_double_ratchet_new_responder(
                session.as_ptr(),
                1,
                bootstrap.as_ptr(),
                bob_private.as_ptr(),
                alice_public.as_ptr(),
            )
        };
        assert!(!alice.is_null() && !bob.is_null());

        let aad = b"route-bound";
        let mut header = [0u8; DOUBLE_RATCHET_HEADER_LEN];
        let mut ciphertext = vec![0u8; 64];
        let encrypted = unsafe {
            serein_core_double_ratchet_encrypt(
                alice,
                [1; 12].as_ptr(),
                b"hello".as_ptr(),
                5,
                aad.as_ptr(),
                aad.len(),
                std::ptr::null(),
                header.as_mut_ptr(),
                header.len(),
                ciphertext.as_mut_ptr(),
                ciphertext.len(),
            )
        };
        assert_eq!(encrypted, 21);
        let mut plaintext = vec![0u8; 48];
        assert_eq!(
            unsafe {
                serein_core_double_ratchet_decrypt(
                    bob,
                    header.as_ptr(),
                    [1; 12].as_ptr(),
                    ciphertext.as_ptr(),
                    encrypted as usize,
                    aad.as_ptr(),
                    aad.len(),
                    [0x91; 32].as_ptr(),
                    plaintext.as_mut_ptr(),
                    plaintext.len(),
                )
            },
            5
        );
        assert_eq!(&plaintext[..5], b"hello");

        let mut reply_header = [0u8; DOUBLE_RATCHET_HEADER_LEN];
        let mut reply_ciphertext = vec![0u8; 64];
        let reply_len = unsafe {
            serein_core_double_ratchet_encrypt(
                bob,
                [2; 12].as_ptr(),
                b"world".as_ptr(),
                5,
                aad.as_ptr(),
                aad.len(),
                [0x42; 32].as_ptr(),
                reply_header.as_mut_ptr(),
                reply_header.len(),
                reply_ciphertext.as_mut_ptr(),
                reply_ciphertext.len(),
            )
        };
        assert_eq!(reply_len, 21);
        assert_eq!(
            unsafe {
                serein_core_double_ratchet_decrypt(
                    alice,
                    reply_header.as_ptr(),
                    [2; 12].as_ptr(),
                    reply_ciphertext.as_ptr(),
                    reply_len as usize,
                    aad.as_ptr(),
                    aad.len(),
                    [0x52; 32].as_ptr(),
                    plaintext.as_mut_ptr(),
                    plaintext.len(),
                )
            },
            5
        );
        assert_eq!(&plaintext[..5], b"world");

        let snapshot_len = unsafe { serein_core_double_ratchet_snapshot_len(alice) };
        let mut snapshot = vec![0u8; snapshot_len];
        assert_eq!(
            unsafe {
                serein_core_double_ratchet_snapshot(alice, snapshot.as_mut_ptr(), snapshot.len())
            },
            snapshot_len as isize
        );
        let restored =
            unsafe { serein_core_double_ratchet_restore(snapshot.as_ptr(), snapshot.len()) };
        assert!(!restored.is_null());
        let restored_len = unsafe {
            serein_core_double_ratchet_encrypt(
                restored,
                [3; 12].as_ptr(),
                b"after restore".as_ptr(),
                13,
                aad.as_ptr(),
                aad.len(),
                std::ptr::null(),
                reply_header.as_mut_ptr(),
                reply_header.len(),
                reply_ciphertext.as_mut_ptr(),
                reply_ciphertext.len(),
            )
        };
        assert_eq!(restored_len, 29);
        unsafe {
            serein_core_double_ratchet_free(alice);
            serein_core_double_ratchet_free(bob);
            serein_core_double_ratchet_free(restored);
        }
        snapshot.zeroize();
        ciphertext.zeroize();
        reply_ciphertext.zeroize();
        plaintext.zeroize();
    }

    fn pair() -> (DoubleRatchet, DoubleRatchet) {
        let session = [0x77; 16];
        let bootstrap = [0x51; 32];
        let alice_private = [0x31; 32];
        let bob_private = [0x72; 32];
        let alice_initial = DhKeyPair::from_private(alice_private).unwrap();
        let bob_initial = DhKeyPair::from_private(bob_private).unwrap();
        let alice =
            DoubleRatchet::new_initiator(session, 0, bootstrap, alice_private, bob_initial.public)
                .unwrap();
        let bob =
            DoubleRatchet::new_responder(session, 1, bootstrap, bob_private, alice_initial.public)
                .unwrap();
        (alice, bob)
    }

    #[test]
    fn zero_dh_private_keys_are_rejected_without_mutating_reply_state() {
        assert!(matches!(
            DhKeyPair::from_private([0; 32]),
            Err(DoubleRatchetError::InvalidDhKey)
        ));
        let (_alice, mut bob) = pair();
        let before = bob.snapshot();
        assert!(matches!(
            bob.encrypt(&[7; 12], b"reply", b"aad", Some([0; 32])),
            Err(DoubleRatchetError::InvalidDhKey)
        ));
        assert_eq!(bob.snapshot(), before);
    }

    #[test]
    fn x25519_dh_and_initial_chains_match_across_roles() {
        let (mut alice, mut bob) = pair();
        let nonce = [0x11; 12];
        let aad = b"conversation=one";
        let (header, ciphertext) = alice.encrypt(&nonce, b"first", aad, None).unwrap();
        assert_eq!(
            bob.decrypt(header, &nonce, &ciphertext, aad, [0x98; 32])
                .unwrap(),
            b"first"
        );
    }

    #[test]
    fn double_ratchet_rotates_dh_on_reply_and_recovers_after_peer_turn() {
        let (mut alice, mut bob) = pair();
        let aad = b"route";
        let (h0, c0) = alice.encrypt(&[1; 12], b"A0", aad, None).unwrap();
        assert_eq!(
            bob.decrypt(h0, &[1; 12], &c0, aad, [0x91; 32]).unwrap(),
            b"A0"
        );
        let old_bob_dh = bob.local_dh_public();
        let (h1, c1) = bob.encrypt(&[2; 12], b"B0", aad, Some([0x42; 32])).unwrap();
        assert_ne!(h1.dh_public, old_bob_dh);
        assert_eq!(
            alice.decrypt(h1, &[2; 12], &c1, aad, [0x52; 32]).unwrap(),
            b"B0"
        );
        let (h2, c2) = alice.encrypt(&[3; 12], b"A1", aad, None).unwrap();
        assert_ne!(h2.dh_public, h0.dh_public);
        assert_eq!(
            bob.decrypt(h2, &[3; 12], &c2, aad, [0x63; 32]).unwrap(),
            b"A1"
        );
        let (h3, c3) = bob.encrypt(&[4; 12], b"B1", aad, None).unwrap();
        assert_eq!(
            alice.decrypt(h3, &[4; 12], &c3, aad, [0x74; 32]).unwrap(),
            b"B1"
        );
    }

    #[test]
    fn session_skipped_key_cap_is_preflighted_before_new_dh_work() {
        let (mut alice, _bob) = pair();
        let second_chain = DhKeyPair::from_private([0x44; 32]).unwrap().public;
        for number in 0..MAX_SKIPPED_PER_CHAIN as u32 {
            alice.skipped.insert((alice.remote_dh, number), [0xA1; 32]);
            alice.skipped.insert((second_chain, number), [0xB2; 32]);
        }
        assert_eq!(alice.skipped_key_count(), MAX_SKIPPED_PER_SESSION);
        let next_remote = DhKeyPair::from_private([0x55; 32]).unwrap().public;
        let header = DoubleRatchetHeader {
            session_id: alice.session_id,
            direction: 1,
            dh_public: next_remote,
            previous_chain_length: 0,
            message_number: 1,
        };
        let before = alice.snapshot();
        assert!(matches!(
            alice.prepare_receive(header, &mut [0x66; 32]),
            Err(DoubleRatchetError::SkippedKeyLimit)
        ));
        assert_eq!(
            alice.snapshot(),
            before,
            "session-cap rejection must be transactional"
        );
    }

    #[test]
    fn excessive_new_dh_chain_gap_is_rejected_before_dh_work_or_state_change() {
        let (mut alice, mut bob) = pair();
        let (first_header, first_ciphertext) =
            alice.encrypt(&[1; 12], b"start", b"aad", None).unwrap();
        bob.decrypt(
            first_header,
            &[1; 12],
            &first_ciphertext,
            b"aad",
            [0x91; 32],
        )
        .unwrap();
        let (reply_header, reply_ciphertext) = bob
            .encrypt(&[2; 12], b"reply", b"aad", Some([0x42; 32]))
            .unwrap();
        let mut excessive = reply_header;
        excessive.message_number = MAX_SKIPPED_PER_CHAIN as u32 + 1;
        let before = alice.snapshot();
        assert!(matches!(
            alice.decrypt(excessive, &[2; 12], &reply_ciphertext, b"aad", [0x52; 32]),
            Err(DoubleRatchetError::ExcessiveGap { .. })
        ));
        assert_eq!(alice.snapshot(), before);
    }

    #[test]
    fn double_ratchet_failed_authentication_does_not_commit_dh_or_chain_state() {
        let (mut alice, mut bob) = pair();
        let aad = b"aad";
        let (h0, c0) = alice.encrypt(&[1; 12], b"start", aad, None).unwrap();
        bob.decrypt(h0, &[1; 12], &c0, aad, [0x91; 32]).unwrap();
        let (h1, c1) = bob
            .encrypt(&[2; 12], b"reply", aad, Some([0x42; 32]))
            .unwrap();
        let mut bad = c1.clone();
        bad[0] ^= 1;
        let before = bob.snapshot();
        let before_alice = alice.snapshot();
        assert!(matches!(
            alice.decrypt(h1, &[2; 12], &bad, aad, [0x52; 32]),
            Err(DoubleRatchetError::AuthenticationFailed)
        ));
        assert_eq!(alice.snapshot(), before_alice);
        assert_eq!(bob.next_send_number(), 1);
        assert_eq!(
            alice.decrypt(h1, &[2; 12], &c1, aad, [0x52; 32]).unwrap(),
            b"reply"
        );
        assert_ne!(alice.snapshot(), before);
    }

    #[test]
    fn bounded_out_of_order_messages_survive_snapshot_and_reject_replay() {
        let (mut alice, mut bob) = pair();
        let aad = b"aad";
        let mut frames = Vec::new();
        for i in 0..5u8 {
            frames.push(alice.encrypt(&[i + 1; 12], &[i], aad, None).unwrap());
        }
        assert_eq!(
            bob.decrypt(frames[4].0, &[5; 12], &frames[4].1, aad, [0x90; 32])
                .unwrap(),
            [4]
        );
        let mut snapshot = bob.snapshot();
        let mut restored = DoubleRatchet::restore_snapshot(&snapshot).unwrap();
        snapshot.zeroize();
        assert_eq!(restored.skipped_key_count(), 4);
        for i in 0..4u8 {
            assert_eq!(
                restored
                    .decrypt(
                        frames[i as usize].0,
                        &[i + 1; 12],
                        &frames[i as usize].1,
                        aad,
                        [0x90; 32]
                    )
                    .unwrap(),
                [i]
            );
        }
        assert_eq!(restored.skipped_key_count(), 0);
        assert_eq!(
            restored.next_receive_number(),
            5,
            "consuming skipped keys must not rewind the active chain"
        );
        let (next_header, next_ciphertext) = alice.encrypt(&[9; 12], &[5], aad, None).unwrap();
        assert_eq!(
            restored
                .decrypt(next_header, &[9; 12], &next_ciphertext, aad, [0x90; 32])
                .unwrap(),
            [5]
        );
        assert_eq!(restored.next_receive_number(), 6);
        assert!(matches!(
            restored.decrypt(frames[0].0, &[1; 12], &frames[0].1, aad, [0x90; 32]),
            Err(DoubleRatchetError::DuplicateOrExpired)
        ));
    }

    #[test]
    fn header_is_fixed_versioned_and_authentication_binds_dh_and_previous_count() {
        let header = DoubleRatchetHeader {
            session_id: [1; 16],
            direction: 1,
            dh_public: [2; 32],
            previous_chain_length: 0x01020304,
            message_number: 0x05060708,
        };
        assert_eq!(
            DoubleRatchetHeader::decode(&header.encode()).unwrap(),
            header
        );
        let mut bad = header.encode();
        bad[0] = 99;
        assert!(matches!(
            DoubleRatchetHeader::decode(&bad),
            Err(DoubleRatchetError::MalformedHeader)
        ));
        let (mut alice, mut bob) = pair();
        let (h, c) = alice
            .encrypt(&[9; 12], b"secret", b"context", None)
            .unwrap();
        let mut changed = h;
        changed.previous_chain_length = 1;
        assert!(matches!(
            bob.decrypt(changed, &[9; 12], &c, b"context", [3; 32]),
            Err(DoubleRatchetError::AuthenticationFailed)
                | Err(DoubleRatchetError::DuplicateOrExpired)
        ));
    }
}
