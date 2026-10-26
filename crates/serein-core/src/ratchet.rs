//! Serein symmetric sending/receiving chain ratchet (development foundation).
//!
//! This module deliberately separates message-key evolution from transport and
//! platform AEAD. Callers must authenticate `RatchetHeader::encode()` as AEAD
//! associated data and must persist state only inside the platform's existing
//! encrypted local store. The seed must come from the authenticated session
//! bootstrap. This is a symmetric ratchet stage, **not yet a complete Double
//! Ratchet**: it has no DH ratchet, prekey handshake, identity-signature layer,
//! or post-compromise recovery. Do not claim forward secrecy against compromise
//! of the bootstrap seed until those layers are integrated.

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit as AesKeyInit, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

pub const RATCHET_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 22;
pub const MAX_SKIPPED_PER_CHAIN: usize = 1_000;
pub const MAX_SKIPPED_PER_SESSION: usize = 2_000;
pub const MAX_RATCHET_PLAINTEXT_BYTES: usize = 32_768;
pub const MAX_RATCHET_AAD_BYTES: usize = 4_096;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RatchetHeader {
    pub session_id: [u8; 16],
    pub direction: u8,
    pub message_number: u32,
}

impl RatchetHeader {
    pub fn encode(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = RATCHET_VERSION;
        out[1..17].copy_from_slice(&self.session_id);
        out[17] = self.direction;
        out[18..22].copy_from_slice(&self.message_number.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RatchetError> {
        if bytes.len() != HEADER_LEN || bytes[0] != RATCHET_VERSION {
            return Err(RatchetError::MalformedHeader);
        }
        let session_id: [u8; 16] = bytes[1..17]
            .try_into()
            .map_err(|_| RatchetError::MalformedHeader)?;
        let direction = bytes[17];
        if direction > 1 || session_id.iter().all(|b| *b == 0) {
            return Err(RatchetError::MalformedHeader);
        }
        let message_number = u32::from_be_bytes(
            bytes[18..22]
                .try_into()
                .map_err(|_| RatchetError::MalformedHeader)?,
        );
        Ok(Self {
            session_id,
            direction,
            message_number,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum RatchetError {
    InvalidSessionId,
    InvalidBootstrapSecret,
    InvalidDhOutput,
    InvalidChainKey,
    KdfFailure,
    InvalidDirection,
    MalformedHeader,
    InvalidSnapshot,
    WrongSession,
    WrongDirection,
    CounterExhausted,
    AuthenticationFailed,
    EncryptionFailed,
    InvalidInputLength,
    StaleSendTicket,
    ExcessiveGap { gap: usize, maximum: usize },
    SkippedKeyLimit,
    DuplicateOrExpired,
    StaleReceiveTicket,
}

/// A one-use message key. It is zeroized when dropped; callers should also
/// zeroize any exported byte copies immediately after platform AEAD use.
pub struct MessageKey([u8; 32]);

impl MessageKey {
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for MessageKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A speculative send transition. Encrypt with `message_key()` first; commit
/// only after AEAD sealing succeeds, so local failures do not silently burn a
/// chain key.
pub struct SendTicket {
    generation: u64,
    header: RatchetHeader,
    message_key: MessageKey,
    next_chain_key: Option<[u8; 32]>,
    next_send_number: u32,
}

impl SendTicket {
    pub fn header(&self) -> RatchetHeader {
        self.header
    }
    pub fn message_key(&self) -> &[u8; 32] {
        self.message_key.expose()
    }
}

impl Drop for SendTicket {
    fn drop(&mut self) {
        if let Some(key) = self.next_chain_key.as_mut() {
            key.zeroize();
        }
    }
}

/// A speculative receive transition. Decrypt/authenticate with `message_key()`
/// first; call `commit_receive` only after AEAD verification succeeds. Dropping
/// this ticket leaves the ratchet unchanged, preventing forged ciphertext from
/// consuming a message number or skipped key.
pub struct ReceiveTicket {
    generation: u64,
    message_number: u32,
    message_key: MessageKey,
    next_chain_key: Option<[u8; 32]>,
    next_receive_number: u32,
    skipped_to_add: Vec<(u32, [u8; 32])>,
    consume_skipped: bool,
}

impl ReceiveTicket {
    pub fn message_key(&self) -> &[u8; 32] {
        self.message_key.expose()
    }
}

impl Drop for ReceiveTicket {
    fn drop(&mut self) {
        if let Some(key) = self.next_chain_key.as_mut() {
            key.zeroize();
        }
        for (_, key) in &mut self.skipped_to_add {
            key.zeroize();
        }
    }
}

/// Per-device-pair directional chains. `send_direction` is assigned by the
/// authenticated session bootstrap (initiator=0, responder=1); peers must use
/// opposite values and the same session identifier.
pub struct SymmetricRatchet {
    session_id: [u8; 16],
    send_direction: u8,
    send_chain_key: [u8; 32],
    receive_chain_key: [u8; 32],
    send_number: u32,
    send_generation: u64,
    receive_number: u32,
    receive_generation: u64,
    skipped: BTreeMap<u32, [u8; 32]>,
}

impl SymmetricRatchet {
    pub fn new(
        session_id: [u8; 16],
        send_direction: u8,
        send_chain_key: [u8; 32],
        receive_chain_key: [u8; 32],
    ) -> Result<Self, RatchetError> {
        if session_id.iter().all(|b| *b == 0) {
            return Err(RatchetError::InvalidSessionId);
        }
        if send_direction > 1 {
            return Err(RatchetError::InvalidDirection);
        }
        if send_chain_key.iter().all(|b| *b == 0) || receive_chain_key.iter().all(|b| *b == 0) {
            return Err(RatchetError::InvalidChainKey);
        }
        Ok(Self {
            session_id,
            send_direction,
            send_chain_key,
            receive_chain_key,
            send_number: 0,
            send_generation: 0,
            receive_number: 0,
            receive_generation: 0,
            skipped: BTreeMap::new(),
        })
    }

    /// Prepare a send without mutating live state. Commit only after AEAD
    /// sealing succeeds; dropping a ticket leaves the sending chain unchanged.
    pub fn prepare_send(&self) -> Result<SendTicket, RatchetError> {
        let next_send_number = self
            .send_number
            .checked_add(1)
            .ok_or(RatchetError::CounterExhausted)?;
        let (message_key, next_chain_key) = chain_step(&self.send_chain_key);
        Ok(SendTicket {
            generation: self.send_generation,
            header: RatchetHeader {
                session_id: self.session_id,
                direction: self.send_direction,
                message_number: self.send_number,
            },
            message_key: MessageKey(message_key),
            next_chain_key: Some(next_chain_key),
            next_send_number,
        })
    }

    /// Commit a prepared send after the caller has successfully sealed it.
    pub fn commit_send(&mut self, mut ticket: SendTicket) -> Result<(), RatchetError> {
        if ticket.generation != self.send_generation {
            return Err(RatchetError::StaleSendTicket);
        }
        let next_generation = self
            .send_generation
            .checked_add(1)
            .ok_or(RatchetError::CounterExhausted)?;
        let Some(mut next_chain_key) = ticket.next_chain_key.take() else {
            return Err(RatchetError::StaleSendTicket);
        };
        self.send_chain_key.zeroize();
        std::mem::swap(&mut self.send_chain_key, &mut next_chain_key);
        next_chain_key.zeroize();
        self.send_number = ticket.next_send_number;
        self.send_generation = next_generation;
        Ok(())
    }

    /// Encrypt one message with a fresh 96-bit nonce. The encoded ratchet header
    /// is always authenticated as the first part of AAD; caller context follows.
    pub fn encrypt(
        &mut self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        external_aad: &[u8],
    ) -> Result<(RatchetHeader, Vec<u8>), RatchetError> {
        if plaintext.len() > MAX_RATCHET_PLAINTEXT_BYTES
            || external_aad.len() > MAX_RATCHET_AAD_BYTES
        {
            return Err(RatchetError::InvalidInputLength);
        }
        let ticket = self.prepare_send()?;
        let header = ticket.header();
        let cipher = <Aes256Gcm as AesKeyInit>::new_from_slice(ticket.message_key())
            .map_err(|_| RatchetError::AuthenticationFailed)?;
        let mut aad = Vec::with_capacity(HEADER_LEN + external_aad.len());
        aad.extend_from_slice(&header.encode());
        aad.extend_from_slice(external_aad);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| RatchetError::EncryptionFailed)?;
        self.commit_send(ticket)?;
        aad.zeroize();
        Ok((header, ciphertext))
    }

    /// Generate exactly one message key and advance the sending chain. The
    /// caller must either send this message or accept that the peer will later
    /// observe a gap. Prefer `encrypt` for transactional AEAD integration.
    pub fn next_sending_key(&mut self) -> Result<(RatchetHeader, MessageKey), RatchetError> {
        let next_number = self
            .send_number
            .checked_add(1)
            .ok_or(RatchetError::CounterExhausted)?;
        let (message_key, next_chain_key) = chain_step(&self.send_chain_key);
        self.send_chain_key.zeroize();
        self.send_chain_key = next_chain_key;
        let header = RatchetHeader {
            session_id: self.session_id,
            direction: self.send_direction,
            message_number: self.send_number,
        };
        self.send_number = next_number;
        Ok((header, MessageKey(message_key)))
    }

    /// Prepare a peer-message transition without mutating live state. The caller
    /// must authenticate/decrypt with the ticket key, then commit. Dropping the
    /// ticket after a failed tag check is a no-op on the ratchet.
    pub fn prepare_receive(&self, header: RatchetHeader) -> Result<ReceiveTicket, RatchetError> {
        if header.session_id != self.session_id {
            return Err(RatchetError::WrongSession);
        }
        if header.direction > 1 || header.direction == self.send_direction {
            return Err(RatchetError::WrongDirection);
        }
        let next_receive_number = header
            .message_number
            .checked_add(1)
            .ok_or(RatchetError::CounterExhausted)?;

        if let Some(key) = self.skipped.get(&header.message_number) {
            return Ok(ReceiveTicket {
                generation: self.receive_generation,
                message_number: header.message_number,
                message_key: MessageKey(*key),
                next_chain_key: None,
                next_receive_number: self.receive_number,
                skipped_to_add: Vec::new(),
                consume_skipped: true,
            });
        }
        if header.message_number < self.receive_number {
            return Err(RatchetError::DuplicateOrExpired);
        }

        let gap = (header.message_number - self.receive_number) as usize;
        if gap > MAX_SKIPPED_PER_CHAIN {
            return Err(RatchetError::ExcessiveGap {
                gap,
                maximum: MAX_SKIPPED_PER_CHAIN,
            });
        }
        if self.skipped.len().saturating_add(gap) > MAX_SKIPPED_PER_SESSION {
            return Err(RatchetError::SkippedKeyLimit);
        }

        let mut candidate_chain_key = self.receive_chain_key;
        let mut candidate_number = self.receive_number;
        let mut skipped_to_add = Vec::with_capacity(gap);
        while candidate_number < header.message_number {
            let (message_key, next_chain_key) = chain_step(&candidate_chain_key);
            candidate_chain_key.zeroize();
            candidate_chain_key = next_chain_key;
            skipped_to_add.push((candidate_number, message_key));
            candidate_number = candidate_number
                .checked_add(1)
                .ok_or(RatchetError::CounterExhausted)?;
        }

        if candidate_number != header.message_number {
            return Err(RatchetError::CounterExhausted);
        }
        let (message_key, next_chain_key) = chain_step(&candidate_chain_key);
        candidate_chain_key.zeroize();
        Ok(ReceiveTicket {
            generation: self.receive_generation,
            message_number: header.message_number,
            message_key: MessageKey(message_key),
            next_chain_key: Some(next_chain_key),
            next_receive_number,
            skipped_to_add,
            consume_skipped: false,
        })
    }

    /// Commit a prepared receive only after the caller has verified the AEAD
    /// authentication tag. A ticket prepared against older state is rejected.
    pub fn commit_receive(&mut self, mut ticket: ReceiveTicket) -> Result<(), RatchetError> {
        if ticket.generation != self.receive_generation {
            return Err(RatchetError::StaleReceiveTicket);
        }
        let next_generation = self
            .receive_generation
            .checked_add(1)
            .ok_or(RatchetError::CounterExhausted)?;
        if ticket.consume_skipped {
            let Some(mut stored) = self.skipped.remove(&ticket.message_number) else {
                return Err(RatchetError::StaleReceiveTicket);
            };
            stored.zeroize();
        } else {
            let Some(mut next_chain_key) = ticket.next_chain_key.take() else {
                return Err(RatchetError::StaleReceiveTicket);
            };
            self.receive_chain_key.zeroize();
            std::mem::swap(&mut self.receive_chain_key, &mut next_chain_key);
            next_chain_key.zeroize();
            self.receive_number = ticket.next_receive_number;
            for (number, key) in std::mem::take(&mut ticket.skipped_to_add) {
                self.skipped.insert(number, key);
            }
        }
        self.receive_generation = next_generation;
        Ok(())
    }

    /// Authenticate and decrypt a peer message transactionally. Neither the
    /// receiving chain nor a skipped key is committed until the AEAD tag passes.
    pub fn decrypt(
        &mut self,
        header: RatchetHeader,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        external_aad: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        if ciphertext.len() < 16
            || ciphertext.len() > MAX_RATCHET_PLAINTEXT_BYTES + 16
            || external_aad.len() > MAX_RATCHET_AAD_BYTES
        {
            return Err(RatchetError::InvalidInputLength);
        }
        let ticket = self.prepare_receive(header)?;
        let cipher = <Aes256Gcm as AesKeyInit>::new_from_slice(ticket.message_key())
            .map_err(|_| RatchetError::AuthenticationFailed)?;
        let mut aad = Vec::with_capacity(HEADER_LEN + external_aad.len());
        aad.extend_from_slice(&header.encode());
        aad.extend_from_slice(external_aad);
        let mut plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| RatchetError::AuthenticationFailed)?;
        aad.zeroize();
        if let Err(error) = self.commit_receive(ticket) {
            plaintext.zeroize();
            return Err(error);
        }
        Ok(plaintext)
    }

    pub fn skipped_key_count(&self) -> usize {
        self.skipped.len()
    }
    pub fn next_send_number(&self) -> u32 {
        self.send_number
    }

    /// Export a bounded binary state snapshot. The returned bytes contain live
    /// secret chain keys and skipped message keys: encrypt/authenticate them
    /// with the platform's local-storage key, then zeroize the plaintext bytes.
    pub fn snapshot_len(&self) -> usize {
        96 + self.skipped.len() * 36
    }

    pub fn snapshot(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.snapshot_len());
        out.extend_from_slice(b"SRST");
        out.push(RATCHET_VERSION);
        out.extend_from_slice(&self.session_id);
        out.push(self.send_direction);
        out.extend_from_slice(&self.send_chain_key);
        out.extend_from_slice(&self.receive_chain_key);
        out.extend_from_slice(&self.send_number.to_be_bytes());
        out.extend_from_slice(&self.receive_number.to_be_bytes());
        out.extend_from_slice(&(self.skipped.len() as u16).to_be_bytes());
        for (number, key) in &self.skipped {
            out.extend_from_slice(&number.to_be_bytes());
            out.extend_from_slice(key);
        }
        out
    }

    /// Restore a snapshot only after the caller has authenticated it using its
    /// encrypted local store. Rejects malformed, oversized, duplicate, or
    /// inconsistent state instead of attempting recovery from partial bytes.
    pub fn restore_snapshot(bytes: &[u8]) -> Result<Self, RatchetError> {
        const FIXED: usize = 96;
        if bytes.len() < FIXED || &bytes[..4] != b"SRST" || bytes[4] != RATCHET_VERSION {
            return Err(RatchetError::InvalidSnapshot);
        }
        let session_id: [u8; 16] = bytes[5..21]
            .try_into()
            .map_err(|_| RatchetError::InvalidSnapshot)?;
        let send_direction = bytes[21];
        if session_id.iter().all(|b| *b == 0) || send_direction > 1 {
            return Err(RatchetError::InvalidSnapshot);
        }
        let send_chain_key: [u8; 32] = bytes[22..54]
            .try_into()
            .map_err(|_| RatchetError::InvalidSnapshot)?;
        let receive_chain_key: [u8; 32] = bytes[54..86]
            .try_into()
            .map_err(|_| RatchetError::InvalidSnapshot)?;
        let send_number = u32::from_be_bytes(
            bytes[86..90]
                .try_into()
                .map_err(|_| RatchetError::InvalidSnapshot)?,
        );
        let receive_number = u32::from_be_bytes(
            bytes[90..94]
                .try_into()
                .map_err(|_| RatchetError::InvalidSnapshot)?,
        );
        if send_chain_key.iter().all(|b| *b == 0) || receive_chain_key.iter().all(|b| *b == 0) {
            return Err(RatchetError::InvalidSnapshot);
        }
        let skipped_count = u16::from_be_bytes(
            bytes[94..96]
                .try_into()
                .map_err(|_| RatchetError::InvalidSnapshot)?,
        ) as usize;
        if skipped_count > MAX_SKIPPED_PER_CHAIN
            || skipped_count > MAX_SKIPPED_PER_SESSION
            || bytes.len() != FIXED + skipped_count * 36
        {
            return Err(RatchetError::InvalidSnapshot);
        }
        let mut skipped: BTreeMap<u32, [u8; 32]> = BTreeMap::new();
        for entry in bytes[FIXED..].as_chunks::<36>().0 {
            let number = u32::from_be_bytes(
                entry[..4]
                    .try_into()
                    .map_err(|_| RatchetError::InvalidSnapshot)?,
            );
            let mut key: [u8; 32] = entry[4..]
                .try_into()
                .map_err(|_| RatchetError::InvalidSnapshot)?;
            if key.iter().all(|b| *b == 0)
                || number >= receive_number
                || skipped.contains_key(&number)
            {
                key.zeroize();
                for value in skipped.values_mut() {
                    value.zeroize();
                }
                return Err(RatchetError::InvalidSnapshot);
            }
            skipped.insert(number, key);
        }
        Ok(Self {
            session_id,
            send_direction,
            send_chain_key,
            receive_chain_key,
            send_number,
            send_generation: 0,
            receive_number,
            receive_generation: 0,
            skipped,
        })
    }

    pub fn next_receive_number(&self) -> u32 {
        self.receive_number
    }
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }
    pub fn send_direction(&self) -> u8 {
        self.send_direction
    }
}

impl Drop for SymmetricRatchet {
    fn drop(&mut self) {
        self.send_chain_key.zeroize();
        self.receive_chain_key.zeroize();
        for key in self.skipped.values_mut() {
            key.zeroize();
        }
    }
}

/// Derive both independent directional chain seeds from the authenticated
/// bootstrap secret. Both peers call this with the same session id and
/// initiator direction; the responder swaps the returned pair for its send and
/// receive direction. This KDF does not authenticate a peer or replace X3DH.
pub fn derive_directional_chains(
    bootstrap_secret: &[u8; 32],
    session_id: &[u8; 16],
    initiator_direction: u8,
) -> Result<([u8; 32], [u8; 32]), RatchetError> {
    if session_id.iter().all(|b| *b == 0) {
        return Err(RatchetError::InvalidSessionId);
    }
    if bootstrap_secret.iter().all(|b| *b == 0) {
        return Err(RatchetError::InvalidBootstrapSecret);
    }
    if initiator_direction > 1 {
        return Err(RatchetError::InvalidDirection);
    }
    // Fixed-size, unambiguous domain-separation input: label || session ID || direction.
    let first = derive_chain_seed(bootstrap_secret, session_id, initiator_direction);
    let second = derive_chain_seed(bootstrap_secret, session_id, initiator_direction ^ 1);
    Ok((*first, *second))
}

/// Root KDF step for the DH layer: `root_key` is HKDF-SHA256 salt and the
/// platform-generated DH output is input key material. The two fixed 32-byte
/// outputs are the next root key and a fresh directional chain key. Rejects
/// non-contributory all-zero DH results before deriving anything.
pub fn derive_root_step(
    root_key: &[u8; 32],
    dh_output: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), RatchetError> {
    if root_key.iter().all(|b| *b == 0) {
        return Err(RatchetError::InvalidBootstrapSecret);
    }
    if dh_output.iter().all(|b| *b == 0) {
        return Err(RatchetError::InvalidDhOutput);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut output = Zeroizing::new([0u8; 64]);
    hkdf.expand(b"Serein/DR/v1/root-ratchet-step", &mut output[..])
        .map_err(|_| RatchetError::KdfFailure)?;
    let root =
        Zeroizing::new(<[u8; 32]>::try_from(&output[..32]).map_err(|_| RatchetError::KdfFailure)?);
    let chain =
        Zeroizing::new(<[u8; 32]>::try_from(&output[32..]).map_err(|_| RatchetError::KdfFailure)?);
    Ok((*root, *chain))
}

fn derive_chain_seed(
    bootstrap_secret: &[u8; 32],
    session_id: &[u8; 16],
    direction: u8,
) -> Zeroizing<[u8; 32]> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(bootstrap_secret)
        .expect("HMAC accepts a 32-byte key");
    mac.update(b"Serein/DR/v1/directional-chain");
    mac.update(session_id);
    mac.update(&[direction]);
    let mut output = mac.finalize().into_bytes();
    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(&output);
    output.zeroize();
    result
}

fn chain_step(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let message_key = hmac_label(chain_key, b"Serein/DR/v1/message-key");
    let next_chain_key = hmac_label(chain_key, b"Serein/DR/v1/next-chain-key");
    (message_key, next_chain_key)
}

fn hmac_label(key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(label);
    let mut output = mac.finalize().into_bytes();
    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(&output);
    output.zeroize();
    *result
}

const FFI_INVALID_ARGUMENT: isize = -1;

/// Derive initiator-to-responder and responder-to-initiator chain seeds.
/// Returns 1 on success, 0 for invalid cryptographic input, or -1 for null pointers.
/// # Safety
/// Input pointers must be readable for 32 and 16 bytes; output must be writable
/// for 64 bytes. The output must not overlap the input buffers.
#[no_mangle]
pub unsafe extern "C" fn serein_core_ratchet_derive_chains(
    bootstrap: *const u8,
    session: *const u8,
    initiator_direction: u8,
    output: *mut u8,
) -> i32 {
    if bootstrap.is_null() || session.is_null() || output.is_null() {
        return -1;
    }
    if ffi_ranges_overlap(output, 64, bootstrap, 32) || ffi_ranges_overlap(output, 64, session, 16)
    {
        return -1;
    }
    let mut bootstrap_key: [u8; 32] = unsafe { std::slice::from_raw_parts(bootstrap, 32) }
        .try_into()
        .ok()
        .unwrap();
    let session_id: [u8; 16] = unsafe { std::slice::from_raw_parts(session, 16) }
        .try_into()
        .ok()
        .unwrap();
    match derive_directional_chains(&bootstrap_key, &session_id, initiator_direction) {
        Ok((mut first, mut second)) => {
            let out = unsafe { std::slice::from_raw_parts_mut(output, 64) };
            out[..32].copy_from_slice(&first);
            out[32..].copy_from_slice(&second);
            first.zeroize();
            second.zeroize();
            bootstrap_key.zeroize();
            1
        }
        Err(_) => {
            bootstrap_key.zeroize();
            0
        }
    }
}

/// Apply one root-ratchet KDF step to platform-computed DH output.
/// Returns 1 on success, 0 for invalid/all-zero input, or -1 for null pointers.
/// # Safety
/// Each input must be readable for 32 bytes and output writable for 64 bytes;
/// output must not overlap input buffers.
#[no_mangle]
pub unsafe extern "C" fn serein_core_ratchet_root_step(
    root: *const u8,
    dh: *const u8,
    output: *mut u8,
) -> i32 {
    if root.is_null() || dh.is_null() || output.is_null() {
        return -1;
    }
    if ffi_ranges_overlap(output, 64, root, 32) || ffi_ranges_overlap(output, 64, dh, 32) {
        return -1;
    }
    let mut root_key: [u8; 32] = unsafe { std::slice::from_raw_parts(root, 32) }
        .try_into()
        .ok()
        .unwrap();
    let mut dh_secret: [u8; 32] = unsafe { std::slice::from_raw_parts(dh, 32) }
        .try_into()
        .ok()
        .unwrap();
    match derive_root_step(&root_key, &dh_secret) {
        Ok((mut next_root, mut chain)) => {
            let out = unsafe { std::slice::from_raw_parts_mut(output, 64) };
            out[..32].copy_from_slice(&next_root);
            out[32..].copy_from_slice(&chain);
            next_root.zeroize();
            chain.zeroize();
            root_key.zeroize();
            dh_secret.zeroize();
            1
        }
        Err(_) => {
            root_key.zeroize();
            dh_secret.zeroize();
            0
        }
    }
}

fn ffi_error_code(error: RatchetError) -> isize {
    match error {
        RatchetError::AuthenticationFailed => -5,
        RatchetError::WrongSession
        | RatchetError::WrongDirection
        | RatchetError::DuplicateOrExpired => -4,
        RatchetError::ExcessiveGap { .. } | RatchetError::SkippedKeyLimit => -7,
        RatchetError::InvalidInputLength
        | RatchetError::MalformedHeader
        | RatchetError::InvalidSnapshot => -3,
        RatchetError::CounterExhausted | RatchetError::KdfFailure => -6,
        _ => -2,
    }
}

/// Create an opaque native/WASM ratchet handle from directional chain seeds.
/// # Safety
/// The three input pointers must reference readable 16/32/32-byte buffers. The
/// returned handle must be freed exactly once with `serein_core_ratchet_free`.
#[no_mangle]
pub unsafe extern "C" fn serein_core_ratchet_new(
    session: *const u8,
    direction: u8,
    send_ck: *const u8,
    receive_ck: *const u8,
) -> *mut SymmetricRatchet {
    if session.is_null() || send_ck.is_null() || receive_ck.is_null() {
        return std::ptr::null_mut();
    }
    let session: [u8; 16] = unsafe { std::slice::from_raw_parts(session, 16) }
        .try_into()
        .ok()
        .unwrap();
    let mut send: [u8; 32] = unsafe { std::slice::from_raw_parts(send_ck, 32) }
        .try_into()
        .ok()
        .unwrap();
    let mut receive: [u8; 32] = unsafe { std::slice::from_raw_parts(receive_ck, 32) }
        .try_into()
        .ok()
        .unwrap();
    let result = SymmetricRatchet::new(session, direction, send, receive);
    send.zeroize();
    receive.zeroize();
    result
        .map(Box::new)
        .map(Box::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Restore from a locally AEAD-authenticated snapshot. Caller owns the result.
/// # Safety
/// `snapshot` must reference `len` readable bytes, and the returned handle must
/// be freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn serein_core_ratchet_restore(
    snapshot: *const u8,
    len: usize,
) -> *mut SymmetricRatchet {
    if snapshot.is_null() || len == 0 {
        return std::ptr::null_mut();
    }
    let bytes = unsafe { std::slice::from_raw_parts(snapshot, len) };
    SymmetricRatchet::restore_snapshot(bytes)
        .map(Box::new)
        .map(Box::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Free and zeroize an opaque ratchet handle. Null is accepted.
/// # Safety
/// A non-null pointer must be a live handle returned by this library and must
/// not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn serein_core_ratchet_free(handle: *mut SymmetricRatchet) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// Current snapshot length, or zero for a null handle.
/// # Safety
/// A non-null pointer must be a live handle returned by this library.
#[no_mangle]
pub unsafe extern "C" fn serein_core_ratchet_snapshot_len(
    handle: *const SymmetricRatchet,
) -> usize {
    if handle.is_null() {
        return 0;
    }
    unsafe { &*handle }.snapshot_len()
}

/// Copy raw secret state to caller storage; encrypt it before persistence.
/// Returns bytes written or a negative error.
/// # Safety
/// `handle` must be live; `out` must be writable for `capacity` bytes and not
/// overlap the handle's internal memory.
#[no_mangle]
pub unsafe extern "C" fn serein_core_ratchet_snapshot(
    handle: *const SymmetricRatchet,
    out: *mut u8,
    capacity: usize,
) -> isize {
    if handle.is_null() || out.is_null() {
        return FFI_INVALID_ARGUMENT;
    }
    let mut bytes = unsafe { &*handle }.snapshot();
    if bytes.len() > capacity {
        bytes.zeroize();
        return FFI_INVALID_ARGUMENT;
    }
    unsafe { std::slice::from_raw_parts_mut(out, bytes.len()) }.copy_from_slice(&bytes);
    let len = bytes.len() as isize;
    bytes.zeroize();
    len
}

/// Encrypt one ratcheted message. The fixed 22-byte header is returned
/// separately and is authenticated as AAD before caller context.
/// Returns ciphertext length or a negative error code.
/// # Safety
/// Input ranges must be readable; output ranges writable and large enough.
/// Outputs must not overlap inputs, each other, or the live handle.
#[no_mangle]
pub unsafe extern "C" fn serein_core_ratchet_encrypt(
    handle: *mut SymmetricRatchet,
    nonce: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
    aad: *const u8,
    aad_len: usize,
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
        || header_capacity < HEADER_LEN
        || ciphertext_capacity < plaintext_len.saturating_add(16)
    {
        return FFI_INVALID_ARGUMENT;
    }
    let header_len = HEADER_LEN;
    let cipher_len = plaintext_len + 16;
    if ffi_ranges_overlap(header_out, header_len, ciphertext_out, cipher_len)
        || ffi_ranges_overlap(header_out, header_len, plaintext, plaintext_len)
        || ffi_ranges_overlap(header_out, header_len, aad, aad_len)
        || ffi_ranges_overlap(ciphertext_out, cipher_len, plaintext, plaintext_len)
        || ffi_ranges_overlap(ciphertext_out, cipher_len, aad, aad_len)
        || ffi_ranges_overlap(header_out, header_len, nonce, 12)
        || ffi_ranges_overlap(ciphertext_out, cipher_len, nonce, 12)
    {
        return FFI_INVALID_ARGUMENT;
    }
    let nonce: &[u8; 12] = match unsafe { std::slice::from_raw_parts(nonce, 12) }.try_into() {
        Ok(v) => v,
        Err(_) => return FFI_INVALID_ARGUMENT,
    };
    let plain = if plaintext_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) }
    };
    let context = if aad_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(aad, aad_len) }
    };
    match unsafe { &mut *handle }.encrypt(nonce, plain, context) {
        Ok((header, ciphertext)) => {
            unsafe { std::slice::from_raw_parts_mut(header_out, HEADER_LEN) }
                .copy_from_slice(&header.encode());
            unsafe { std::slice::from_raw_parts_mut(ciphertext_out, ciphertext.len()) }
                .copy_from_slice(&ciphertext);
            ciphertext.len() as isize
        }
        Err(error) => ffi_error_code(error),
    }
}

/// Authenticate and decrypt one ratcheted message; state commits only on a
/// valid tag. Returns cleartext length or a negative error code.
/// # Safety
/// Input ranges must be readable and output writable. `out` must be non-null
/// even for empty plaintext. Output must not overlap inputs or the live handle.
#[no_mangle]
pub unsafe extern "C" fn serein_core_ratchet_decrypt(
    handle: *mut SymmetricRatchet,
    header: *const u8,
    nonce: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut u8,
    out_capacity: usize,
) -> isize {
    if handle.is_null()
        || header.is_null()
        || nonce.is_null()
        || ciphertext.is_null()
        || out.is_null()
        || (aad_len > 0 && aad.is_null())
        || !(16..=MAX_RATCHET_PLAINTEXT_BYTES + 16).contains(&ciphertext_len)
        || aad_len > MAX_RATCHET_AAD_BYTES
        || out_capacity < ciphertext_len - 16
    {
        return FFI_INVALID_ARGUMENT;
    }
    let plain_len = ciphertext_len - 16;
    if ffi_ranges_overlap(out, plain_len.max(1), header, HEADER_LEN)
        || ffi_ranges_overlap(out, plain_len.max(1), nonce, 12)
        || ffi_ranges_overlap(out, plain_len.max(1), ciphertext, ciphertext_len)
        || ffi_ranges_overlap(out, plain_len.max(1), aad, aad_len)
    {
        return FFI_INVALID_ARGUMENT;
    }
    let parsed_header =
        match RatchetHeader::decode(unsafe { std::slice::from_raw_parts(header, HEADER_LEN) }) {
            Ok(h) => h,
            Err(e) => return ffi_error_code(e),
        };
    let nonce: &[u8; 12] = match unsafe { std::slice::from_raw_parts(nonce, 12) }.try_into() {
        Ok(v) => v,
        Err(_) => return FFI_INVALID_ARGUMENT,
    };
    let encrypted = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };
    let context = if aad_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(aad, aad_len) }
    };
    match unsafe { &mut *handle }.decrypt(parsed_header, nonce, encrypted, context) {
        Ok(mut clear) => {
            unsafe { std::slice::from_raw_parts_mut(out, clear.len()) }.copy_from_slice(&clear);
            let len = clear.len() as isize;
            clear.zeroize();
            len
        }
        Err(error) => ffi_error_code(error),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn peers() -> (SymmetricRatchet, SymmetricRatchet) {
        let bootstrap = [0x42; 32];
        let session = [0x19; 16];
        let (i2r, r2i) = derive_directional_chains(&bootstrap, &session, 0).unwrap();
        let initiator = SymmetricRatchet::new(session, 0, i2r, r2i).unwrap();
        let responder = SymmetricRatchet::new(session, 1, r2i, i2r).unwrap();
        (initiator, responder)
    }

    #[test]
    fn c_abi_round_trip_rejects_tampering_and_restores_encrypted_store_snapshots() {
        let bootstrap = [0x71; 32];
        let session = [0x29; 16];
        let (i2r, r2i) = derive_directional_chains(&bootstrap, &session, 0).unwrap();
        let mut derived = [0u8; 64];
        assert_eq!(
            unsafe {
                serein_core_ratchet_derive_chains(
                    bootstrap.as_ptr(),
                    session.as_ptr(),
                    0,
                    derived.as_mut_ptr(),
                )
            },
            1
        );
        assert_eq!(&derived[..32], &i2r);
        assert_eq!(&derived[32..], &r2i);
        let dh = [0x36; 32];
        let (expected_root, expected_chain) = derive_root_step(&bootstrap, &dh).unwrap();
        let mut root_output = [0u8; 64];
        assert_eq!(
            unsafe {
                serein_core_ratchet_root_step(
                    bootstrap.as_ptr(),
                    dh.as_ptr(),
                    root_output.as_mut_ptr(),
                )
            },
            1
        );
        assert_eq!(&root_output[..32], &expected_root);
        assert_eq!(&root_output[32..], &expected_chain);
        let alice =
            unsafe { serein_core_ratchet_new(session.as_ptr(), 0, i2r.as_ptr(), r2i.as_ptr()) };
        let bob =
            unsafe { serein_core_ratchet_new(session.as_ptr(), 1, r2i.as_ptr(), i2r.as_ptr()) };
        assert!(!alice.is_null() && !bob.is_null());

        let nonce = [0x53; 12];
        let context = b"ffi-context";
        let clear = b"ffi protocol payload";
        let mut header = [0u8; HEADER_LEN];
        let mut ciphertext = vec![0u8; clear.len() + 16];
        let encrypted_len = unsafe {
            serein_core_ratchet_encrypt(
                alice,
                nonce.as_ptr(),
                clear.as_ptr(),
                clear.len(),
                context.as_ptr(),
                context.len(),
                header.as_mut_ptr(),
                header.len(),
                ciphertext.as_mut_ptr(),
                ciphertext.len(),
            )
        };
        assert_eq!(encrypted_len, ciphertext.len() as isize);

        let mut tampered = ciphertext.clone();
        tampered[0] ^= 1;
        let mut plaintext = vec![0u8; clear.len()];
        let failed = unsafe {
            serein_core_ratchet_decrypt(
                bob,
                header.as_ptr(),
                nonce.as_ptr(),
                tampered.as_ptr(),
                tampered.len(),
                context.as_ptr(),
                context.len(),
                plaintext.as_mut_ptr(),
                plaintext.len(),
            )
        };
        assert_eq!(failed, -5);
        let decrypted = unsafe {
            serein_core_ratchet_decrypt(
                bob,
                header.as_ptr(),
                nonce.as_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                context.as_ptr(),
                context.len(),
                plaintext.as_mut_ptr(),
                plaintext.len(),
            )
        };
        assert_eq!(decrypted, clear.len() as isize);
        assert_eq!(&plaintext, clear);

        let snapshot_len = unsafe { serein_core_ratchet_snapshot_len(bob) };
        let mut snapshot = vec![0u8; snapshot_len];
        assert_eq!(
            unsafe { serein_core_ratchet_snapshot(bob, snapshot.as_mut_ptr(), snapshot.len()) },
            snapshot_len as isize
        );
        let restored = unsafe { serein_core_ratchet_restore(snapshot.as_ptr(), snapshot.len()) };
        assert!(!restored.is_null());
        unsafe {
            serein_core_ratchet_free(alice);
            serein_core_ratchet_free(bob);
            serein_core_ratchet_free(restored);
        }
        snapshot.zeroize();
        ciphertext.zeroize();
        tampered.zeroize();
        plaintext.zeroize();
    }

    #[test]
    fn root_step_rejects_noncontributory_dh_and_domain_separates_root_from_chain() {
        let root = [0x12; 32];
        let dh = [0x34; 32];
        let (next_root, sending_chain) = derive_root_step(&root, &dh).unwrap();
        let (same_root, same_chain) = derive_root_step(&root, &dh).unwrap();
        assert_eq!(next_root, same_root);
        assert_eq!(sending_chain, same_chain);
        assert_ne!(next_root, sending_chain);
        assert!(matches!(
            derive_root_step(&root, &[0; 32]),
            Err(RatchetError::InvalidDhOutput)
        ));
        assert!(matches!(
            derive_root_step(&[0; 32], &dh),
            Err(RatchetError::InvalidBootstrapSecret)
        ));
    }

    #[test]
    fn peers_derive_matching_directional_chains_but_sending_directions_are_independent() {
        let (mut alice, mut bob) = peers();
        let (header, alice_key) = alice.next_sending_key().unwrap();
        let bob_ticket = bob.prepare_receive(header).unwrap();
        assert_eq!(alice_key.expose(), bob_ticket.message_key());
        bob.commit_receive(bob_ticket).unwrap();
        let (reply_header, bob_reply) = bob.next_sending_key().unwrap();
        let alice_ticket = alice.prepare_receive(reply_header).unwrap();
        assert_eq!(bob_reply.expose(), alice_ticket.message_key());
        alice.commit_receive(alice_ticket).unwrap();
        assert_ne!(alice_key.expose(), bob_reply.expose());
    }

    #[test]
    fn ratchet_aead_round_trip_binds_header_and_external_context() {
        let (mut alice, mut bob) = peers();
        let nonce = [0xA5; 12];
        let context = b"conversation=alpha; sender=alice; recipient=bob";
        let (header, ciphertext) = alice
            .encrypt(&nonce, b"first ratcheted payload", context)
            .unwrap();
        assert_eq!(header.message_number, 0);
        assert_eq!(header.direction, 0);
        assert_eq!(
            bob.decrypt(header, &nonce, &ciphertext, context).unwrap(),
            b"first ratcheted payload"
        );
        assert_eq!(alice.next_send_number(), 1);
        assert_eq!(bob.next_receive_number(), 1);

        let (next_header, next_ciphertext) = alice
            .encrypt(&[0xA6; 12], b"second payload", context)
            .unwrap();
        assert!(matches!(
            bob.decrypt(
                next_header,
                &[0xA6; 12],
                &next_ciphertext,
                b"different context"
            ),
            Err(RatchetError::AuthenticationFailed)
        ));
        assert_eq!(
            bob.next_receive_number(),
            1,
            "failed authentication must not advance the chain"
        );
        assert_eq!(
            bob.decrypt(next_header, &[0xA6; 12], &next_ciphertext, context)
                .unwrap(),
            b"second payload"
        );
    }

    #[test]
    fn oversized_payloads_are_rejected_before_any_ratchet_transition() {
        let (mut alice, mut bob) = peers();
        let oversized = vec![0x55; MAX_RATCHET_PLAINTEXT_BYTES + 1];
        assert!(matches!(
            alice.encrypt(&[1; 12], &oversized, b""),
            Err(RatchetError::InvalidInputLength)
        ));
        assert_eq!(alice.next_send_number(), 0);
        let header = RatchetHeader {
            session_id: bob.session_id(),
            direction: 0,
            message_number: 0,
        };
        assert!(matches!(
            bob.decrypt(
                header,
                &[1; 12],
                &[0; MAX_RATCHET_PLAINTEXT_BYTES + 17],
                b""
            ),
            Err(RatchetError::InvalidInputLength)
        ));
        assert_eq!(bob.next_receive_number(), 0);
    }

    #[test]
    fn tampered_ciphertext_does_not_consume_a_message_key() {
        let (mut alice, mut bob) = peers();
        let nonce = [0x31; 12];
        let (header, mut ciphertext) = alice.encrypt(&nonce, b"auth test", b"context").unwrap();
        ciphertext[0] ^= 0x80;
        assert_eq!(
            bob.decrypt(header, &nonce, &ciphertext, b"context"),
            Err(RatchetError::AuthenticationFailed)
        );
        assert_eq!(bob.next_receive_number(), 0);
        ciphertext[0] ^= 0x80;
        assert_eq!(
            bob.decrypt(header, &nonce, &ciphertext, b"context")
                .unwrap(),
            b"auth test"
        );
    }

    #[test]
    fn out_of_order_messages_are_delivered_once_and_skipped_keys_are_consumed() {
        let (mut alice, mut bob) = peers();
        let mut messages = Vec::new();
        for _ in 0..4 {
            messages.push(alice.next_sending_key().unwrap());
        }
        let key3 = bob.prepare_receive(messages[3].0).unwrap();
        assert_eq!(key3.message_key(), messages[3].1.expose());
        bob.commit_receive(key3).unwrap();
        assert_eq!(bob.skipped_key_count(), 3);
        for (header, expected_key) in messages.iter().take(3) {
            let delivered = bob.prepare_receive(*header).unwrap();
            assert_eq!(delivered.message_key(), expected_key.expose());
            bob.commit_receive(delivered).unwrap();
        }
        assert_eq!(bob.skipped_key_count(), 0);
        assert!(matches!(
            bob.prepare_receive(messages[0].0),
            Err(RatchetError::DuplicateOrExpired)
        ));
    }

    #[test]
    fn too_large_gaps_fail_before_chain_state_changes() {
        let (mut alice, mut bob) = peers();
        let before = bob.next_receive_number();
        let excessive = RatchetHeader {
            session_id: bob.session_id(),
            direction: 0,
            message_number: MAX_SKIPPED_PER_CHAIN as u32 + 1,
        };
        assert!(
            matches!(bob.prepare_receive(excessive), Err(RatchetError::ExcessiveGap { gap, maximum }) if gap == MAX_SKIPPED_PER_CHAIN + 1 && maximum == MAX_SKIPPED_PER_CHAIN)
        );
        assert_eq!(bob.next_receive_number(), before);
        let (first_header, first_key) = alice.next_sending_key().unwrap();
        let first_ticket = bob.prepare_receive(first_header).unwrap();
        assert_eq!(first_ticket.message_key(), first_key.expose());
        bob.commit_receive(first_ticket).unwrap();
    }

    #[test]
    fn headers_are_fixed_length_versioned_and_bound_to_session_direction_and_counter() {
        let h = RatchetHeader {
            session_id: [7; 16],
            direction: 1,
            message_number: 0x01020304,
        };
        assert_eq!(RatchetHeader::decode(&h.encode()).unwrap(), h);
        assert_eq!(
            RatchetHeader::decode(&h.encode()[..HEADER_LEN - 1]),
            Err(RatchetError::MalformedHeader)
        );
        let mut wrong_version = h.encode();
        wrong_version[0] = 99;
        assert_eq!(
            RatchetHeader::decode(&wrong_version),
            Err(RatchetError::MalformedHeader)
        );
        let mut wrong_direction = h.encode();
        wrong_direction[17] = 2;
        assert_eq!(
            RatchetHeader::decode(&wrong_direction),
            Err(RatchetError::MalformedHeader)
        );
    }

    #[test]
    fn encrypted_snapshot_restores_counters_and_out_of_order_keys() {
        let (mut alice, mut bob) = peers();
        let context = b"snapshot-test";
        let mut frames = Vec::new();
        for n in 0..3u8 {
            let nonce = [n + 1; 12];
            let (header, ciphertext) = alice.encrypt(&nonce, &[n], context).unwrap();
            frames.push((header, nonce, ciphertext));
        }
        assert_eq!(
            bob.decrypt(frames[2].0, &frames[2].1, &frames[2].2, context)
                .unwrap(),
            [2]
        );
        let snapshot = bob.snapshot();
        let mut restored = SymmetricRatchet::restore_snapshot(&snapshot).unwrap();
        assert_eq!(restored.next_receive_number(), 3);
        assert_eq!(restored.skipped_key_count(), 2);
        assert_eq!(
            restored
                .decrypt(frames[0].0, &frames[0].1, &frames[0].2, context)
                .unwrap(),
            [0]
        );
        assert_eq!(
            restored
                .decrypt(frames[1].0, &frames[1].1, &frames[1].2, context)
                .unwrap(),
            [1]
        );
        assert_eq!(restored.skipped_key_count(), 0);
    }

    #[test]
    fn malformed_snapshots_fail_closed_and_enforce_skipped_key_bounds() {
        let (alice, _) = peers();
        let snapshot = alice.snapshot();
        assert!(matches!(
            SymmetricRatchet::restore_snapshot(&snapshot[..snapshot.len() - 1]),
            Err(RatchetError::InvalidSnapshot)
        ));
        let mut wrong_version = snapshot.clone();
        wrong_version[4] ^= 1;
        assert!(matches!(
            SymmetricRatchet::restore_snapshot(&wrong_version),
            Err(RatchetError::InvalidSnapshot)
        ));
        let mut over_limit = snapshot.clone();
        over_limit[94..96].copy_from_slice(&((MAX_SKIPPED_PER_CHAIN + 1) as u16).to_be_bytes());
        assert!(matches!(
            SymmetricRatchet::restore_snapshot(&over_limit),
            Err(RatchetError::InvalidSnapshot)
        ));
    }

    #[test]
    fn session_and_direction_mismatches_fail_closed() {
        let (mut alice, bob) = peers();
        let mut header = alice.next_sending_key().unwrap().0;
        header.session_id[0] ^= 1;
        assert!(matches!(
            bob.prepare_receive(header),
            Err(RatchetError::WrongSession)
        ));
        header.session_id = bob.session_id();
        header.direction = 1;
        assert!(matches!(
            bob.prepare_receive(header),
            Err(RatchetError::WrongDirection)
        ));
    }

    #[test]
    fn dropping_uncommitted_receive_ticket_preserves_chain_for_authentication_retry() {
        let (mut alice, mut bob) = peers();
        let (header, sender_key) = alice.next_sending_key().unwrap();
        let before = bob.next_receive_number();
        let tentative = bob.prepare_receive(header).unwrap();
        assert_eq!(tentative.message_key(), sender_key.expose());
        drop(tentative); // Represents AEAD tag failure: do not commit.
        assert_eq!(bob.next_receive_number(), before);
        let retry = bob.prepare_receive(header).unwrap();
        assert_eq!(retry.message_key(), sender_key.expose());
        bob.commit_receive(retry).unwrap();
        assert_eq!(bob.next_receive_number(), before + 1);
    }

    #[test]
    fn concurrent_receive_tickets_cannot_commit_over_newer_state() {
        let (mut alice, mut bob) = peers();
        let (header, _) = alice.next_sending_key().unwrap();
        let first = bob.prepare_receive(header).unwrap();
        let stale = bob.prepare_receive(header).unwrap();
        bob.commit_receive(first).unwrap();
        assert!(matches!(
            bob.commit_receive(stale),
            Err(RatchetError::StaleReceiveTicket)
        ));
    }
}
