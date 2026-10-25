//! First-party, dependency-free Serein domain primitives shared by the Rust API,
//! WebAssembly clients, and native FFI adapters. Cryptographic protocols do not
//! belong here until independently reviewed and selected.

use std::{slice, str};

pub const MAX_CIPHERTEXT_CHARS: usize = 90_000;
/// Shared composer limit, measured as Unicode scalar values across Rust and JS.
pub const MAX_MESSAGE_CHARACTERS: usize = 4_000;
pub const MESSAGE_COUNTER_WARNING_CHARACTERS: usize = MAX_MESSAGE_CHARACTERS * 9 / 10;
pub const DEFAULT_HISTORY_PAGE: i64 = 100;
pub const MAX_HISTORY_PAGE: i64 = 200;
static VERSION_C: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();

pub fn message_character_count(value: &str) -> usize { value.chars().count() }
pub fn truncate_message(value: &str) -> String { value.chars().take(MAX_MESSAGE_CHARACTERS).collect() }
pub fn normalize_username(value: &str) -> String { value.trim().to_ascii_lowercase() }
pub fn valid_username(value: &str) -> bool {
    (3..=32).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b,b'_'|b'.'|b'-'))
}
pub fn valid_email(value: &str) -> bool {
    if value.len() > 254 || !value.is_ascii() { return false; }
    let Some((local,domain))=value.split_once('@') else { return false; };
    if local.is_empty() || local.len()>64 || domain.is_empty() || domain.len()>253 || domain.contains('@')
        || local.starts_with('.') || local.ends_with('.') || local.contains("..") { return false; }
    if !local.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b,b'.'|b'_'|b'%'|b'+'|b'-')) { return false; }
    let labels=domain.split('.').collect::<Vec<_>>();
    labels.len()>=2 && labels.iter().all(|label| !label.is_empty() && label.len()<=63
        && label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && label.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        && label.bytes().all(|b| b.is_ascii_alphanumeric() || b==b'-'))
}
/// Registration-only password requirements. Sign-in must never call this policy.
pub const PASSWORD_MIN_CODEPOINTS: usize = 8;
pub const PASSWORD_MAX_UTF8_BYTES: usize = 1024;
pub const PASSWORD_REQ_LENGTH: u8 = 1 << 0;
pub const PASSWORD_REQ_ASCII_UPPER: u8 = 1 << 1;
pub const PASSWORD_REQ_ASCII_LOWER: u8 = 1 << 2;
pub const PASSWORD_REQ_ASCII_DIGIT: u8 = 1 << 3;
pub const PASSWORD_REQ_UTF8_LIMIT: u8 = 1 << 4;
pub const PASSWORD_REQ_ALL: u8 = PASSWORD_REQ_LENGTH | PASSWORD_REQ_ASCII_UPPER
    | PASSWORD_REQ_ASCII_LOWER | PASSWORD_REQ_ASCII_DIGIT | PASSWORD_REQ_UTF8_LIMIT;

pub fn registration_password_requirements(password: &str) -> [bool; 5] {
    [
        password.chars().count() >= PASSWORD_MIN_CODEPOINTS,
        password.bytes().any(|b| b.is_ascii_uppercase()),
        password.bytes().any(|b| b.is_ascii_lowercase()),
        password.bytes().any(|b| b.is_ascii_digit()),
        password.len() <= PASSWORD_MAX_UTF8_BYTES,
    ]
}

pub fn registration_password_requirement_mask(password: &str) -> u8 {
    registration_password_requirements(password).into_iter().enumerate()
        .fold(0, |mask, (index, satisfied)| mask | if satisfied { 1 << index } else { 0 })
}

/// Return one bit per registration-password rule (see PASSWORD_REQ_* constants).
/// Invalid UTF-8 and null input return zero; the caller owns the input buffer.
/// # Safety
/// For non-null `data`, the pointer must be readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn serein_core_registration_password_requirements(data: *const u8, len: usize) -> u8 {
    if data.is_null() { return 0; }
    let bytes = unsafe { slice::from_raw_parts(data, len) };
    str::from_utf8(bytes).map(registration_password_requirement_mask).unwrap_or(0)
}

pub fn valid_theme(value: &str) -> bool { matches!(value,"system"|"light"|"dark") }
pub fn valid_font_scale(value: &str) -> bool { matches!(value,"system"|"standard"|"large"|"extra_large") }
pub fn history_page_limit(requested: Option<i64>) -> i64 { requested.unwrap_or(DEFAULT_HISTORY_PAGE).clamp(1,MAX_HISTORY_PAGE) }

/// Fixed datagram framing for an already-authenticated/encrypted payload.
/// This framing is NOT a transport protocol and supplies no authentication,
/// replay protection, reliability, congestion control, or key management.
pub const PACKET_HEADER_LEN: usize = 37;
/// IPv6 minimum MTU (1280) minus IPv6+UDP headers (48 bytes).
pub const MAX_UDP_PACKET_LEN: usize = 1232;
pub const MAX_PACKET_PAYLOAD: usize = MAX_UDP_PACKET_LEN - PACKET_HEADER_LEN;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadType { Text = 0x01, Audio = 0x02, Video = 0x03, Control = 0x04 }

impl TryFrom<u8> for PayloadType {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Text), 0x02 => Ok(Self::Audio),
            0x03 => Ok(Self::Video), 0x04 => Ok(Self::Control), _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketView<'a> {
    pub sender_id: &'a [u8; 16],
    pub receiver_id: &'a [u8; 16],
    pub payload_type: PayloadType,
    pub payload: &'a [u8],
}

/// Write a packet into caller-owned storage without allocating. The payload is
/// copied once into the final wire buffer; parsing returns borrowed slices.
pub fn encode_packet_into(sender_id: &[u8; 16], receiver_id: &[u8; 16], payload_type: PayloadType, payload: &[u8], output: &mut [u8]) -> Option<usize> {
    if sender_id.iter().all(|b| *b == 0) || receiver_id.iter().all(|b| *b == 0)
        || payload.len() > MAX_PACKET_PAYLOAD || output.len() < PACKET_HEADER_LEN + payload.len() {
        return None;
    }
    output[..16].copy_from_slice(sender_id);
    output[16..32].copy_from_slice(receiver_id);
    output[32] = payload_type as u8;
    output[33..37].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    output[37..37 + payload.len()].copy_from_slice(payload);
    Some(PACKET_HEADER_LEN + payload.len())
}

/// Parse a packet without copying its IDs or payload.
pub fn parse_packet(packet: &[u8]) -> Option<PacketView<'_>> {
    if !(PACKET_HEADER_LEN..=MAX_UDP_PACKET_LEN).contains(&packet.len()) { return None; }
    let sender_id: &[u8; 16] = packet[..16].try_into().ok()?;
    let receiver_id: &[u8; 16] = packet[16..32].try_into().ok()?;
    if sender_id.iter().all(|b| *b == 0) || receiver_id.iter().all(|b| *b == 0) { return None; }
    let payload_type = PayloadType::try_from(packet[32]).ok()?;
    let payload_len = u32::from_be_bytes(packet[33..37].try_into().ok()?) as usize;
    if payload_len > MAX_PACKET_PAYLOAD || packet.len() != PACKET_HEADER_LEN + payload_len { return None; }
    Some(PacketView { sender_id, receiver_id, payload_type, payload: &packet[PACKET_HEADER_LEN..] })
}

/// C ABI view into caller-owned packet memory. Pointers are borrowed and remain
/// valid only while the original packet buffer remains alive and unchanged.
/// This format is not authenticated: callers must not treat IDs as trusted.
#[repr(C)]
pub struct SereinPacketView {
    pub sender_id: *const u8,
    pub receiver_id: *const u8,
    pub payload_type: u8,
    pub payload: *const u8,
    pub payload_len: usize,
}

/// Parse a packet in place and return pointers into the original buffer.
/// `packet` and `out` must be valid for the supplied lengths and properly aligned;
/// `out` must not overlap the packet buffer.
///
/// # Safety
/// The caller guarantees the pointer and non-overlap requirements above.
#[no_mangle]
pub unsafe extern "C" fn serein_core_packet_view(packet: *const u8, packet_len: usize, out: *mut SereinPacketView) -> u8 {
    if packet.is_null() || out.is_null() || !(PACKET_HEADER_LEN..=MAX_UDP_PACKET_LEN).contains(&packet_len) { return 0; }
    let bytes = unsafe { slice::from_raw_parts(packet, packet_len) };
    let Some(view) = parse_packet(bytes) else { return 0; };
    unsafe {
        std::ptr::write(out, SereinPacketView {
            sender_id: packet,
            receiver_id: packet.add(16),
            payload_type: view.payload_type as u8,
            payload: packet.add(PACKET_HEADER_LEN),
            payload_len: view.payload.len(),
        });
    }
    1
}

/// Encode into caller-owned memory. Returns packet length, or -1 on invalid input.
/// This avoids Rust-side allocation; it is not a zero-copy send API.
///
/// # Safety
/// Every non-null pointer must be valid for its declared size. The mutable output
/// region must not overlap the sender, receiver, or payload input regions.
#[no_mangle]
pub unsafe extern "C" fn serein_core_packet_encode(sender_id: *const u8, receiver_id: *const u8, payload_type: u8, payload: *const u8, payload_len: usize, output: *mut u8, output_capacity: usize) -> isize {
    if sender_id.is_null() || receiver_id.is_null() || output.is_null()
        || payload_len > MAX_PACKET_PAYLOAD || output_capacity > MAX_UDP_PACKET_LEN
        || (payload_len > 0 && payload.is_null()) { return -1; }
    let Ok(payload_type) = PayloadType::try_from(payload_type) else { return -1; };
    let sender: &[u8; 16] = match unsafe { slice::from_raw_parts(sender_id, 16) }.try_into() { Ok(value) => value, Err(_) => return -1 };
    let receiver: &[u8; 16] = match unsafe { slice::from_raw_parts(receiver_id, 16) }.try_into() { Ok(value) => value, Err(_) => return -1 };
    let payload_bytes: &[u8] = if payload_len == 0 { &[] } else { unsafe { slice::from_raw_parts(payload, payload_len) } };
    let output_bytes = unsafe { slice::from_raw_parts_mut(output, output_capacity) };
    match encode_packet_into(sender, receiver, payload_type, payload_bytes, output_bytes) {
        Some(length) => length as isize,
        None => -1,
    }
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte-b'A'), b'a'..=b'z' => Some(byte-b'a'+26),
        b'0'..=b'9' => Some(byte-b'0'+52), b'+' => Some(62), b'/' => Some(63), _ => None,
    }
}
/// Accept canonical padded RFC 4648 Base64 and return the decoded byte length.
pub fn canonical_base64_len(value: &str) -> Option<usize> {
    let bytes=value.as_bytes();
    if bytes.is_empty() || bytes.len()%4!=0 { return None; }
    let padding=if bytes.ends_with(b"=="){2}else if bytes.ends_with(b"="){1}else{0};
    let data_len=bytes.len().checked_sub(padding)?;
    if data_len==0 { return None; }
    for byte in &bytes[..data_len] { base64_value(*byte)?; }
    if bytes[data_len..].iter().any(|b|*b!=b'=') { return None; }
    match padding {
        0 if data_len%4==0 => {},
        1 if data_len%4==3 && base64_value(bytes[data_len-1].checked_sub(0)?)? & 0b11 == 0 => {},
        2 if data_len%4==2 && base64_value(bytes[data_len-1])? & 0b1111 == 0 => {},
        _ => return None,
    }
    Some((bytes.len()/4)*3-padding)
}
/// Validate the untrusted AES-GCM envelope shape. This checks encoding and lengths,
/// not the authentication tag: only the recipient with a key can verify that tag.
pub fn valid_ciphertext_parts(iv: &str, ciphertext: &str) -> bool {
    if iv.len()>24 || ciphertext.len()>MAX_CIPHERTEXT_CHARS { return false; }
    canonical_base64_len(iv)==Some(12)
        && canonical_base64_len(ciphertext).is_some_and(|n|(16..=((MAX_CIPHERTEXT_CHARS/4)*3)).contains(&n))
}

/// C ABI used by first-party JNI, Swift/C, and wasm adapters. Input pointers must
/// refer to `len` readable bytes for the duration of the call.
#[no_mangle]
pub extern "C" fn serein_core_max_message_characters() -> u32 { MAX_MESSAGE_CHARACTERS as u32 }
#[no_mangle]
pub extern "C" fn serein_core_message_warning_characters() -> u32 { MESSAGE_COUNTER_WARNING_CHARACTERS as u32 }
/// Count Unicode scalar values in UTF-8 text. Returns `u32::MAX` for invalid input.
/// A null pointer is accepted only for an empty string.
#[no_mangle]
pub unsafe extern "C" fn serein_core_message_character_count(data: *const u8, len: usize) -> u32 {
    if data.is_null() { return if len == 0 { 0 } else { u32::MAX }; }
    if len > MAX_MESSAGE_CHARACTERS.saturating_mul(4) { return u32::MAX; }
    let bytes = unsafe { slice::from_raw_parts(data, len) };
    str::from_utf8(bytes).map(|value| message_character_count(value) as u32).unwrap_or(u32::MAX)
}
#[no_mangle]
pub unsafe extern "C" fn serein_core_validate_username(data: *const u8, len: usize) -> u8 {
    if data.is_null() || len>32 { return 0; }
    let bytes=unsafe { slice::from_raw_parts(data,len) };
    str::from_utf8(bytes).ok().filter(|s|valid_username(s)).map_or(0,|_|1)
}
#[no_mangle]
pub unsafe extern "C" fn serein_core_validate_email(data: *const u8, len: usize) -> u8 {
    if data.is_null() || len>254 { return 0; }
    let bytes=unsafe { slice::from_raw_parts(data,len) };
    str::from_utf8(bytes).ok().filter(|s|valid_email(s)).map_or(0,|_|1)
}
#[no_mangle]
pub unsafe extern "C" fn serein_core_validate_ciphertext(iv: *const u8, iv_len: usize, cipher: *const u8, cipher_len: usize) -> u8 {
    if iv.is_null() || cipher.is_null() || iv_len>24 || cipher_len>MAX_CIPHERTEXT_CHARS { return 0; }
    let iv_bytes=unsafe { slice::from_raw_parts(iv,iv_len) };
    let cipher_bytes=unsafe { slice::from_raw_parts(cipher,cipher_len) };
    match (str::from_utf8(iv_bytes),str::from_utf8(cipher_bytes)) {
        (Ok(iv),Ok(ciphertext)) if valid_ciphertext_parts(iv,ciphertext)=>1,
        _=>0,
    }
}
#[no_mangle]
pub extern "C" fn serein_core_history_page_limit(requested: i64) -> i64 { history_page_limit(Some(requested)) }
#[no_mangle]
pub extern "C" fn serein_core_version() -> *const u8 { VERSION_C.as_ptr() }
#[no_mangle]
pub extern "C" fn serein_core_alloc(len: usize) -> *mut u8 {
    if len==0 { return std::ptr::null_mut(); }
    Box::into_raw(vec![0u8;len].into_boxed_slice()) as *mut u8
}
#[no_mangle]
pub unsafe extern "C" fn serein_core_dealloc(data: *mut u8, len: usize) {
    if !data.is_null() && len>0 { unsafe { drop(Box::from_raw(slice::from_raw_parts_mut(data,len))); } }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn shared_message_character_limit_counts_unicode_scalars_and_truncates(){
        let text="a😀e\u{301}";
        assert_eq!(message_character_count(text),4);
        assert_eq!(message_character_count(&"x".repeat(MAX_MESSAGE_CHARACTERS+1)),MAX_MESSAGE_CHARACTERS+1);
        assert_eq!(truncate_message(&format!("{}Z","😀".repeat(MAX_MESSAGE_CHARACTERS))),"😀".repeat(MAX_MESSAGE_CHARACTERS));
        assert_eq!(MESSAGE_COUNTER_WARNING_CHARACTERS,3_600);
        assert_eq!(serein_core_max_message_characters(),4_000);
        let bytes=text.as_bytes();
        assert_eq!(unsafe{serein_core_message_character_count(bytes.as_ptr(),bytes.len())},4);
        assert_eq!(unsafe{serein_core_message_character_count(std::ptr::null(),0)},0);
        let invalid=[0xffu8];assert_eq!(unsafe{serein_core_message_character_count(invalid.as_ptr(),invalid.len())},u32::MAX);
    }
    #[test] fn packet_encode_parse_round_trip_uses_fixed_big_endian_header() {
        let sender = [1u8; 16]; let receiver = [2u8; 16]; let payload = [9u8, 8, 7, 6];
        let mut output = [0u8; MAX_UDP_PACKET_LEN];
        let length = encode_packet_into(&sender, &receiver, PayloadType::Video, &payload, &mut output).unwrap();
        assert_eq!(length, PACKET_HEADER_LEN + payload.len());
        assert_eq!(&output[33..37], &(payload.len() as u32).to_be_bytes());
        let parsed = parse_packet(&output[..length]).unwrap();
        assert_eq!(parsed.sender_id, &sender); assert_eq!(parsed.receiver_id, &receiver);
        assert_eq!(parsed.payload_type, PayloadType::Video); assert_eq!(parsed.payload, &payload);
        assert_eq!(parsed.payload.as_ptr(), unsafe { output.as_ptr().add(PACKET_HEADER_LEN) });
    }
    #[test] fn packet_parser_rejects_bad_type_length_and_oversized_payload() {
        let sender = [1u8; 16]; let receiver = [2u8; 16]; let payload = [3u8; 2];
        let mut output = [0u8; MAX_UDP_PACKET_LEN];
        let length = encode_packet_into(&sender, &receiver, PayloadType::Text, &payload, &mut output).unwrap();
        output[32] = 0xff; assert!(parse_packet(&output[..length]).is_none());
        output[32] = PayloadType::Text as u8; output[36] = 3; assert!(parse_packet(&output[..length]).is_none());
        assert!(encode_packet_into(&sender, &receiver, PayloadType::Audio, &vec![0; MAX_PACKET_PAYLOAD + 1], &mut output).is_none());
        assert!(encode_packet_into(&[0; 16], &receiver, PayloadType::Control, &payload, &mut output).is_none());
    }
    #[test] fn c_packet_view_borrows_original_encrypted_payload() {
        let sender = [1u8; 16]; let receiver = [2u8; 16]; let payload = [5u8, 4, 3];
        let mut packet = [0u8; PACKET_HEADER_LEN + 3];
        let length = encode_packet_into(&sender, &receiver, PayloadType::Control, &payload, &mut packet).unwrap();
        let mut view = SereinPacketView { sender_id: std::ptr::null(), receiver_id: std::ptr::null(), payload_type: 0, payload: std::ptr::null(), payload_len: 0 };
        let ok = unsafe { serein_core_packet_view(packet.as_ptr(), length, &mut view) };
        assert_eq!(ok, 1); assert_eq!(view.payload_len, payload.len());
        assert_eq!(view.payload, unsafe { packet.as_ptr().add(PACKET_HEADER_LEN) });
    }
    #[test] fn username_normalization_and_policy_are_shared(){assert_eq!(normalize_username(" Alice_7 "),"alice_7");assert!(valid_username("alice.7"));assert!(!valid_username("Upper"));assert!(!valid_username("ab"));}
    #[test] fn registration_password_policy_is_shared_and_counts_utf8_correctly(){
        assert_eq!(registration_password_requirements("Serein123"),[true,true,true,true,true]);
        assert_eq!(registration_password_requirements("password1"),[true,false,true,true,true]);
        assert_eq!(registration_password_requirements("PASSWORD1"),[true,true,false,true,true]);
        assert_eq!(registration_password_requirements("Password"),[true,true,true,false,true]);
        assert_eq!(registration_password_requirements("Abc123"),[false,true,true,true,true]);
        assert_eq!(registration_password_requirements("😀😀😀😀😀Aa1"),[true,true,true,true,true]);
        assert_eq!(registration_password_requirements(&("A".to_owned()+&"a".repeat(1022)+"1")),[true,true,true,true,true]);
        assert!(!registration_password_requirements(&("A".to_owned()+&"a".repeat(1023)+"1"))[4]);
        assert_eq!(registration_password_requirement_mask("Serein123"),PASSWORD_REQ_ALL);
        let bytes=b"Serein123";
        assert_eq!(unsafe { serein_core_registration_password_requirements(bytes.as_ptr(),bytes.len()) },PASSWORD_REQ_ALL);
        assert_eq!(unsafe { serein_core_registration_password_requirements(std::ptr::null(),0) },0);
        let invalid=[0xffu8];
        assert_eq!(unsafe { serein_core_registration_password_requirements(invalid.as_ptr(),invalid.len()) },0);
    }
    #[test] fn email_policy_rejects_obvious_invalid_values(){assert!(valid_email("person+tag@example.org"));assert!(!valid_email("missing-at"));assert!(!valid_email("person@localhost"));assert!(!valid_email("person..name@example.org"));assert!(!valid_email("person@-example.org"));assert!(!valid_email("person\n@example.org"));assert!(!valid_email("a@b@c.org"));}
    #[test] fn theme_and_font_values_are_allowlisted(){assert!(valid_theme("dark"));assert!(!valid_theme("ultraviolet"));assert!(valid_font_scale("system"));assert!(valid_font_scale("large"));assert!(valid_font_scale("extra_large"));assert!(!valid_font_scale("huge"));}
    #[test] fn history_page_is_bounded(){assert_eq!(history_page_limit(None),100);assert_eq!(history_page_limit(Some(0)),1);assert_eq!(history_page_limit(Some(500)),200);}
    #[test] fn base64_lengths_and_padding_bits_are_checked(){assert_eq!(canonical_base64_len("AAAAAAAAAAAAAAAA"),Some(12));assert_eq!(canonical_base64_len("AAAAAAAAAAAAAAAAAAAAAA=="),Some(16));assert_eq!(canonical_base64_len("AA=="),Some(1));assert_eq!(canonical_base64_len("AB=="),None);assert_eq!(canonical_base64_len("not-base64"),None);}
    #[test] fn gcm_envelope_requires_twelve_byte_iv_and_tag(){assert!(valid_ciphertext_parts("AAAAAAAAAAAAAAAA","AAAAAAAAAAAAAAAAAAAAAA=="));assert!(!valid_ciphertext_parts("short","AAAAAAAAAAAAAAAAAAAAAA=="));assert!(!valid_ciphertext_parts("AAAAAAAAAAAAAAAA","AA=="));}
}
