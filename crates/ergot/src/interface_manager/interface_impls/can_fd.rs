//! CAN FD Interface Implementation
//!
//! This implementation uses CAN FD frames with an optimized header layout that puts
//! hardware-filterable fields in the CAN extended ID (29-bit), reducing payload overhead.
//!
//! ## CAN Extended ID Layout (29 bits)
//!
//! ```text
//! ┌──────────┬──────────┬──────────┬───────────┬──────────┐
//! │ Priority │ dst_node │ dst_port │ frame_kind│ reserved │
//! │  (3 bits)│ (8 bits) │ (8 bits) │  (3 bits) │ (7 bits) │
//! └──────────┴──────────┴──────────┴───────────┴──────────┘
//!   Bits 28-26  25-18      17-10       9-7         6-0
//! ```
//!
//! This layout enables CAN hardware filtering on:
//! - Destination node ID (filter messages for this device)
//! - Destination port ID (filter messages for specific services)
//! - Frame kind (filter requests, responses, or topic messages)
//! - Priority (CAN arbitration - lower ID = higher priority)
//!
//! ## Payload Layout
//!
//! The remaining header fields are encoded in the CAN FD payload using postcard varint encoding:
//!
//! ```text
//! ┌──────────────┬─────────────┬──────────┬─────────┬───────────────┬──────────┐
//! │ dst.net_id   │ src address │ src_port │ seq_no  │ ttl           │ body     │
//! │ (1-3 bytes)  │ (1-5 bytes) │ (1 byte) │(1-3 b)  │ (1 byte)      │ (N bytes)│
//! └──────────────┴─────────────┴──────────┴─────────┴───────────────┴──────────┘
//! ```
//!
//! For broadcast/any-port messages (port 0 or 255), the AnyAllAppendix is also included.
//!
//! ## Overhead Comparison
//!
//! For a typical message with low network IDs:
//! - Standard ergot header: ~12-14 bytes
//! - CAN FD optimized: ~6-8 bytes in payload (rest in CAN ID)
//!
//! ## Usage
//!
//! This module provides traits and types that can be used with various CAN implementations:
//! - `embedded-can` for embedded targets
//! - `socketcan` for Linux
//! - Other platform-specific CAN drivers

use core::fmt;

use postcard::{Serializer, ser_flavors::{self, Flavor}};
use serde::{Deserialize, Serialize};

use crate::{
    Address, AnyAllAppendix, FrameKind, HeaderSeq, Key, ProtocolError,
    interface_manager::InterfaceSink,
    nash::NameHash,
};

// ============================================================================
// Constants
// ============================================================================

/// Maximum CAN FD payload size
pub const CAN_FD_MAX_PAYLOAD: usize = 64;

/// Maximum header size in CAN FD payload (excluding what's in the ID)
///
/// ```text
/// dst.network_id:  u16, varint: 3 bytes max
/// src (full addr): u32, varint: 5 bytes max
/// src.port_id:     u8:          1 byte
/// seq_no:          u16, varint: 3 bytes max
/// ttl:             u8:          1 byte
/// ================================= 13 bytes
/// AnyAllAppendix (if present):
///   key:           [u8; 8]:     8 bytes
///   nash:          u32, varint: 5 bytes max
/// ================================= 26 bytes max
/// ```
pub const MAX_CAN_PAYLOAD_HDR_SIZE: usize = 26;

/// Minimum usable payload after header (for very small messages)
pub const MIN_CAN_PAYLOAD_BODY: usize = CAN_FD_MAX_PAYLOAD - MAX_CAN_PAYLOAD_HDR_SIZE;

// ============================================================================
// CAN ID Encoding
// ============================================================================

/// Priority level for CAN arbitration (lower = higher priority)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CanPriority {
    /// Highest priority (0) - for critical/real-time messages
    Critical = 0,
    /// High priority (1)
    High = 1,
    /// Normal priority (2) - default
    #[default]
    Normal = 2,
    /// Low priority (3)
    Low = 3,
    /// Bulk priority (4) - for large transfers
    Bulk = 4,
    /// Background priority (5)
    Background = 5,
    /// Lowest priority (6)
    Lowest = 6,
    /// Reserved (7)
    Reserved = 7,
}

impl CanPriority {
    /// Convert from raw 3-bit value
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x7 {
            0 => Self::Critical,
            1 => Self::High,
            2 => Self::Normal,
            3 => Self::Low,
            4 => Self::Bulk,
            5 => Self::Background,
            6 => Self::Lowest,
            _ => Self::Reserved,
        }
    }

    /// Convert to raw 3-bit value
    pub const fn to_bits(self) -> u8 {
        self as u8
    }
}

/// Encoded CAN extended ID containing routing-critical header fields
///
/// Layout (29 bits):
/// - Bits 28-26: Priority (3 bits)
/// - Bits 25-18: Destination node ID (8 bits)
/// - Bits 17-10: Destination port ID (8 bits)
/// - Bits 9-7: Frame kind (3 bits, maps ENDPOINT_REQ=1, ENDPOINT_RESP=2, TOPIC_MSG=3, ERROR=7)
/// - Bits 6-0: Reserved (7 bits, set to 0)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanFrameId(u32);

impl CanFrameId {
    // Bit positions
    const PRIORITY_SHIFT: u32 = 26;
    const DST_NODE_SHIFT: u32 = 18;
    const DST_PORT_SHIFT: u32 = 10;
    const KIND_SHIFT: u32 = 7;

    // Masks
    const PRIORITY_MASK: u32 = 0x7 << Self::PRIORITY_SHIFT;
    const DST_NODE_MASK: u32 = 0xFF << Self::DST_NODE_SHIFT;
    const DST_PORT_MASK: u32 = 0xFF << Self::DST_PORT_SHIFT;
    const KIND_MASK: u32 = 0x7 << Self::KIND_SHIFT;

    /// Maximum valid extended CAN ID (29 bits)
    pub const MAX_EXTENDED_ID: u32 = 0x1FFF_FFFF;

    /// Create a new CAN frame ID from header fields
    pub const fn new(
        priority: CanPriority,
        dst_node_id: u8,
        dst_port_id: u8,
        kind: FrameKind,
    ) -> Self {
        let kind_bits = Self::frame_kind_to_bits(kind);
        let id = ((priority.to_bits() as u32) << Self::PRIORITY_SHIFT)
            | ((dst_node_id as u32) << Self::DST_NODE_SHIFT)
            | ((dst_port_id as u32) << Self::DST_PORT_SHIFT)
            | ((kind_bits as u32) << Self::KIND_SHIFT);
        Self(id)
    }

    /// Create from an ergot HeaderSeq with default priority
    pub const fn from_header(hdr: &HeaderSeq) -> Self {
        Self::from_header_with_priority(hdr, CanPriority::Normal)
    }

    /// Create from an ergot HeaderSeq with specified priority
    pub const fn from_header_with_priority(hdr: &HeaderSeq, priority: CanPriority) -> Self {
        Self::new(priority, hdr.dst.node_id, hdr.dst.port_id, hdr.kind)
    }

    /// Parse from raw 29-bit CAN extended ID
    pub const fn from_raw(id: u32) -> Self {
        Self(id & Self::MAX_EXTENDED_ID)
    }

    /// Get the raw 29-bit CAN extended ID value
    pub const fn to_raw(self) -> u32 {
        self.0
    }

    /// Extract priority
    pub const fn priority(self) -> CanPriority {
        CanPriority::from_bits(((self.0 & Self::PRIORITY_MASK) >> Self::PRIORITY_SHIFT) as u8)
    }

    /// Extract destination node ID
    pub const fn dst_node_id(self) -> u8 {
        ((self.0 & Self::DST_NODE_MASK) >> Self::DST_NODE_SHIFT) as u8
    }

    /// Extract destination port ID
    pub const fn dst_port_id(self) -> u8 {
        ((self.0 & Self::DST_PORT_MASK) >> Self::DST_PORT_SHIFT) as u8
    }

    /// Extract frame kind
    pub const fn frame_kind(self) -> FrameKind {
        let bits = ((self.0 & Self::KIND_MASK) >> Self::KIND_SHIFT) as u8;
        Self::bits_to_frame_kind(bits)
    }

    /// Convert FrameKind to 3-bit representation
    const fn frame_kind_to_bits(kind: FrameKind) -> u8 {
        match kind.0 {
            0 => 0,   // RESERVED
            1 => 1,   // ENDPOINT_REQ
            2 => 2,   // ENDPOINT_RESP
            3 => 3,   // TOPIC_MSG
            255 => 7, // PROTOCOL_ERROR
            _ => 0,   // Unknown -> RESERVED
        }
    }

    /// Convert 3-bit representation back to FrameKind
    const fn bits_to_frame_kind(bits: u8) -> FrameKind {
        match bits {
            0 => FrameKind::RESERVED,
            1 => FrameKind::ENDPOINT_REQ,
            2 => FrameKind::ENDPOINT_RESP,
            3 => FrameKind::TOPIC_MSG,
            7 => FrameKind::PROTOCOL_ERROR,
            _ => FrameKind::RESERVED,
        }
    }

    /// Create a filter mask for matching destination node ID only
    pub const fn filter_mask_node_only() -> u32 {
        Self::DST_NODE_MASK
    }

    /// Create a filter mask for matching destination node and port
    pub const fn filter_mask_node_port() -> u32 {
        Self::DST_NODE_MASK | Self::DST_PORT_MASK
    }

    /// Create a filter mask for matching destination node, port, and kind
    pub const fn filter_mask_full() -> u32 {
        Self::DST_NODE_MASK | Self::DST_PORT_MASK | Self::KIND_MASK
    }
}

impl fmt::Display for CanFrameId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CanId(pri={:?}, dst={}:{}, kind={:?})",
            self.priority(),
            self.dst_node_id(),
            self.dst_port_id(),
            self.frame_kind().0
        )
    }
}

// ============================================================================
// CAN Payload Header (fields not in the CAN ID)
// ============================================================================

/// Header fields that go in the CAN FD payload
///
/// This is serialized using postcard for compact encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanPayloadHeader {
    /// Destination network ID (for routing to other networks)
    pub dst_network_id: u16,
    /// Full source address (network_id << 16 | node_id << 8 | port_id)
    pub src: u32,
    /// Sequence number for request/response correlation
    pub seq_no: u16,
    /// Time-to-live, decremented at each hop
    pub ttl: u8,
}

impl CanPayloadHeader {
    /// Create from an ergot HeaderSeq
    pub fn from_header(hdr: &HeaderSeq) -> Self {
        Self {
            dst_network_id: hdr.dst.network_id,
            src: hdr.src.as_u32(),
            seq_no: hdr.seq_no,
            ttl: hdr.ttl,
        }
    }

    /// Reconstruct source Address
    pub fn src_address(&self) -> Address {
        Address::from_word(self.src)
    }
}

// ============================================================================
// Frame Encoding/Decoding
// ============================================================================

/// Error when encoding a CAN frame
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanEncodeError {
    /// Message too large for CAN FD payload
    PayloadTooLarge,
    /// Serialization failed
    SerializationError,
}

/// Error when decoding a CAN frame
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanDecodeError {
    /// Payload too short
    PayloadTooShort,
    /// Deserialization failed
    DeserializationError,
    /// Invalid frame kind in CAN ID
    InvalidFrameKind,
}

/// A decoded CAN FD frame
#[derive(Debug)]
pub struct CanFrame<'a> {
    /// Reconstructed header
    pub header: HeaderSeq,
    /// Message body (or error)
    pub body: Result<&'a [u8], ProtocolError>,
}

/// Encode an ergot message into CAN ID + payload
///
/// Returns (CAN extended ID, payload slice length used)
pub fn encode_frame<T: Serialize>(
    hdr: &HeaderSeq,
    body: &T,
    priority: CanPriority,
    buf: &mut [u8],
) -> Result<(CanFrameId, usize), CanEncodeError> {
    if buf.len() < MAX_CAN_PAYLOAD_HDR_SIZE {
        return Err(CanEncodeError::PayloadTooLarge);
    }

    let can_id = CanFrameId::from_header_with_priority(hdr, priority);
    let payload_hdr = CanPayloadHeader::from_header(hdr);

    let ser = ser_flavors::Slice::new(buf);
    let mut serializer = Serializer { output: ser };

    // Serialize payload header
    payload_hdr
        .serialize(&mut serializer)
        .map_err(|_| CanEncodeError::SerializationError)?;

    // Serialize any/all appendix if present
    if let Some(app) = hdr.any_all.as_ref() {
        serializer
            .output
            .try_extend(&app.key.0)
            .map_err(|_| CanEncodeError::SerializationError)?;
        let nash_val: u32 = app.nash.as_ref().map(NameHash::to_u32).unwrap_or(0);
        nash_val
            .serialize(&mut serializer)
            .map_err(|_| CanEncodeError::SerializationError)?;
    }

    // Serialize body
    body.serialize(&mut serializer)
        .map_err(|_| CanEncodeError::SerializationError)?;

    let used = serializer
        .output
        .finalize()
        .map_err(|_| CanEncodeError::SerializationError)?;

    if used.len() > CAN_FD_MAX_PAYLOAD {
        return Err(CanEncodeError::PayloadTooLarge);
    }

    Ok((can_id, used.len()))
}

/// Encode a raw (pre-serialized) ergot message into CAN ID + payload
pub fn encode_frame_raw(
    hdr: &HeaderSeq,
    body: &[u8],
    priority: CanPriority,
    buf: &mut [u8],
) -> Result<(CanFrameId, usize), CanEncodeError> {
    // Don't do an early bounds check here - the actual header size varies based on
    // address values (varint encoding) and presence of AnyAll appendix. Let
    // serialization fail if there's not enough space, then check final size against
    // CAN_FD_MAX_PAYLOAD.

    let can_id = CanFrameId::from_header_with_priority(hdr, priority);
    let payload_hdr = CanPayloadHeader::from_header(hdr);

    let ser = ser_flavors::Slice::new(buf);
    let mut serializer = Serializer { output: ser };

    // Serialize payload header
    payload_hdr
        .serialize(&mut serializer)
        .map_err(|_| CanEncodeError::SerializationError)?;

    // Serialize any/all appendix if present
    if let Some(app) = hdr.any_all.as_ref() {
        serializer
            .output
            .try_extend(&app.key.0)
            .map_err(|_| CanEncodeError::SerializationError)?;
        let nash_val: u32 = app.nash.as_ref().map(NameHash::to_u32).unwrap_or(0);
        nash_val
            .serialize(&mut serializer)
            .map_err(|_| CanEncodeError::SerializationError)?;
    }

    // Append raw body
    serializer
        .output
        .try_extend(body)
        .map_err(|_| CanEncodeError::SerializationError)?;

    let used = serializer
        .output
        .finalize()
        .map_err(|_| CanEncodeError::SerializationError)?;

    if used.len() > CAN_FD_MAX_PAYLOAD {
        return Err(CanEncodeError::PayloadTooLarge);
    }

    Ok((can_id, used.len()))
}

/// Encode a protocol error into CAN ID + payload
pub fn encode_frame_err(
    hdr: &HeaderSeq,
    err: ProtocolError,
    priority: CanPriority,
    buf: &mut [u8],
) -> Result<(CanFrameId, usize), CanEncodeError> {
    if buf.len() < MAX_CAN_PAYLOAD_HDR_SIZE + 2 {
        return Err(CanEncodeError::PayloadTooLarge);
    }

    let can_id = CanFrameId::from_header_with_priority(hdr, priority);
    let payload_hdr = CanPayloadHeader::from_header(hdr);

    let ser = ser_flavors::Slice::new(buf);
    let mut serializer = Serializer { output: ser };

    // Serialize payload header
    payload_hdr
        .serialize(&mut serializer)
        .map_err(|_| CanEncodeError::SerializationError)?;

    // Serialize error
    err.serialize(&mut serializer)
        .map_err(|_| CanEncodeError::SerializationError)?;

    let used = serializer
        .output
        .finalize()
        .map_err(|_| CanEncodeError::SerializationError)?;

    Ok((can_id, used.len()))
}

/// Decode a CAN FD frame into an ergot message
pub fn decode_frame<'a>(can_id: CanFrameId, payload: &'a [u8]) -> Result<CanFrame<'a>, CanDecodeError> {
    // Deserialize payload header
    let (payload_hdr, remain) = postcard::take_from_bytes::<CanPayloadHeader>(payload)
        .map_err(|_| CanDecodeError::DeserializationError)?;

    let kind = can_id.frame_kind();
    let is_err = kind == FrameKind::PROTOCOL_ERROR;
    let any_all = [0, 255].contains(&can_id.dst_port_id());

    // Reconstruct destination address from CAN ID + payload
    let dst = Address {
        network_id: payload_hdr.dst_network_id,
        node_id: can_id.dst_node_id(),
        port_id: can_id.dst_port_id(),
    };

    // Parse any/all appendix if needed
    let (any_all_appendix, body_data) = if any_all && !is_err {
        if remain.len() < 8 + 1 {
            return Err(CanDecodeError::PayloadTooShort);
        }
        let key = Key(remain[..8].try_into().unwrap());
        let (nash_val, body) = postcard::take_from_bytes::<u32>(&remain[8..])
            .map_err(|_| CanDecodeError::DeserializationError)?;
        let nash = NameHash::from_u32(nash_val);
        (Some(AnyAllAppendix { key, nash }), body)
    } else {
        (None, remain)
    };

    // Handle error frames
    let body = if is_err {
        let (err, _) = postcard::take_from_bytes::<ProtocolError>(body_data)
            .map_err(|_| CanDecodeError::DeserializationError)?;
        Err(err)
    } else {
        Ok(body_data)
    };

    Ok(CanFrame {
        header: HeaderSeq {
            src: payload_hdr.src_address(),
            dst,
            any_all: any_all_appendix,
            seq_no: payload_hdr.seq_no,
            kind,
            ttl: payload_hdr.ttl,
        },
        body,
    })
}

// ============================================================================
// Interface Implementation
// ============================================================================

use crate::interface_manager::Interface;

/// A CAN FD interface implementation
///
/// This interface encodes ergot messages with routing-critical fields in the
/// CAN extended ID for hardware filtering, and remaining fields in the payload.
pub struct CanFdInterface;

impl Interface for CanFdInterface {
    type Sink = CanFdSink;
}

/// Configuration for the CAN FD interface
#[derive(Debug, Clone)]
pub struct CanFdConfig {
    /// Default priority for outgoing messages
    pub default_priority: CanPriority,
    /// This CAN segment's network ID (for address rewriting on bridges)
    pub local_network_id: Option<u16>,
}

impl Default for CanFdConfig {
    fn default() -> Self {
        Self {
            default_priority: CanPriority::Normal,
            local_network_id: None,
        }
    }
}

/// Trait for sending CAN FD frames
///
/// Implement this trait to integrate with your CAN driver (e.g., embedded-can, socketcan)
pub trait CanFdTransmit {
    /// Error type for transmission failures
    type Error;

    /// Transmit a CAN FD frame
    ///
    /// # Arguments
    /// * `id` - The 29-bit extended CAN ID
    /// * `data` - The payload data (up to 64 bytes)
    fn transmit(&mut self, id: u32, data: &[u8]) -> Result<(), Self::Error>;
}

/// Interface sink for CAN FD
///
/// Wraps a CAN transmitter and encodes ergot messages into CAN FD frames.
pub struct CanFdSink<T: CanFdTransmit = DummyTransmit> {
    tx: T,
    config: CanFdConfig,
    buf: [u8; CAN_FD_MAX_PAYLOAD],
}

impl<T: CanFdTransmit> CanFdSink<T> {
    /// Create a new CAN FD sink with the given transmitter and config
    pub fn new(tx: T, config: CanFdConfig) -> Self {
        Self {
            tx,
            config,
            buf: [0u8; CAN_FD_MAX_PAYLOAD],
        }
    }

    /// Get mutable access to the underlying transmitter
    pub fn transmitter_mut(&mut self) -> &mut T {
        &mut self.tx
    }
}

impl<T: CanFdTransmit> InterfaceSink for CanFdSink<T> {
    fn send_ty<B: Serialize>(&mut self, hdr: &HeaderSeq, body: &B) -> Result<(), ()> {
        if hdr.kind == FrameKind::PROTOCOL_ERROR {
            return Err(());
        }

        let (can_id, len) = encode_frame(hdr, body, self.config.default_priority, &mut self.buf)
            .map_err(|_| ())?;

        self.tx
            .transmit(can_id.to_raw(), &self.buf[..len])
            .map_err(|_| ())
    }

    fn send_raw(&mut self, hdr: &HeaderSeq, body: &[u8]) -> Result<(), ()> {
        if hdr.kind == FrameKind::PROTOCOL_ERROR {
            return Err(());
        }

        let (can_id, len) =
            encode_frame_raw(hdr, body, self.config.default_priority, &mut self.buf)
                .map_err(|_| ())?;

        self.tx
            .transmit(can_id.to_raw(), &self.buf[..len])
            .map_err(|_| ())
    }

    fn send_err(&mut self, hdr: &HeaderSeq, err: ProtocolError) -> Result<(), ()> {
        if hdr.kind != FrameKind::PROTOCOL_ERROR {
            return Err(());
        }

        let (can_id, len) =
            encode_frame_err(hdr, err, self.config.default_priority, &mut self.buf)
                .map_err(|_| ())?;

        self.tx
            .transmit(can_id.to_raw(), &self.buf[..len])
            .map_err(|_| ())
    }
}

/// Dummy transmitter for type signatures (not usable)
#[doc(hidden)]
pub struct DummyTransmit;

impl CanFdTransmit for DummyTransmit {
    type Error = ();

    fn transmit(&mut self, _id: u32, _data: &[u8]) -> Result<(), Self::Error> {
        Err(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_id_roundtrip() {
        let id = CanFrameId::new(
            CanPriority::High,
            42,  // dst_node
            123, // dst_port
            FrameKind::ENDPOINT_REQ,
        );

        assert_eq!(id.priority(), CanPriority::High);
        assert_eq!(id.dst_node_id(), 42);
        assert_eq!(id.dst_port_id(), 123);
        assert_eq!(id.frame_kind(), FrameKind::ENDPOINT_REQ);

        // Verify it fits in 29 bits
        assert!(id.to_raw() <= CanFrameId::MAX_EXTENDED_ID);
    }

    #[test]
    fn test_can_id_from_header() {
        let hdr = HeaderSeq {
            src: Address {
                network_id: 1,
                node_id: 10,
                port_id: 20,
            },
            dst: Address {
                network_id: 2,
                node_id: 30,
                port_id: 40,
            },
            any_all: None,
            seq_no: 0x1234,
            kind: FrameKind::TOPIC_MSG,
            ttl: 16,
        };

        let id = CanFrameId::from_header(&hdr);

        assert_eq!(id.dst_node_id(), 30);
        assert_eq!(id.dst_port_id(), 40);
        assert_eq!(id.frame_kind(), FrameKind::TOPIC_MSG);
        assert_eq!(id.priority(), CanPriority::Normal);
    }

    #[test]
    fn test_frame_kind_encoding() {
        // Test all frame kinds round-trip correctly
        for (kind, expected_bits) in [
            (FrameKind::RESERVED, 0),
            (FrameKind::ENDPOINT_REQ, 1),
            (FrameKind::ENDPOINT_RESP, 2),
            (FrameKind::TOPIC_MSG, 3),
            (FrameKind::PROTOCOL_ERROR, 7),
        ] {
            let id = CanFrameId::new(CanPriority::Normal, 0, 0, kind);
            assert_eq!(id.frame_kind(), kind, "Frame kind {:?} failed", kind);
            let bits = (id.to_raw() >> CanFrameId::KIND_SHIFT) & 0x7;
            assert_eq!(bits, expected_bits as u32);
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let hdr = HeaderSeq {
            src: Address {
                network_id: 100,
                node_id: 5,
                port_id: 10,
            },
            dst: Address {
                network_id: 200,
                node_id: 15,
                port_id: 20,
            },
            any_all: None,
            seq_no: 0xABCD,
            kind: FrameKind::ENDPOINT_REQ,
            ttl: 8,
        };

        let body: u32 = 0x12345678;
        let mut buf = [0u8; CAN_FD_MAX_PAYLOAD];

        let (can_id, len) = encode_frame(&hdr, &body, CanPriority::High, &mut buf).unwrap();

        // Decode
        let decoded = decode_frame(can_id, &buf[..len]).unwrap();

        assert_eq!(decoded.header.src, hdr.src);
        assert_eq!(decoded.header.dst, hdr.dst);
        assert_eq!(decoded.header.seq_no, hdr.seq_no);
        assert_eq!(decoded.header.kind, hdr.kind);
        assert_eq!(decoded.header.ttl, hdr.ttl);

        // Verify body
        let decoded_body: u32 = postcard::from_bytes(decoded.body.unwrap()).unwrap();
        assert_eq!(decoded_body, body);
    }

    #[test]
    fn test_priority_ordering() {
        // Lower CAN ID = higher priority in CAN arbitration
        let high = CanFrameId::new(CanPriority::Critical, 10, 10, FrameKind::ENDPOINT_REQ);
        let low = CanFrameId::new(CanPriority::Lowest, 10, 10, FrameKind::ENDPOINT_REQ);

        assert!(high.to_raw() < low.to_raw());
    }

    #[test]
    fn test_filter_masks() {
        // Create two IDs differing only in port
        let id1 = CanFrameId::new(CanPriority::Normal, 42, 1, FrameKind::ENDPOINT_REQ);
        let id2 = CanFrameId::new(CanPriority::Normal, 42, 2, FrameKind::ENDPOINT_REQ);

        // They should match with node-only mask
        let mask = CanFrameId::filter_mask_node_only();
        assert_eq!(id1.to_raw() & mask, id2.to_raw() & mask);

        // But differ with node+port mask
        let mask = CanFrameId::filter_mask_node_port();
        assert_ne!(id1.to_raw() & mask, id2.to_raw() & mask);
    }

    #[test]
    fn test_payload_size() {
        // Verify we can fit a reasonable payload after headers
        let hdr = HeaderSeq {
            src: Address {
                network_id: 0xFFFF,
                node_id: 0xFF,
                port_id: 0xFF,
            },
            dst: Address {
                network_id: 0xFFFF,
                node_id: 0xFF,
                port_id: 0xFF,
            },
            any_all: None,
            seq_no: 0xFFFF,
            kind: FrameKind::ENDPOINT_REQ,
            ttl: 0xFF,
        };

        let body: [u8; 32] = [0xAB; 32];
        let mut buf = [0u8; CAN_FD_MAX_PAYLOAD];

        let result = encode_frame_raw(&hdr, &body, CanPriority::Normal, &mut buf);

        // With worst-case header (no any/all), we should fit 32 bytes of body
        // Header: ~13 bytes worst case without any/all
        assert!(result.is_ok(), "Should fit 32-byte body with max header");
    }

    #[test]
    fn test_large_raw_payload_with_small_header() {
        // Regression test: encode_frame_raw should not reject valid payloads
        // that fit when the actual header is small (low network IDs, no any/all)
        let hdr = HeaderSeq {
            src: Address {
                network_id: 1,
                node_id: 2,
                port_id: 3,
            },
            dst: Address {
                network_id: 1,
                node_id: 4,
                port_id: 5,
            },
            any_all: None,
            seq_no: 100,
            kind: FrameKind::ENDPOINT_REQ,
            ttl: 16,
        };

        // With small addresses, header is ~7-8 bytes, so 50 bytes of body should fit
        let body: [u8; 50] = [0xCD; 50];
        let mut buf = [0u8; CAN_FD_MAX_PAYLOAD];

        let result = encode_frame_raw(&hdr, &body, CanPriority::Normal, &mut buf);
        assert!(
            result.is_ok(),
            "Should fit 50-byte body with minimal header, got {:?}",
            result
        );

        let (_, len) = result.unwrap();
        assert!(len <= CAN_FD_MAX_PAYLOAD);
        assert!(len >= 50); // At least the body size
    }
}
