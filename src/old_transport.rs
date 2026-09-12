//! Reliable UDP framing used by the 2001-era EQMac/TAKP client.

use crate::transport::Application;
use anyhow::{ensure, Result};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{SocketAddr, UdpSocket},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const MAX_APPLICATION: usize = 16 * 1024 * 1024;
const FRAGMENT_FIRST: usize = 510;
const FRAGMENT_NEXT: usize = 512;
const MAX_FRAGMENTS: usize = 1 + MAX_APPLICATION / FRAGMENT_NEXT;
const MAX_FRAGMENT_GROUPS: usize = 16;
const WINDOW: usize = 2048;

const A_ARQ: u8 = 1 << 1;
const A_CLOSING_1: u8 = 1 << 2;
const A_FRAGMENT: u8 = 1 << 3;
const A_ASQ: u8 = 1 << 4;
const A_SEQUENCE_START: u8 = 1 << 5;
const A_CLOSING_2: u8 = 1 << 6;
const B_ARSP: u8 = 1 << 2;
const B_RESEND_BEFORE: u8 = 1 << 3;

struct Pending {
    arq: u16,
    wire: Vec<u8>,
    sent: Instant,
    attempts: u8,
}

struct Fragment {
    opcode: Option<u16>,
    parts: Vec<Option<Vec<u8>>>,
}

struct Decoded {
    header_a: u8,
    arsp: Option<u16>,
    resend_before: Option<u16>,
    selective_ack: Vec<u8>,
    arq: Option<u16>,
    fragment: Option<(u16, u16, u16)>,
    opcode: Option<u16>,
    body: Vec<u8>,
}

/// One legacy EQ UDP stream. Unlike the later Daybreak stream, it begins with
/// an application packet and has no separate session negotiation datagram.
pub(crate) struct OldSession {
    socket: UdpSocket,
    next_sequence: u16,
    next_arq: u16,
    next_asq: u8,
    next_fragment: u16,
    sent_start: bool,
    last_received_arq: Option<u16>,
    ack_pending: bool,
    last_ack: Instant,
    reorder: HashMap<u16, Decoded>,
    pending: VecDeque<Pending>,
    fragments: HashMap<u16, Fragment>,
    applications: VecDeque<Application>,
    last_receive: Instant,
    closed: bool,
}

impl OldSession {
    /// Open a legacy stream to an EQMac login, world, or zone endpoint.
    pub(crate) fn connect_cancellable(address: SocketAddr, stop: &AtomicBool) -> Result<Self> {
        ensure!(!stop.load(Ordering::Relaxed), "shutdown requested");
        let socket = UdpSocket::bind(if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        socket.connect(address)?;
        socket.set_read_timeout(Some(Duration::from_millis(50)))?;
        Ok(Self {
            socket,
            next_sequence: 0,
            next_arq: 0,
            next_asq: 0,
            next_fragment: 0,
            sent_start: false,
            last_received_arq: None,
            ack_pending: false,
            last_ack: Instant::now(),
            reorder: HashMap::new(),
            pending: VecDeque::new(),
            fragments: HashMap::new(),
            applications: VecDeque::new(),
            last_receive: Instant::now(),
            closed: false,
        })
    }

    /// Return whole seconds since the last valid server datagram.
    pub(crate) fn last_received_seconds(&self) -> u64 {
        self.last_receive.elapsed().as_secs()
    }

    /// Send one reliable application packet, using EQMac's 510/512-byte fragments.
    pub(crate) fn send(&mut self, opcode: u16, body: &[u8]) -> Result<()> {
        ensure!(!self.closed, "session is closed");
        ensure!(body.len() <= MAX_APPLICATION, "application too large");
        if body.len() < FRAGMENT_NEXT {
            self.send_part(Some(opcode), body, None, true)?;
            return Ok(());
        }

        let total = 1 + body
            .len()
            .saturating_sub(FRAGMENT_FIRST)
            .div_ceil(FRAGMENT_NEXT);
        let total = u16::try_from(total)?;
        let fragment_id = self.next_fragment;
        self.next_fragment = self.next_fragment.wrapping_add(1);
        let mut offset = 0;
        for current in 0..total {
            let length = if current == 0 {
                FRAGMENT_FIRST
            } else {
                FRAGMENT_NEXT
            }
            .min(body.len() - offset);
            self.send_part(
                (current == 0).then_some(opcode),
                &body[offset..offset + length],
                Some((fragment_id, current, total)),
                current == 0,
            )?;
            offset += length;
        }
        Ok(())
    }

    fn send_part(
        &mut self,
        opcode: Option<u16>,
        body: &[u8],
        fragment: Option<(u16, u16, u16)>,
        include_asq: bool,
    ) -> Result<()> {
        ensure!(self.pending.len() < WINDOW, "outgoing reliable window full");
        let arq = self.next_arq;
        self.next_arq = self.next_arq.wrapping_add(1);
        let mut header_a = A_ARQ;
        if !self.sent_start {
            header_a |= A_SEQUENCE_START;
            self.sent_start = true;
        }
        if fragment.is_some() {
            header_a |= A_FRAGMENT;
        }
        if include_asq {
            header_a |= A_ASQ;
        }
        let wire = self.frame(header_a, Some(arq), fragment, opcode, body, include_asq);
        self.socket.send(&wire)?;
        self.pending.push_back(Pending {
            arq,
            wire,
            sent: Instant::now(),
            attempts: 1,
        });
        Ok(())
    }

    fn frame(
        &mut self,
        header_a: u8,
        arq: Option<u16>,
        fragment: Option<(u16, u16, u16)>,
        opcode: Option<u16>,
        body: &[u8],
        include_asq: bool,
    ) -> Vec<u8> {
        let arsp = self.ack_pending.then_some(self.last_received_arq).flatten();
        if arsp.is_some() {
            self.ack_pending = false;
            self.last_ack = Instant::now();
        }
        let mut wire = Vec::with_capacity(body.len() + 20);
        wire.push(header_a);
        wire.push(if arsp.is_some() { B_ARSP } else { 0 });
        wire.extend_from_slice(&self.next_sequence.to_be_bytes());
        self.next_sequence = self.next_sequence.wrapping_add(1);
        if let Some(arsp) = arsp {
            wire.extend_from_slice(&arsp.to_be_bytes());
        }
        if let Some(arq) = arq {
            wire.extend_from_slice(&arq.to_be_bytes());
        }
        if let Some((sequence, current, total)) = fragment {
            wire.extend_from_slice(&sequence.to_be_bytes());
            wire.extend_from_slice(&current.to_be_bytes());
            wire.extend_from_slice(&total.to_be_bytes());
        }
        if include_asq {
            wire.extend_from_slice(&[0, self.next_asq]);
            self.next_asq = self.next_asq.wrapping_add(1);
        }
        if let Some(opcode) = opcode {
            wire.extend_from_slice(&opcode.to_be_bytes());
        }
        if opcode.is_some() || fragment.is_some() {
            wire.extend_from_slice(body);
        }
        let crc = crc32fast::hash(&wire);
        wire.extend_from_slice(&crc.to_be_bytes());
        wire
    }

    /// Drive acknowledgements and retransmits, returning the next application packet.
    pub(crate) fn receive(&mut self) -> Result<Option<Application>> {
        if let Some(application) = self.applications.pop_front() {
            return Ok(Some(application));
        }
        ensure!(!self.closed, "server closed session");

        if self.ack_pending && self.last_ack.elapsed() >= Duration::from_millis(100) {
            self.send_ack()?;
        }
        for pending in &mut self.pending {
            if pending.sent.elapsed() >= Duration::from_secs(3) {
                ensure!(pending.attempts < 10, "server did not acknowledge a packet");
                self.socket.send(&pending.wire)?;
                pending.sent = Instant::now();
                pending.attempts += 1;
            }
        }
        ensure!(
            self.last_receive.elapsed() < Duration::from_secs(60),
            "server stopped responding"
        );

        let mut wire = [0; 65536];
        match self.socket.recv(&mut wire) {
            Ok(length) => {
                let packet = decode(&wire[..length])?;
                self.last_receive = Instant::now();
                self.process(packet)?;
            }
            Err(error) if timed_out(&error) => (),
            Err(error) => return Err(error.into()),
        }
        Ok(self.applications.pop_front())
    }

    fn send_ack(&mut self) -> Result<()> {
        let wire = self.frame(0, None, None, None, &[], false);
        self.socket.send(&wire)?;
        Ok(())
    }

    fn process(&mut self, packet: Decoded) -> Result<()> {
        if let Some(arsp) = packet.arsp {
            self.acknowledge(arsp);
        }
        if let Some(before) = packet.resend_before {
            for pending in &mut self.pending {
                if before.wrapping_sub(pending.arq) < 32768 {
                    pending.sent = Instant::now()
                        .checked_sub(Duration::from_secs(3))
                        .unwrap_or_else(Instant::now);
                }
            }
        }
        if !packet.selective_ack.is_empty() {
            // The legacy bit field describes packets after ARSP. One retires
            // that packet; zero requests retransmission of that packet.
            let start = packet.arsp.unwrap_or(0).wrapping_add(1);
            for (byte_index, byte) in packet.selective_ack.iter().enumerate() {
                for bit in 0..8 {
                    let arq = start.wrapping_add((byte_index * 8 + bit) as u16);
                    if byte & (0x80 >> bit) != 0 {
                        self.pending.retain(|pending| pending.arq != arq);
                    } else {
                        if let Some(pending) = self.pending.iter_mut().find(|p| p.arq == arq) {
                            pending.sent = Instant::now()
                                .checked_sub(Duration::from_secs(3))
                                .unwrap_or_else(Instant::now);
                        }
                    }
                }
            }
        }
        if packet.header_a & (A_CLOSING_1 | A_CLOSING_2) == (A_CLOSING_1 | A_CLOSING_2) {
            self.closed = true;
            return Ok(());
        }

        let Some(arq) = packet.arq else {
            return self.deliver(packet);
        };
        if packet.header_a & A_SEQUENCE_START != 0 {
            if self.last_received_arq.is_some() {
                self.reorder.clear();
            }
            self.last_received_arq = Some(arq.wrapping_sub(1));
        } else if self.last_received_arq.is_none() {
            if arq == 0 {
                self.last_received_arq = Some(u16::MAX);
            } else {
                ensure!(
                    self.reorder.len() < WINDOW,
                    "incoming reliable window exceeded"
                );
                self.reorder.entry(arq).or_insert(packet);
                return Ok(());
            }
        }
        if let Some(last) = self.last_received_arq {
            let expected = last.wrapping_add(1);
            let distance = arq.wrapping_sub(expected);
            if distance >= 32768 {
                self.ack_pending = true;
                return Ok(());
            }
            ensure!(
                distance < WINDOW as u16,
                "incoming reliable window exceeded"
            );
            if distance > 0 {
                self.reorder.entry(arq).or_insert(packet);
                return Ok(());
            }
        }
        self.accept(arq, packet)?;
        while let Some(last) = self.last_received_arq {
            let expected = last.wrapping_add(1);
            let Some(packet) = self.reorder.remove(&expected) else {
                break;
            };
            self.accept(expected, packet)?;
        }
        Ok(())
    }

    fn accept(&mut self, arq: u16, packet: Decoded) -> Result<()> {
        self.last_received_arq = Some(arq);
        self.ack_pending = true;
        self.deliver(packet)
    }

    fn deliver(&mut self, packet: Decoded) -> Result<()> {
        let Some((sequence, current, total)) = packet.fragment else {
            if let Some(opcode) = packet.opcode {
                self.applications.push_back(Application {
                    opcode,
                    body: packet.body,
                });
            }
            return Ok(());
        };
        ensure!(total > 0 && current < total, "invalid fragment indexes");
        ensure!(
            usize::from(total) <= MAX_FRAGMENTS,
            "fragment count exceeds application limit"
        );
        if !self.fragments.contains_key(&sequence) {
            ensure!(
                self.fragments.len() < MAX_FRAGMENT_GROUPS,
                "too many fragment groups"
            );
        }
        let fragment = self.fragments.entry(sequence).or_insert_with(|| Fragment {
            opcode: None,
            parts: vec![None; total as usize],
        });
        ensure!(
            fragment.parts.len() == total as usize,
            "fragment count changed"
        );
        if packet.opcode.is_some() {
            fragment.opcode = packet.opcode;
        }
        fragment.parts[current as usize] = Some(packet.body);
        if fragment.opcode.is_some() && fragment.parts.iter().all(Option::is_some) {
            let mut fragment = self.fragments.remove(&sequence).unwrap();
            let mut body = Vec::new();
            for part in &mut fragment.parts {
                body.extend(part.take().unwrap());
            }
            ensure!(
                body.len() <= MAX_APPLICATION,
                "reassembled application too large"
            );
            self.applications.push_back(Application {
                opcode: fragment.opcode.unwrap(),
                body,
            });
        }
        Ok(())
    }

    fn acknowledge(&mut self, arsp: u16) {
        while self
            .pending
            .front()
            .is_some_and(|pending| arsp.wrapping_sub(pending.arq) < 32768)
        {
            self.pending.pop_front();
        }
    }

    /// Send the legacy closing flags once.
    pub(crate) fn close(&mut self) -> Result<()> {
        if !self.closed {
            let arq = self.next_arq;
            self.next_arq = self.next_arq.wrapping_add(1);
            let wire = self.frame(
                A_CLOSING_1 | A_CLOSING_2 | A_ARQ,
                Some(arq),
                None,
                None,
                &[],
                false,
            );
            self.socket.send(&wire)?;
            self.closed = true;
        }
        Ok(())
    }
}

impl Drop for OldSession {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn decode(wire: &[u8]) -> Result<Decoded> {
    ensure!(wire.len() >= 10, "truncated legacy datagram");
    let payload_end = wire.len() - 4;
    let expected = u32::from_be_bytes(wire[payload_end..].try_into().unwrap());
    ensure!(
        crc32fast::hash(&wire[..payload_end]) == expected,
        "invalid legacy CRC"
    );

    let header_a = wire[0];
    let header_b = wire[1];
    let mut position = 4; // two header bytes and the global sequence
    let arsp = if header_b & B_ARSP != 0 {
        Some(take_word(wire, &mut position, payload_end)?)
    } else {
        None
    };
    let resend_before = if header_b & B_RESEND_BEFORE != 0 {
        Some(take_word(wire, &mut position, payload_end)?)
    } else {
        None
    };
    let selective_length = usize::from(header_b >> 4);
    ensure!(
        position + selective_length <= payload_end,
        "truncated selective ACK"
    );
    let selective_ack = wire[position..position + selective_length].to_vec();
    position += selective_length;
    let arq = if header_a & A_ARQ != 0 {
        Some(take_word(wire, &mut position, payload_end)?)
    } else {
        None
    };
    let fragment = if header_a & A_FRAGMENT != 0 {
        Some((
            take_word(wire, &mut position, payload_end)?,
            take_word(wire, &mut position, payload_end)?,
            take_word(wire, &mut position, payload_end)?,
        ))
    } else {
        None
    };
    if header_a & A_ASQ != 0 {
        let length = if header_a & A_ARQ != 0 { 2 } else { 1 };
        ensure!(position + length <= payload_end, "truncated ASQ");
        position += length;
    }
    let has_application = payload_end.saturating_sub(position) > 0
        && header_a & (A_CLOSING_1 | A_CLOSING_2) != (A_CLOSING_1 | A_CLOSING_2);
    let opcode = if has_application && fragment.is_none_or(|(_, current, _)| current == 0) {
        Some(take_word(wire, &mut position, payload_end)?)
    } else {
        None
    };
    Ok(Decoded {
        header_a,
        arsp,
        resend_before,
        selective_ack,
        arq,
        fragment,
        opcode,
        body: wire[position..payload_end].to_vec(),
    })
}

fn take_word(wire: &[u8], position: &mut usize, end: usize) -> Result<u16> {
    ensure!(*position + 2 <= end, "truncated legacy header");
    let value = u16::from_be_bytes(wire[*position..*position + 2].try_into().unwrap());
    *position += 2;
    Ok(value)
}

fn timed_out(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> (OldSession, UdpSocket) {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let session =
            OldSession::connect_cancellable(peer.local_addr().unwrap(), &AtomicBool::new(false))
                .unwrap();
        (session, peer)
    }

    #[test]
    fn first_application_uses_old_stream_flags_byte_order_and_crc() {
        let (mut session, peer) = session();
        session.send(0x5900, &[]).unwrap();
        let mut wire = [0; 64];
        let length = peer.recv(&mut wire).unwrap();
        assert_eq!(length, 14);
        assert_eq!(
            &wire[..length],
            &[0x32, 0, 0, 0, 0, 0, 0, 0, 0x59, 0, 0xe4, 0xf5, 0xdc, 0x6e]
        );
        let decoded = decode(&wire[..length]).unwrap();
        assert_eq!(decoded.opcode, Some(0x5900));
        assert_eq!(decoded.arq, Some(0));
    }

    #[test]
    fn fragmented_application_reassembles_after_reordering() {
        let (mut sender, peer) = session();
        let body: Vec<_> = (0..=u8::MAX).cycle().take(1300).collect();
        sender.send(0x3640, &body).unwrap();
        let mut wires = Vec::new();
        for _ in 0..3 {
            let mut wire = vec![0; 1024];
            let length = peer.recv(&mut wire).unwrap();
            wire.truncate(length);
            wires.push(wire);
        }

        let (mut receiver, _unused) = session();
        assert_eq!(decode(&wires[0]).unwrap().fragment, Some((0, 0, 3)));
        assert_eq!(decode(&wires[1]).unwrap().fragment, Some((0, 1, 3)));
        assert_eq!(decode(&wires[2]).unwrap().fragment, Some((0, 2, 3)));
        for index in [1, 0, 2] {
            receiver.process(decode(&wires[index]).unwrap()).unwrap();
        }
        let application = receiver.applications.pop_front().unwrap();
        assert_eq!(application.opcode, 0x3640);
        assert_eq!(application.body.len(), body.len());
        assert_eq!(application.body, body);
    }

    #[test]
    fn acknowledgment_removes_every_prior_reliable_packet() {
        let (mut session, _peer) = session();
        session.send(0x5900, &[]).unwrap();
        session.send(0x0100, &[0; 40]).unwrap();
        assert_eq!(session.pending.len(), 2);
        session.acknowledge(1);
        assert!(session.pending.is_empty());
    }

    #[test]
    fn selective_ack_retires_set_bits_and_retries_clear_bits() {
        let (mut session, _peer) = session();
        for opcode in [0x5900, 0x0100, 0x8800] {
            session.send(opcode, &[]).unwrap();
        }
        let third_sent = session.pending[2].sent;
        session
            .process(Decoded {
                header_a: 0,
                arsp: Some(0),
                resend_before: None,
                selective_ack: vec![0x80],
                arq: None,
                fragment: None,
                opcode: None,
                body: Vec::new(),
            })
            .unwrap();
        assert_eq!(session.pending.len(), 1);
        assert_eq!(session.pending[0].arq, 2);
        assert!(session.pending[0].sent < third_sent);
    }

    #[test]
    fn server_style_stream_can_start_at_arq_zero_without_sequence_start() {
        let (mut sender, peer) = session();
        sender.sent_start = true;
        sender.send(0xdd41, b"Welcome\0").unwrap();
        let mut wire = [0; 64];
        let length = peer.recv(&mut wire).unwrap();
        assert_eq!(wire[0] & A_SEQUENCE_START, 0);

        let (mut receiver, _unused) = session();
        receiver.process(decode(&wire[..length]).unwrap()).unwrap();
        let application = receiver.applications.pop_front().unwrap();
        assert_eq!(application.opcode, 0xdd41);
        assert_eq!(application.body, b"Welcome\0");
    }
}
