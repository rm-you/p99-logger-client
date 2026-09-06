use anyhow::{bail, ensure, Result};
use std::{
    cell::Cell,
    collections::{HashMap, VecDeque},
    io,
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

const MAX_APPLICATION: usize = 16 * 1024 * 1024;
const WINDOW: u16 = 2048;

/// A fully reassembled application packet from an EQ UDP session.
#[derive(Debug)]
pub struct Application {
    pub opcode: u16,
    pub body: Vec<u8>,
}

struct Pending {
    sequence: u16,
    packet: Vec<u8>,
    sent: Instant,
    attempts: u8,
}

/// One independent, reliable EQ UDP session. Sequence numbers and CRC state
/// belong to this socket and are discarded on world/zone transitions.
pub struct Session {
    socket: UdpSocket,
    id: u32,
    crc_seed: u32,
    crc_bytes: usize,
    compression: bool,
    max_datagram: usize,
    next_send: u16,
    next_receive: u16,
    ack_pending: bool,
    last_ack: Instant,
    reorder: HashMap<u16, (u16, Vec<u8>)>,
    pending: VecDeque<Pending>,
    fragment: Option<(usize, Vec<u8>)>,
    applications: VecDeque<Application>,
    last_receive: Instant,
    started: Instant,
    next_stats: Instant,
    stats_request: Option<(u16, Instant)>,
    rtt: u32,
    rtt_min: u32,
    rtt_max: u32,
    rtt_sum: u64,
    rtt_count: u64,
    sent_count: Cell<u64>,
    received_count: u64,
    closed: bool,
}

impl Session {
    /// Return the local UDP address selected for this session.
    pub fn local_address(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
    /// Return whole seconds since the last valid server datagram.
    pub fn last_received_seconds(&self) -> u64 {
        self.last_receive.elapsed().as_secs()
    }
    /// Negotiate a new reliable EQ UDP session with the remote endpoint.
    pub fn connect(address: SocketAddr, echo_response: bool) -> Result<Self> {
        let socket = UdpSocket::bind(if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        socket.connect(address)?;
        socket.set_read_timeout(Some(Duration::from_millis(50)))?;
        let id = rand::random::<u32>();
        let mut request = vec![0, 1];
        request.extend_from_slice(&2u32.to_be_bytes());
        request.extend_from_slice(&id.to_be_bytes());
        request.extend_from_slice(&512u32.to_be_bytes());
        let mut buffer = vec![0; 65536];
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut last_send: Option<Instant> = None;
        loop {
            ensure!(
                Instant::now() < deadline,
                "UDP session negotiation timed out"
            );
            if last_send.is_none_or(|sent| sent.elapsed() >= Duration::from_secs(1)) {
                socket.send(&request)?;
                last_send = Some(Instant::now());
            }
            let n = match socket.recv(&mut buffer) {
                Ok(n) => n,
                Err(e) if timed_out(&e) => continue,
                Err(e) => return Err(e.into()),
            };
            if n < 17 || buffer[..2] != [0, 2] || be32(&buffer[2..6]) != id {
                continue;
            }
            let crc_bytes = buffer[10] as usize;
            ensure!(crc_bytes <= 4, "unsupported CRC size");
            ensure!(
                buffer[11] <= 1 && buffer[12] == 0,
                "unsupported UDP encoding negotiation"
            );
            let max_datagram = be32(&buffer[13..17]) as usize;
            ensure!(
                (64..=65507).contains(&max_datagram),
                "invalid negotiated datagram size"
            );
            if echo_response {
                socket.send(&buffer[..n])?;
            }
            return Ok(Self {
                socket,
                id,
                crc_seed: be32(&buffer[6..10]),
                crc_bytes,
                compression: buffer[11] == 1,
                max_datagram,
                next_send: 0,
                next_receive: 0,
                ack_pending: false,
                last_ack: Instant::now(),
                reorder: HashMap::new(),
                pending: VecDeque::new(),
                fragment: None,
                applications: VecDeque::new(),
                last_receive: Instant::now(),
                started: Instant::now(),
                next_stats: Instant::now() + Duration::from_secs(10),
                stats_request: None,
                rtt: 0,
                rtt_min: 0,
                rtt_max: 0,
                rtt_sum: 0,
                rtt_count: 0,
                sent_count: Cell::new(1 + u64::from(echo_response)),
                received_count: 1,
                closed: false,
            });
        }
    }

    fn datagram(&self, opcode: u16, body: &[u8]) -> Vec<u8> {
        let mut packet = opcode.to_be_bytes().to_vec();
        if self.compression {
            let compressed = miniz_oxide::deflate::compress_to_vec_zlib(body, 6);
            if compressed.len() < body.len() {
                packet.push(0x5a);
                packet.extend(compressed);
            } else {
                packet.push(0xa5);
                packet.extend_from_slice(body);
            }
        } else {
            packet.extend_from_slice(body);
        }
        let crc = checksum(self.crc_seed, &packet).to_be_bytes();
        packet.extend_from_slice(&crc[4 - self.crc_bytes..]);
        packet
    }

    fn control(&self, opcode: u16, body: &[u8]) -> Result<()> {
        self.socket.send(&self.datagram(opcode, body))?;
        self.sent_count.set(self.sent_count.get() + 1);
        Ok(())
    }

    /// Send one reliable application packet, fragmenting it when necessary.
    pub fn send(&mut self, opcode: u16, body: &[u8]) -> Result<()> {
        ensure!(!self.closed, "session is closed");
        ensure!(body.len() <= MAX_APPLICATION - 3, "application too large");
        let mut application = Vec::with_capacity(body.len() + 3);
        if opcode & 0xff == 0 {
            application.push(0);
        }
        application.extend_from_slice(&opcode.to_le_bytes());
        application.extend_from_slice(body);
        let capacity = self.max_datagram - 4 - self.crc_bytes - usize::from(self.compression);
        if application.len() <= capacity {
            self.reliable(9, &application)?;
        } else {
            let mut first = u32::try_from(application.len())?.to_be_bytes().to_vec();
            first.extend_from_slice(&application[..capacity - 4]);
            self.reliable(13, &first)?;
            for part in application[capacity - 4..].chunks(capacity) {
                self.reliable(13, part)?;
            }
        }
        Ok(())
    }

    /// Send an unsequenced application packet, used for position heartbeats.
    pub fn send_unreliable(&self, opcode: u16, body: &[u8]) -> Result<()> {
        ensure!(
            opcode & 0xff != 0,
            "unreliable opcode requires nonzero low byte"
        );
        let op = opcode.to_le_bytes();
        let mut packet = vec![op[0]];
        let mut rest = vec![op[1]];
        rest.extend_from_slice(body);
        if self.compression {
            packet.push(0x5a);
            packet.extend(miniz_oxide::deflate::compress_to_vec_zlib(&rest, 6));
        } else {
            packet.extend(rest);
        }
        let crc = checksum(self.crc_seed, &packet).to_be_bytes();
        packet.extend_from_slice(&crc[4 - self.crc_bytes..]);
        ensure!(
            packet.len() <= self.max_datagram,
            "unreliable packet exceeds datagram limit"
        );
        self.socket.send(&packet)?;
        self.sent_count.set(self.sent_count.get() + 1);
        Ok(())
    }

    fn reliable(&mut self, opcode: u16, body: &[u8]) -> Result<()> {
        ensure!(
            self.pending.len() < WINDOW as usize,
            "outgoing reliable window full"
        );
        let sequence = self.next_send;
        let mut framed = sequence.to_be_bytes().to_vec();
        framed.extend_from_slice(body);
        let packet = self.datagram(opcode, &framed);
        self.socket.send(&packet)?;
        self.sent_count.set(self.sent_count.get() + 1);
        self.pending.push_back(Pending {
            sequence,
            packet,
            sent: Instant::now(),
            attempts: 1,
        });
        self.next_send = sequence.wrapping_add(1);
        Ok(())
    }

    /// Drive retransmits and acknowledgements, returning the next full packet.
    pub fn receive(&mut self) -> Result<Option<Application>> {
        if self.ack_pending && self.last_ack.elapsed() >= Duration::from_millis(100) {
            self.control(0x15, &self.next_receive.wrapping_sub(1).to_be_bytes())?;
            self.ack_pending = false;
            self.last_ack = Instant::now();
        }
        if let Some(application) = self.applications.pop_front() {
            return Ok(Some(application));
        }
        ensure!(!self.closed, "server closed session");
        for pending in &mut self.pending {
            if pending.sent.elapsed() >= Duration::from_secs(1) {
                ensure!(
                    pending.attempts < 15,
                    "server did not acknowledge a reliable packet"
                );
                self.socket.send(&pending.packet)?;
                self.sent_count.set(self.sent_count.get() + 1);
                pending.sent = Instant::now();
                pending.attempts += 1;
            }
        }
        ensure!(
            self.last_receive.elapsed() < Duration::from_secs(60),
            "server stopped responding"
        );
        if Instant::now() >= self.next_stats {
            let token =
                u16::try_from(self.started.elapsed().as_millis() % (u128::from(u16::MAX) + 1))?;
            let mut stats = token.to_be_bytes().to_vec();
            let average = u32::try_from(self.rtt_sum.checked_div(self.rtt_count).unwrap_or(0))
                .unwrap_or(u32::MAX);
            for value in [self.rtt, average, self.rtt_min, self.rtt_max, self.rtt] {
                stats.extend_from_slice(&value.to_be_bytes());
            }
            stats.extend_from_slice(&self.sent_count.get().to_be_bytes());
            stats.extend_from_slice(&self.received_count.to_be_bytes());
            self.control(7, &stats)?;
            self.stats_request = Some((token, Instant::now()));
            self.next_stats = Instant::now() + Duration::from_secs(30);
        }
        let mut packet = vec![0; 65536];
        match self.socket.recv(&mut packet) {
            Ok(n) => {
                self.received_count += 1;
                if n < 2 + self.crc_bytes {
                    return Ok(None);
                }
                if packet[..2] == [0, 2] {
                    return Ok(None);
                }
                let end = n - self.crc_bytes;
                let expected = checksum(self.crc_seed, &packet[..end]).to_be_bytes();
                if packet[end..n] != expected[4 - self.crc_bytes..] {
                    return Ok(None);
                }
                self.last_receive = Instant::now();
                self.process(&packet[..end], false, 0)?;
            }
            Err(e) if timed_out(&e) => (),
            Err(e) => return Err(e.into()),
        }
        Ok(self.applications.pop_front())
    }

    fn process(&mut self, packet: &[u8], nested: bool, depth: usize) -> Result<()> {
        ensure!(
            depth < 8 && packet.len() >= 2,
            "invalid nested transport packet"
        );
        if packet[0] != 0 {
            let mut application = vec![packet[0]];
            if !nested && self.compression {
                match packet[1] {
                    0xa5 => application.extend_from_slice(&packet[2..]),
                    0x5a => application.extend(
                        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(
                            &packet[2..],
                            MAX_APPLICATION,
                        )
                        .map_err(|_| anyhow::anyhow!("invalid compressed raw application"))?,
                    ),
                    _ => bail!("unsupported raw application encoding"),
                }
            } else {
                application.extend_from_slice(&packet[1..]);
            }
            return self.application(&application, depth + 1);
        }
        let opcode = u16::from_be_bytes(packet[..2].try_into().unwrap());
        let decompressed;
        let mut body = &packet[2..];
        if !nested && self.compression {
            ensure!(!body.is_empty(), "missing compression marker");
            match body[0] {
                0xa5 => body = &body[1..],
                0x5a => {
                    decompressed = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(
                        &body[1..],
                        MAX_APPLICATION,
                    )
                    .map_err(|_| anyhow::anyhow!("invalid compressed packet"))?;
                    body = &decompressed;
                }
                _ => bail!("unsupported compression marker"),
            }
        }
        match opcode {
            3 => {
                for part in split_combined(body)? {
                    self.process(part, true, depth + 1)?;
                }
            }
            0x19 => {
                for part in split_combined(body)? {
                    self.application(part, depth + 1)?;
                }
            }
            9 | 13 => {
                ensure!(body.len() >= 2, "missing reliable sequence");
                let sequence = u16::from_be_bytes(body[..2].try_into().unwrap());
                let distance = sequence.wrapping_sub(self.next_receive);
                if distance >= 32768 {
                    self.ack_pending = true;
                    return Ok(());
                }
                ensure!(distance < WINDOW, "incoming reliable window exceeded");
                self.reorder
                    .entry(sequence)
                    .or_insert_with(|| (opcode, body[2..].to_vec()));
                while let Some((op, part)) = self.reorder.remove(&self.next_receive) {
                    self.ordered(op, &part)?;
                    self.next_receive = self.next_receive.wrapping_add(1);
                }
                if distance > 0 {
                    self.control(0x11, &sequence.to_be_bytes())?;
                }
                // A single cumulative acknowledgment covers a burst, including
                // all reliable subpackets in a combined datagram.
                self.ack_pending = true;
            }
            0x15 => {
                ensure!(body.len() == 2, "invalid cumulative acknowledgment");
                let ack = u16::from_be_bytes(body.try_into().unwrap());
                if self.pending.iter().any(|p| p.sequence == ack) {
                    while let Some(pending) = self.pending.pop_front() {
                        if pending.sequence == ack {
                            break;
                        }
                    }
                }
            }
            0x11 => {
                ensure!(body.len() == 2, "invalid out-of-order acknowledgment");
                let seen = u16::from_be_bytes(body.try_into().unwrap());
                for pending in &mut self.pending {
                    if seen.wrapping_sub(pending.sequence) < WINDOW {
                        self.socket.send(&pending.packet)?;
                        self.sent_count.set(self.sent_count.get() + 1);
                        pending.sent = Instant::now();
                    }
                }
            }
            5 => self.closed = true,
            6 => (),
            8 => {
                ensure!(body.len() == 38, "invalid session statistics response");
                if let Some((token, sent)) = self.stats_request {
                    if body[..2] == token.to_be_bytes() {
                        self.rtt = u32::try_from(sent.elapsed().as_millis()).unwrap_or(u32::MAX);
                        self.rtt_min = if self.rtt_count == 0 {
                            self.rtt
                        } else {
                            self.rtt_min.min(self.rtt)
                        };
                        self.rtt_max = self.rtt_max.max(self.rtt);
                        self.rtt_sum += u64::from(self.rtt);
                        self.rtt_count += 1;
                        self.stats_request = None;
                    }
                }
            }
            7 => {
                ensure!(body.len() == 38, "invalid session statistics request");
                let mut reply = body[..2].to_vec();
                let elapsed = u32::try_from(self.started.elapsed().as_millis()).unwrap_or(u32::MAX);
                reply.extend_from_slice(&elapsed.to_be_bytes());
                reply.extend_from_slice(&body[22..38]);
                reply.extend_from_slice(&self.sent_count.get().to_be_bytes());
                reply.extend_from_slice(&self.received_count.to_be_bytes());
                self.control(8, &reply)?;
            }
            _ => (),
        }
        Ok(())
    }

    fn ordered(&mut self, opcode: u16, body: &[u8]) -> Result<()> {
        if opcode == 9 {
            ensure!(
                self.fragment.is_none(),
                "ordinary packet interrupted fragment assembly"
            );
            return self.application(body, 0);
        }
        if let Some((size, collected)) = &mut self.fragment {
            ensure!(
                collected.len() + body.len() <= *size,
                "fragment exceeds declared size"
            );
            collected.extend_from_slice(body);
        } else {
            ensure!(body.len() >= 4, "missing fragment length");
            let size = be32(&body[..4]) as usize;
            ensure!(
                (2..=MAX_APPLICATION).contains(&size) && body.len() - 4 <= size,
                "invalid fragment size"
            );
            self.fragment = Some((size, body[4..].to_vec()));
        }
        if self
            .fragment
            .as_ref()
            .is_some_and(|(size, data)| *size == data.len())
        {
            let (_, data) = self.fragment.take().unwrap();
            self.application(&data, 0)?;
        }
        Ok(())
    }

    fn application(&mut self, mut bytes: &[u8], depth: usize) -> Result<()> {
        ensure!(
            depth < 8 && bytes.len() >= 2,
            "invalid nested application packet"
        );
        if bytes[..2] == [0, 0x19] {
            for part in split_combined(&bytes[2..])? {
                self.application(part, depth + 1)?;
            }
            return Ok(());
        }
        if bytes[0] == 0 {
            bytes = &bytes[1..];
        }
        ensure!(bytes.len() >= 2, "truncated escaped application opcode");
        self.applications.push_back(Application {
            opcode: u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            body: bytes[2..].to_vec(),
        });
        Ok(())
    }

    /// Send the session disconnect control packet once.
    pub fn close(&mut self) -> Result<()> {
        if !self.closed {
            self.control(5, &self.id.to_be_bytes())?;
            self.closed = true;
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn timed_out(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.try_into().unwrap())
}
fn checksum(seed: u32, packet: &[u8]) -> u32 {
    let mut hash = crc32fast::Hasher::new();
    hash.update(&seed.to_le_bytes());
    hash.update(packet);
    hash.finalize()
}

fn split_combined(mut bytes: &[u8]) -> Result<Vec<&[u8]>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let mut length = bytes[0] as usize;
        bytes = &bytes[1..];
        if length == 255 {
            ensure!(bytes.len() >= 2, "truncated combined length");
            length = u16::from_be_bytes(bytes[..2].try_into().unwrap()) as usize;
            bytes = &bytes[2..];
        }
        ensure!(
            length > 0 && length <= bytes.len(),
            "invalid combined length"
        );
        result.push(&bytes[..length]);
        bytes = &bytes[length..];
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> (Session, UdpSocket) {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(peer.local_addr().unwrap()).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        (
            Session {
                socket,
                id: 7,
                crc_seed: 0x1122_3344,
                crc_bytes: 2,
                compression: true,
                max_datagram: 512,
                next_send: 0,
                next_receive: 0,
                ack_pending: false,
                last_ack: Instant::now(),
                reorder: HashMap::new(),
                pending: VecDeque::new(),
                fragment: None,
                applications: VecDeque::new(),
                last_receive: Instant::now(),
                started: Instant::now(),
                next_stats: Instant::now() + Duration::from_secs(10),
                stats_request: None,
                rtt: 0,
                rtt_min: 0,
                rtt_max: 0,
                rtt_sum: 0,
                rtt_count: 0,
                sent_count: Cell::new(0),
                received_count: 0,
                closed: false,
            },
            peer,
        )
    }

    fn packet(session: &Session, op: u16, seq: u16, body: &[u8]) -> Vec<u8> {
        let mut data = seq.to_be_bytes().to_vec();
        data.extend_from_slice(body);
        session.datagram(op, &data)
    }

    #[test]
    fn reordered_fragments_cross_sequence_wrap_once() {
        let (mut session, _peer) = session();
        session.next_receive = 65534;
        let mut first = 6u32.to_be_bytes().to_vec();
        first.extend_from_slice(&[4, 16]);
        for (seq, data) in [(0, &b"!"[..]), (65534, &first), (65535, &b"hey"[..])] {
            let frame = packet(&session, 13, seq, data);
            session
                .process(&frame[..frame.len() - 2], false, 0)
                .unwrap();
        }
        assert_eq!(session.next_receive, 1);
        let chat = session.applications.pop_front().unwrap();
        assert_eq!((chat.opcode, chat.body), (0x1004, b"hey!".to_vec()));
        let duplicate = packet(&session, 13, 0, b"!");
        session
            .process(&duplicate[..duplicate.len() - 2], false, 0)
            .unwrap();
        assert!(session.applications.is_empty());
        assert!(session.reorder.is_empty());
    }

    #[test]
    fn damaged_datagram_is_discarded_then_retransmission_delivered() {
        let (mut session, peer) = session();
        let frame = packet(&session, 9, 0, b"\x04\x10hello");
        let mut damaged = frame.clone();
        damaged[5] ^= 0x80;
        peer.send_to(&damaged, session.socket.local_addr().unwrap())
            .unwrap();
        assert!(session.receive().unwrap().is_none());
        peer.send_to(&frame, session.socket.local_addr().unwrap())
            .unwrap();
        assert_eq!(session.receive().unwrap().unwrap().body, b"hello");
    }

    #[test]
    fn outgoing_fragment_sizes_and_cumulative_ack() {
        let (mut session, _peer) = session();
        let body: Vec<u8> = (0..=u8::MAX).cycle().take(2056).collect();
        session.send(0x5072, &body).unwrap();
        assert_eq!(session.pending.len(), 5);
        assert!(session.pending.iter().all(|p| p.packet.len() <= 512));
        let frames: Vec<_> = session.pending.iter().map(|p| p.packet.clone()).collect();
        for frame in frames {
            session
                .process(&frame[..frame.len() - 2], false, 0)
                .unwrap();
        }
        assert_eq!(session.applications.pop_front().unwrap().body, body);
        let ack = session.datagram(0x15, &4u16.to_be_bytes());
        session.process(&ack[..ack.len() - 2], false, 0).unwrap();
        assert!(session.pending.is_empty());
    }

    #[test]
    fn raw_position_packet_uses_marker_between_opcode_bytes() {
        let (mut session, peer) = session();
        let position = [0; 36];
        session.send_unreliable(0x14cb, &position).unwrap();
        let mut bytes = [0; 512];
        let n = peer.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..2], &[0xcb, 0x5a]);
        assert!(n < 41);
        peer.send_to(&bytes[..n], session.socket.local_addr().unwrap())
            .unwrap();
        let packet = session.receive().unwrap().unwrap();
        assert_eq!(packet.opcode, 0x14cb);
        assert_eq!(packet.body, position);
    }

    #[test]
    fn reliable_burst_gets_one_cumulative_ack() {
        let (mut session, peer) = session();
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        for sequence in 0..200 {
            let frame = packet(&session, 9, sequence, b"\x04\x10hello");
            session
                .process(&frame[..frame.len() - 2], false, 0)
                .unwrap();
        }
        let mut wire = [0; 512];
        assert!(
            peer.recv(&mut wire).is_err(),
            "burst must not ACK each packet"
        );
        session.last_ack = Instant::now()
            .checked_sub(Duration::from_millis(100))
            .unwrap();
        assert!(session.receive().unwrap().is_some());
        let n = peer.recv(&mut wire).unwrap();
        assert_eq!(&wire[..n], session.datagram(0x15, &199u16.to_be_bytes()));
        assert!(!session.ack_pending);
    }
}
