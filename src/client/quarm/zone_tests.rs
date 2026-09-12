//! Synthetic zone peer: no login service, accounts, or captured packets.
use super::*;
use std::{net::UdpSocket, panic::AssertUnwindSafe, thread};

struct ZonePeer {
    socket: UdpSocket,
    client: Option<std::net::SocketAddr>,
    sequence: u16,
    ack: u16,
}

impl ZonePeer {
    fn new() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        Self {
            socket,
            client: None,
            sequence: 0,
            ack: 0,
        }
    }

    /// Read the small unfragmented packets used by this zone-entry fixture.
    fn receive(&mut self) -> ([u8; 2], Vec<u8>) {
        loop {
            let mut wire = [0; 2048];
            let (length, address) = self.socket.recv_from(&mut wire).unwrap();
            assert!(length >= 10);
            let end = length - 4;
            assert_eq!(
                crc32fast::hash(&wire[..end]).to_be_bytes(),
                wire[end..length]
            );
            assert_eq!(*self.client.get_or_insert(address), address);
            assert_eq!(wire[0] & 0x4c, 0, "unexpected fragmentation or close");
            assert_eq!(wire[1] & !0x04, 0, "unexpected selective ACK");
            let mut position = 4 + usize::from(wire[1] & 0x04 != 0) * 2;
            if wire[0] & 0x02 != 0 {
                self.ack = u16::from_be_bytes(wire[position..position + 2].try_into().unwrap());
                position += 2;
            }
            if wire[0] & 0x10 != 0 {
                position += if wire[0] & 0x02 != 0 { 2 } else { 1 };
            }
            if position == end {
                continue;
            }
            let opcode = wire[position..position + 2].try_into().unwrap();
            return (opcode, wire[position + 2..end].to_vec());
        }
    }

    fn expect(&mut self, opcode: [u8; 2], body: &[u8]) {
        let packet = self.receive();
        assert_eq!(packet.0, opcode);
        assert_eq!(packet.1, body);
    }

    /// Send a reliable application and acknowledge the last client packet.
    fn send(&mut self, opcode: [u8; 2], body: &[u8]) {
        let mut wire = vec![0x12, 0x04];
        wire.extend(self.sequence.to_be_bytes());
        wire.extend(self.ack.to_be_bytes());
        wire.extend(self.sequence.to_be_bytes());
        wire.extend([0, self.sequence as u8]);
        wire.extend(opcode);
        wire.extend(body);
        wire.extend(crc32fast::hash(&wire).to_be_bytes());
        self.socket.send_to(&wire, self.client.unwrap()).unwrap();
        self.sequence += 1;
    }
}

#[test]
fn dll_version_precedes_zone_ready_and_answers_requests() {
    for request_during_connection in [false, true] {
        let mut peer = ZonePeer::new();
        let port = peer.socket.local_addr().unwrap().port();
        let stop = CancellationToken::default();
        let worker_stop = stop.clone();
        let worker = thread::spawn(move || {
            let config = super::tests::config();
            let mut handler = |_| Ok(());
            let mut events = Events::new(&config, &mut handler);
            zone(
                &config,
                &worker_stop,
                &RunOptions::default(),
                None,
                &mut events,
                "127.0.0.1",
                port,
            )
        });
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            peer.expect([0xe8, 0x41], &10.0f32.to_le_bytes());
            let entry = peer.receive();
            assert_eq!(entry.0, [0x28, 0x40]);
            assert_eq!(entry.1.len(), 68);

            if request_during_connection {
                peer.send([0xf5, 0x40], &[0, 0, 0, 1, 0, 0, 4, 0]);
                peer.expect([0xf5, 0x40], &[0, 0, 0, 1, 7, 0, 4, 0x80]);
            }
            peer.send([0x36, 0x40], &[]); // The state machine only observes the profile opcode.
            peer.send([0x36, 0x41], &[]);
            peer.expect([0x5d, 0x40], &[]);
            let mut zone = [0; 96];
            zone[64..71].copy_from_slice(b"example");
            peer.send([0x5b, 0x40], &zone);
            peer.expect([0x0a, 0x40], &[]);
            peer.send([0xd8, 0x40], &[]);
            peer.expect([0xd8, 0x40], &[]);
            peer.send([0x6f, 0x40], &[]);
            let filters = peer.receive();
            assert_eq!(filters.0, [0xff, 0x41]);
            assert_eq!(filters.1.len(), 68);
            // Quarm checks the version when ClientUpdate completes zone entry.
            peer.expect([0xf5, 0x40], &[0, 0, 0, 1, 7, 0, 4, 0]);
            peer.expect([0xf3, 0x40], &[0; 15]);

            // Responses, unrelated features, and repeated readiness must not
            // generate more announcements or enable unsupported capabilities.
            peer.send([0xf5, 0x40], &[0, 0, 0, 1, 7, 0, 4, 0x80]);
            peer.send([0xf5, 0x40], &[0, 0, 0, 1, 30, 0, 5, 0]);
            peer.send([0x6f, 0x40], &[]);
            peer.send([0xf5, 0x40], &[0, 0, 0, 1, 0, 0, 4, 0]);
            peer.expect([0xf5, 0x40], &[0, 0, 0, 1, 7, 0, 4, 0x80]);
        }));
        stop.cancel();
        worker.join().unwrap().unwrap();
        if let Err(error) = outcome {
            std::panic::resume_unwind(error);
        }
    }
}
