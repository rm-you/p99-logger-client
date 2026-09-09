//! Synthetic loopback peers exercise the public API without accounts or captures.
use anyhow::{bail, Result};
use p99_logger_client::client::{
    CancellationToken, Client, ClientConfig, ClientEvent, ClientIdentity, ConnectionStage,
    ConnectionState, LoginError, RunOptions,
};
use std::{
    net::{SocketAddr, UdpSocket},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

fn config(port: u16) -> ClientConfig {
    let mut config = ClientConfig::new(
        "EXAMPLE_ACCOUNT",
        "EXAMPLE_PASSWORD",
        "Test Server",
        "ExampleCharacter",
    );
    config.host = "127.0.0.1".into();
    config.port = port;
    config
}

fn client(config: ClientConfig) -> Client {
    Client::new(
        config,
        ClientIdentity {
            hostname: "test-device".into(),
            username: "test-user".into(),
        },
    )
    .unwrap()
}

fn peer() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
}

fn receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buffer = [0; 2048];
    let (length, address) = socket.recv_from(&mut buffer).unwrap();
    (buffer[..length].to_vec(), address)
}

fn negotiate(socket: &UdpSocket) -> (SocketAddr, Vec<u8>) {
    let (request, address) = receive(socket);
    assert_eq!(&request[..6], &[0, 1, 0, 0, 0, 2]);
    let id = request[6..10].to_vec();
    let mut response = vec![0, 2];
    response.extend(&id);
    response.extend(1234u32.to_be_bytes());
    response.extend([2, 0, 0]);
    response.extend(512u32.to_be_bytes());
    socket.send_to(&response, address).unwrap();
    let (ready, sender) = receive(socket);
    assert_eq!(sender, address);
    assert_eq!(&ready[..6], &[0, 9, 0, 0, 1, 0]);
    (address, id)
}

fn closed_packet(id: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 5];
    packet.extend(id);
    let mut crc = crc32fast::Hasher::new();
    crc.update(&1234u32.to_le_bytes());
    crc.update(&packet);
    packet.extend(&crc.finalize().to_be_bytes()[2..]);
    packet
}

#[test]
fn cancellation_before_start_never_resolves_or_connects() {
    let mut settings = config(1);
    settings.host = "this host cannot resolve".into();
    let cancel = CancellationToken::default();
    cancel.cancel();
    let mut states = Vec::new();
    client(settings)
        .run(&cancel, RunOptions::default(), |event| {
            if let ClientEvent::Status(status) = event {
                states.push(status.state);
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(states, [ConnectionState::Stopped]);
}

#[test]
fn handler_failure_is_returned_without_reconnecting_or_calling_it_again() {
    let mut settings = config(1);
    settings.host = "this host cannot resolve".into();
    let mut calls = 0;
    let error = client(settings)
        .run(&CancellationToken::default(), RunOptions::default(), |_| {
            calls += 1;
            bail!("UI event receiver closed")
        })
        .unwrap_err();
    assert_eq!(calls, 1);
    assert!(error.to_string().contains("UI event receiver closed"));
}

#[test]
fn cancellation_interrupts_udp_negotiation() {
    let socket = peer();
    let engine = client(config(socket.local_addr().unwrap().port()));
    let cancel = CancellationToken::default();
    let worker_cancel = cancel.clone();
    let (done, result) = mpsc::channel();
    let worker = thread::spawn(move || {
        done.send(engine.run(&worker_cancel, RunOptions::default(), |_| Ok(())))
            .unwrap();
    });
    let (request, _) = receive(&socket);
    assert_eq!(&request[..2], &[0, 1]);
    cancel.cancel();
    result
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn cancellation_during_login_closes_the_session_and_stops_without_retry() {
    let socket = peer();
    let engine = client(config(socket.local_addr().unwrap().port()));
    let cancel = CancellationToken::default();
    let worker_cancel = cancel.clone();
    let (done, result) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut states = Vec::new();
        let outcome = engine.run(&worker_cancel, RunOptions::default(), |event| {
            if let ClientEvent::Status(status) = event {
                states.push(status.state);
            }
            Ok(())
        });
        done.send((outcome, states)).unwrap();
    });
    let (address, id) = negotiate(&socket);
    cancel.cancel();
    let (packet, sender) = receive(&socket);
    assert_eq!(sender, address);
    assert_eq!(packet, closed_packet(&id));
    let (outcome, states) = result.recv_timeout(Duration::from_secs(2)).unwrap();
    outcome.unwrap();
    assert_eq!(
        states,
        [ConnectionState::Connecting, ConnectionState::Stopped]
    );
    worker.join().unwrap();
}

#[test]
fn server_disconnect_retries_only_when_requested_and_retry_wait_is_cancellable() {
    for reconnect in [false, true] {
        let socket = peer();
        let engine = client(config(socket.local_addr().unwrap().port()));
        let server = thread::spawn(move || {
            let (address, id) = negotiate(&socket);
            socket.send_to(&closed_packet(&id), address).unwrap();
        });
        let cancel = CancellationToken::default();
        let mut states = Vec::new();
        let mut retries = 0;
        let start = Instant::now();
        let outcome = engine.run(
            &cancel,
            RunOptions {
                reconnect,
                ..RunOptions::default()
            },
            |event| {
                match event {
                    ClientEvent::Status(status) => states.push(status.state),
                    ClientEvent::Reconnecting { delay_seconds, .. } => {
                        retries += 1;
                        assert_eq!(delay_seconds, 30);
                        cancel.cancel();
                    }
                    _ => (),
                }
                Ok(())
            },
        );
        server.join().unwrap();
        assert_eq!(retries, usize::from(reconnect));
        assert_eq!(
            &states[..2],
            &[ConnectionState::Connecting, ConnectionState::Disconnected]
        );
        if reconnect {
            outcome.unwrap();
            assert_eq!(states.last(), Some(&ConnectionState::Stopped));
        } else {
            assert!(outcome.is_err());
        }
        assert!(start.elapsed() < Duration::from_secs(3));
    }
}

#[test]
fn invalid_settings_fail_before_start_without_disclosing_credentials() {
    let mut settings = config(1);
    settings.character = "x".repeat(64);
    let result: Result<_> = Client::new(
        settings,
        ClientIdentity {
            hostname: "test".into(),
            username: "test".into(),
        },
    );
    let error = result.err().unwrap().to_string();
    assert!(error.contains("character name"));
    assert!(!error.contains("EXAMPLE_ACCOUNT") && !error.contains("EXAMPLE_PASSWORD"));
}

/// Construct encrypted replies from synthetic values, never from a packet capture.
fn login_reply() -> Vec<u8> {
    use eq_login_protocol::crypto::{des_encrypt, DesKeyIv};
    let mut clear = vec![0; 32];
    clear[0] = 1;
    clear[8..12].copy_from_slice(&eq_login_protocol::LOGIN_RESULT_FAILURE_STATUS.to_le_bytes());
    let mut body = vec![0; 10];
    body[0] = 3;
    body[5] = 2;
    body.extend(des_encrypt(&clear, DesKeyIv::default()));
    body
}

fn application_packet(sequence: u16, opcode: u16, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 9];
    packet.extend(sequence.to_be_bytes());
    packet.extend(opcode.to_le_bytes());
    packet.extend(body);
    let mut crc = crc32fast::Hasher::new();
    crc.update(&1234u32.to_le_bytes());
    crc.update(&packet);
    packet.extend(&crc.finalize().to_be_bytes()[2..]);
    packet
}

#[test]
fn rejected_credentials_close_login_and_never_enter_the_retry_loop() {
    for reconnect in [true, false] {
        let socket = peer();
        let engine = client(config(socket.local_addr().unwrap().port()));
        let cancel = CancellationToken::default();
        let worker_cancel = cancel.clone();
        let (done, result) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut retries = 0;
            let mut stages = Vec::new();
            let outcome = engine.run(
                &worker_cancel,
                RunOptions {
                    reconnect,
                    ..RunOptions::default()
                },
                |event| {
                    if let ClientEvent::Progress(stage) = &event {
                        stages.push(*stage);
                    }
                    if matches!(event, ClientEvent::Reconnecting { .. }) {
                        retries += 1;
                    }
                    Ok(())
                },
            );
            done.send((outcome, retries, stages)).unwrap();
        });
        let (address, id) = negotiate(&socket);
        socket
            .send_to(&application_packet(0, 0x16, &[]), address)
            .unwrap();
        loop {
            let (packet, sender) = receive(&socket);
            assert_eq!(sender, address);
            if packet.starts_with(&[0, 9, 0, 1, 2, 0]) {
                break;
            }
        }
        let mut response = login_reply();
        // The proven SSO detector also accepts the optional one-byte trailer.
        if reconnect {
            response.push(0);
        }
        socket
            .send_to(&application_packet(1, 0x17, &response), address)
            .unwrap();
        let outcome = result.recv_timeout(Duration::from_secs(3));
        cancel.cancel();
        worker.join().unwrap();
        let (outcome, retries, stages) =
            outcome.expect("credential rejection must end immediately");
        let error = outcome.unwrap_err();
        assert_eq!(
            error.downcast_ref::<LoginError>(),
            Some(&LoginError::InvalidCredentials)
        );
        assert_eq!(retries, 0);
        assert_eq!(
            stages,
            [
                ConnectionStage::ConnectingLogin,
                ConnectionStage::Authenticating
            ]
        );
        assert!(
            !error.to_string().contains("EXAMPLE_ACCOUNT")
                && !error.to_string().contains("EXAMPLE_PASSWORD")
        );
        loop {
            let (packet, _) = receive(&socket);
            if packet.starts_with(&[0, 5]) {
                assert_eq!(packet, closed_packet(&id));
                break;
            }
        }
        // No server-list or world request follows the rejected login.
        socket
            .set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        assert!(socket.recv_from(&mut [0; 2048]).is_err());
    }
}
