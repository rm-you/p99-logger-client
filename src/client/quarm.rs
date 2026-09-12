use super::{
    CancellationToken, ClientCommand, ClientConfig, ClientEvent, ConnectionStage, ConnectionState,
    DecodeError, Events, LoginError, RecordEvent, RunOptions,
};
use crate::{chat, old_transport::OldSession, transport::Application};
use anyhow::{bail, ensure, Context, Result};
use eq_login_protocol::crypto::{des_encrypt, DesKeyIv};
use std::{
    net::ToSocketAddrs,
    sync::mpsc::Receiver,
    time::{Duration, Instant},
};

const VERANT_DES: DesKeyIv = DesKeyIv {
    key: [0x13, 0xd9, 0x13, 0x6d, 0xd0, 0x34, 0x15, 0xfb],
    iv: [0x13, 0xd9, 0x13, 0x6d, 0xd0, 0x34, 0x15, 0xfb],
};

const LOGIN_SESSION_READY: u16 = 0x5900;
const LOGIN_PC: u16 = 0x0100;
const LOGIN_ERROR: u16 = 0x0200;
const LOGIN_ACCEPTED: u16 = 0x0400;
const LOGIN_SERVER_LIST: u16 = 0x4600;
const LOGIN_PLAY: u16 = 0x4700;
const LOGIN_COMPLETE: u16 = 0x8800;

const WORLD_LOGIN: u16 = 0x5818;
const WORLD_CHARACTER_LIST: u16 = 0x4740;
const WORLD_ENTER: u16 = 0x0180;
const WORLD_ZONE_SERVER: u16 = 0x0480;

const ZONE_DATA_RATE: u16 = 0xe841;
const ZONE_ENTRY: u16 = 0x2840;
const ZONE_PLAYER_PROFILE: u16 = 0x3640;
const ZONE_WEATHER: u16 = 0x3641;
const ZONE_REQUEST_NEW: u16 = 0x5d40;
const ZONE_NEW: u16 = 0x5b40;
const ZONE_REQUEST_SPAWNS: u16 = 0x0a40;
const ZONE_EXPERIENCE_READY: u16 = 0xd840;
const ZONE_AVATAR_READY: u16 = 0x6f40;
const ZONE_SERVER_FILTER: u16 = 0xff41;
const ZONE_CLIENT_UPDATE: u16 = 0xf340;
const ZONE_CHANNEL_MESSAGE: u16 = 0x0741;
const ZONE_SPAWN_APPEARANCE: u16 = 0xf540;
const ZONE_LOGOUT: u16 = 0x5041;
const ZONE_CHANGE_REQUEST: u16 = 0x4d41;

// akplus-dll af2bd327, eqgame.cpp: DLL_VERSION and DLL_VERSION_MESSAGE_ID.
// This announcement is independent of the optional gameplay feature handshakes.
const DLL_VERSION: u16 = 7;
const DLL_MESSAGE_TYPE: u16 = 256;
const DLL_VERSION_FEATURE: u16 = 4;

struct Credentials {
    account: String,
    key: [u8; 10],
}

struct ServerEntry {
    name: String,
    ip: String,
}

/// Run one complete TAKP/EQMac login, world selection, and Quarm zone attempt.
pub(super) fn run(
    config: &ClientConfig,
    stop: &CancellationToken,
    options: &RunOptions,
    commands: Option<&Receiver<ClientCommand>>,
    log: &mut Events<'_>,
) -> Result<()> {
    ensure!(!stop.is_cancelled(), "shutdown requested");
    let (credentials, world_ip) = login(config, stop, log)?;
    world(
        config,
        &credentials,
        &world_ip,
        stop,
        options,
        commands,
        log,
    )
}

fn address(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .find(std::net::SocketAddr::is_ipv4)
        .context("no IPv4 address for server")
}

fn next(
    session: &mut OldSession,
    deadline: Instant,
    stop: &CancellationToken,
) -> Result<Application> {
    loop {
        ensure!(!stop.is_cancelled(), "shutdown requested");
        ensure!(Instant::now() < deadline, "application handshake timed out");
        if let Some(packet) = session.receive()? {
            return Ok(packet);
        }
    }
}

/// Authenticate through the legacy TAKP login service and select a world.
fn login(
    config: &ClientConfig,
    stop: &CancellationToken,
    log: &mut Events<'_>,
) -> Result<(Credentials, String)> {
    let mut session =
        OldSession::connect_cancellable(address(&config.host, config.port)?, stop.flag())?;
    session.send(LOGIN_SESSION_READY, &[])?;
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut account = None;
    let mut selected = None;
    let mut sent_login = false;
    let mut sent_complete = false;
    let mut requested_list = false;
    loop {
        let packet = next(&mut session, deadline, stop)?;
        match packet.opcode {
            LOGIN_SESSION_READY if !sent_login => {
                log.send(ClientEvent::Progress(ConnectionStage::Authenticating))?;
                session.send(LOGIN_PC, &login_credentials(config)?)?;
                sent_login = true;
            }
            LOGIN_ACCEPTED if account.is_none() => {
                account = Some(login_account(&packet.body)?);
                session.send(LOGIN_COMPLETE, &[])?;
                sent_complete = true;
                log.diagnostic("TAKP login server authenticated the account".into())?;
            }
            LOGIN_COMPLETE if sent_complete && !requested_list => {
                log.send(ClientEvent::Progress(ConnectionStage::SelectingServer))?;
                session.send(LOGIN_SERVER_LIST, &[])?;
                requested_list = true;
            }
            LOGIN_SERVER_LIST if requested_list && selected.is_none() => {
                let servers = parse_server_list(&packet.body)?;
                let server = servers
                    .into_iter()
                    .find(|server| server.name.eq_ignore_ascii_case(&config.server))
                    .context("configured server name was not found in the TAKP server list")?;
                let mut request = server.ip.as_bytes().to_vec();
                request.push(0);
                session.send(LOGIN_PLAY, &request)?;
                selected = Some(server.ip);
            }
            LOGIN_PLAY if selected.is_some() => {
                ensure!(packet.body.len() >= 11, "truncated TAKP play response");
                let key: [u8; 10] = packet.body[1..11].try_into().unwrap();
                ensure!(
                    key.iter().all(u8::is_ascii_alphanumeric),
                    "invalid TAKP session key"
                );
                session.close()?;
                log.send(ClientEvent::Progress(ConnectionStage::ConnectingWorld))?;
                return Ok((
                    Credentials {
                        account: account.context("play response before authentication")?,
                        key,
                    },
                    selected.unwrap(),
                ));
            }
            LOGIN_ERROR => {
                let message = String::from_utf8_lossy(cstr(&packet.body)).into_owned();
                if account.is_none() {
                    return Err(LoginError::InvalidCredentials.into());
                }
                bail!("TAKP login server rejected world entry: {message}");
            }
            _ => (),
        }
    }
}

fn login_credentials(config: &ClientConfig) -> Result<Vec<u8>> {
    let mut clear = [0; 40];
    put_string(&mut clear[..20], &config.user)?;
    put_string(&mut clear[20..], &config.pass)?;
    Ok(des_encrypt(&clear, VERANT_DES))
}

fn login_account(body: &[u8]) -> Result<String> {
    ensure!(body.len() >= 21, "truncated TAKP login response");
    let account = std::str::from_utf8(cstr(&body[..10]))?;
    ensure!(
        account.starts_with("LS#") && account.len() > 3,
        "invalid TAKP account session"
    );
    Ok(account.to_owned())
}

fn parse_server_list(body: &[u8]) -> Result<Vec<ServerEntry>> {
    ensure!(body.len() >= 5, "truncated TAKP server list");
    let count = usize::from(u16::from_le_bytes(body[..2].try_into().unwrap()));
    let mut position = 5;
    let mut servers = Vec::with_capacity(count);
    for _ in 0..count {
        let name = take_string(body, &mut position)?;
        let ip = take_string(body, &mut position)?;
        ensure!(position + 13 <= body.len(), "truncated TAKP server flags");
        position += 13;
        servers.push(ServerEntry { name, ip });
    }
    ensure!(servers.len() == count, "TAKP server count mismatch");
    Ok(servers)
}

fn take_string(body: &[u8], position: &mut usize) -> Result<String> {
    let tail = body.get(*position..).context("truncated TAKP string")?;
    let length = tail
        .iter()
        .position(|&byte| byte == 0)
        .context("unterminated TAKP string")?;
    let result = String::from_utf8_lossy(&tail[..length]).into_owned();
    *position += length + 1;
    Ok(result)
}

/// Authenticate to the MacPC world server, choose a character, and follow its handoff.
fn world(
    config: &ClientConfig,
    credentials: &Credentials,
    ip: &str,
    stop: &CancellationToken,
    options: &RunOptions,
    commands: Option<&Receiver<ClientCommand>>,
    log: &mut Events<'_>,
) -> Result<()> {
    let mut session = OldSession::connect_cancellable(address(ip, 9000)?, stop.flag())?;
    session.send(WORLD_LOGIN, &world_login(credentials)?)?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut entered = false;
    loop {
        let packet = next(&mut session, deadline, stop)?;
        record_chat(config, "", &packet, log)?;
        log.diagnostic(format!(
            "Quarm world received 0x{:04x} ({} bytes)",
            packet.opcode,
            packet.body.len()
        ))?;
        match packet.opcode {
            WORLD_CHARACTER_LIST if !entered => {
                ensure!(
                    character_exists(&packet.body, &config.character)?,
                    "configured character is absent from character selection"
                );
                log.send(ClientEvent::Progress(ConnectionStage::SelectingCharacter))?;
                if options.world_only {
                    session.close()?;
                    return Ok(());
                }
                let mut enter = [0; 64];
                put_string(&mut enter, &config.character)?;
                session.send(WORLD_ENTER, &enter)?;
                entered = true;
                log.send(ClientEvent::Progress(ConnectionStage::ConnectingZone))?;
            }
            WORLD_ZONE_SERVER if entered => {
                let (host, port) = zone_destination(&packet.body)?;
                session.close()?;
                return zone(config, stop, options, commands, log, &host, port);
            }
            _ => (),
        }
    }
}

fn character_exists(body: &[u8], character: &str) -> Result<bool> {
    ensure!(body.len() >= 640, "truncated EQMac character list");
    Ok(body[..640]
        .as_chunks::<64>()
        .0
        .iter()
        .any(|name| cstr(name).eq_ignore_ascii_case(character.as_bytes())))
}

fn world_login(credentials: &Credentials) -> Result<[u8; 200]> {
    let mut body = [0; 200];
    put_string(&mut body[..127], &credentials.account)?;
    let key_start = credentials.account.len() + 1;
    ensure!(
        key_start + credentials.key.len() <= 127,
        "TAKP session fields are too large"
    );
    body[key_start..key_start + credentials.key.len()].copy_from_slice(&credentials.key);
    Ok(body)
}

/// Read the world-to-zone endpoint advertised by an EQMac world server.
fn zone_destination(body: &[u8]) -> Result<(String, u16)> {
    ensure!(body.len() >= 130, "truncated EQMac zone handoff");
    let host = std::str::from_utf8(cstr(&body[..128]))?.to_owned();
    // Unlike the Titanium handoff, EQMac carries this port in network byte order.
    let port = u16::from_be_bytes(body[128..130].try_into().unwrap());
    ensure!(!host.is_empty() && port != 0, "invalid EQMac zone endpoint");
    Ok((host, port))
}

/// Complete the EQMac zone admission sequence and collect communications.
fn zone(
    config: &ClientConfig,
    stop: &CancellationToken,
    options: &RunOptions,
    commands: Option<&Receiver<ClientCommand>>,
    log: &mut Events<'_>,
    host: &str,
    port: u16,
) -> Result<()> {
    let mut session = OldSession::connect_cancellable(address(host, port)?, stop.flag())?;
    session.send(ZONE_DATA_RATE, &10.0f32.to_le_bytes())?;
    let mut entry = [0; 68];
    put_string(&mut entry[4..], &config.character)?;
    session.send(ZONE_ENTRY, &entry)?;
    log.send(ClientEvent::Progress(ConnectionStage::LoadingCharacter))?;

    let connected = Instant::now();
    let mut ready = false;
    let mut saw_profile = false;
    let mut requested_zone = false;
    let mut requested_spawns = false;
    let mut replied_experience = false;
    let mut sent_ready = false;
    let mut zone_name = String::new();
    let mut packets = 0u64;
    let mut progress = Instant::now();
    loop {
        if stop.is_cancelled()
            || options
                .zone_duration
                .is_some_and(|duration| connected.elapsed() >= duration)
        {
            session.close()?;
            return Ok(());
        }
        ensure!(
            ready || connected.elapsed() < Duration::from_secs(60),
            "zone admission timed out"
        );
        if progress.elapsed() >= Duration::from_secs(30) {
            log.status(
                if ready && session.last_received_seconds() < 60 {
                    ConnectionState::Connected
                } else {
                    ConnectionState::Zoning
                },
                packets,
                Some(session.last_received_seconds()),
            )?;
            log.diagnostic(format!(
                "Quarm zone session: {packets} application packets, {} communication records",
                log.messages
            ))?;
            progress = Instant::now();
        }
        if ready {
            if let Some(commands) = commands {
                for command in commands.try_iter().take(64) {
                    match command {
                        ClientCommand::SendChat(message) => match chat::encode_outbound_for(
                            config.protocol,
                            &message,
                            &config.character,
                        ) {
                            Ok(body) => session.send(ZONE_CHANNEL_MESSAGE, &body)?,
                            Err(error) => log.diagnostic(format!(
                                "Rejected invalid outbound chat command: {error}"
                            ))?,
                        },
                    }
                }
            }
        }
        let Some(packet) = session.receive()? else {
            continue;
        };
        packets += 1;
        if !ready {
            log.diagnostic(format!(
                "Quarm zone received 0x{:04x} ({} bytes)",
                packet.opcode,
                packet.body.len()
            ))?;
        }
        match packet.opcode {
            ZONE_PLAYER_PROFILE => saw_profile = true,
            ZONE_WEATHER if !requested_zone => {
                session.send(ZONE_REQUEST_NEW, &[])?;
                requested_zone = true;
            }
            ZONE_NEW if !requested_spawns => {
                ensure!(packet.body.len() >= 96, "truncated EQMac zone description");
                zone_name = String::from_utf8_lossy(cstr(&packet.body[64..96])).into_owned();
                log.zone.clone_from(&zone_name);
                log.status(
                    ConnectionState::Zoning,
                    packets,
                    Some(session.last_received_seconds()),
                )?;
                session.send(ZONE_REQUEST_SPAWNS, &[])?;
                requested_spawns = true;
            }
            ZONE_EXPERIENCE_READY if requested_spawns && !replied_experience => {
                session.send(ZONE_EXPERIENCE_READY, &[])?;
                replied_experience = true;
            }
            ZONE_AVATAR_READY if replied_experience && !sent_ready => {
                ensure!(saw_profile, "zone became ready before player profile");
                session.send(ZONE_SERVER_FILTER, &server_filters())?;
                // ClientUpdate completes admission and triggers the server's version check.
                session.send(ZONE_SPAWN_APPEARANCE, &dll_version_message(false))?;
                session.send(ZONE_CLIENT_UPDATE, &[0; 15])?;
                sent_ready = true;
                ready = true;
                log.send(ClientEvent::Progress(ConnectionStage::EnteringWorld))?;
                log.send(ClientEvent::Progress(ConnectionStage::Ready))?;
                log.status(
                    ConnectionState::Connected,
                    packets,
                    Some(session.last_received_seconds()),
                )?;
                log.diagnostic(format!(
                    "Quarm zone login sequence complete for {zone_name}; waiting for ongoing server traffic"
                ))?;
            }
            ZONE_SPAWN_APPEARANCE => {
                if let Some(response) = dll_version_reply(&packet.body) {
                    session.send(ZONE_SPAWN_APPEARANCE, &response)?;
                }
            }
            ZONE_LOGOUT => bail!("server logged the character out"),
            ZONE_CHANGE_REQUEST => bail!("server requested a new zone; reconnecting through world"),
            _ => (),
        }
        record_chat(config, &zone_name, &packet, log)?;
    }
}

/// Encode the DLL version announcement, or a reply with the response bit set.
fn dll_version_message(response: bool) -> [u8; 8] {
    let mut body = [0; 8]; // Custom DLL messages use spawn ID zero.
    body[2..4].copy_from_slice(&DLL_MESSAGE_TYPE.to_le_bytes());
    let parameter = (u32::from(response) << 31)
        | (u32::from(DLL_VERSION_FEATURE) << 16)
        | u32::from(DLL_VERSION);
    body[4..].copy_from_slice(&parameter.to_le_bytes());
    body
}

/// Answer only well-formed DLL version requests, during admission or normal play.
fn dll_version_reply(body: &[u8]) -> Option<[u8; 8]> {
    let body: &[u8; 8] = body.try_into().ok()?;
    let spawn_id = u16::from_le_bytes(body[..2].try_into().unwrap());
    let appearance = u16::from_le_bytes(body[2..4].try_into().unwrap());
    let parameter = u32::from_le_bytes(body[4..].try_into().unwrap());
    // Comparing the full high word also excludes responses (bit 31), preventing loops.
    (spawn_id == 0
        && appearance == DLL_MESSAGE_TYPE
        && parameter >> 16 == u32::from(DLL_VERSION_FEATURE))
    .then(|| dll_version_message(true))
}

fn record_chat(
    config: &ClientConfig,
    zone: &str,
    packet: &Application,
    log: &mut Events<'_>,
) -> Result<()> {
    match chat::parse_for(
        config.protocol,
        packet.opcode,
        &packet.body,
        config.include_raw,
    ) {
        Ok(Some(event)) => log.record(zone, RecordEvent::Chat(event)),
        Ok(None) => Ok(()),
        Err(error) => log.record(
            zone,
            RecordEvent::DecodeError(DecodeError {
                kind: "decode_error",
                opcode: packet.opcode,
                payload_hex: hex::encode(&packet.body),
                error: error.to_string(),
            }),
        ),
    }
}

fn server_filters() -> [u8; 68] {
    let mut filters = [0; 68];
    for index in 5..=14 {
        filters[index * 4] = 1;
    }
    filters
}

fn put_string(destination: &mut [u8], value: &str) -> Result<()> {
    ensure!(
        value.len() < destination.len() && !value.contains('\0'),
        "string exceeds protocol field size"
    );
    destination[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}

fn cstr(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len())]
}

#[cfg(test)]
mod zone_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use eq_login_protocol::crypto::des_decrypt;

    pub(super) fn config() -> ClientConfig {
        ClientConfig::for_protocol(
            super::super::ServerProtocol::Quarm,
            "EXAMPLE_ACCOUNT",
            "EXAMPLE_PASSWORD",
            "The Project Quarm Server",
            "ExampleCharacter",
        )
    }

    #[test]
    fn dll_version_ignores_other_features_responses_and_malformed_messages() {
        let request = [0, 0, 0, 1, 0, 0, 4, 0];
        for length in 0..8 {
            assert!(dll_version_reply(&request[..length]).is_none());
        }
        let mut oversized = request.to_vec();
        oversized.push(0);
        assert!(dll_version_reply(&oversized).is_none());
        for (offset, value) in [
            (0, 1),
            (2, 1),
            (3, 0),
            (6, 2),
            (6, 3),
            (6, 5),
            (6, 7),
            (6, 255),
            (7, 128),
        ] {
            let mut other = request;
            other[offset] = value;
            assert!(dll_version_reply(&other).is_none());
        }
        let mut arbitrary_value = request;
        arbitrary_value[4..6].fill(255);
        assert_eq!(
            dll_version_reply(&arbitrary_value),
            Some([0, 0, 0, 1, 7, 0, 4, 128])
        );
    }

    #[test]
    fn zone_handoff_uses_network_byte_order_for_the_port() {
        // EQMacEmu world/client.cpp serializes ntohs(GetCPort()) in this field.
        let mut body = [0; 130];
        put_string(&mut body[..128], "203.0.113.20").unwrap();
        body[128..].copy_from_slice(&7000u16.to_be_bytes());
        assert_eq!(
            zone_destination(&body).unwrap(),
            ("203.0.113.20".into(), 7000)
        );
        assert!(zone_destination(&body[..129]).is_err());
        body[128..].fill(0);
        assert!(zone_destination(&body).is_err());
    }

    #[test]
    fn pc_login_uses_the_verant_key_and_fixed_20_byte_fields() {
        let encrypted = login_credentials(&config()).unwrap();
        assert_eq!(encrypted.len(), 40);
        let clear = des_decrypt(&encrypted, VERANT_DES).unwrap();
        assert_eq!(cstr(&clear[..20]), b"EXAMPLE_ACCOUNT");
        assert_eq!(cstr(&clear[20..]), b"EXAMPLE_PASSWORD");
    }

    #[test]
    fn old_server_list_layout_selects_names_and_addresses() {
        let mut body = vec![2, 0, 0, 0, 0];
        for (name, ip, id) in [
            ("The Al'Kabor Project Server", "198.51.100.10", 1u32),
            ("The Project Quarm Server", "203.0.113.20", 2u32),
        ] {
            body.extend_from_slice(name.as_bytes());
            body.push(0);
            body.extend_from_slice(ip.as_bytes());
            body.push(0);
            body.push(0);
            body.extend_from_slice(&1u32.to_le_bytes());
            body.extend_from_slice(&id.to_le_bytes());
            body.extend_from_slice(&123u32.to_le_bytes());
        }
        body.extend_from_slice(&[0; 26]);
        let servers = parse_server_list(&body).unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[1].name, "The Project Quarm Server");
        assert_eq!(servers[1].ip, "203.0.113.20");
    }

    #[test]
    fn world_login_is_the_200_byte_windows_eqmac_form() {
        let credentials = Credentials {
            account: "LS#12345".into(),
            key: *b"ABCDEFGHIJ",
        };
        let body = world_login(&credentials).unwrap();
        assert_eq!(body.len(), 200);
        assert_eq!(cstr(&body[..127]), b"LS#12345");
        assert_eq!(&body[9..19], b"ABCDEFGHIJ");
        assert!(body[19..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn character_list_uses_ten_fixed_64_byte_name_fields() {
        let mut body = vec![0; 1620];
        put_string(&mut body[3 * 64..4 * 64], "ExampleCharacter").unwrap();
        assert!(character_exists(&body, "examplecharacter").unwrap());
        assert!(!character_exists(&body, "MissingCharacter").unwrap());
        assert!(character_exists(&body[..639], "ExampleCharacter").is_err());
    }

    #[test]
    fn mac_filters_enable_every_chat_and_combat_category() {
        let filters = server_filters();
        for index in 0..17 {
            let value = u32::from_le_bytes(filters[index * 4..index * 4 + 4].try_into().unwrap());
            assert_eq!(value, u32::from((5..=14).contains(&index)));
        }
    }
}
