use super::{
    CancellationToken, ClientConfig, ClientEvent, ClientIdentity, ConnectionStage, ConnectionState,
    DecodeError, Events, LoginError, RecordEvent, RunOptions,
};
use crate::{
    assets::Assets,
    chat,
    p99::{self, WorldCodec},
    transport::{Application, Session},
};
use anyhow::{bail, ensure, Context, Result};
use eq_login_protocol::{
    crypto::{des_decrypt, DesKeyIv},
    login::{encrypt_login_credentials, is_bad_password_login_result},
    server_list::parse_server_list,
};
use std::{
    net::{IpAddr, ToSocketAddrs},
    time::{Duration, Instant},
};

struct Credentials {
    account: u32,
    key: [u8; 10],
}

/// Run one complete login/world/zone attempt with fresh session credentials.
pub(super) fn run(
    config: &ClientConfig,
    identity: &ClientIdentity,
    assets: &Assets,
    stop: &CancellationToken,
    options: &RunOptions,
    log: &mut Events<'_>,
) -> Result<()> {
    ensure!(!stop.is_cancelled(), "shutdown requested");
    let (credentials, ip) = login(config, stop, log)?;
    let context = CharacterSession {
        config,
        identity,
        credentials: &credentials,
        stop,
        duration: options.zone_duration,
    };
    world(&context, assets, &ip, options.world_only, log)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoginOpcode {
    Ready,
    Accepted,
    ServerList,
    PlayResponse,
    Unknown(u16),
}

impl From<u16> for LoginOpcode {
    fn from(value: u16) -> Self {
        match value {
            0x16 => Self::Ready,
            0x17 => Self::Accepted,
            0x18 => Self::ServerList,
            0x21 => Self::PlayResponse,
            value => Self::Unknown(value),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorldOpcode {
    ApprovalChallenge,
    FileManifest,
    ValidationResult,
    CharacterList,
    ZoneHandoff,
    Unknown(u16),
}

impl From<u16> for WorldOpcode {
    fn from(value: u16) -> Self {
        match value {
            0x3c25 => Self::ApprovalChallenge,
            0x52a4 => Self::FileManifest,
            0x1251 => Self::ValidationResult,
            0x4513 => Self::CharacterList,
            0x61b6 => Self::ZoneHandoff,
            value => Self::Unknown(value),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ZoneOpcode {
    PlayerProfile,
    Weather,
    PlayerSpawn,
    ZoneDescription,
    ExperienceUpdate,
    ValidationRejected,
    LoggedOut,
    ZoneHandoff,
    Unknown(u16),
}

impl From<u16> for ZoneOpcode {
    fn from(value: u16) -> Self {
        match value {
            0x75df => Self::PlayerProfile,
            0x254d => Self::Weather,
            0x7213 => Self::PlayerSpawn,
            0x0920 => Self::ZoneDescription,
            0x0587 => Self::ExperienceUpdate,
            0x1252 => Self::ValidationRejected,
            0x3cdc => Self::LoggedOut,
            0x61b6 => Self::ZoneHandoff,
            value => Self::Unknown(value),
        }
    }
}

/// Resolve an endpoint to the IPv4 address required by the Titanium client.
fn address(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .find(std::net::SocketAddr::is_ipv4)
        .context("no IPv4 address for server")
}

/// Wait for one application packet while enforcing shutdown and a deadline.
fn next(session: &mut Session, deadline: Instant, stop: &CancellationToken) -> Result<Application> {
    loop {
        ensure!(!stop.is_cancelled(), "shutdown requested");
        ensure!(Instant::now() < deadline, "application handshake timed out");
        if let Some(packet) = session.receive()? {
            return Ok(packet);
        }
    }
}

/// Authenticate, select the configured server, and return its world endpoint.
fn login(
    config: &ClientConfig,
    stop: &CancellationToken,
    log: &mut Events<'_>,
) -> Result<(Credentials, String)> {
    let mut session =
        Session::connect_cancellable(address(&config.host, config.port)?, false, stop.flag())?;
    let mut ready = vec![0; 12];
    ready[0] = 2;
    ready[9] = 8;
    session.send(1, &ready)?;
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut credentials = None;
    let mut selected = None;
    let mut sent_credentials = false;
    loop {
        let packet = next(&mut session, deadline, stop)?;
        match LoginOpcode::from(packet.opcode) {
            LoginOpcode::Ready if !sent_credentials => {
                log.send(ClientEvent::Progress(ConnectionStage::Authenticating))?;
                let mut body = vec![0; 10];
                body[0] = 3;
                body[5] = 2;
                body.extend(encrypt_login_credentials(
                    &config.user,
                    &config.pass,
                    DesKeyIv::default(),
                ));
                session.send(2, &body)?;
                sent_credentials = true;
            }
            LoginOpcode::Accepted => {
                credentials = Some(login_credentials(&packet.body)?);
                log.send(ClientEvent::Progress(ConnectionStage::SelectingServer))?;
                let mut request = vec![0; 10];
                request[0] = 4;
                session.send(4, &request)?;
                log.diagnostic("Login server authenticated the account".into())?;
            }
            LoginOpcode::ServerList => {
                ensure!(packet.body.len() >= 20, "truncated server list");
                let mut body = 0x18u16.to_le_bytes().to_vec();
                body.extend(packet.body);
                let (servers, _) = parse_server_list(&body).context("invalid server list")?;
                let server = servers
                    .into_iter()
                    .find(|server| server.name.eq_ignore_ascii_case(&config.server))
                    .context("configured server name was not found in the server list")?;
                ensure!(
                    matches!(server.status, 0 | 2),
                    "configured server is unavailable or locked"
                );
                let mut request = vec![0; 14];
                request[0] = 5;
                request[10..14].copy_from_slice(&server.runtime_id.to_le_bytes());
                session.send(0x0d, &request)?;
                selected = Some(server.ip);
            }
            LoginOpcode::PlayResponse => {
                ensure!(
                    packet.body.len() >= 20 && packet.body[10] > 0,
                    "login server denied world entry"
                );
                session.close()?;
                let selection = (
                    credentials.context("play response before authentication")?,
                    selected.context("play response before selection")?,
                );
                log.send(ClientEvent::Progress(ConnectionStage::ConnectingWorld))?;
                return Ok(selection);
            }
            _ => (),
        }
    }
}

/// Use the SSO crate's failure signature before parsing the successful session key.
fn login_credentials(body: &[u8]) -> Result<Credentials> {
    let mut application = 0x17u16.to_le_bytes().to_vec();
    application.extend_from_slice(body);
    if is_bad_password_login_result(&application, DesKeyIv::default()) {
        return Err(LoginError::InvalidCredentials.into());
    }
    ensure!(body.len() >= 34, "invalid login response");
    let ciphertext = &body[10..];
    let clear = des_decrypt(&ciphertext[..ciphertext.len() / 8 * 8], DesKeyIv::default())?;
    ensure!(clear.len() >= 23, "invalid login response");
    let account = le32(&clear[8..12]);
    ensure!(
        account != 0 && account != u32::MAX && clear[0] == 1,
        "login was rejected"
    );
    let key = cstr(&clear[12..23])
        .try_into()
        .context("invalid login session key")?;
    Ok(Credentials { account, key })
}

/// Build the current P99 CRC1 client-validation response.
fn crc1(
    assets: &Assets,
    local_ip: IpAddr,
    identity: &ClientIdentity,
    key: &[u8],
) -> Result<Vec<u8>> {
    let spells = assets.spells()?;
    let mut body = vec![0; 2056];
    body[..4].copy_from_slice(&(!spells.crc32).to_le_bytes());
    body[4..8].copy_from_slice(&u32::try_from(spells.size)?.to_le_bytes());
    // Current V62 replaces the legacy random spell samples with this metadata
    // block. These fields also occur in successful, decoded stock responses.
    body[8..12].fill(0xff);
    body[45] = 1;
    body[46] = 27;
    put_string(&mut body[50..66], &identity.hostname)?;
    put_string(&mut body[66..82], &identity.username)?;
    body[82..86].copy_from_slice(&[127, 0, 0, 1]);
    if let IpAddr::V4(ip) = local_ip {
        if !ip.is_loopback() {
            body[86..90].copy_from_slice(&ip.octets());
        }
    }
    p99::session_xor(&mut body[..2048], key)?;
    Ok(body)
}

struct CharacterSession<'a> {
    config: &'a ClientConfig,
    identity: &'a ClientIdentity,
    credentials: &'a Credentials,
    stop: &'a CancellationToken,
    duration: Option<Duration>,
}

/// Warn about unscanned files while allowing the server to evaluate checksum zero.
fn file_response(assets: &Assets, manifest: &[u8], log: &mut Events<'_>) -> Result<Vec<u8>> {
    let response = assets.file_response(manifest)?;
    if !response.unknown_files.is_empty() {
        log.diagnostic(format!(
            "Warning: asset inventory has no entry for {}; sending checksum 0",
            response.unknown_files.join(", ")
        ))?;
    }
    Ok(response.body)
}

/// Complete world validation, select the character, and follow its zone handoff.
fn world(
    context: &CharacterSession<'_>,
    assets: &Assets,
    ip: &str,
    world_only: bool,
    log: &mut Events<'_>,
) -> Result<()> {
    let config = context.config;
    let credentials = context.credentials;
    let stop = context.stop;
    let mut session = Session::connect_cancellable(address(ip, 9000)?, true, stop.flag())?;
    let mut login_info = vec![0; 464];
    login_info[192] = 0xcc;
    let account = credentials.account.to_string();
    login_info[..account.len()].copy_from_slice(account.as_bytes());
    login_info[account.len() + 1..account.len() + 1 + credentials.key.len()]
        .copy_from_slice(&credentials.key);
    let mut codec = WorldCodec::new(&login_info)?;
    session.send(0x4dd0, &login_info)?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut accepted = false;
    let mut entered = false;
    loop {
        let mut packet = next(&mut session, deadline, stop)?;
        if let Some(event) = chat::parse(packet.opcode, &packet.body, config.include_raw)? {
            log.record("", RecordEvent::Chat(event))?;
        }
        log.diagnostic(format!(
            "World received 0x{:04x} ({} bytes)",
            packet.opcode,
            packet.body.len()
        ))?;
        match WorldOpcode::from(packet.opcode) {
            WorldOpcode::ApprovalChallenge => {
                session.send(0x3c25, &codec.approve(&packet.body)?)?;
            }
            WorldOpcode::FileManifest => {
                codec.manifest(&mut packet.body)?;
                let mut response = file_response(assets, &packet.body, log)?;
                codec.file_response(&mut response)?;
                session.send(
                    0x5072,
                    &crc1(
                        assets,
                        session.local_address()?.ip(),
                        context.identity,
                        &credentials.key,
                    )?,
                )?;
                session.send(0x1251, &response)?;
            }
            WorldOpcode::ValidationResult => {
                ensure!(
                    packet.body == [0],
                    "world client validation returned {}",
                    hex::encode(&packet.body)
                );
                accepted = true;
                log.send(ClientEvent::Progress(ConnectionStage::SelectingCharacter))?;
                log.diagnostic("World accepted native V62 client validation".into())?;
                session.send(0x7752, &0u32.to_le_bytes())?;
                session.send(0x5e99, &[])?;
                if world_only {
                    session.close()?;
                    return Ok(());
                }
            }
            WorldOpcode::CharacterList if accepted && !entered => {
                // A populated character-select record must contain the exact,
                // NUL-terminated configured name before we request entry.
                let mut name = config.character.as_bytes().to_vec();
                name.push(0);
                ensure!(
                    packet
                        .body
                        .windows(name.len())
                        .any(|bytes| bytes.eq_ignore_ascii_case(&name)),
                    "configured character is absent from character selection"
                );
                let mut enter = vec![0; 72];
                put_string(&mut enter[..64], &config.character)?;
                session.send(0x7cba, &enter)?;
                entered = true;
                log.send(ClientEvent::Progress(ConnectionStage::ConnectingZone))?;
            }
            WorldOpcode::ZoneHandoff => {
                ensure!(entered && packet.body.len() >= 130, "invalid zone handoff");
                let host = std::str::from_utf8(cstr(&packet.body[..128]))?.to_owned();
                let port = u16::from_le_bytes(packet.body[128..130].try_into().unwrap());
                let manifest = codec.zone_manifest(&packet.body)?;
                let response = file_response(assets, &manifest, log)?;
                session.send(0x509d, &[])?;
                session.close()?;
                return zone(context, &mut codec, &host, port, response, log);
            }
            _ => (),
        }
    }
}

/// Enter the zone, keep the character stationary, and collect communications.
fn zone(
    context: &CharacterSession<'_>,
    codec: &mut WorldCodec,
    host: &str,
    port: u16,
    mut checksums: Vec<u8>,
    log: &mut Events<'_>,
) -> Result<()> {
    let config = context.config;
    let credentials = context.credentials;
    let stop = context.stop;
    let duration = context.duration;
    let mut session = Session::connect_cancellable(address(host, port)?, true, stop.flag())?;
    session.send(0x7752, &0u32.to_le_bytes())?;
    let mut entry = vec![0; 68];
    put_string(&mut entry[4..], &config.character)?;
    codec.zone_entry(&entry)?;
    session.send(0x7213, &entry)?;
    log.send(ClientEvent::Progress(ConnectionStage::LoadingCharacter))?;
    let connected = Instant::now();
    let mut ready = false;
    let mut saw_spawn = false;
    let mut saw_profile = false;
    let mut saw_weather = false;
    let mut requested = false;
    let mut got_zone = false;
    let mut replied_experience = false;
    let mut zone_name = String::new();
    let mut progress = Instant::now();
    let mut packets = 0u64;
    let mut stationary = [0u8; 36];
    let mut position_sequence = 0u16;
    let mut last_position = Instant::now()
        .checked_sub(Duration::from_secs(2))
        .unwrap_or_else(Instant::now);
    loop {
        if stop.is_cancelled() || duration.is_some_and(|limit| connected.elapsed() >= limit) {
            session.close()?;
            // The outer run reports Stopped after the session has closed.
            return Ok(());
        }
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
                "Zone session: {packets} application packets, {} communication records",
                log.messages
            ))?;
            progress = Instant::now();
        }
        ensure!(
            ready || connected.elapsed() < Duration::from_secs(60),
            "zone admission timed out"
        );
        if ready && last_position.elapsed() >= Duration::from_secs(2) {
            stationary[2..4].copy_from_slice(&position_sequence.to_le_bytes());
            session.send_unreliable(0x14cb, &stationary)?;
            position_sequence = position_sequence.wrapping_add(1);
            last_position = Instant::now();
        }
        let Some(mut packet) = session.receive()? else {
            continue;
        };
        packets += 1;
        if !ready {
            log.diagnostic(format!(
                "Zone received 0x{:04x} ({} bytes)",
                packet.opcode,
                packet.body.len()
            ))?;
        }
        match ZoneOpcode::from(packet.opcode) {
            ZoneOpcode::PlayerProfile => {
                ensure!(
                    packet.body.len() == 19592,
                    "unexpected Titanium player profile size"
                );
                for offset in [13116, 13120, 13124, 13128] {
                    ensure!(
                        f32::from_le_bytes(packet.body[offset..offset + 4].try_into().unwrap())
                            .is_finite(),
                        "invalid player position"
                    );
                }
                // Preserve the server's saved coordinates. Velocity and
                // animation stay zero; this collector never navigates.
                stationary[4..8].copy_from_slice(&packet.body[13120..13124]);
                stationary[24..28].copy_from_slice(&packet.body[13116..13120]);
                stationary[28..32].copy_from_slice(&packet.body[13124..13128]);
                let heading = f32::from_le_bytes(packet.body[13128..13132].try_into().unwrap());
                let heading = heading.rem_euclid(512.0) * 8.0;
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let heading = heading as u16;
                stationary[32..34].copy_from_slice(&(heading & 0x0fff).to_le_bytes());
                saw_profile = true;
            }
            ZoneOpcode::Weather => saw_weather = true,
            ZoneOpcode::PlayerSpawn if !saw_spawn => {
                p99::session_xor(&mut packet.body, &credentials.key)?;
                ensure!(
                    packet.body.len() == 385
                        && cstr(&packet.body[7..71])
                            .eq_ignore_ascii_case(config.character.as_bytes()),
                    "zone returned a different character spawn"
                );
                codec.zone_spawn(&packet.body)?;
                let id = u16::try_from(le32(&packet.body[340..344]))
                    .context("spawn ID exceeds Titanium position field")?;
                stationary[..2].copy_from_slice(&id.to_le_bytes());
                saw_spawn = true;
            }
            ZoneOpcode::ZoneDescription if !ready => {
                ensure!(packet.body.len() >= 96, "truncated zone description");
                zone_name = String::from_utf8_lossy(cstr(&packet.body[64..96])).into_owned();
                log.zone.clone_from(&zone_name);
                log.status(
                    ConnectionState::Zoning,
                    packets,
                    Some(session.last_received_seconds()),
                )?;
                got_zone = true;
                session.send(0x067a, &0u32.to_le_bytes())?;
                session.send(0x5e3a, &0u32.to_le_bytes())?;
                session.send(0x7752, &0u32.to_le_bytes())?;
                session.send(0x0322, &[])?;
            }
            ZoneOpcode::ExperienceUpdate if got_zone && !ready && !replied_experience => {
                session.send(0x0587, &[])?;
                replied_experience = true;
            }
            ZoneOpcode::ExperienceUpdate if got_zone && !ready && replied_experience => {
                session.send(0x6563, &chat::server_filters())?;
                session.send(0x5e20, &[])?;
                session.send(0x0c11, &1u32.to_le_bytes())?;
                ready = true;
                log.send(ClientEvent::Progress(ConnectionStage::Ready))?;
                log.status(
                    ConnectionState::Connected,
                    packets,
                    Some(session.last_received_seconds()),
                )?;
                log.diagnostic(format!("Zone login sequence complete for {zone_name}; waiting for ongoing server traffic"))?;
            }
            ZoneOpcode::ValidationRejected => bail!("server rejected zone validation"),
            ZoneOpcode::LoggedOut => bail!("server logged the character out"),
            ZoneOpcode::ZoneHandoff => {
                bail!("server requested a new zone; reconnecting through world")
            }
            _ => (),
        }
        if saw_spawn && saw_profile && saw_weather && !requested {
            codec.file_response(&mut checksums)?;
            session.send(0x1251, &checksums)?;
            session.send(0x7ac5, &[])?;
            session.send(0x367d, &[])?;
            session.send(0x5966, &[])?;
            requested = true;
            log.send(ClientEvent::Progress(ConnectionStage::EnteringWorld))?;
        }
        match chat::parse(packet.opcode, &packet.body, config.include_raw) {
            Ok(Some(event)) => log.record(&zone_name, RecordEvent::Chat(event))?,
            Ok(None) => (),
            Err(error) => log.record(
                &zone_name,
                RecordEvent::DecodeError(DecodeError {
                    kind: "decode_error",
                    opcode: packet.opcode,
                    payload_hex: hex::encode(&packet.body),
                    error: error.to_string(),
                }),
            )?,
        }
    }
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
    &bytes[..bytes.iter().position(|&v| v == 0).unwrap_or(bytes.len())]
}
fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_asset_warning_reaches_the_host_without_aborting_the_response() {
        let assets: Assets =
            serde_json::from_str(r#"{"client":"test","files":{"absent.eqg":null}}"#).unwrap();
        let config = ClientConfig::new(
            "EXAMPLE_ACCOUNT",
            "EXAMPLE_PASSWORD",
            "Test Server",
            "ExampleCharacter",
        );
        let mut received = Vec::new();
        let mut handler = |event| {
            received.push(event);
            Ok(())
        };
        let mut log = Events::new(&config, &mut handler);
        let manifest = b"\x11\x00\x01unknown.eqg\0\x12\x00\x01absent.eqg\0";
        let response = file_response(&assets, manifest, &mut log).unwrap();
        let mut expected = crc32fast::hash(manifest).to_le_bytes().to_vec();
        expected.extend(b"\x11\x00\x00\x00\x00\x00\x12\x00\x00\x00\x00\x00");
        assert_eq!(response, expected);
        assert_eq!(received.len(), 1);
        let super::super::ClientEvent::Diagnostic(message) = &received[0] else {
            panic!("expected diagnostic event");
        };
        assert!(message.contains("unknown.eqg") && message.contains("checksum 0"));
        assert!(!message.contains("absent.eqg"));
    }

    #[test]
    fn validation_uses_host_metadata_and_the_current_session_key() {
        let assets: Assets = serde_json::from_str(
            r#"{"client":"test","files":{"spells_us.txt":{"crc32":1234,"size":5678}}}"#,
        )
        .unwrap();
        let identity = ClientIdentity {
            hostname: "TEST-DEVICE".into(),
            username: "test-user".into(),
        };
        let ip = "192.0.2.10".parse().unwrap();
        let first = crc1(&assets, ip, &identity, b"0123456789").unwrap();
        let mut second = crc1(&assets, ip, &identity, b"abcdefghij").unwrap();
        assert_ne!(first, second);
        p99::session_xor(&mut second[..2048], b"abcdefghij").unwrap();
        assert_eq!(second.len(), 2056);
        assert_eq!(&second[..4], &(!1234u32).to_le_bytes());
        assert_eq!(&second[4..8], &5678u32.to_le_bytes());
        assert_eq!(cstr(&second[50..66]), b"TEST-DEVICE");
        assert_eq!(cstr(&second[66..82]), b"test-user");
        assert_eq!(&second[82..90], &[127, 0, 0, 1, 192, 0, 2, 10]);
    }
}

#[cfg(test)]
mod login_tests {
    use super::*;
    use eq_login_protocol::crypto::des_encrypt;

    #[test]
    fn valid_session_keys_and_malformed_responses_are_not_bad_passwords() {
        let mut clear = vec![0; 32];
        clear[0] = 1;
        clear[8..12].copy_from_slice(&12345u32.to_le_bytes());
        clear[12..22].copy_from_slice(b"EXAMPLEKEY");
        let mut body = vec![0; 10];
        body[0] = 3;
        body[5] = 2;
        body.extend(des_encrypt(&clear, DesKeyIv::default()));
        let credentials = login_credentials(&body).unwrap();
        assert_eq!(credentials.account, 12345);
        assert_eq!(&credentials.key, b"EXAMPLEKEY");
        for length in [0, 10, 18, 26] {
            let error = login_credentials(&body[..length]).err().unwrap();
            assert!(!error.is::<LoginError>());
        }
    }
}
