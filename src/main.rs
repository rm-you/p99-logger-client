use anyhow::{bail, ensure, Context, Result};
use eq_login_protocol::{
    crypto::{des_decrypt, DesKeyIv},
    login::encrypt_login_credentials,
    server_list::parse_server_list,
};
use p99_logger_client::{
    assets::Assets,
    chat,
    p99::{self, WorldCodec},
    transport::{Application, Session},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashSet,
    fs,
    io::{self, Write},
    net::{IpAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default = "default_host")]
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    user: String,
    pass: String,
    server: String,
    character: String,
    #[serde(default)]
    assets: Option<PathBuf>,
    #[serde(default)]
    output: Option<PathBuf>,
    #[serde(default)]
    health: Option<PathBuf>,
    #[serde(default)]
    include_raw: bool,
    #[serde(default)]
    channels: Option<HashSet<chat::ChannelName>>,
    #[serde(default = "default_reconnect")]
    reconnect_seconds: u64,
}

impl Config {
    /// Return whether a decoded communication belongs in the JSONL output.
    fn logs(&self, event: &chat::ChatEvent) -> bool {
        self.channels
            .as_ref()
            .is_none_or(|channels| channels.contains(&event.channel_name))
    }
}

fn default_host() -> String {
    "login.eqemulator.net".into()
}
const fn default_port() -> u16 {
    5998
}
const fn default_reconnect() -> u64 {
    30
}

/// Load a caller-supplied checksum inventory or the one compiled into the client.
fn load_assets(path: Option<&Path>) -> Result<Assets> {
    match path {
        Some(path) => serde_json::from_slice(&fs::read(path).context("read asset inventory")?)
            .context("parse asset inventory"),
        None => serde_json::from_slice(include_bytes!("../assets.json"))
            .context("parse built-in asset inventory"),
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn connection_defaults_require_only_account_server_and_character() {
        let config: Config = serde_json::from_str(
            r#"{
                "user": "EXAMPLE_LOGIN_ACCOUNT",
                "pass": "EXAMPLE_PASSWORD",
                "server": "Project 1999: Green (Velious, PvE)",
                "character": "ExampleCharacter"
            }"#,
        )
        .unwrap();

        assert_eq!(config.host, "login.eqemulator.net");
        assert_eq!(config.port, 5998);
        assert_eq!(config.assets, None);
        assert_eq!(config.reconnect_seconds, 30);
        assert_eq!(config.output, None);
        assert_eq!(config.health, None);
        assert!(!config.include_raw);
        assert_eq!(config.channels, None);
    }

    #[test]
    fn built_in_inventory_is_complete_and_an_asset_path_overrides_it() {
        let assets = load_assets(None).unwrap();
        assert_eq!(assets.files.len(), 68);
        assert!(assets.spells().is_ok());

        let config: Config = serde_json::from_str(
            r#"{
                "user": "EXAMPLE_LOGIN_ACCOUNT",
                "pass": "EXAMPLE_PASSWORD",
                "server": "Project 1999: Green (Velious, PvE)",
                "character": "ExampleCharacter",
                "assets": "/custom/assets.json"
            }"#,
        )
        .unwrap();
        assert_eq!(config.assets, Some(PathBuf::from("/custom/assets.json")));
    }

    #[test]
    fn raw_packet_logging_is_opt_in() {
        let config: Config = serde_json::from_str(
            r#"{
                "user": "EXAMPLE_LOGIN_ACCOUNT",
                "pass": "EXAMPLE_PASSWORD",
                "server": "Project 1999: Blue (Velious, PvE)",
                "character": "ExampleCharacter",
                "include_raw": true
            }"#,
        )
        .unwrap();

        assert!(config.include_raw);
    }

    #[test]
    fn channel_filter_accepts_canonical_names_and_chat_aliases() {
        let config: Config = serde_json::from_str(
            r#"{
                "user": "EXAMPLE_LOGIN_ACCOUNT",
                "pass": "EXAMPLE_PASSWORD",
                "server": "Project 1999: Blue (Velious, PvE)",
                "character": "ExampleCharacter",
                "channels": ["auc", "ooc", "gu"]
            }"#,
        )
        .unwrap();
        let channels = config.channels.as_ref().unwrap();

        assert_eq!(channels.len(), 3);
        assert!(channels.contains(&chat::ChannelName::Auction));
        assert!(channels.contains(&chat::ChannelName::Ooc));
        assert!(channels.contains(&chat::ChannelName::Guild));

        let event = |channel| {
            let mut body = vec![0; 148];
            body[132..136].copy_from_slice(&u32::to_le_bytes(channel));
            body.push(0);
            chat::parse(0x1004, &body, false).unwrap().unwrap()
        };
        assert!(config.logs(&event(4)));
        assert!(!config.logs(&event(8)));
    }
}

struct ChatLog {
    file: Option<fs::File>,
    session: String,
    messages: u64,
}

#[derive(Serialize)]
struct LogRecord<'a, T> {
    timestamp: String,
    server: &'a str,
    character: &'a str,
    zone: &'a str,
    session_id: &'a str,
    message_id: u64,
    #[serde(flatten)]
    event: &'a T,
}

impl ChatLog {
    /// Open the optional append-only JSONL destination.
    fn new(config: &Config) -> Result<Self> {
        let file = config
            .output
            .as_ref()
            .map(|path| fs::OpenOptions::new().create(true).append(true).open(path))
            .transpose()
            .context("open JSONL output")?;
        Ok(Self {
            file,
            session: String::new(),
            messages: 0,
        })
    }

    /// Add common session metadata and write one complete JSONL record.
    fn emit<T: Serialize>(&mut self, config: &Config, zone: &str, event: T) -> Result<()> {
        self.messages += 1;
        let record = LogRecord {
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            server: &config.server,
            character: &config.character,
            zone,
            session_id: &self.session,
            message_id: self.messages,
            event: &event,
        };
        let mut bytes = serde_json::to_vec(&record)?;
        bytes.push(b'\n');
        if let Some(file) = &mut self.file {
            file.write_all(&bytes)?;
        }
        io::stdout().lock().write_all(&bytes)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum HealthState {
    Connecting,
    Connected,
    Zoning,
    Disconnected,
    Stopped,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HealthStatus {
    state: HealthState,
    timestamp: i64,
    messages: u64,
    packets: u64,
    last_received_seconds: Option<u64>,
}

/// Atomically replace the health file with the collector's latest state.
fn health(
    config: &Config,
    state: HealthState,
    messages: u64,
    packets: u64,
    last_received_seconds: Option<u64>,
) -> Result<()> {
    if let Some(path) = &config.health {
        let status = HealthStatus {
            state,
            timestamp: chrono::Utc::now().timestamp(),
            messages,
            packets,
            last_received_seconds,
        };
        let mut temporary = path.as_os_str().to_owned();
        temporary.push(".tmp");
        let temporary = PathBuf::from(temporary);
        fs::write(&temporary, serde_json::to_vec(&status)?)?;
        fs::rename(temporary, path)?;
    }
    Ok(())
}

struct Credentials {
    account: u32,
    key: [u8; 10],
}

#[derive(Serialize)]
struct DecodeErrorEvent {
    #[serde(rename = "type")]
    kind: &'static str,
    opcode: u16,
    payload_hex: String,
    error: String,
}

#[derive(Deserialize)]
struct CapturedPacket {
    direction: String,
    opcode: u16,
    payload_hex: String,
    time: Value,
}

#[derive(Serialize)]
struct TimestampedEvent<'a, T> {
    timestamp: &'a Value,
    #[serde(flatten)]
    event: &'a T,
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
fn next(session: &mut Session, deadline: Instant, stop: &AtomicBool) -> Result<Application> {
    loop {
        ensure!(!stop.load(Ordering::Relaxed), "shutdown requested");
        ensure!(Instant::now() < deadline, "application handshake timed out");
        if let Some(packet) = session.receive()? {
            return Ok(packet);
        }
    }
}

/// Authenticate, select the configured server, and return its world endpoint.
fn login(config: &Config, stop: &AtomicBool) -> Result<(Credentials, String)> {
    let mut session = Session::connect(address(&config.host, config.port)?, false)?;
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
                ensure!(packet.body.len() >= 34, "login was rejected");
                let ciphertext = &packet.body[10..];
                let clear =
                    des_decrypt(&ciphertext[..ciphertext.len() / 8 * 8], DesKeyIv::default())?;
                ensure!(clear.len() >= 23, "invalid login response");
                let account = le32(&clear[8..12]);
                ensure!(
                    account != 0 && account != u32::MAX && clear[0] == 1,
                    "login was rejected"
                );
                let key = cstr(&clear[12..23])
                    .try_into()
                    .context("invalid login session key")?;
                credentials = Some(Credentials { account, key });
                let mut request = vec![0; 10];
                request[0] = 4;
                session.send(4, &request)?;
                eprintln!("Login server authenticated the account");
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
                return Ok((
                    credentials.context("play response before authentication")?,
                    selected.context("play response before selection")?,
                ));
            }
            _ => (),
        }
    }
}

/// Build the current P99 CRC1 client-validation response.
fn crc1(assets: &Assets, session: &Session, key: &[u8]) -> Result<Vec<u8>> {
    let spells = assets.spells()?;
    let mut body = vec![0; 2056];
    body[..4].copy_from_slice(&(!spells.crc32).to_le_bytes());
    body[4..8].copy_from_slice(&u32::try_from(spells.size)?.to_le_bytes());
    // Current V62 replaces the legacy random spell samples with this metadata
    // block. These fields also occur in successful, decoded stock responses.
    body[8..12].fill(0xff);
    body[45] = 1;
    body[46] = 27;
    let hostname = fs::read_to_string("/etc/hostname")
        .context("read container hostname")?
        .trim()
        .to_uppercase();
    put_string(&mut body[50..66], &hostname)?;
    let username = std::env::var("USER").unwrap_or_else(|_| "nobody".into());
    put_string(&mut body[66..82], &username)?;
    body[82..86].copy_from_slice(&[127, 0, 0, 1]);
    if let IpAddr::V4(ip) = session.local_address()?.ip() {
        if !ip.is_loopback() {
            body[86..90].copy_from_slice(&ip.octets());
        }
    }
    p99::session_xor(&mut body[..2048], key)?;
    Ok(body)
}

struct CharacterSession<'a> {
    config: &'a Config,
    credentials: &'a Credentials,
    stop: &'a AtomicBool,
    duration: u64,
}

/// Complete world validation, select the character, and follow its zone handoff.
fn world(
    context: &CharacterSession<'_>,
    assets: &Assets,
    ip: &str,
    world_only: bool,
    log: &mut ChatLog,
) -> Result<()> {
    let config = context.config;
    let credentials = context.credentials;
    let stop = context.stop;
    let mut session = Session::connect(address(ip, 9000)?, true)?;
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
            if config.logs(&event) {
                log.emit(config, "", event)?;
            }
        }
        eprintln!(
            "World received 0x{:04x} ({} bytes)",
            packet.opcode,
            packet.body.len()
        );
        match WorldOpcode::from(packet.opcode) {
            WorldOpcode::ApprovalChallenge => {
                session.send(0x3c25, &codec.approve(&packet.body)?)?;
            }
            WorldOpcode::FileManifest => {
                codec.manifest(&mut packet.body)?;
                let mut response = assets.file_response(&packet.body)?;
                codec.file_response(&mut response)?;
                session.send(0x5072, &crc1(assets, &session, &credentials.key)?)?;
                session.send(0x1251, &response)?;
            }
            WorldOpcode::ValidationResult => {
                ensure!(
                    packet.body == [0],
                    "world client validation returned {}",
                    hex::encode(&packet.body)
                );
                accepted = true;
                eprintln!("World accepted native V62 client validation");
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
            }
            WorldOpcode::ZoneHandoff => {
                ensure!(entered && packet.body.len() >= 130, "invalid zone handoff");
                let host = std::str::from_utf8(cstr(&packet.body[..128]))?.to_owned();
                let port = u16::from_le_bytes(packet.body[128..130].try_into().unwrap());
                let manifest = codec.zone_manifest(&packet.body)?;
                let response = assets.file_response(&manifest)?;
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
    log: &mut ChatLog,
) -> Result<()> {
    let config = context.config;
    let credentials = context.credentials;
    let stop = context.stop;
    let duration = context.duration;
    let mut session = Session::connect(address(host, port)?, true)?;
    session.send(0x7752, &0u32.to_le_bytes())?;
    let mut entry = vec![0; 68];
    put_string(&mut entry[4..], &config.character)?;
    codec.zone_entry(&entry)?;
    session.send(0x7213, &entry)?;
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
        if stop.load(Ordering::Relaxed)
            || (duration > 0 && connected.elapsed() >= Duration::from_secs(duration))
        {
            session.close()?;
            health(config, HealthState::Stopped, log.messages, packets, None)?;
            return Ok(());
        }
        if progress.elapsed() >= Duration::from_secs(30) {
            health(
                config,
                if ready && session.last_received_seconds() < 60 {
                    HealthState::Connected
                } else {
                    HealthState::Zoning
                },
                log.messages,
                packets,
                Some(session.last_received_seconds()),
            )?;
            eprintln!(
                "Zone session: {packets} application packets, {} communication records",
                log.messages
            );
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
            eprintln!(
                "Zone received 0x{:04x} ({} bytes)",
                packet.opcode,
                packet.body.len()
            );
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
                health(
                    config,
                    HealthState::Connected,
                    log.messages,
                    packets,
                    Some(session.last_received_seconds()),
                )?;
                eprintln!("Zone login sequence complete for {zone_name}; waiting for ongoing server traffic");
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
        }
        match chat::parse(packet.opcode, &packet.body, config.include_raw) {
            Ok(Some(event)) if config.logs(&event) => log.emit(config, &zone_name, event)?,
            Ok(Some(_)) => (),
            Ok(None) => (),
            Err(error) => log.emit(
                config,
                &zone_name,
                DecodeErrorEvent {
                    kind: "decode_error",
                    opcode: packet.opcode,
                    payload_hex: hex::encode(&packet.body),
                    error: error.to_string(),
                },
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

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("health") => {
            let path = args.get(2).context("usage: health STATUS_JSON")?;
            let status: HealthStatus = serde_json::from_slice(&fs::read(path)?)?;
            let age = chrono::Utc::now().timestamp() - status.timestamp;
            ensure!(
                status.state == HealthState::Connected
                    && (0..=60).contains(&age)
                    && status.last_received_seconds.is_some_and(|seconds| {
                        seconds
                            .checked_add(age.cast_unsigned())
                            .is_some_and(|total| total < 60)
                    }),
                "collector is not connected"
            );
            return Ok(());
        }
        Some("scan-assets") => {
            ensure!(
                args.len() == 4 || args.len() == 5,
                "usage: scan-assets INSTALL OUTPUT [FILE_LIST]"
            );
            let list = if let Some(path) = args.get(4) {
                fs::read_to_string(path)?
            } else {
                include_str!("../protocol/p99-v62-files.txt").to_owned()
            };
            let names: Vec<_> = list
                .lines()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect();
            let assets = Assets::scan(Path::new(&args[2]), &names)?;
            fs::write(&args[3], serde_json::to_vec_pretty(&assets)?)?;
            eprintln!("Inventoried {} files", assets.files.len());
            return Ok(());
        }
        Some("decode-events") => {
            ensure!(
                args.len() == 3,
                "usage: decode-events APPLICATION_PACKETS_JSON"
            );
            let records: Vec<CapturedPacket> = serde_json::from_slice(&fs::read(&args[2])?)?;
            let mut output = io::BufWriter::new(io::stdout().lock());
            for record in records {
                if record.direction != "server" {
                    continue;
                }
                let body = hex::decode(&record.payload_hex)?;
                if let Some(event) = chat::parse(record.opcode, &body, true)? {
                    serde_json::to_writer(
                        &mut output,
                        &TimestampedEvent {
                            timestamp: &record.time,
                            event: &event,
                        },
                    )?;
                    writeln!(output)?;
                }
            }
            return Ok(());
        }
        _ => (),
    }
    ensure!(
        args.len() >= 2,
        "usage: p99-logger-client CONFIG [--world-only]"
    );
    let config: Config = serde_json::from_slice(&fs::read(&args[1])?)?;
    ensure!(
        !config.user.is_empty()
            && !config.pass.is_empty()
            && !config.server.is_empty()
            && !config.character.is_empty(),
        "required config fields are empty"
    );
    let assets = load_assets(config.assets.as_deref())?;
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stop))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stop))?;
    let duration = args
        .windows(2)
        .find(|args| args[0] == "--duration")
        .map(|args| args[1].parse::<u64>())
        .transpose()?
        .unwrap_or(0);
    let world_only = args.iter().any(|arg| arg == "--world-only");
    ensure!(
        config.reconnect_seconds >= 10,
        "reconnect_seconds must be at least 10"
    );
    let mut log = ChatLog::new(&config)?;
    loop {
        log.session = format!("{:016x}", rand::random::<u64>());
        log.messages = 0;
        health(&config, HealthState::Connecting, 0, 0, None)?;
        let result = login(&config, &stop).and_then(|(credentials, ip)| {
            let context = CharacterSession {
                config: &config,
                credentials: &credentials,
                stop: &stop,
                duration,
            };
            world(&context, &assets, &ip, world_only, &mut log)
        });
        if result.is_ok() || stop.load(Ordering::Relaxed) {
            health(&config, HealthState::Stopped, log.messages, 0, None)?;
            return Ok(());
        }
        health(&config, HealthState::Disconnected, log.messages, 0, None)?;
        if duration > 0 || world_only {
            return result;
        }
        eprintln!(
            "Connection ended: {:#}. Reconnecting in {} seconds",
            result.unwrap_err(),
            config.reconnect_seconds
        );
        let retry = Instant::now() + Duration::from_secs(config.reconnect_seconds);
        while Instant::now() < retry && !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(200));
        }
        if stop.load(Ordering::Relaxed) {
            health(&config, HealthState::Stopped, log.messages, 0, None)?;
            return Ok(());
        }
    }
}
