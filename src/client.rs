//! Blocking, cancellable session engine for native applications and the CLI.
//!
//! The host supplies credentials and validation metadata, starts a worker, and
//! consumes events on its UI thread. It owns credential persistence and logs.
//! This example stops on a full or closed queue rather than dropping records.
//!
//! ```no_run
//! use p99_logger_client::{chat::OutboundChat, client::{CancellationToken,
//!     Client, ClientCommand, ClientConfig, ClientIdentity, RunOptions}};
//! use std::{sync::mpsc, thread};
//!
//! # fn example() -> anyhow::Result<()> {
//! let config = ClientConfig::new("EXAMPLE_ACCOUNT", "EXAMPLE_PASSWORD",
//!     "Project 1999: Green (Velious, PvE)", "ExampleCharacter");
//! // Supply short metadata chosen by the host app (1 to 15 bytes per field).
//! let identity = ClientIdentity { hostname: "example-device".into(),
//!     username: "example-user".into() };
//! let client = Client::new(config, identity)?;
//! let cancel = CancellationToken::default();
//! let worker_cancel = cancel.clone();
//! let (events, receiver) = mpsc::sync_channel(512);
//! let (commands, command_queue) = mpsc::sync_channel(32);
//! let worker = thread::spawn(move || {
//!     client.run_with_commands(&worker_cancel, RunOptions::default(), &command_queue, |event| {
//!         events.try_send(event).map_err(|_| anyhow::anyhow!("UI event queue unavailable"))
//!     })
//! });
//! // After observing ConnectionStage::Ready, this is equivalent to `/say ok`.
//! commands.try_send(ClientCommand::SendChat(OutboundChat::Say("ok".into())))?;
//! // During the UI event loop, drain receiver.try_iter() and render the events.
//! // On Disconnect or app shutdown, cancel and await worker completion.
//! cancel.cancel();
//! worker.join().expect("session worker panicked")?;
//! # drop(receiver);
//! # Ok(())
//! # }
//! ```

mod quarm;
mod session;

use crate::{
    assets::Assets,
    chat::{ChannelName, ChatEvent, OutboundChat},
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Receiver,
        Arc,
    },
    time::{Duration, Instant},
};

/// Wire protocol and client family used by a server.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerProtocol {
    /// Project 1999's Titanium/P99-V62 protocol.
    #[default]
    #[serde(alias = "p99", alias = "project_1999")]
    Project1999,
    /// Project Quarm's Windows TAKP/EQMac protocol.
    Quarm,
}

impl ServerProtocol {
    /// Return the public login endpoint normally used by this protocol.
    #[must_use]
    pub const fn default_endpoint(self) -> (&'static str, u16) {
        match self {
            Self::Project1999 => ("login.eqemulator.net", 5998),
            Self::Quarm => ("loginserver.takproject.net", 6000),
        }
    }
}

impl FromStr for ServerProtocol {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "p99" | "project1999" | "project_1999" => Ok(Self::Project1999),
            "quarm" => Ok(Self::Quarm),
            _ => anyhow::bail!("unknown server protocol {value:?}"),
        }
    }
}

/// Connection and logging preferences. Intentionally does not implement Debug
/// or Serialize, so credentials are not included in diagnostic output.
#[derive(Clone)]
pub struct ClientConfig {
    pub protocol: ServerProtocol,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
    pub server: String,
    pub character: String,
    pub include_raw: bool,
    /// None logs every channel; an empty set logs no decoded chat.
    pub channels: Option<HashSet<ChannelName>>,
    pub reconnect_delay: Duration,
}

impl ClientConfig {
    /// Configure a character with the default login endpoint and all chat channels.
    pub fn new(
        user: impl Into<String>,
        pass: impl Into<String>,
        server: impl Into<String>,
        character: impl Into<String>,
    ) -> Self {
        Self::for_protocol(ServerProtocol::Project1999, user, pass, server, character)
    }

    /// Configure a character with a protocol's normal login endpoint.
    pub fn for_protocol(
        protocol: ServerProtocol,
        user: impl Into<String>,
        pass: impl Into<String>,
        server: impl Into<String>,
        character: impl Into<String>,
    ) -> Self {
        let (host, port) = protocol.default_endpoint();
        Self {
            protocol,
            host: host.into(),
            port,
            user: user.into(),
            pass: pass.into(),
            server: server.into(),
            character: character.into(),
            include_raw: false,
            channels: None,
            reconnect_delay: Duration::from_secs(30),
        }
    }

    fn validate(&self) -> Result<()> {
        for value in [
            &self.host,
            &self.user,
            &self.pass,
            &self.server,
            &self.character,
        ] {
            ensure!(
                !value.is_empty() && !value.contains('\0'),
                "required connection fields must be nonempty and contain no NUL"
            );
        }
        ensure!(self.port != 0, "login port must be nonzero");
        if self.protocol == ServerProtocol::Quarm {
            ensure!(
                self.user.len() < 20 && self.pass.len() < 20,
                "Quarm login fields must fit in 19 bytes"
            );
        }
        ensure!(
            self.character.len() < 64,
            "character name exceeds protocol field size"
        );
        ensure!(
            self.reconnect_delay >= Duration::from_secs(10),
            "reconnect delay must be at least 10 seconds"
        );
        Ok(())
    }

    /// Return whether a decoded communication should be delivered to the caller.
    #[must_use]
    pub fn logs(&self, event: &ChatEvent) -> bool {
        self.channels
            .as_ref()
            .is_none_or(|channels| channels.contains(&event.channel_name))
    }
}

/// Host-provided metadata for the V62 validation packet. Each field must fit
/// within 15 UTF-8 bytes; the engine uppercases hostname before checking its size.
#[derive(Clone)]
pub struct ClientIdentity {
    pub hostname: String,
    pub username: String,
}

/// Cooperative shutdown, shared between the session worker and its owner.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Request shutdown. A cancelled token remains cancelled; use a new one to reconnect.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    fn flag(&self) -> &AtomicBool {
        &self.0
    }
}

impl From<Arc<AtomicBool>> for CancellationToken {
    /// Adopt an existing shutdown flag, for example one registered with a signal handler.
    fn from(flag: Arc<AtomicBool>) -> Self {
        Self(flag)
    }
}

/// A confirmed login rejection that cannot be resolved by reconnecting.
/// Hosts can downcast the error returned by `Client::run` to present a specific message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginError {
    /// The login server rejected the account/password pair.
    InvalidCredentials,
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCredentials => f.write_str("Login account or password was rejected"),
        }
    }
}

impl std::error::Error for LoginError {}

/// Limits for one run; transient failures reconnect until cancellation by default.
#[derive(Clone, Debug)]
pub struct RunOptions {
    pub reconnect: bool,
    pub world_only: bool,
    /// Optional maximum time in the zone, including zone admission.
    pub zone_duration: Option<Duration>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            reconnect: true,
            world_only: false,
            zone_duration: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Connecting,
    Connected,
    Zoning,
    Disconnected,
    Stopped,
}

/// Periodic session state suitable for a UI status indicator or health adapter.
#[derive(Clone, Debug, Serialize)]
pub struct SessionStatus {
    pub state: ConnectionState,
    pub timestamp: i64,
    pub session_id: String,
    pub zone: String,
    pub messages: u64,
    pub packets: u64,
    pub last_received_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DecodeError {
    #[serde(rename = "type")]
    kind: &'static str,
    pub opcode: u16,
    pub payload_hex: String,
    pub error: String,
}

/// Preserves the existing flat chat/decode_error JSON representation.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum RecordEvent {
    Chat(ChatEvent),
    DecodeError(DecodeError),
}

/// An owned communication record that can cross a thread or UI boundary.
#[derive(Clone, Debug, Serialize)]
pub struct Record {
    pub timestamp: String,
    pub server: String,
    pub character: String,
    pub zone: String,
    pub session_id: String,
    pub message_id: u64,
    #[serde(flatten)]
    pub event: RecordEvent,
}

/// Ordered connection milestones, from the start of an attempt to zone admission.
/// These describe completed protocol work, not elapsed time or packet counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStage {
    ConnectingLogin,
    Authenticating,
    SelectingServer,
    ConnectingWorld,
    SelectingCharacter,
    ConnectingZone,
    LoadingCharacter,
    EnteringWorld,
    Ready,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ClientEvent {
    Status(SessionStatus),
    Progress(ConnectionStage),
    Record(Box<Record>),
    Diagnostic(String),
    Reconnecting { error: String, delay_seconds: u64 },
}

/// Work submitted by the host while the character is connected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientCommand {
    SendChat(OutboundChat),
}

/// A reusable native client. The caller owns the worker thread and event storage.
pub struct Client {
    config: ClientConfig,
    identity: ClientIdentity,
    assets: Assets,
}

impl Client {
    /// Validate settings and use the checksum inventory bundled with the crate.
    pub fn new(config: ClientConfig, mut identity: ClientIdentity) -> Result<Self> {
        config.validate()?;
        identity.hostname = identity.hostname.to_uppercase();
        for value in [&identity.hostname, &identity.username] {
            ensure!(
                !value.is_empty() && value.len() < 16 && !value.contains('\0'),
                "client identity fields must contain 1 to 15 bytes and no NUL"
            );
        }
        Ok(Self {
            config,
            identity,
            assets: Assets::bundled()?,
        })
    }

    /// Replace the bundled checksum inventory with an application-supplied one.
    pub fn with_assets(mut self, assets: Assets) -> Result<Self> {
        assets.spells()?;
        self.assets = assets;
        Ok(self)
    }

    /// Connect and deliver events synchronously until completion or cancellation.
    /// Run on a worker thread and keep the handler fast (typically enqueue events).
    /// A confirmed credential rejection returns `LoginError` without reconnecting.
    /// A handler error terminates the run, without reconnecting or invoking it again.
    /// Network waits and retry delays observe cancellation; system DNS resolution
    /// remains a blocking platform call. Sessions close when the run unwinds.
    pub fn run(
        &self,
        cancel: &CancellationToken,
        options: RunOptions,
        mut handler: impl FnMut(ClientEvent) -> Result<()>,
    ) -> Result<()> {
        self.run_inner(cancel, options, None, &mut handler)
    }

    /// Connect and process commands from a nonblocking host-owned queue.
    /// Commands are consumed only after zone admission and may remain queued
    /// while a reconnect is in progress. Dropping every sender disables input.
    pub fn run_with_commands(
        &self,
        cancel: &CancellationToken,
        options: RunOptions,
        commands: &Receiver<ClientCommand>,
        mut handler: impl FnMut(ClientEvent) -> Result<()>,
    ) -> Result<()> {
        self.run_inner(cancel, options, Some(commands), &mut handler)
    }

    fn run_inner(
        &self,
        cancel: &CancellationToken,
        options: RunOptions,
        commands: Option<&Receiver<ClientCommand>>,
        handler: &mut dyn FnMut(ClientEvent) -> Result<()>,
    ) -> Result<()> {
        let mut events = Events::new(&self.config, handler);
        loop {
            if cancel.is_cancelled() {
                return events.status(ConnectionState::Stopped, 0, None);
            }
            events.reset();
            events.status(ConnectionState::Connecting, 0, None)?;
            events.send(ClientEvent::Progress(ConnectionStage::ConnectingLogin))?;
            let result = session::run(
                &self.config,
                &self.identity,
                &self.assets,
                cancel,
                &options,
                commands,
                &mut events,
            );
            if result
                .as_ref()
                .is_err_and(|error| error.is::<EventDeliveryError>())
            {
                return result;
            }
            if result.is_ok() || cancel.is_cancelled() {
                return events.status(ConnectionState::Stopped, 0, None);
            }
            events.status(ConnectionState::Disconnected, 0, None)?;
            if !options.reconnect || result.as_ref().is_err_and(|error| error.is::<LoginError>()) {
                return result;
            }
            events.send(ClientEvent::Reconnecting {
                error: format!("{:#}", result.unwrap_err()),
                delay_seconds: self.config.reconnect_delay.as_secs(),
            })?;
            let retry = Instant::now()
                .checked_add(self.config.reconnect_delay)
                .context("reconnect delay exceeds clock range")?;
            while Instant::now() < retry && !cancel.is_cancelled() {
                std::thread::sleep(
                    retry
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(200)),
                );
            }
        }
    }
}

#[derive(Debug)]
struct EventDeliveryError(anyhow::Error);

impl fmt::Display for EventDeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "deliver client event: {}", self.0)
    }
}

impl std::error::Error for EventDeliveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

struct Events<'a> {
    config: &'a ClientConfig,
    handler: &'a mut dyn FnMut(ClientEvent) -> Result<()>,
    session_id: String,
    zone: String,
    messages: u64,
}

impl<'a> Events<'a> {
    fn new(
        config: &'a ClientConfig,
        handler: &'a mut dyn FnMut(ClientEvent) -> Result<()>,
    ) -> Self {
        Self {
            config,
            handler,
            session_id: String::new(),
            zone: String::new(),
            messages: 0,
        }
    }

    fn reset(&mut self) {
        self.session_id = format!("{:016x}", rand::random::<u64>());
        self.zone.clear();
        self.messages = 0;
    }

    fn send(&mut self, event: ClientEvent) -> Result<()> {
        (self.handler)(event).map_err(|error| EventDeliveryError(error).into())
    }

    fn diagnostic(&mut self, message: String) -> Result<()> {
        self.send(ClientEvent::Diagnostic(message))
    }

    fn status(
        &mut self,
        state: ConnectionState,
        packets: u64,
        last_received_seconds: Option<u64>,
    ) -> Result<()> {
        self.send(ClientEvent::Status(SessionStatus {
            state,
            timestamp: chrono::Utc::now().timestamp(),
            session_id: self.session_id.clone(),
            zone: self.zone.clone(),
            messages: self.messages,
            packets,
            last_received_seconds,
        }))
    }

    fn record(&mut self, zone: &str, event: RecordEvent) -> Result<()> {
        if let RecordEvent::Chat(chat) = &event {
            if !self.config.logs(chat) {
                return Ok(());
            }
        }
        self.messages += 1;
        self.send(ClientEvent::Record(Box::new(Record {
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            server: self.config.server.clone(),
            character: self.config.character.clone(),
            zone: zone.to_owned(),
            session_id: self.session_id.clone(),
            message_id: self.messages,
            event,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat;

    #[test]
    fn protocol_names_are_stable_and_p99_aliases_remain_readable() {
        assert_eq!(
            serde_json::to_string(&ServerProtocol::Project1999).unwrap(),
            r#""project1999""#
        );
        for name in [r#""project1999""#, r#""p99""#, r#""project_1999""#] {
            assert_eq!(
                serde_json::from_str::<ServerProtocol>(name).unwrap(),
                ServerProtocol::Project1999
            );
        }
        assert_eq!(
            "QUARM".parse::<ServerProtocol>().unwrap(),
            ServerProtocol::Quarm
        );
    }

    fn chat(channel: u32) -> ChatEvent {
        let mut packet = vec![0; 148];
        packet[64..70].copy_from_slice(b"Sender");
        packet[132..136].copy_from_slice(&channel.to_le_bytes());
        packet.extend(b"Example message\0");
        chat::parse(0x1004, &packet, false).unwrap().unwrap()
    }

    #[test]
    fn records_preserve_flat_json_filtering_and_per_session_ids() {
        let mut config = ClientConfig::new(
            "EXAMPLE_ACCOUNT",
            "EXAMPLE_PASSWORD",
            "Test Server",
            "ExampleCharacter",
        );
        config.channels = Some(HashSet::from([ChannelName::Auction]));
        let mut received = Vec::new();
        let mut handler = |event| {
            received.push(event);
            Ok(())
        };
        let mut events = Events::new(&config, &mut handler);
        events.reset();
        events
            .record("testzone", RecordEvent::Chat(chat(8)))
            .unwrap();
        events
            .record("testzone", RecordEvent::Chat(chat(4)))
            .unwrap();
        events
            .record(
                "testzone",
                RecordEvent::DecodeError(DecodeError {
                    kind: "decode_error",
                    opcode: 0x1004,
                    payload_hex: "00".into(),
                    error: "synthetic truncation".into(),
                }),
            )
            .unwrap();
        assert_eq!(events.messages, 2);
        events.reset();
        events
            .record("testzone", RecordEvent::Chat(chat(4)))
            .unwrap();

        let records: Vec<_> = received
            .into_iter()
            .map(|event| match event {
                ClientEvent::Record(record) => serde_json::to_value(record).unwrap(),
                _ => panic!("unexpected event"),
            })
            .collect();
        assert_eq!(records.len(), 3);
        let record = &records[0];
        assert_eq!(record["type"], "chat");
        assert_eq!(record["channel_name"], "auction");
        assert_eq!(record["channel"], 4);
        assert_eq!(record["text"], "Example message");
        assert_eq!(record["sender"], "Sender");
        assert_eq!(record["server"], "Test Server");
        assert_eq!(record["character"], "ExampleCharacter");
        assert_eq!(record["zone"], "testzone");
        assert_eq!(record["message_id"], 1);
        assert!(record.get("event").is_none() && record.get("payload_hex").is_none());
        assert!(
            chrono::DateTime::parse_from_rfc3339(record["timestamp"].as_str().unwrap()).is_ok()
        );
        assert_eq!(records[1]["type"], "decode_error");
        assert_eq!(records[1]["message_id"], 2);
        assert_eq!(records[1]["payload_hex"], "00");
        assert_eq!(records[1]["session_id"], record["session_id"]);
        assert_eq!(records[2]["message_id"], 1);
        assert_ne!(records[2]["session_id"], record["session_id"]);
        let serialized = serde_json::to_string(&records).unwrap();
        assert!(
            !serialized.contains("EXAMPLE_ACCOUNT") && !serialized.contains("EXAMPLE_PASSWORD")
        );
    }

    #[test]
    fn default_channels_include_unknown_and_empty_filter_suppresses_chat() {
        let mut config = ClientConfig::new(
            "EXAMPLE_ACCOUNT",
            "EXAMPLE_PASSWORD",
            "Test Server",
            "ExampleCharacter",
        );
        assert!(config.logs(&chat(999)));
        config.channels = Some(HashSet::new());
        assert!(!config.logs(&chat(999)) && !config.logs(&chat(4)));
    }
}
