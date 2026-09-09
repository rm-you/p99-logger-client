use anyhow::{ensure, Context, Result};
use p99_logger_client::{
    assets::Assets,
    chat,
    client::{
        CancellationToken, Client, ClientConfig, ClientEvent, ClientIdentity, ConnectionState,
        Record, RunOptions, SessionStatus,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashSet,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
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
    /// Translate the existing flat JSON settings into the embeddable engine config.
    fn client_config(&self) -> ClientConfig {
        ClientConfig {
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
            pass: self.pass.clone(),
            server: self.server.clone(),
            character: self.character.clone(),
            include_raw: self.include_raw,
            channels: self.channels.clone(),
            reconnect_delay: Duration::from_secs(self.reconnect_seconds),
        }
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
        None => Assets::bundled(),
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
    fn built_in_inventory_covers_multiple_zones_and_an_asset_path_overrides_it() {
        let assets = load_assets(None).unwrap();
        assert!(assets.spells().is_ok());
        for zone in ["ecommons", "qeynos", "freportw", "sebilis", "velketor"] {
            assert!(assets.files[&format!("{zone}.s3d")].is_some());
        }
        assert!(assets.files.values().all(Option::is_some));

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
        assert!(config.client_config().logs(&event(4)));
        assert!(!config.client_config().logs(&event(8)));
    }
}

/// The CLI adapter writes the library's flat records to stdout and an optional file.
struct ChatLog {
    file: Option<fs::File>,
}

impl ChatLog {
    fn new(config: &Config) -> Result<Self> {
        let file = config
            .output
            .as_ref()
            .map(|path| fs::OpenOptions::new().create(true).append(true).open(path))
            .transpose()
            .context("open JSONL output")?;
        Ok(Self { file })
    }

    fn emit(&mut self, record: &Record) -> Result<()> {
        let mut bytes = serde_json::to_vec(record)?;
        bytes.push(b'\n');
        if let Some(file) = &mut self.file {
            file.write_all(&bytes)?;
        }
        io::stdout().lock().write_all(&bytes)?;
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HealthStatus {
    state: ConnectionState,
    timestamp: i64,
    messages: u64,
    packets: u64,
    last_received_seconds: Option<u64>,
}

/// Atomically replace the CLI health file from a library status event.
fn health(path: &Path, status: &SessionStatus) -> Result<()> {
    let value = HealthStatus {
        state: status.state,
        timestamp: status.timestamp,
        messages: status.messages,
        packets: status.packets,
        last_received_seconds: status.last_received_seconds,
    };
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    fs::write(&temporary, serde_json::to_vec(&value)?)?;
    fs::rename(temporary, path)?;
    Ok(())
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

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("health") => {
            let path = args.get(2).context("usage: health STATUS_JSON")?;
            let status: HealthStatus = serde_json::from_slice(&fs::read(path)?)?;
            let age = chrono::Utc::now().timestamp() - status.timestamp;
            ensure!(
                status.state == ConnectionState::Connected
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
            let directory = Path::new(&args[2]);
            let assets = if let Some(path) = args.get(4) {
                let names: Vec<_> = fs::read_to_string(path)?
                    .lines()
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
                    .collect();
                Assets::scan(directory, &names)?
            } else {
                Assets::scan_all(directory)?
            };
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
    let identity = ClientIdentity {
        hostname: fs::read_to_string("/etc/hostname")
            .context("read container hostname")?
            .trim()
            .to_owned(),
        username: std::env::var("USER").unwrap_or_else(|_| "nobody".into()),
    };
    let mut client = Client::new(config.client_config(), identity)?;
    if config.assets.is_some() {
        client = client.with_assets(load_assets(config.assets.as_deref())?)?;
    }
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stop))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stop))?;
    let zone_duration = args
        .windows(2)
        .find(|args| args[0] == "--duration")
        .map(|args| args[1].parse::<u64>())
        .transpose()?
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs);
    let world_only = args.iter().any(|arg| arg == "--world-only");
    let options = RunOptions {
        reconnect: zone_duration.is_none() && !world_only,
        world_only,
        zone_duration,
    };
    let mut log = ChatLog::new(&config)?;
    client.run(
        &CancellationToken::from(stop),
        options,
        |event| match event {
            ClientEvent::Record(record) => log.emit(&record),
            ClientEvent::Progress(_) => Ok(()),
            ClientEvent::Status(status) => {
                if let Some(path) = &config.health {
                    health(path, &status)?;
                }
                Ok(())
            }
            ClientEvent::Diagnostic(message) => {
                eprintln!("{message}");
                Ok(())
            }
            ClientEvent::Reconnecting {
                error,
                delay_seconds,
            } => {
                eprintln!("Connection ended: {error}. Reconnecting in {delay_seconds} seconds");
                Ok(())
            }
        },
    )
}
