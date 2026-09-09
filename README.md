# p99-logger-client

A native Rust client that logs into Project 1999, enters an existing character,
keeps the character at its saved position, and writes received communications
as JSONL. It runs headlessly without Wine, the EverQuest executable, or game
assets at runtime. The small checksum inventory required by the server is built
into the executable image.

The client targets the Titanium/P99 V62 protocol. Live tests on P99 Green have
received auction and OOC messages, including complete item-link data. It never
sends chat, navigates, attacks, or performs other gameplay.

## Configuration

Copy [config.example.json](config.example.json) to a private location and set
the login account, password, exact server-list name, and existing character.
Keep the configuration and output private. The included Compose setup uses
`.local/`, which Git and Docker both exclude.

The public P99 server-list names are:

| Server | `server` value |
| --- | --- |
| Green | `Project 1999: Green (Velious, PvE)` |
| Blue | `Project 1999: Blue (Velious, PvE)` |

The only required values are the login account, password, server, and
character. A fictional Blue configuration is:

```json
{
  "user": "EXAMPLE_LOGIN_ACCOUNT",
  "pass": "EXAMPLE_PASSWORD",
  "server": "Project 1999: Blue (Velious, PvE)",
  "character": "ExampleCharacter"
}
```

The account and character must already exist; this client does not create or
modify them. The `server` value is matched case-insensitively against the name
returned by the live server list, so retain its punctuation and spacing.

The optional fields are `host` (default `login.eqemulator.net`), `port`
(default `5998`), `assets`, `output`, `health`, `channels`, `include_raw`
(default `false`), and `reconnect_seconds` (default `30`). With no `output`,
JSONL is written only to standard output. When `assets` is omitted, the client
uses the inventory compiled into the binary; set it to a readable path to
override that inventory. The example supplies the fixed `output` and `health`
paths used by Compose, so users still edit only the four required values.

Omit `channels` to log every decoded communication category. Set it to a list
to keep only selected categories. These examples are equivalent; the short
names match the familiar EverQuest chat commands:

```json
"channels": ["auction", "ooc"]
```

```json
"channels": ["auc", "ooc"]
```

To collect only guild chat, use `"channels": ["gu"]`. The canonical names are
`guild`, `group`, `shout`, `auction`, `ooc`, `broadcast`, `tell`, `say`,
`gm_say`, `raid`, `emote`, `motd`, `system`, `guild_motd`, and `unknown`.
Filtering applies to decoded chat records; malformed recognized packets remain
visible as `decode_error` records.

The repository and published image include checksums for the installed zone
and model archives, along with the world validation files. The server supplies
a manifest of filenames during world login and zone handoff; the client looks
up and sends only the requested checksums. No zone selection is needed in the
configuration.

To refresh the inventory after a P99 patch or use a different installation,
generate it from the current game files; the files are not needed afterward:

```sh
mkdir -p .local/collector/config .local/collector/data
cp config.example.json .local/collector/config/config.json
chmod 600 .local/collector/config/config.json

docker run --rm --network none --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=/absolute/path/to/EverQuest,target=/eq,readonly" \
  --mount "type=bind,source=$(pwd)/.local/collector/config,target=/out" \
  ghcr.io/rm-you/p99-logger-client:latest \
  scan-assets /eq /out/assets.json
```

Then add `"assets": "/config/assets.json"` to the private configuration. The
Compose configuration already mounts that directory read-only at `/config`.

By default, `scan-assets` inventories the known validation files, all installed
`.s3d` and `.eqg` archives, and zone `_chr.txt` and `_assets.txt` lists. Account
settings, character settings, and chat logs are not scanned. Only filenames,
sizes, and CRC32 values for measured files are stored; absent files are omitted.

To scan an exact set of files instead, pass a text file containing their names
as the final `scan-assets` argument. For an unrecognized filename in a server
manifest, the client emits a warning and sends checksum `0`, letting the server
decide whether to accept it. Older inventories containing explicit `null`
entries remain supported and also send `0`. If the server requires the real
checksum, refresh the inventory; retrying alone cannot fix it. Malformed
manifests still fail validation. The expanded inventory covers installed
assets, but live zone entry has only been verified in East Commonlands.

## Run with Compose

```sh
P99_UID=$(id -u) P99_GID=$(id -g) docker compose up -d
tail -f .local/collector/data/chat.jsonl
docker compose ps
docker compose logs --tail 30 collector
```

The container runs as the configured unprivileged UID/GID, drops all Linux
capabilities, uses a read-only root filesystem and configuration mount, and
appends JSONL to `.local/collector/data/chat.jsonl`. Its health check requires
completed zone entry and recent valid server traffic.

On connection loss, the process reports the failure and repeats the complete
login flow after `reconnect_seconds`, deriving fresh keys for every session.
SIGTERM closes the active session. Docker's `unless-stopped` policy restarts a
process that exits. The JSONL file is append-only and needs an external
retention policy.

EverQuest may temporarily deny a new world entry when the previous session did
not exit cleanly. The collector treats that response as a connection failure
and keeps retrying; it does not reuse the rejected session's keys.

## JSONL records

Each record includes a UTC timestamp, server, character, zone, local session
ID, message ID, numeric channel, channel name, sender, nonempty target, and
original opcode. Successfully decoded records contain readable text without
duplicating the original packet and message bytes. Set `include_raw` to `true`
when collecting reverse-engineering data to add `payload_hex`, `message`, and
`message_hex`.

Item links retain their complete 45-character body, label, item ID, wire
byte offsets, and decoded-text byte offsets. Empty item-link arrays are omitted.
MOTD, guild MOTD, emotes, special messages, and string-table messages are also
logged. Unknown channel IDs are preserved rather than dropped. Malformed recognized communication
packets always produce `decode_error` records with their original bytes.

Auction and OOC have live native coverage. Guild, group, shout, tell, say,
raid, broadcast, GM-say, emote, and unknown channel IDs share the tested
channel decoder but have not all been exercised live.

### Item-link positions

Each item link includes `text_start` and `text_end`: the inclusive start and
exclusive end in UTF-8 bytes of its label in the decoded `text` string. These
ranges remain correct when non-UTF-8 wire bytes become replacement characters.
JavaScript consumers must convert UTF-8 byte positions before slicing strings.
For formatted game messages, ranges refer to the individual argument's `text`.

The existing `start` and `end` fields retain their original wire-byte meaning,
including link metadata and delimiters. Use the new fields to display inline
links; do not apply wire offsets to decoded text. All item-link fields remain
available when raw packet logging is disabled.

## Embed in a native application

The same crate exposes the complete login/world/zone session engine through
`p99_logger_client::client`. The CLI is an adapter for JSON configuration,
JSONL files, process signals, and health files; the library does not read those
files, install signal handlers, or print to stdout/stderr.

For a sibling phone UI repository, add:

```toml
[dependencies]
p99-logger-client = { path = "../p99-logger-client", default-features = false }
```

After the API is released, replace `path` with this repository's `git` URL and
the release `tag`. Disabling default features removes the CLI and its signal
dependency. The network engine and bundled asset inventory remain available.

Create a `client::ClientConfig` from the app's configuration screen, then
construct `Client::new(config, identity)`. `ClientIdentity` contains the short
hostname and username metadata used in V62 validation (1–15 UTF-8 bytes each;
hostname is uppercased). These are host metadata, separate from login
credentials. The host app supplies them; the library has no Linux filesystem
or environment-variable dependency. Use `Client::with_assets` to override
the bundled checksums when needed.

Run `Client::run` on a dedicated worker thread with a `CancellationToken` and
`RunOptions`. It emits owned `ClientEvent` values for status, communication
records, diagnostics, and reconnect attempts. `RecordEvent` distinguishes
decoded chat from decode errors; chat contains typed channels and item links.
Serializing a `Record` produces the same flat schema as the CLI's JSONL.

Keep the event handler quick: enqueue events for the UI thread, and explicitly
handle a full queue. Returning an error stops the client and closes its session
without retrying or invoking that handler again. Calling `cancel()` interrupts
network waits and reconnect delays; platform DNS resolution can still block.
Wait for the worker to finish before starting another connection. A cancelled
token stays cancelled, so create a new token for the next run. The module's
Rustdoc includes a compiling worker/queue example.

The phone app owns credential storage, its UI, and lifecycle decisions, including
when to disconnect as it backgrounds. `ClientConfig` intentionally has no
`Debug` or `Serialize` implementation. No message-sending API is provided yet.

## Build and release

```sh
docker build -t p99-logger-client .
```

The Docker build checks formatting, runs Rust tests and Clippy with and without
the CLI feature, and creates a stripped static binary in a `scratch` image.
The mobile-library workflow checks compilation for Android and iOS on ARM64;
device packaging and lifecycle behavior are the phone UI repository's job.
The GitHub Actions workflow builds `linux/amd64`. Pull requests build without
publishing. Merges to `main`, version tags, and manual runs publish
provenance/SBOM-enabled images to
`ghcr.io/rm-you/p99-logger-client`, tagged by commit; the default branch also
publishes `latest`.

The login crypto and server-list parser are pinned to the proven Rust
implementation in
[p99-login-proxy](https://github.com/eq-p99-tools/p99-login-proxy).
