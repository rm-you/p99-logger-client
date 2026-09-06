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

The repository and published image include the checksum inventory for the
current P99 files. To override it after a P99 patch or add files requested by a
different zone, generate an inventory from a current installation; the game
files are not needed afterward:

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

The default inventory list covers the world manifest and East Commonlands.
Other zones may request additional files. Add their filenames to a text file
and pass its path as the final `scan-assets` argument. Missing files are
recorded explicitly, and an unknown manifest entry fails with a diagnostic.

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

Item links retain their complete 45-character body, label, item ID, and wire
byte offsets. Empty item-link arrays are omitted. MOTD, guild MOTD, emotes,
special messages, and string-table messages are also logged. Unknown channel
IDs are preserved rather than dropped. Malformed recognized communication
packets always produce `decode_error` records with their original bytes.

Auction and OOC have live native coverage. Guild, group, shout, tell, say,
raid, broadcast, GM-say, emote, and unknown channel IDs share the tested
channel decoder but have not all been exercised live.

## Build and release

```sh
docker build -t p99-logger-client .
```

The Docker build checks formatting, runs the Rust tests, runs Clippy with
warnings denied, and creates a stripped static binary in a `scratch` image.
The GitHub Actions workflow builds `linux/amd64`. Pull requests build without
publishing. Merges to `main`, version tags, and manual runs publish
provenance/SBOM-enabled images to
`ghcr.io/rm-you/p99-logger-client`, tagged by commit; the default branch also
publishes `latest`.

The login crypto and server-list parser are pinned to the proven Rust
implementation in
[p99-login-proxy](https://github.com/eq-p99-tools/p99-login-proxy).
