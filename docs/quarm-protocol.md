# Project Quarm protocol plan

Quarm uses the Windows TAKP/EQMac client family rather than Project 1999's
Titanium client. This implementation therefore shares the public session and
JSONL APIs while selecting a separate login endpoint, transport, opcode table,
packet layouts, and zone-entry state machine.

The implementation was derived from the Project Quarm server fork at commit
[`4a6018e`](https://github.com/SecretsOTheP/EQMacEmu/tree/4a6018e4acd1b26b62c05482df6044e79f3dcb63).
It has unit and synthetic UDP coverage, but it has not connected to the TAKP
login server or a live Quarm world or zone server. A local server stack is not
required for the remaining work.

## Configuration

Selecting `"protocol": "quarm"` defaults to
`loginserver.takproject.net:6000`. `host` and `port` remain optional overrides.
The expected registered world name is currently `The Project Quarm Server`;
world matching is case-insensitive but otherwise exact.

```json
{
  "protocol": "quarm",
  "user": "EXAMPLE_TAKP_LOGIN_ACCOUNT",
  "pass": "EXAMPLE_PASSWORD",
  "server": "The Project Quarm Server",
  "character": "ExampleCharacter"
}
```

## Implemented flow

All three connections use EQMac's legacy reliable UDP stream. It starts with an
application datagram rather than the later Daybreak session negotiation. The
transport implements CRC32, global and reliable sequence numbers, cumulative
acknowledgements, resend requests, 510/512-byte fragmentation, out-of-order
reassembly, timeouts, and the legacy close flags.

Login proceeds as follows:

1. Send `OP_SessionReady` (`0x5900`) and wait for the server's version response.
2. Send `OP_LoginPC` (`0x0100`) with fixed 20-byte username and password fields,
   encrypted with the legacy Verant DES-CBC key and IV.
3. Read the `LS#` account identifier from `OP_LoginAccepted` (`0x0400`), complete
   login with `0x8800`, and request the old-format server list with `0x4600`.
4. Match the configured world, send its listed address with `0x4700`, and retain
   the ten-byte session key returned after world authorization.

World selection opens port 9000 on the chosen address, sends the 200-byte
Windows form of `OP_SendLoginInfo` (`0x5818`) containing the `LS#` identifier and
session key, verifies the configured character in `OP_SendCharInfo` (`0x4740`),
sends the 64-byte `OP_EnterWorld` (`0x0180`), and follows the host/port in
`OP_ZoneServerInfo` (`0x0480`). Its two-byte port is in network byte order
(big-endian), as written by `Client::Clearance` in the server source; it differs
from the Titanium handoff. The server source treats the world approval and
checksum packets as optional client input, so this client does not invent
checksum payloads.

Zone admission follows the server's connecting-opcode state machine:

1. Send `OP_DataRate` (`0xe841`) with `10.0f32`, then the 68-byte
   `OP_ZoneEntry` (`0x2840`) containing the character name.
2. Receive the player profile and initial zone stream. On weather, request the
   zone description with `OP_ReqNewZone` (`0x5d40`).
3. Receive `OP_NewZone` (`0x5b40`), request zone spawns with
   `OP_ReqClientSpawn` (`0x0a40`), and echo the empty `OP_SendExpZonein`
   (`0xd840`) readiness marker.
4. After `OP_ZoneInAvatarSet` (`0x6f40`), send the 17-word show-all
   `OP_SetServerFilter` (`0xff41`) and one 15-byte `OP_ClientUpdate` (`0xf340`)
   to enter the server's connected state. No further movement packets are
   generated.

Once ready, the client decodes the EQMac forms of channel chat, MOTD, guild
MOTD, emotes, special messages, and formatted string messages. Channel chat
uses a 136-byte fixed header. Item links preserve the seven-character EQMac
action/item body and derive the decimal item ID from its six item digits,
matching the stock client and
[Zeal link builder](https://github.com/CoastalRedwood/Zeal/blob/e24a3edc58dc92e6352081b53fe89e9caf58f6df/Zeal/looting.cpp#L69-L72).
Typed outbound chat uses the same EQMac structure and the stock client's
four-byte trailer.

## Offline validation

Tests cover:

- legacy wire byte order, flags, CRC, cumulative ACKs, fragmented payloads,
  server-style stream startup, and out-of-order delivery;
- the Verant login cipher and fixed credential fields using fictional values;
- old-format server-list parsing, the 200-byte Windows world login, the
  character-list layout, the network-order zone port, and the 17-word server filter;
- EQMac inbound and outbound channel headers, unescaped percent text, item-link
  bodies, and protocol-specific system-message offsets;
- the existing P99 client API and transport, ensuring the default protocol and
  current behavior remain intact.

No packet captures, credentials, client files, or live-server responses are
used by these tests.

## Approval and first live test

Before connecting, confirm the following with Secrets or another Quarm team
member:

- approval for a headless client that logs in one normal account and existing
  character, remains stationary, and receives chat;
- whether the production server requires `OP_ChecksumExe` or
  `OP_ChecksumSpell` despite the current source accepting world login without
  them;
- whether Quarm expects the custom DLL `SpawnAppearance` feature handshake from
  every client, and whether ignoring optional shared-bank negotiation is safe;
- whether one zeroed 15-byte `OP_ClientUpdate` at the ready transition is
  acceptable, or whether it should carry the server-assigned spawn ID and saved
  position from the encrypted player profile;
- whether reliable-stream acknowledgements alone are sufficient while the
  character is idle, and any preferred keepalive interval;
- the exact live server-list name, an approved account/character and quiet test
  zone, connection duration, retry rate, and one-box restrictions;
- whether receive-only testing should precede the optional outbound `/say ok`
  check.

The first approved run should disable automatic reconnect, enable raw records,
stop after a short fixed duration, and retain diagnostics locally. Progress
should be reviewed after login, world selection, zone admission, and idle chat
receipt before enabling long-running or container deployment.
