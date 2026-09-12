# Project Quarm protocol notes

Quarm uses the Windows TAKP/EQMac client family rather than Project 1999's
Titanium client. This implementation therefore shares the public session and
JSONL APIs while selecting a separate login endpoint, transport, opcode table,
packet layouts, and zone-entry state machine.

The implementation was derived from the Project Quarm server fork at commit
[`4a6018e`](https://github.com/SecretsOTheP/EQMacEmu/tree/4a6018e4acd1b26b62c05482df6044e79f3dcb63).
It has unit and synthetic UDP coverage. The Android consumer has exercised live
login, character selection, zone entry, received chat, and outbound tells. The
DLL version announcement described below awaits a live retest.

## Configuration

Selecting `"protocol": "quarm"` defaults to
`loginserver.takproject.net:6000`. `host` and `port` remain optional overrides.
The observed server-list name is `The Project Quarm Server Server`;
world matching is case-insensitive but otherwise exact.

```json
{
  "protocol": "quarm",
  "user": "EXAMPLE_TAKP_LOGIN_ACCOUNT",
  "pass": "EXAMPLE_PASSWORD",
  "server": "The Project Quarm Server Server",
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
   `OP_SetServerFilter` (`0xff41`), the DLL version announcement described below,
   and one 15-byte `OP_ClientUpdate` (`0xf340`)
   to enter the server's connected state. No further movement packets are
   generated.

### DLL version announcement

The current Quarm DLL advertises integer version `7` with custom
`OP_SpawnAppearance` messages. This implementation follows
[`akplus-dll@af2bd327`'s announcement and request handler](https://github.com/SecretsOTheP/akplus-dll/blob/af2bd327cb61c3b7534bb6a07cb2b7a56b17467c/eqgame_dll/eqgame.cpp#L2441-L2457);
the compiled DLL in that revision was also checked against the source.
No DLL is bundled or loaded.

- Opcode bytes are `f5 40` (`0xf540` in this transport's opcode convention).
- The eight-byte body contains little-endian spawn ID `0`, appearance type
  `256` (`ClientDllMessage`), and parameter `(4 << 16) | 7` (`CodeVersion`).
- The announcement precedes `OP_ClientUpdate`, which triggers the server's
  version check as it completes admission. It is sent once per zone entry.
- A version request receives the same message with parameter bit 31 set.
  Requests work both while connecting and after admission; responses are not
  answered, avoiding reply loops.
- Other appearance types, feature IDs, nonzero spawn IDs, and malformed bodies
  are ignored. Buff stacking, shared bank, and use-from-bag have independent
  feature negotiations and are not enabled by this announcement.

The server initializes an unannounced version to `0` and compares it with
`Quarm:WarnDllVersionBelow` (source default `1`). This protocol integer is
separate from a Windows DLL file version or the mobile app's release version.

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
- exact version announcement and response bytes through a synthetic localhost
  zone peer, ordering before zone-ready, requests before/after admission,
  duplicate readiness, malformed messages, and ignored optional features;
- EQMac inbound and outbound channel headers, unescaped percent text, item-link
  bodies, and protocol-specific system-message offsets;
- the existing P99 client API and transport, ensuring the default protocol and
  current behavior remain intact.

No packet captures, credentials, client files, or live-server responses are
used by these tests.

## Validation limits

The version announcement is verified against the published DLL and a synthetic
zone peer; disappearance of the live server warning still needs confirmation.
The production `WarnDllVersionBelow` value has not been queried. Existing live
coverage does not establish every channel, long-duration idle behavior, or
optional gameplay feature compatibility. The client still sends the existing
zeroed 15-byte readiness update and does not implement shared-bank or buff
feature negotiation.
