use anyhow::{ensure, Result};
use serde::Serialize;

/// Titanium uses mixed polarity: guild/social/group/shout/auction/OOC and
/// melee-miss filters show messages when set to one. Most spell filters use
/// zero. This matches the successful stock client's 29-word filter packet.
#[must_use]
pub fn server_filters() -> [u8; 116] {
    let mut filters = [0; 116];
    for index in (1..=7).chain(14..=17) {
        filters[index * 4] = 1;
    }
    filters
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelName {
    Guild,
    Group,
    Shout,
    Auction,
    Ooc,
    Broadcast,
    Tell,
    Say,
    GmSay,
    Raid,
    Emote,
    Motd,
    System,
    GuildMotd,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommunicationOpcode {
    Motd,
    ChannelMessage,
    Emote,
    SpecialMessage,
    FormattedMessage,
    SimpleMessage,
    GuildMotd,
    Unknown(u16),
}

impl From<u16> for CommunicationOpcode {
    fn from(value: u16) -> Self {
        match value {
            0x024d => Self::Motd,
            0x1004 => Self::ChannelMessage,
            0x547a => Self::Emote,
            0x2372 => Self::SpecialMessage,
            0x5a48 => Self::FormattedMessage,
            0x673c => Self::SimpleMessage,
            0x475a => Self::GuildMotd,
            value => Self::Unknown(value),
        }
    }
}

/// Map a wire channel ID to its stable JSON name while preserving unknown IDs.
#[must_use]
pub const fn channel_name(id: u32) -> ChannelName {
    match id {
        0 => ChannelName::Guild,
        2 => ChannelName::Group,
        3 => ChannelName::Shout,
        4 => ChannelName::Auction,
        5 => ChannelName::Ooc,
        6 => ChannelName::Broadcast,
        7 => ChannelName::Tell,
        8 => ChannelName::Say,
        11 => ChannelName::GmSay,
        15 => ChannelName::Raid,
        22 => ChannelName::Emote,
        _ => ChannelName::Unknown,
    }
}

fn u32_at(body: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(body[offset..offset + 4].try_into().unwrap())
}

fn cstr(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.iter().position(|&v| v == 0).unwrap_or(bytes.len())]
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(cstr(bytes)).into_owned()
}

fn nonempty_text(bytes: &[u8]) -> Option<String> {
    match text(bytes) {
        value if value.is_empty() => None,
        value => Some(value),
    }
}

fn hex_number(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => 0,
        };
        value * 16 + u32::from(digit)
    })
}

#[derive(Debug, Serialize)]
pub struct ItemLink {
    pub body: String,
    pub text: String,
    pub start: usize,
    pub end: usize,
    pub item_id: u32,
}

#[derive(Debug, Serialize)]
pub struct Message {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_hex: Option<String>,
    pub text: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub item_links: Vec<ItemLink>,
}

#[derive(Debug, Serialize)]
pub struct ChatEvent {
    #[serde(rename = "type")]
    kind: &'static str,
    pub opcode: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hex: Option<String>,
    pub channel_name: ChannelName,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<Message>>,
}

impl ChatEvent {
    fn new(opcode: u16, payload: &[u8], channel_name: ChannelName, include_raw: bool) -> Self {
        Self {
            kind: "chat",
            opcode,
            payload_hex: include_raw.then(|| hex::encode(payload)),
            channel_name,
            message: None,
            channel: None,
            sender: None,
            target: None,
            string_id: None,
            arguments: None,
        }
    }

    fn with_message(mut self, message: Message) -> Self {
        self.message = Some(message);
        self
    }
}

/// Extract readable text and complete item-link bodies from a wire message.
/// Link offsets are wire-message byte offsets including both 0x12 delimiters.
pub fn message(bytes: &[u8], include_raw: bool) -> Message {
    let bytes = cstr(bytes);
    let mut links = Vec::new();
    let mut readable = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes[pos] == 0x12 && pos + 46 < bytes.len() {
            let body = &bytes[pos + 1..pos + 46];
            if body.iter().all(u8::is_ascii_hexdigit) {
                if let Some(tail) = bytes[pos + 46..].iter().position(|&b| b == 0x12) {
                    let end = pos + 46 + tail;
                    let label = &bytes[pos + 46..end];
                    links.push(ItemLink {
                        body: String::from_utf8_lossy(body).into_owned(),
                        text: String::from_utf8_lossy(label).into_owned(),
                        start: pos,
                        end: end + 1,
                        item_id: hex_number(&body[1..6]),
                    });
                    readable.extend_from_slice(label);
                    pos = end + 1;
                    continue;
                }
            }
        }
        readable.push(bytes[pos]);
        pos += 1;
    }
    Message {
        message: include_raw.then(|| String::from_utf8_lossy(bytes).into_owned()),
        message_hex: include_raw.then(|| hex::encode(bytes)),
        text: String::from_utf8_lossy(&readable).into_owned(),
        item_links: links,
    }
}

/// Decode every Titanium communication packet, without filtering channel IDs.
/// String-table messages retain their ID/arguments even without local eqstr.
pub fn parse(opcode: u16, body: &[u8], include_raw: bool) -> Result<Option<ChatEvent>> {
    let event = match CommunicationOpcode::from(opcode) {
        CommunicationOpcode::Motd => ChatEvent::new(opcode, body, ChannelName::Motd, include_raw)
            .with_message(message(body, include_raw)),
        CommunicationOpcode::ChannelMessage => {
            ensure!(body.len() >= 149, "truncated ChannelMessage");
            ensure!(body[148..].contains(&0), "unterminated ChannelMessage");
            let channel = u32_at(body, 132);
            let mut event = ChatEvent::new(opcode, body, channel_name(channel), include_raw)
                .with_message(message(&body[148..], include_raw));
            event.channel = Some(channel);
            event.sender = Some(text(&body[64..128]));
            event.target = nonempty_text(&body[..64]);
            event
        }
        CommunicationOpcode::Emote => {
            ensure!(body.len() >= 5, "truncated Emote");
            ChatEvent::new(opcode, body, ChannelName::Emote, include_raw)
                .with_message(message(&body[4..], include_raw))
        }
        CommunicationOpcode::SpecialMessage => {
            ensure!(body.len() >= 24, "truncated SpecialMesg");
            let sender = cstr(&body[11..]);
            let offset = 11 + sender.len() + 1 + 12;
            ensure!(offset < body.len(), "truncated SpecialMesg text");
            let mut event = ChatEvent::new(opcode, body, ChannelName::System, include_raw)
                .with_message(message(&body[offset..], include_raw));
            event.sender = Some(String::from_utf8_lossy(sender).into_owned());
            event
        }
        CommunicationOpcode::FormattedMessage => {
            ensure!(body.len() >= 12, "truncated FormattedMessage");
            let arguments = body[12..]
                .split(|&b| b == 0)
                .take_while(|arg| !arg.is_empty())
                .map(|argument| message(argument, include_raw))
                .collect();
            let mut event = ChatEvent::new(opcode, body, ChannelName::System, include_raw);
            event.string_id = Some(u32_at(body, 4));
            event.arguments = Some(arguments);
            event
        }
        CommunicationOpcode::SimpleMessage => {
            ensure!(body.len() >= 12, "truncated SimpleMessage");
            let mut event = ChatEvent::new(opcode, body, ChannelName::System, include_raw);
            event.string_id = Some(u32_at(body, 0));
            event
        }
        CommunicationOpcode::GuildMotd => {
            ensure!(body.len() >= 137, "truncated guild MOTD");
            let mut event = ChatEvent::new(opcode, body, ChannelName::GuildMotd, include_raw)
                .with_message(message(&body[136..], include_raw));
            event.sender = Some(text(&body[68..132]));
            event.target = nonempty_text(&body[4..68]);
            event
        }
        CommunicationOpcode::Unknown(_) => return Ok(None),
    };
    Ok(Some(event))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_channel_ids_are_logged_including_unknown() {
        for channel in [0, 2, 3, 4, 5, 6, 7, 8, 11, 15, 22, 999] {
            let mut body = vec![0; 148];
            body[64..70].copy_from_slice(b"Trader");
            body[132..136].copy_from_slice(&u32::to_le_bytes(channel));
            body.extend_from_slice(b"hello\0");
            let event = parse(0x1004, &body, false).unwrap().unwrap();
            assert_eq!(event.channel, Some(channel));
            assert_eq!(event.sender.as_deref(), Some("Trader"));
            assert_eq!(event.message.as_ref().unwrap().text, "hello");
            let json = serde_json::to_value(&event).unwrap();
            assert_eq!(json["text"], "hello");
            for field in [
                "payload_hex",
                "message",
                "message_hex",
                "item_links",
                "target",
                "language",
                "language_skill",
            ] {
                assert!(json.get(field).is_none());
            }
        }
        assert!(parse(0xffff, &[], false).unwrap().is_none());
    }

    #[test]
    fn links_keep_their_body_and_wire_offsets() {
        let link = b"00002A0000000000000000000000000000000ABCDEF12";
        assert_eq!(link.len(), 45);
        let mut input = b"WTS \x12".to_vec();
        input.extend(link);
        input.extend_from_slice(b"Item\x12 \xff");
        let event = message(&input, false);
        assert_eq!(event.message, None);
        assert_eq!(event.message_hex, None);
        assert_eq!(event.text, "WTS Item �");
        assert_eq!(event.item_links[0].item_id, 42);
        assert_eq!(event.item_links[0].start, 4);
        assert_eq!(event.item_links[0].end, 55);
        assert_eq!(event.item_links[0].body, std::str::from_utf8(link).unwrap());
        let json = serde_json::to_value(&event).unwrap();
        for field in ["action_id", "hash", "augment_ids", "is_evolving"] {
            assert!(json["item_links"][0].get(field).is_none());
        }
        assert!(message(b"bad \x12short\x12", false).item_links.is_empty());
    }

    #[test]
    fn raw_mode_preserves_packet_and_message_bytes() {
        let mut body = vec![0; 148];
        body[64..70].copy_from_slice(b"Trader");
        body[132..136].copy_from_slice(&4_u32.to_le_bytes());
        body.extend_from_slice(b"hello\0");
        let event = parse(0x1004, &body, true).unwrap().unwrap();
        let message = event.message.as_ref().unwrap();
        assert_eq!(event.payload_hex, Some(hex::encode(&body)));
        assert_eq!(message.message.as_deref(), Some("hello"));
        assert_eq!(message.message_hex.as_deref(), Some("68656c6c6f"));
    }
}
