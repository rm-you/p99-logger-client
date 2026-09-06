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
    pub action_id: u32,
    pub item_id: u32,
    pub hash: u32,
}

#[derive(Debug, Serialize)]
pub struct Message {
    pub message: String,
    pub message_hex: String,
    pub text: String,
    pub item_links: Vec<ItemLink>,
}

#[derive(Debug, Serialize)]
pub struct ChatEvent {
    #[serde(rename = "type")]
    kind: &'static str,
    pub opcode: u16,
    pub payload_hex: String,
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
    pub language: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language_skill: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_spawn_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<Message>>,
}

impl ChatEvent {
    fn new(opcode: u16, payload: &[u8], channel_name: ChannelName) -> Self {
        Self {
            kind: "chat",
            opcode,
            payload_hex: hex::encode(payload),
            channel_name,
            message: None,
            channel: None,
            sender: None,
            target: None,
            language: None,
            language_skill: None,
            color: None,
            target_spawn_id: None,
            string_id: None,
            arguments: None,
        }
    }

    fn with_message(mut self, message: Message) -> Self {
        self.message = Some(message);
        self
    }
}

/// Preserve original bytes and item-link bodies alongside readable text. Link
/// offsets are byte offsets in `message_hex`, including both 0x12 delimiters.
pub fn message(bytes: &[u8]) -> Message {
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
                        action_id: hex_number(&body[0..1]),
                        item_id: hex_number(&body[1..6]),
                        hash: hex_number(&body[37..45]),
                    });
                    readable.push(b'[');
                    readable.extend_from_slice(label);
                    readable.push(b']');
                    pos = end + 1;
                    continue;
                }
            }
        }
        readable.push(bytes[pos]);
        pos += 1;
    }
    Message {
        message: String::from_utf8_lossy(bytes).into_owned(),
        message_hex: hex::encode(bytes),
        text: String::from_utf8_lossy(&readable).into_owned(),
        item_links: links,
    }
}

/// Decode every Titanium communication packet, without filtering channel IDs.
/// String-table messages retain their ID/arguments even without local eqstr.
pub fn parse(opcode: u16, body: &[u8]) -> Result<Option<ChatEvent>> {
    let event = match CommunicationOpcode::from(opcode) {
        CommunicationOpcode::Motd => {
            ChatEvent::new(opcode, body, ChannelName::Motd).with_message(message(body))
        }
        CommunicationOpcode::ChannelMessage => {
            ensure!(body.len() >= 149, "truncated ChannelMessage");
            ensure!(body[148..].contains(&0), "unterminated ChannelMessage");
            let channel = u32_at(body, 132);
            let mut event = ChatEvent::new(opcode, body, channel_name(channel))
                .with_message(message(&body[148..]));
            event.channel = Some(channel);
            event.sender = Some(text(&body[64..128]));
            event.target = Some(text(&body[..64]));
            event.language = Some(u32_at(body, 128));
            event.language_skill = Some(u32_at(body, 144));
            event
        }
        CommunicationOpcode::Emote => {
            ensure!(body.len() >= 5, "truncated Emote");
            ChatEvent::new(opcode, body, ChannelName::Emote).with_message(message(&body[4..]))
        }
        CommunicationOpcode::SpecialMessage => {
            ensure!(body.len() >= 24, "truncated SpecialMesg");
            let sender = cstr(&body[11..]);
            let offset = 11 + sender.len() + 1 + 12;
            ensure!(offset < body.len(), "truncated SpecialMesg text");
            let mut event = ChatEvent::new(opcode, body, ChannelName::System)
                .with_message(message(&body[offset..]));
            event.sender = Some(String::from_utf8_lossy(sender).into_owned());
            event.color = Some(u32_at(body, 3));
            event.target_spawn_id = Some(u32_at(body, 7));
            event
        }
        CommunicationOpcode::FormattedMessage => {
            ensure!(body.len() >= 12, "truncated FormattedMessage");
            let arguments = body[12..]
                .split(|&b| b == 0)
                .take_while(|arg| !arg.is_empty())
                .map(message)
                .collect();
            let mut event = ChatEvent::new(opcode, body, ChannelName::System);
            event.string_id = Some(u32_at(body, 4));
            event.color = Some(u32_at(body, 8));
            event.arguments = Some(arguments);
            event
        }
        CommunicationOpcode::SimpleMessage => {
            ensure!(body.len() >= 12, "truncated SimpleMessage");
            let mut event = ChatEvent::new(opcode, body, ChannelName::System);
            event.string_id = Some(u32_at(body, 0));
            event.color = Some(u32_at(body, 4));
            event
        }
        CommunicationOpcode::GuildMotd => {
            ensure!(body.len() >= 137, "truncated guild MOTD");
            let mut event = ChatEvent::new(opcode, body, ChannelName::GuildMotd)
                .with_message(message(&body[136..]));
            event.sender = Some(text(&body[68..132]));
            event.target = Some(text(&body[4..68]));
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
            let event = parse(0x1004, &body).unwrap().unwrap();
            assert_eq!(event.channel, Some(channel));
            assert_eq!(event.sender.as_deref(), Some("Trader"));
            assert_eq!(event.message.as_ref().unwrap().text, "hello");
            let json = serde_json::to_value(&event).unwrap();
            assert_eq!(json["text"], "hello");
            assert!(json["message"].is_string());
        }
        assert!(parse(0xffff, &[]).unwrap().is_none());
    }

    #[test]
    fn links_and_invalid_utf8_are_lossless() {
        let link = b"00002A0000000000000000000000000000000ABCDEF12";
        assert_eq!(link.len(), 45);
        let mut input = b"WTS \x12".to_vec();
        input.extend(link);
        input.extend_from_slice(b"Item\x12 \xff");
        let event = message(&input);
        assert_eq!(event.message_hex, hex::encode(&input));
        assert_eq!(event.item_links[0].item_id, 42);
        assert_eq!(event.item_links[0].hash, 0xABCD_EF12_u32);
        assert_eq!(event.item_links[0].body, std::str::from_utf8(link).unwrap());
        let json = serde_json::to_value(&event).unwrap();
        for field in ["augment_ids", "is_evolving", "evolve_group", "evolve_level"] {
            assert!(json["item_links"][0].get(field).is_none());
        }
        assert!(message(b"bad \x12short\x12").item_links.is_empty());
    }
}
