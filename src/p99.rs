use anyhow::{ensure, Context, Result};
use num_bigint::BigUint;
use rand::RngCore;

/// The legacy application header participates in the V62 digest. Its length
/// includes the four-byte opcode/length header, unlike the UDP payload length.
pub fn packet_digest(opcode: u16, body: &[u8]) -> Result<[u8; 16]> {
    let length = u16::try_from(body.len() + 4).context("application digest length overflow")?;
    let mut digest = md5::Context::new();
    digest.consume(opcode.to_le_bytes());
    digest.consume(length.to_le_bytes());
    digest.consume(body);
    Ok(digest.compute().0)
}

pub struct WorldCodec {
    key: [u8; 16],
    incoming: Option<[u8; 16]>,
    outgoing: Option<[u8; 16]>,
}

impl WorldCodec {
    /// Derive the initial world codec key from the exact login-info packet.
    pub fn new(login_info: &[u8]) -> Result<Self> {
        ensure!(login_info.len() == 464, "invalid Titanium world login size");
        Ok(Self {
            key: md5::compute(login_info).0,
            incoming: None,
            outgoing: None,
        })
    }

    /// Answer the world's approval challenge and initialize rolling state.
    pub fn approve(&mut self, challenge: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            challenge.len() == 544,
            "unexpected world approval challenge size"
        );
        let bigint = |bytes: &[u8]| -> Result<BigUint> {
            let count = bytes.get(268..272).context("truncated approval integer")?;
            let words = usize::try_from(u32::from_le_bytes(count.try_into()?))?;
            ensure!((1..=64).contains(&words), "invalid world approval integer");
            let integer = bytes
                .get(8..8 + words * 4)
                .context("truncated approval integer words")?;
            Ok(BigUint::from_bytes_le(integer))
        };
        let modulus = bigint(challenge.get(..272).context("missing approval modulus")?)?;
        let exponent = bigint(challenge.get(272..).context("missing approval exponent")?)?;
        ensure!(
            modulus.bits() >= 64 && exponent.bits() > 0,
            "invalid world approval public key"
        );
        // A zero nonce encodes to zero words, which the Titanium vlong header
        // cannot represent. Setting the low bit guarantees a nonzero value.
        let random = BigUint::from(rand::thread_rng().next_u64() | 1);
        let encrypted = random.modpow(&exponent, &modulus).to_bytes_le();
        ensure!(encrypted.len() <= 256, "approval integer too large");
        let mut body = vec![0; 272];
        body[8..8 + encrypted.len()].copy_from_slice(&encrypted);
        let words = u32::try_from(encrypted.len().div_ceil(4))?;
        // Titanium's vlong multiplication allocates 2*n-1 words.
        body[264..268].copy_from_slice(&(words * 2 - 1).to_le_bytes());
        body[268..272].copy_from_slice(&words.to_le_bytes());
        self.encode_approval(&mut body)?;
        Ok(body)
    }

    /// Encode an approval body and seed the incoming manifest decoder.
    pub fn encode_approval(&mut self, body: &mut [u8]) -> Result<()> {
        ensure!(body.len() == 272, "invalid approval response size");
        body[..9].fill(0);
        let seed = packet_digest(0x3c25, body)?;
        body[..8].fill(0xff);
        body[8] = 1;
        self.incoming = Some(packet_digest(0x52a4, body)?);
        encode(&mut body[..9], &self.key, &seed);
        Ok(())
    }

    /// Decode the world manifest and seed its checksum response encoder.
    pub fn manifest(&mut self, body: &mut [u8]) -> Result<()> {
        let seed = self.incoming.context("manifest arrived before approval")?;
        decode(body, &self.key, &seed);
        self.outgoing = Some(packet_digest(0x1251, body)?);
        Ok(())
    }

    /// Encode a world or zone file-checksum response with rolling state.
    pub fn file_response(&self, body: &mut [u8]) -> Result<()> {
        let seed = self.outgoing.context("file response before manifest")?;
        encode(body, &self.key, &seed);
        Ok(())
    }

    /// Decode the file manifest embedded in a world-to-zone handoff.
    pub fn zone_manifest(&self, handoff: &[u8]) -> Result<Vec<u8>> {
        ensure!(handoff.len() > 130, "zone handoff has no file manifest");
        let mut header = handoff.to_vec();
        header[130..].fill(0);
        let seed = packet_digest(0x61b6, &header)?;
        let mut manifest = handoff[130..].to_vec();
        decode(&mut manifest, &self.key, &seed);
        Ok(manifest)
    }

    /// Rekey the codec for a new zone from the zone-entry packet.
    pub fn zone_entry(&mut self, entry: &[u8]) -> Result<()> {
        ensure!(entry.len() == 68, "invalid Titanium zone entry size");
        self.key = md5::compute(entry).0;
        self.outgoing = None;
        Ok(())
    }

    /// Seed the zone checksum encoder from the decoded player spawn.
    pub fn zone_spawn(&mut self, body: &[u8]) -> Result<()> {
        ensure!(body.len() == 385, "unexpected Titanium player spawn size");
        self.outgoing = Some(packet_digest(0x7213, body)?);
        Ok(())
    }
}

/// XOR permutation used by the V62 application codec. Zero and the key byte
/// are fixed points, so neither C string terminators nor nonzero bytes vanish.
const fn xor_nonzero(value: u8, key: u8) -> u8 {
    if value == 0 || value == key {
        value
    } else {
        value ^ key
    }
}

/// Encode an application body with its session key and outgoing rolling state.
///
/// The first byte is unchanged. Each lane remembers the next nonzero plaintext
/// byte, starting at the end of the body with the supplied 16-byte state.
pub fn encode(body: &mut [u8], key: &[u8; 16], seed: &[u8; 16]) {
    let mut rolling = *seed;
    for i in (1..body.len()).rev() {
        let plain = body[i];
        if plain != 0 {
            body[i] = xor_nonzero(xor_nonzero(plain, key[i % 16]), rolling[i % 16]);
            rolling[i % 16] = plain;
        }
    }
}

/// Reverse the application codec, retaining the exact original bytes.
pub fn decode(body: &mut [u8], key: &[u8; 16], seed: &[u8; 16]) {
    let mut rolling = *seed;
    for i in (1..body.len()).rev() {
        if body[i] != 0 {
            body[i] = xor_nonzero(xor_nonzero(body[i], rolling[i % 16]), key[i % 16]);
            rolling[i % 16] = body[i];
        }
    }
}

/// CRC1 uses the login server's ten-byte session key, independently of the
/// world approval digests. The same permutation encodes and decodes it.
pub fn session_xor(body: &mut [u8], session_key: &[u8]) -> Result<()> {
    ensure!(!session_key.is_empty(), "missing login session key");
    for (index, byte) in body.iter_mut().enumerate() {
        *byte = xor_nonzero(*byte, session_key[index % session_key.len()]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_key_oracle_vector_skips_empty_lane_entries() {
        // Measured from the isolated current V62 encoder using zero keys and
        // synthetic bytes 0..357. The zero at offset 256 is skipped in its lane.
        let mut body: Vec<u8> = (0..=u8::MAX).cycle().take(358).collect();
        encode(&mut body, &[0; 16], &[0; 16]);
        assert_eq!(
            &body[..16],
            &[0, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
        );
        assert_eq!(body[240], 224);
        assert_eq!(body[256], 0);
        assert_eq!(&body[342..], &(86..102).collect::<Vec<u8>>());
    }

    #[test]
    fn inverse_preserves_all_byte_values_and_terminators() {
        let key = std::array::from_fn(|i| u8::try_from(i * 17).unwrap());
        let seed = std::array::from_fn(|i| u8::try_from(i * 13 + 19).unwrap());
        for length in [0, 1, 15, 16, 17, 358, 996, 2056] {
            let plain: Vec<u8> = (0..=u8::MAX).cycle().take(length).collect();
            let mut body = plain.clone();
            encode(&mut body, &key, &seed);
            assert!(body.iter().zip(&plain).all(|(a, b)| (*a == 0) == (*b == 0)));
            decode(&mut body, &key, &seed);
            assert_eq!(body, plain);
        }
    }
}
