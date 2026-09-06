use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::Read, path::Path};

#[derive(Debug, Serialize, Deserialize)]
pub struct FileChecksum {
    pub crc32: u32,
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Assets {
    pub client: String,
    pub files: BTreeMap<String, Option<FileChecksum>>,
}

impl Assets {
    /// Generate an inventory from the user's installation. Absence is explicit,
    /// distinct from a profile which has never checked a requested filename.
    pub fn scan(directory: &Path, names: &[String]) -> Result<Self> {
        let mut files = BTreeMap::new();
        for name in names {
            ensure!(
                Path::new(name)
                    .file_name()
                    .is_some_and(|part| part == Path::new(name).as_os_str()),
                "asset inventory entries must be filenames"
            );
            let relative = if name.eq_ignore_ascii_case("GlobalLoad.txt") {
                "Resources/GlobalLoad.txt"
            } else {
                name
            };
            let candidate = directory.join(relative);
            let parent = candidate.parent().context("asset path has no parent")?;
            let basename = candidate
                .file_name()
                .context("asset path has no filename")?;
            let path = fs::read_dir(parent)?
                .filter_map(std::result::Result::ok)
                .map(|entry| entry.path())
                .find(|path| {
                    path.file_name().is_some_and(|n| {
                        n.to_string_lossy()
                            .eq_ignore_ascii_case(&basename.to_string_lossy())
                    })
                });
            let value = if let Some(path) = path {
                let mut file = fs::File::open(path)?;
                let size = file.metadata()?.len();
                let mut buffer = vec![0; 65536];
                let mut crc = crc32fast::Hasher::new();
                loop {
                    let count = file.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    crc.update(&buffer[..count]);
                }
                Some(FileChecksum {
                    crc32: crc.finalize(),
                    size,
                })
            } else {
                None
            };
            files.insert(name.to_lowercase(), value);
        }
        Ok(Self {
            client: "Titanium/P99-V62".into(),
            files,
        })
    }

    /// Build the checksum response requested by a world or zone manifest.
    pub fn file_response(&self, manifest: &[u8]) -> Result<Vec<u8>> {
        let mut output = crc32fast::hash(manifest).to_le_bytes().to_vec();
        for entry in parse_manifest(manifest)? {
            if entry.is_skipped() {
                continue;
            }
            let checksum = self
                .files
                .get(&entry.name.to_lowercase())
                .with_context(|| format!("asset inventory has no entry for {}", entry.name))?;
            let crc = checksum.as_ref().map_or(0, |checksum| checksum.crc32);
            output.extend_from_slice(&entry.id.to_le_bytes());
            output.extend_from_slice(&crc.to_le_bytes());
        }
        Ok(output)
    }

    /// Return the spell-file metadata used by the V62 CRC1 response.
    pub fn spells(&self) -> Result<&FileChecksum> {
        self.files
            .get("spells_us.txt")
            .and_then(Option::as_ref)
            .context("spells_us.txt missing from asset inventory")
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ManifestEntry {
    pub id: u16,
    pub flags: u8,
    pub name: String,
}

impl ManifestEntry {
    const fn is_skipped(&self) -> bool {
        self.flags == 2
    }
}

/// Parse and validate a V62 file manifest without accepting path components.
pub fn parse_manifest(mut bytes: &[u8]) -> Result<Vec<ManifestEntry>> {
    let mut entries = Vec::new();
    while !bytes.is_empty() {
        ensure!(bytes.len() >= 4, "truncated file manifest");
        let id = u16::from_le_bytes([bytes[0], bytes[1]]);
        let flags = bytes[2];
        ensure!(
            matches!(flags, 1 | 2 | 5 | 9),
            "unsupported file manifest flags"
        );
        let end = bytes[3..]
            .iter()
            .position(|&b| b == 0)
            .context("unterminated manifest filename")?
            + 3;
        let name = std::str::from_utf8(&bytes[3..end])?;
        ensure!(
            !name.is_empty()
                && name.len() <= 200
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_'),
            "invalid manifest filename"
        );
        ensure!(
            !entries.iter().any(|entry: &ManifestEntry| entry.id == id),
            "duplicate manifest ID"
        );
        entries.push(ManifestEntry {
            id,
            flags,
            name: name.to_owned(),
        });
        bytes = &bytes[end + 1..];
    }
    ensure!(!entries.is_empty(), "empty file manifest");
    Ok(entries)
}
