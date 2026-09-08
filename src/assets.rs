use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
};

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
    /// Load the checksum inventory compiled into the library without filesystem access.
    pub fn bundled() -> Result<Self> {
        serde_json::from_slice(include_bytes!("../assets.json"))
            .context("parse built-in asset inventory")
    }

    /// Inventory known validation files and every installed zone/model archive.
    /// Check optional zone companions explicitly, including files that are absent.
    pub fn scan_all(directory: &Path) -> Result<Self> {
        let mut names: BTreeSet<String> = include_str!("../protocol/p99-v62-files.txt")
            .lines()
            .map(str::to_ascii_lowercase)
            .collect();
        let mut roots = BTreeSet::new();
        for (name, path) in directory_entries(directory)? {
            let archive = name
                .strip_suffix(".s3d")
                .or_else(|| name.strip_suffix(".eqg"));
            let companion = name
                .strip_suffix("_chr.txt")
                .or_else(|| name.strip_suffix("_assets.txt"));
            if archive.is_none() && companion.is_none() {
                continue;
            }
            if !path.is_file() {
                continue;
            }
            if let Some(root) = companion.or_else(|| archive.filter(|root| !root.contains('_'))) {
                roots.insert(root.to_owned());
            }
            if companion.is_some() {
                let text = fs::read_to_string(&path)?;
                for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
                    if name.ends_with("_assets.txt") {
                        let line = line.to_ascii_lowercase();
                        ensure!(
                            valid_asset_name(&line)
                                && (line.ends_with(".s3d") || line.ends_with(".eqg")),
                            "invalid asset-list archive"
                        );
                        names.insert(line);
                    } else if let Some((_, archive)) = line.split_once(',') {
                        let archive = archive.split(',').next().unwrap().trim();
                        ensure!(valid_asset_name(archive), "invalid character-list archive");
                        for extension in [".s3d", ".eqg"] {
                            names.insert(format!("{}{extension}", archive.to_ascii_lowercase()));
                        }
                    }
                }
            }
            names.insert(name);
        }
        // Zone manifests can request optional files even when they do not exist
        // locally. Check both archive formats and the stock companion names.
        for root in roots {
            for suffix in [
                ".s3d",
                ".eqg",
                "_obj.s3d",
                "_2_obj.s3d",
                "_chr.s3d",
                "_chr.txt",
                "_assets.txt",
            ] {
                names.insert(format!("{root}{suffix}"));
            }
        }
        Self::scan(directory, &names.into_iter().collect::<Vec<_>>())
    }

    /// Generate an inventory from the user's installation. Absence is explicit,
    /// distinct from a profile which has never checked a requested filename.
    pub fn scan(directory: &Path, names: &[String]) -> Result<Self> {
        let installed = directory_entries(directory)?;
        let resources = if names
            .iter()
            .any(|name| name.eq_ignore_ascii_case("GlobalLoad.txt"))
        {
            installed
                .get("resources")
                .map(|path| directory_entries(path))
                .transpose()?
        } else {
            None
        };
        let mut files = BTreeMap::new();
        for name in names {
            ensure!(
                valid_asset_name(name),
                "asset inventory entries must be filenames"
            );
            let name = name.to_ascii_lowercase();
            let path = if name == "globalload.txt" {
                resources.as_ref().and_then(|files| files.get(&name))
            } else {
                installed.get(&name)
            };
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
            files.insert(name, value);
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

/// Index filenames once so a full installation scan does not repeatedly list it.
fn directory_entries(directory: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let mut entries = BTreeMap::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        ensure!(
            entries.insert(name, entry.path()).is_none(),
            "ambiguous case-insensitive filename in asset directory"
        );
    }
    Ok(entries)
}

fn valid_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
        && name != "."
        && name != ".."
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

#[cfg(test)]
mod tests {
    use super::*;

    struct Installation(PathBuf);

    impl Installation {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("p99-assets-{:016x}", rand::random::<u64>()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write(&self, name: &str, body: &[u8]) {
            let path = self.0.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
        }
    }

    impl Drop for Installation {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn manifest(entries: &[(u16, u8, &str)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (id, flags, name) in entries {
            bytes.extend_from_slice(&id.to_le_bytes());
            bytes.push(*flags);
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn discovers_zones_models_and_absent_dependencies_without_personal_files() {
        let install = Installation::new();
        install.write("NewZone.S3D", b"zone archive");
        install.write("NewZone_chr.txt", b"2\nabc,missing_chr\ndef,present\n");
        install.write("NewZone_assets.txt", b"missing_object.eqg\n");
        install.write("Present.EQG", b"model archive");
        install.write("AnotherZone.eqg", b"new format zone");
        install.write("resources/GLOBALLOAD.TXT", b"global model list");
        install.write("GlobalLoad.txt", b"incorrect root copy");
        install.write("eqclient.ini", b"private settings");
        install.write("eqlog_ExampleCharacter.txt", b"private messages");
        install.write("notes.txt", b"private notes");

        let assets = Assets::scan_all(&install.0).unwrap();
        for (name, content) in [
            ("newzone.s3d", b"zone archive".as_slice()),
            ("present.eqg", b"model archive".as_slice()),
            ("anotherzone.eqg", b"new format zone".as_slice()),
            ("globalload.txt", b"global model list".as_slice()),
        ] {
            let file = assets.files[name].as_ref().unwrap();
            assert_eq!(file.crc32, crc32fast::hash(content));
            assert_eq!(file.size, content.len() as u64);
        }
        for name in [
            "newzone_2_obj.s3d",
            "newzone.eqg",
            "anotherzone_chr.txt",
            "missing_chr.s3d",
            "missing_chr.eqg",
            "missing_object.eqg",
        ] {
            assert!(assets.files[name].is_none(), "{name}");
        }
        for name in ["eqclient.ini", "eqlog_examplecharacter.txt", "notes.txt"] {
            assert!(!assets.files.contains_key(name), "{name}");
        }
    }

    #[test]
    fn responds_only_to_requested_files_with_server_ids_and_manifest_order() {
        let install = Installation::new();
        install.write("FirstZone.s3d", b"first zone");
        install.write("SecondZone.s3d", b"second zone");
        let assets = Assets::scan_all(&install.0).unwrap();
        let request = manifest(&[
            (42, 1, "SECONDZONE.S3D"),
            (8, 9, "secondzone_assets.txt"),
            (99, 2, "unscanned_skipped_file.eqg"),
        ]);
        let mut expected = crc32fast::hash(&request).to_le_bytes().to_vec();
        expected.extend_from_slice(&42_u16.to_le_bytes());
        expected.extend_from_slice(&crc32fast::hash(b"second zone").to_le_bytes());
        expected.extend_from_slice(&8_u16.to_le_bytes());
        expected.extend_from_slice(&0_u32.to_le_bytes());
        assert_eq!(assets.file_response(&request).unwrap(), expected);

        let unknown = manifest(&[(5, 1, "unscanned_file.eqg")]);
        assert!(assets
            .file_response(&unknown)
            .unwrap_err()
            .to_string()
            .contains("no entry"));
    }

    #[test]
    fn explicit_scan_is_limited_to_requested_filenames() {
        let install = Installation::new();
        install.write("NewZone.s3d", b"zone");
        install.write("OtherZone.s3d", b"other");
        let assets =
            Assets::scan(&install.0, &["newzone.s3d".into(), "missing.eqg".into()]).unwrap();
        assert_eq!(assets.files.len(), 2);
        assert!(assets.files["newzone.s3d"].is_some());
        assert!(assets.files["missing.eqg"].is_none());
        assert!(Assets::scan(&install.0, &["../outside.s3d".into()]).is_err());
    }
}
