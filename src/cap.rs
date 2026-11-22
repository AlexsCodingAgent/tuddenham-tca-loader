//! Reading a Java Card CAP file and turning it into the load file a card accepts.
//!
//! A CAP is a JAR: a manifest plus one `.cap` component per Java Card structure. The card does not
//! want the JAR, it wants the components concatenated in the order the Java Card spec fixes
//! (Header, Directory, Import, Applet, Class, Method, StaticField, Export, ConstantPool,
//! RefLocation, Descriptor), each including its own tag and size header. Get the order wrong and
//! the card either rejects the load or, worse, loads something that will not install.
//!
//! Everything here is checked rather than assumed: every component's declared size must match its
//! bytes, the Header must carry the magic number, and the package AID must parse.

use anyhow::{bail, Context as _, Result};
use std::io::{Cursor, Read};

/// Component order fixed by JCVM 3.0 §4.7. Debug is deliberately absent: it is not part of a load
/// file and cards reject a load that includes it.
const ORDER: [(&str, u8); 11] = [
    ("Header", 0x01),
    ("Directory", 0x02),
    ("Import", 0x04),
    ("Applet", 0x03),
    ("Class", 0x06),
    ("Method", 0x07),
    ("StaticField", 0x08),
    ("Export", 0x09),
    ("ConstantPool", 0x0a),
    ("RefLocation", 0x0b),
    ("Descriptor", 0x0c),
];

#[derive(Debug, Clone)]
pub struct Applet {
    pub aid: Vec<u8>,
    pub install_offset: u16,
}

#[derive(Debug, Clone)]
pub struct CapFile {
    pub package_aid: Vec<u8>,
    pub version: (u8, u8),
    pub cap_version: (u8, u8),
    /// The concatenated components, exactly as they go on the wire.
    pub load_file: Vec<u8>,
    /// Every component present, in load order, with its raw bytes.
    pub components: Vec<(String, Vec<u8>)>,
    pub applets: Vec<Applet>,
}

impl CapFile {
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading {}", path.display()))?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(jar: &[u8]) -> Result<Self> {
        let mut zip = zip::ZipArchive::new(Cursor::new(jar)).context("not a CAP (zip) file")?;
        let mut found: Vec<(String, Vec<u8>)> = Vec::new();
        for (name, tag) in ORDER.iter() {
            let candidate = ["", "javacard/", "applet/"]
                .iter()
                .map(|prefix| format!("{prefix}{name}.cap"))
                .find(|path| zip.by_name(path).is_ok());
            let Some(path) = candidate else {
                if matches!(*name, "Header" | "Directory" | "Import" | "Applet" | "Class" | "Method") {
                    bail!("CAP file has no {name}.cap component");
                }
                // StaticField, Export, ConstantPool, RefLocation and Descriptor are legitimately
                // absent from small applets and from library packages
                continue;
            };
            let mut file = zip.by_name(&path)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            if buf.is_empty() {
                bail!("{name}.cap is empty");
            }
            if buf[0] != *tag {
                bail!("{name}.cap starts with tag {:02X}, expected {:02X}", buf[0], tag);
            }
            if buf.len() < 3 {
                bail!("{name}.cap is shorter than its header");
            }
            let declared = u16::from_be_bytes([buf[1], buf[2]]) as usize;
            // the size field counts the bytes after itself, so the whole component is 3 + size
            if declared + 3 != buf.len() {
                bail!("{name}.cap declares {declared} bytes but holds {}", buf.len() - 3);
            }
            found.push((name.to_string(), buf));
        }

        let header = found.iter().find(|(n, _)| n == "Header")
            .map(|(_, b)| b.clone()).expect("header checked above");
        if header.len() < 13 || header[3..7] != [0xDE, 0xCA, 0xFF, 0xED] {
            bail!("Header.cap is missing the Java Card magic number");
        }
        let cap_version = (header[8], header[7]); // major, minor as written in the file
        let pkg_minor = header[10];
        let pkg_major = header[11];
        let aid_len = header[12] as usize;
        if header.len() < 13 + aid_len || aid_len < 5 || aid_len > 16 {
            bail!("Header.cap package AID length {aid_len} is not a valid AID");
        }
        let package_aid = header[13..13 + aid_len].to_vec();

        let mut applets = Vec::new();
        if let Some((_, buf)) = found.iter().find(|(n, _)| n == "Applet") {
            if buf.len() > 4 {
                let count = buf[3] as usize;
                let mut at = 4;
                for _ in 0..count {
                    if at + 1 > buf.len() {
                        break;
                    }
                    let len = buf[at] as usize;
                    at += 1;
                    if at + len + 2 > buf.len() {
                        bail!("Applet.cap entry runs past the component");
                    }
                    let aid = buf[at..at + len].to_vec();
                    at += len;
                    let offset = u16::from_be_bytes([buf[at], buf[at + 1]]);
                    at += 2;
                    applets.push(Applet { aid, install_offset: offset });
                }
            }
        }

        // load order is fixed by the spec, not by the zip
        let mut load_file = Vec::new();
        let mut components = Vec::new();
        for (name, _) in ORDER.iter() {
            if let Some((_, buf)) = found.iter().find(|(n, _)| n == name) {
                load_file.extend_from_slice(buf);
                components.push((name.to_string(), buf.clone()));
            }
        }

        Ok(Self {
            package_aid,
            version: (pkg_major, pkg_minor),
            cap_version,
            load_file,
            components,
            applets,
        })
    }

    /// The AID an instance gets when the caller does not choose one: the sole applet's AID, or the
    /// package AID for a library package with no applet.
    pub fn default_instance_aid(&self) -> &[u8] {
        self.applets.first().map(|a| a.aid.as_slice()).unwrap_or(&self.package_aid)
    }

    pub fn module_aid(&self) -> &[u8] {
        self.applets.first().map(|a| a.aid.as_slice()).unwrap_or(&self.package_aid)
    }

    /// Split the load file into LOAD command payloads. The first block begins with the C4 tag and
    /// the length of the whole file, so its payload is smaller than the rest by that header.
    pub fn blocks(&self, block_size: usize) -> Vec<Vec<u8>> {
        let block_size = block_size.max(16);
        let mut out = Vec::new();
        let size = self.load_file.len();
        let header = c4_header(size);
        let first_capacity = block_size.saturating_sub(header.len()).max(1);
        let mut at = 0usize;
        let mut first = true;
        while at < size {
            let capacity = if first { first_capacity } else { block_size };
            let end = (at + capacity).min(size);
            let mut payload = Vec::with_capacity(capacity + 4);
            if first {
                payload.extend_from_slice(&header);
                first = false;
            }
            payload.extend_from_slice(&self.load_file[at..end]);
            at = end;
            out.push(payload);
        }
        if out.is_empty() {
            out.push(header);
        }
        out
    }
}

fn c4_header(len: usize) -> Vec<u8> {
    let mut out = vec![0xC4u8];
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn component(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn sample() -> Vec<u8> {
        let pkg_aid: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01];
        let app_aid: [u8; 8] = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01, 0x01];

        let mut header_body = vec![0xDE, 0xCA, 0xFF, 0xED, 0x02, 0x02, 0x00];
        header_body.extend_from_slice(&[0x01, 0x02, pkg_aid.len() as u8]);
        header_body.extend_from_slice(&pkg_aid);
        header_body.extend_from_slice(&[0x04, b't', b'e', b's', b't']);

        let mut applet_body = vec![0x01, app_aid.len() as u8];
        applet_body.extend_from_slice(&app_aid);
        applet_body.extend_from_slice(&[0x00, 0x0A]);

        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in [
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n".to_vec()),
            ("Header.cap", component(0x01, &header_body)),
            ("Directory.cap", component(0x02, &[0x00, 0x00])),
            ("Import.cap", component(0x04, &[0x00, 0x00])),
            ("Applet.cap", component(0x03, &applet_body)),
            ("Class.cap", component(0x06, &[0x01, 0x02, 0x03])),
            ("Method.cap", component(0x07, &[0x01, 0x02])),
        ] {
            zip.start_file(name, opts).unwrap();
            zip.write_all(&bytes).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn reads_the_package_and_applet_aids() {
        let cap = CapFile::from_bytes(&sample()).unwrap();
        assert_eq!(hex::encode(&cap.package_aid), "a0000000620101");
        assert_eq!(cap.applets.len(), 1);
        assert_eq!(hex::encode(&cap.applets[0].aid), "a000000062010101");
        assert_eq!(cap.applets[0].install_offset, 10);
        assert_eq!(cap.default_instance_aid(), cap.applets[0].aid.as_slice());
    }

    #[test]
    fn concatenates_in_spec_order_not_zip_order() {
        let cap = CapFile::from_bytes(&sample()).unwrap();
        let names: Vec<&str> = cap.components.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["Header", "Directory", "Import", "Applet", "Class", "Method"]);
        let mut expected = Vec::new();
        for (_, bytes) in cap.components.iter() {
            expected.extend_from_slice(bytes);
        }
        assert_eq!(cap.load_file, expected);
    }

    #[test]
    fn rejects_a_component_whose_size_lies() {
        // a component whose declared size disagrees with its bytes must not reach a card
        let pkg_aid: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01];
        let mut header_body = vec![0xDE, 0xCA, 0xFF, 0xED, 0x02, 0x02, 0x00];
        header_body.extend_from_slice(&[0x01, 0x02, pkg_aid.len() as u8]);
        header_body.extend_from_slice(&pkg_aid);

        let mut lying = vec![0x06u8];
        lying.extend_from_slice(&[0x00, 0x09]); // claims nine bytes, carries two
        lying.extend_from_slice(&[0x01, 0x02]);

        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in [
            ("Header.cap", component(0x01, &header_body)),
            ("Directory.cap", component(0x02, &[0x00, 0x00])),
            ("Import.cap", component(0x04, &[0x00, 0x00])),
            ("Applet.cap", component(0x03, &[0x00])),
            ("Class.cap", lying),
            ("Method.cap", component(0x07, &[0x01])),
        ] {
            zip.start_file(name, opts).unwrap();
            zip.write_all(&bytes).unwrap();
        }
        let jar = zip.finish().unwrap().into_inner();
        let err = CapFile::from_bytes(&jar).unwrap_err().to_string();
        assert!(err.contains("declares"), "{err}");
    }

    #[test]
    fn blocks_carry_the_c4_header_once_and_lose_no_bytes() {
        let cap = CapFile::from_bytes(&sample()).unwrap();
        let blocks = cap.blocks(32);
        assert!(blocks.len() > 1, "sample is big enough to split");
        assert_eq!(blocks[0][0], 0xC4);
        assert_eq!(blocks[0][1] as usize, cap.load_file.len());
        let rebuilt: Vec<u8> = blocks.iter().flat_map(|b| b.iter().copied()).collect();
        let body = &rebuilt[2..];
        assert_eq!(body, cap.load_file.as_slice());
    }

    #[test]
    fn a_large_load_file_uses_a_long_c4_length() {
        let cap = CapFile {
            package_aid: vec![1, 2, 3, 4, 5],
            version: (1, 0),
            cap_version: (3, 0),
            load_file: vec![0xAA; 300],
            components: vec![],
            applets: vec![],
        };
        let blocks = cap.blocks(200);
        assert_eq!(&blocks[0][..3], &[0xC4, 0x82, 0x01]);
        assert_eq!(blocks[0][3], 0x2C); // 300 = 0x012C
    }
}
