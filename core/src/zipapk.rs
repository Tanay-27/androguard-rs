//! The APK as androguard 4.1.3's `APK` class sees it: the zip read by
//! apkInspector's `ZipEntry` (its own, evasion-tolerant reader, not Python's
//! `zipfile`), and the v2/v3 APK Signing Block found the way
//! `APK.parse_v2_v3_signature()` finds it.
//!
//! apkInspector's rules, kept here:
//! - the End of Central Directory is the *last* `PK\5\6` in the file;
//! - the central directory is read from its declared offset until an entry
//!   doesn't start with `PK\1\2` (the declared count and size are ignored);
//!   names are UTF-8 with invalid bytes dropped; a repeated name keeps its
//!   first position and its last entry;
//! - every entry's local header is read up front; one that doesn't start
//!   with `PK\3\4` is skipped (its file can't be read), and local headers are
//!   keyed by the name in the *local* header;
//! - reading uses the local header's method, name and extra lengths, and its
//!   sizes unless either is 0 (then the central directory's); method 0 is
//!   stored, 8 is raw deflate decompressed to the end of the stream whatever
//!   the declared size, and any other method is treated as stored or as
//!   deflate depending on the sizes and whether the data inflates cleanly.
//!
//! The file is untrusted. The source is read through bounded reads (never
//! the whole file at once unless the caller already holds it), at most
//! `MAX_ZIP_ENTRIES` entries are accepted, and no entry may produce more than
//! `MAX_ENTRY_BYTES`. androguard has no such limits: a decompression bomb
//! makes it allocate whatever the stream inflates to.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use flate2::{Decompress, FlushDecompress, Status};

/// Most bytes `read()` will return for one entry. Same as the per-DEX cap in
/// `apk.rs` (no well-formed entry of a real APK comes close).
pub const MAX_ENTRY_BYTES: u64 = crate::apk::MAX_DEX_BYTES;
/// Most central directory entries (real APKs have a few thousand to tens of
/// thousands).
pub const MAX_ZIP_ENTRIES: usize = 1 << 20;
/// Largest v2/v3 signature block value we parse for certificates (real ones
/// are a few KiB).
pub const MAX_SIGNATURE_BLOCK_BYTES: u64 = 16 << 20;

/// Random-access bytes: a file or a buffer.
pub trait ReadAt: Send + Sync {
    fn size(&self) -> u64;
    /// Read up to `buf.len()` bytes at `off`; fewer only at the end.
    fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<usize>;
}

/// A file read with seeks, never loaded whole.
pub struct FileSource {
    f: Mutex<File>,
    len: u64,
}

impl FileSource {
    pub fn open(path: &str) -> Result<FileSource> {
        let f = File::open(path).with_context(|| format!("opening {path}"))?;
        let len = f.metadata()?.len();
        Ok(FileSource { f: Mutex::new(f), len })
    }
}

impl ReadAt for FileSource {
    fn size(&self) -> u64 {
        self.len
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut f = self.f.lock().unwrap_or_else(|e| e.into_inner());
        f.seek(SeekFrom::Start(off))?;
        let mut n = 0;
        while n < buf.len() {
            match f.read(&mut buf[n..])? {
                0 => break,
                k => n += k,
            }
        }
        Ok(n)
    }
}

/// Bytes already in memory (`Vec<u8>`, or a Python `bytes` on the binding side).
pub struct MemSource<T>(pub T);

impl<T: AsRef<[u8]> + Send + Sync> ReadAt for MemSource<T> {
    fn size(&self) -> u64 {
        self.0.as_ref().len() as u64
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let b = self.0.as_ref();
        let Ok(off) = usize::try_from(off) else { return Ok(0) };
        if off >= b.len() {
            return Ok(0);
        }
        let n = buf.len().min(b.len() - off);
        buf[..n].copy_from_slice(&b[off..off + n]);
        Ok(n)
    }
}

/// `f.read(n)` at `off`: up to `n` bytes, short at the end of the source.
fn read_lenient(src: &dyn ReadAt, off: u64, n: u64) -> Result<Vec<u8>> {
    let avail = src.size().saturating_sub(off);
    let n = n.min(avail);
    let mut buf = vec![0u8; usize::try_from(n).map_err(|_| anyhow!("read too large"))?];
    let got = src.read_at(off, &mut buf)?;
    buf.truncate(got);
    Ok(buf)
}

/// `struct.unpack` of `f.read(n)`: all `n` bytes or `struct.error`.
fn read_exact(src: &dyn ReadAt, off: u64, n: u64) -> Result<Vec<u8>> {
    let b = read_lenient(src, off, n)?;
    if (b.len() as u64) < n {
        bail!("unpack requires a buffer of {n} bytes");
    }
    Ok(b)
}

/// A small read-through window, so walking the central directory doesn't
/// cost a system call per field.
struct Window<'a> {
    src: &'a dyn ReadAt,
    start: u64,
    buf: Vec<u8>,
}

impl<'a> Window<'a> {
    const SIZE: u64 = 256 << 10;

    fn new(src: &'a dyn ReadAt) -> Self {
        Window { src, start: 0, buf: Vec::new() }
    }

    /// Up to `n` bytes at `off` (short at the end of the source).
    fn get(&mut self, off: u64, n: u64) -> Result<Vec<u8>> {
        let end = off.saturating_add(n);
        if off < self.start || end > self.start + self.buf.len() as u64 {
            if n > Self::SIZE {
                return read_lenient(self.src, off, n);
            }
            self.buf = read_lenient(self.src, off, Self::SIZE)?;
            self.start = off;
        }
        let a = (off - self.start) as usize;
        let b = (end.min(self.start + self.buf.len() as u64) - self.start) as usize;
        Ok(self.buf[a..b.max(a)].to_vec())
    }

    fn exact(&mut self, off: u64, n: u64) -> Result<Vec<u8>> {
        let b = self.get(off, n)?;
        if (b.len() as u64) < n {
            bail!("unpack requires a buffer of {n} bytes");
        }
        Ok(b)
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// `bytes.decode("utf-8", "ignore")`.
pub fn decode_ignore(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len());
    for chunk in b.utf8_chunks() {
        s.push_str(chunk.valid());
    }
    s
}

/// The last `needle` (4 bytes) starting before `limit`, scanning backwards.
fn rfind_sig(src: &dyn ReadAt, needle: &[u8; 4], limit: u64) -> Result<Option<u64>> {
    const CHUNK: u64 = 1 << 20;
    let limit = limit.min(src.size());
    let mut hi = limit; // search starts strictly below hi
    while hi > 0 {
        let lo = hi.saturating_sub(CHUNK);
        // Overlap 3 bytes into the previous (higher) chunk.
        let buf = read_lenient(src, lo, (hi - lo) + 3)?;
        let cut = ((hi - lo) as usize + 3).min(buf.len());
        let hay = &buf[..cut];
        if let Some(i) = memchr::memmem::rfind(hay, needle) {
            let p = lo + i as u64;
            if p < hi {
                return Ok(Some(p));
            }
        }
        hi = lo;
    }
    Ok(None)
}

#[derive(Clone, Debug)]
struct CdEntry {
    compressed_size: u32,
    uncompressed_size: u32,
    local_offset: u32,
}

#[derive(Clone, Debug)]
struct LocalHeader {
    method: u16,
    compressed_size: u32,
    uncompressed_size: u32,
    name_len: u16,
    extra_len: u16,
}

/// The APK's zip, read as apkInspector reads it.
pub struct ApkZip<'a> {
    src: Box<dyn ReadAt + 'a>,
    /// `namelist()`: central directory names in first-seen order.
    names: Vec<String>,
    cd: HashMap<String, CdEntry>,
    local: HashMap<String, LocalHeader>,
}

/// Why `read()` returned nothing: no such entry (androguard's `KeyError`,
/// turned into `FileNotPresent` by `APK.get_file()`), or a failure.
#[derive(Debug)]
pub enum ReadError {
    NotPresent,
    Failed(anyhow::Error),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::NotPresent => write!(f, "not present"),
            ReadError::Failed(e) => write!(f, "{e:#}"),
        }
    }
}

impl<'a> ApkZip<'a> {
    pub fn open_path(path: &str) -> Result<ApkZip<'a>> {
        ApkZip::open(Box::new(FileSource::open(path)?))
    }

    /// `ZipEntry.parse(...)`: EOCD, central directory and every local header.
    pub fn open(src: Box<dyn ReadAt + 'a>) -> Result<ApkZip<'a>> {
        let s: &dyn ReadAt = src.as_ref();
        let Some(eocd) = rfind_sig(s, b"PK\x05\x06", u64::MAX)? else {
            bail!("End of central directory record (EOCD) signature not found");
        };
        let rec = read_exact(s, eocd, 22)?;
        let cd_offset = le32(&rec, 16) as u64;
        let comment_len = le16(&rec, 20) as u64;
        read_exact(s, eocd + 22, comment_len)?;

        let mut w = Window::new(s);
        let mut names: Vec<String> = Vec::new();
        let mut cd: HashMap<String, CdEntry> = HashMap::new();
        let mut pos = cd_offset;
        loop {
            if w.get(pos, 4)? != b"PK\x01\x02" {
                break;
            }
            let f = w.exact(pos + 4, 42)?;
            let (name_len, extra_len, comment_len) = (le16(&f, 24) as u64, le16(&f, 26) as u64, le16(&f, 28) as u64);
            let entry = CdEntry { compressed_size: le32(&f, 16), uncompressed_size: le32(&f, 20), local_offset: le32(&f, 38) };
            let name = decode_ignore(&w.exact(pos + 46, name_len)?);
            w.exact(pos + 46 + name_len, extra_len)?;
            w.exact(pos + 46 + name_len + extra_len, comment_len)?;
            pos += 46 + name_len + extra_len + comment_len;
            if !cd.contains_key(&name) {
                if names.len() >= MAX_ZIP_ENTRIES {
                    bail!("more than {MAX_ZIP_ENTRIES} central directory entries");
                }
                names.push(name.clone());
            }
            cd.insert(name, entry);
        }

        let mut local: HashMap<String, LocalHeader> = HashMap::new();
        for name in &names {
            let e = &cd[name];
            let off = e.local_offset as u64;
            if w.get(off, 4)? != b"PK\x03\x04" {
                continue;
            }
            let f = w.exact(off + 4, 26)?;
            let h = LocalHeader {
                method: le16(&f, 4),
                compressed_size: le32(&f, 14),
                uncompressed_size: le32(&f, 18),
                name_len: le16(&f, 22),
                extra_len: le16(&f, 24),
            };
            let (nl, el) = (h.name_len as u64, h.extra_len as u64);
            let name_b = w.get(off + 30, nl)?;
            let extra_ok = (w.get(off + 30 + nl, el)?.len() as u64) == el;
            let local_name = if name_b.len() as u64 == nl && extra_ok { decode_ignore(&name_b) } else { name.clone() };
            local.insert(local_name, h);
        }
        Ok(ApkZip { src, names, cd, local })
    }

    /// `namelist()`.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    pub fn source(&self) -> &(dyn ReadAt + 'a) {
        self.src.as_ref()
    }

    /// `ZipEntry.read(name)`.
    pub fn read(&self, name: &str) -> std::result::Result<Vec<u8>, ReadError> {
        self.read_capped(name, MAX_ENTRY_BYTES)
    }

    /// `read()` that fails instead of returning more than `cap` bytes
    /// (`cap` is at most `MAX_ENTRY_BYTES`).
    pub fn read_capped(&self, name: &str, cap: u64) -> std::result::Result<Vec<u8>, ReadError> {
        let local = self.local.get(name).ok_or(ReadError::NotPresent)?;
        let cd = self.cd.get(name).ok_or(ReadError::NotPresent)?;
        self.extract(local, cd, cap.min(MAX_ENTRY_BYTES)).map_err(ReadError::Failed)
    }

    fn extract(&self, l: &LocalHeader, cd: &CdEntry, cap: u64) -> Result<Vec<u8>> {
        let (csize, usize_) = if l.compressed_size == 0 || l.uncompressed_size == 0 {
            (cd.compressed_size as u64, cd.uncompressed_size as u64)
        } else {
            (l.compressed_size as u64, l.uncompressed_size as u64)
        };
        let s = self.src.as_ref();
        let data_off = cd.local_offset as u64 + 30 + l.name_len as u64 + l.extra_len as u64;
        let stored = |n: u64| -> Result<Vec<u8>> {
            if n.min(s.size().saturating_sub(data_off)) > cap {
                bail!("zip entry is over the {cap}-byte limit");
            }
            read_lenient(s, data_off, n)
        };
        match l.method {
            0 => stored(usize_),
            8 => {
                let comp = read_lenient(s, data_off, csize)?;
                let r = inflate_raw(&comp, cap, usize_)?;
                if !r.stream_end {
                    bail!("Error -5 while decompressing data: incomplete or truncated stream");
                }
                Ok(r.out)
            }
            _ if csize == usize_ => stored(usize_),
            _ => {
                let comp = read_lenient(s, data_off, csize)?;
                match inflate_raw(&comp, cap, usize_) {
                    Ok(r) if r.stream_end && r.consumed == comp.len() => Ok(r.out),
                    Err(e) if e.to_string().contains("limit") => Err(e),
                    _ => stored(usize_),
                }
            }
        }
    }
}

struct Inflated {
    out: Vec<u8>,
    stream_end: bool,
    consumed: usize,
}

/// Raw deflate (`zlib.decompress(data, -15)`), stopping at the end of the
/// stream, with output capped at `cap`. A corrupt stream is an error;
/// running out of input is `stream_end == false`.
///
/// `declared` (the entry's declared uncompressed size, untrusted) is only a
/// capacity hint, and is clamped to what `input` can inflate to at most
/// (deflate's ratio is below 1032:1) and to `cap`. A well-formed entry then
/// inflates into one exact allocation; any other is grown as needed and
/// shrunk to fit at the end.
fn inflate_raw(input: &[u8], cap: u64, declared: u64) -> Result<Inflated> {
    let mut d = Decompress::new(false);
    let most = (input.len() as u64).saturating_mul(1032).saturating_add(64);
    // +64: room to read the end of the stream without growing (and copying)
    // a buffer that is already exactly full.
    let hint = declared.min(most).saturating_add(64).min(cap) as usize;
    let mut out: Vec<u8> = Vec::with_capacity(hint.max((input.len() * 4).clamp(64, 1 << 20).min(cap as usize)));
    loop {
        if out.len() == out.capacity() {
            if out.len() as u64 >= cap {
                bail!("zip entry inflates past the {cap}-byte limit");
            }
            let grow = out.len().max(64 << 10).min((cap - out.len() as u64) as usize);
            out.reserve_exact(grow);
        }
        let before_in = d.total_in();
        let before_out = d.total_out();
        let st = d
            .decompress_vec(&input[d.total_in() as usize..], &mut out, FlushDecompress::None)
            .map_err(|e| anyhow!("Error -3 while decompressing data: {e}"))?;
        if st == Status::StreamEnd {
            out.shrink_to_fit();
            return Ok(Inflated { out, stream_end: true, consumed: d.total_in() as usize });
        }
        if d.total_in() == before_in && d.total_out() == before_out && out.len() < out.capacity() {
            // No progress with room to spare: the input is exhausted.
            out.shrink_to_fit();
            return Ok(Inflated { out, stream_end: false, consumed: d.total_in() as usize });
        }
    }
}

// ── APK Signing Block (v2/v3) ────────────────────────────────────────────────

pub const V2_KEY: u32 = 0x7109_871A;
pub const V3_KEY: u32 = 0xF053_68C0;

/// What `APK.parse_v2_v3_signature()` leaves behind.
#[derive(Debug, Default, Clone)]
pub struct SigningBlock {
    /// Whether it got as far as setting `_is_signed_v2/_v3` to False (after
    /// which they're only ever turned True). If not, both stay None.
    pub flags_set: bool,
    pub v2: bool,
    pub v3: bool,
    /// (offset, length) of the first v2 / v3 value in the file.
    pub v2_value: Option<(u64, u64)>,
    pub v3_value: Option<(u64, u64)>,
    /// What it raised, if anything (after setting whatever it had set).
    pub error: Option<String>,
}

/// `APK.parse_v2_v3_signature()` over the raw APK.
pub fn signing_block(src: &dyn ReadAt) -> SigningBlock {
    let mut sb = SigningBlock::default();
    if let Err(e) = scan_signing_block(src, &mut sb) {
        sb.error = Some(format!("{e:#}"));
    }
    sb
}

fn scan_signing_block(src: &dyn ReadAt, sb: &mut SigningBlock) -> Result<()> {
    let n = src.size();
    if n < 21 {
        bail!("negative seek value");
    }
    // Candidates start at n-22 and go down to 0.
    let Some(eocd) = rfind_sig(src, b"PK\x05\x06", n - 21)? else { return Ok(()) };
    let rec = read_exact(src, eocd + 4, 16)?;
    let offset_central = le32(&rec, 12) as u64;
    if offset_central == 0 {
        return Ok(());
    }
    if read_exact(src, offset_central, 4)? != b"PK\x01\x02" {
        bail!("No Central Dir at specified offset");
    }
    let end_offset = offset_central;
    if end_offset < 24 {
        bail!("negative seek value");
    }
    let tail = read_exact(src, end_offset - 24, 24)?;
    let size_of_block = le64(&tail, 0);
    sb.flags_set = true;
    if &tail[8..24] != b"APK Sig Block 42" {
        return Ok(());
    }
    let back = size_of_block.checked_add(8).filter(|&b| b <= end_offset).ok_or_else(|| anyhow!("negative seek value"))?;
    let mut pos = end_offset - back;
    if le64(&read_exact(src, pos, 8)?, 0) != size_of_block {
        bail!("Sizes at beginning and end does not match!");
    }
    pos += 8;
    let mut seen_v2 = false;
    let mut seen_v3 = false;
    while pos < end_offset - 24 {
        let h = read_exact(src, pos, 12)?;
        let (size, key) = (le64(&h, 0), le32(&h, 8));
        pos += 12;
        // value = f.read(size - 4): negative reads to the end of the file.
        let want = if size < 4 {
            n.saturating_sub(pos)
        } else {
            if size - 4 > i64::MAX as u64 {
                bail!("Python int too large to convert to C ssize_t");
            }
            size - 4
        };
        let got = want.min(n.saturating_sub(pos));
        if key == V2_KEY && !seen_v2 {
            seen_v2 = true;
            sb.v2_value = Some((pos, got));
        }
        if key == V3_KEY && !seen_v3 {
            seen_v3 = true;
            sb.v3_value = Some((pos, got));
        }
        pos += got;
    }
    sb.v2 = seen_v2;
    sb.v3 = seen_v3;
    Ok(())
}

/// Read a signing block value located by `signing_block()`.
pub fn read_block_value(src: &dyn ReadAt, at: (u64, u64)) -> Result<Vec<u8>> {
    if at.1 > MAX_SIGNATURE_BLOCK_BYTES {
        bail!("signature block of {} bytes is over the {MAX_SIGNATURE_BLOCK_BYTES}-byte limit", at.1);
    }
    read_lenient(src, at.0, at.1)
}

/// `io.BytesIO` over a byte string, as the signer parsing uses it.
struct Bio<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Bio<'a> {
    fn u32(&mut self) -> Result<u32> {
        let s = self.b.get(self.pos..self.pos + 4).ok_or_else(|| anyhow!("unpack requires a buffer of 4 bytes"))?;
        self.pos += 4;
        Ok(le32(s, 0))
    }
    fn read(&mut self, n: u32) -> &'a [u8] {
        let start = self.pos.min(self.b.len());
        let end = start.saturating_add(n as usize).min(self.b.len());
        self.pos = end.max(self.pos);
        &self.b[start..end]
    }
}

/// `parse_signatures_or_digests()`: only whether it raises matters.
fn check_digests(raw: &[u8]) -> Result<()> {
    if raw.is_empty() {
        return Ok(());
    }
    let mut b = Bio { b: raw, pos: 0 };
    let data_len = b.u32()? as usize;
    while b.pos < data_len {
        b.u32()?;
        let n = b.u32()?;
        b.read(n);
    }
    Ok(())
}

/// `parse_v2_signing_block()` / `parse_v3_signing_block()`: the certificates
/// (DER bytes) of every signer, in order, as far as parsing got, and what it
/// raised, if anything. androguard keeps the signers parsed before an error,
/// and a later call returns those without parsing again.
pub fn signer_certificates(block: &[u8], v3: bool) -> (Vec<Vec<u8>>, Option<String>) {
    let mut certs = Vec::new();
    let r = (|| -> Result<()> {
        let mut b = Bio { b: block, pos: 0 };
        let size_sequence = b.u32()? as u64;
        if size_sequence + 4 != block.len() as u64 {
            bail!("size of sequence and blocksize does not match");
        }
        while b.pos < block.len() {
            let mut signer_certs = Vec::new();
            b.u32()?; // size_signer
            let len_signed = b.u32()?;
            let signed = b.read(len_signed);
            let mut sd = Bio { b: signed, pos: 0 };
            let len_digests = sd.u32()?;
            check_digests(sd.read(len_digests))?;
            let len_certs = sd.u32()? as usize;
            let start = sd.pos;
            while sd.pos < start + len_certs {
                let n = sd.u32()?;
                signer_certs.push(sd.read(n).to_vec());
            }
            if v3 {
                sd.u32()?;
                sd.u32()?;
            }
            let len_attr = sd.u32()?;
            sd.read(len_attr);
            if v3 {
                b.u32()?;
                b.u32()?;
            }
            let len_sigs = b.u32()?;
            check_digests(b.read(len_sigs))?;
            let len_pk = b.u32()?;
            b.read(len_pk);
            certs.extend(signer_certs);
        }
        Ok(())
    })();
    (certs, r.err().map(|e| format!("{e:#}")))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A zip with the given (name, method, data) entries, written plainly.
    pub(crate) fn zip_of(entries: &[(&str, u16, &[u8])], pre_cd: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for (name, method, data) in entries {
            let off = out.len() as u32;
            let payload: Vec<u8> = if *method == 8 {
                let mut c = flate2::Compress::new(flate2::Compression::default(), false);
                let mut v = Vec::with_capacity(data.len() + 64);
                c.compress_vec(data, &mut v, flate2::FlushCompress::Finish).unwrap();
                v
            } else {
                data.to_vec()
            };
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[20, 0, 0, 0]);
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&payload);
            cd.extend_from_slice(b"PK\x01\x02");
            cd.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            cd.extend_from_slice(&method.to_le_bytes());
            cd.extend_from_slice(&[0; 8]);
            cd.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 12]);
            cd.extend_from_slice(&off.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        out.extend_from_slice(pre_cd);
        let cd_off = out.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    fn open(b: Vec<u8>) -> ApkZip<'static> {
        ApkZip::open(Box::new(MemSource(b))).unwrap()
    }

    #[test]
    fn reads_stored_and_deflated_in_cd_order() {
        let z = open(zip_of(&[("b.txt", 0, b"hello"), ("a.txt", 8, b"world world world"), ("b.txt", 0, b"again")], b""));
        assert_eq!(z.names(), &["b.txt".to_string(), "a.txt".to_string()]);
        assert_eq!(z.read("a.txt").unwrap(), b"world world world");
        // A repeated name keeps its first position and its last entry.
        assert_eq!(z.read("b.txt").unwrap(), b"again");
        assert!(matches!(z.read("missing"), Err(ReadError::NotPresent)));
    }

    #[test]
    fn no_eocd_and_truncated_cd_fail() {
        assert!(ApkZip::open(Box::new(MemSource(b"not a zip at all".to_vec()))).is_err());
        let mut b = zip_of(&[("a", 0, b"x")], b"");
        let cd_off = le32(&b, b.len() - 6) as usize;
        b.truncate(cd_off + 10);
        b.extend_from_slice(b"PK\x05\x06");
        b.extend_from_slice(&[0; 12]);
        b.extend_from_slice(&(cd_off as u32).to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        assert!(ApkZip::open(Box::new(MemSource(b))).is_err());
    }

    #[test]
    fn deflate_bomb_is_capped() {
        let zeros = vec![0u8; 4 << 20];
        let mut c = flate2::Compress::new(flate2::Compression::default(), false);
        let mut v = Vec::with_capacity(1 << 20);
        c.compress_vec(&zeros, &mut v, flate2::FlushCompress::Finish).unwrap();
        let e = inflate_raw(&v, 1 << 20, 4 << 20).err().unwrap();
        assert!(e.to_string().contains("limit"), "{e}");
        assert_eq!(inflate_raw(&v, 8 << 20, 0).unwrap().out.len(), 4 << 20);
        // A declared size larger than the input can inflate to is clamped.
        let r = inflate_raw(&v, 8 << 20, u32::MAX as u64).unwrap();
        assert_eq!(r.out.len(), 4 << 20);
        // And a cap below what the stream inflates to still fails.
        let z = open(zip_of(&[("bomb", 8, &zeros)], b""));
        assert!(matches!(z.read_capped("bomb", 1 << 20), Err(ReadError::Failed(_))));
        // Through the zip reader, a bomb within the cap still reads.
        let z = open(zip_of(&[("bomb", 8, &zeros)], b""));
        assert_eq!(z.read("bomb").unwrap().len(), 4 << 20);
    }

    #[test]
    fn corrupt_deflate_is_an_error() {
        let mut b = zip_of(&[("a", 8, b"some text some text")], b"");
        b[30 + 1] = 0xFF; // first payload byte
        b[30 + 2] = 0xFF;
        let z = open(b);
        assert!(matches!(z.read("a"), Err(ReadError::Failed(_))));
    }

    fn signing_block_bytes(pairs: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (k, v) in pairs {
            body.extend_from_slice(&((v.len() + 4) as u64).to_le_bytes());
            body.extend_from_slice(&k.to_le_bytes());
            body.extend_from_slice(v);
        }
        let size = (body.len() + 8 + 16) as u64;
        let mut out = size.to_le_bytes().to_vec();
        out.extend_from_slice(&body);
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(b"APK Sig Block 42");
        out
    }

    fn signer_block(certs: &[&[u8]], v3: bool) -> Vec<u8> {
        let mut signed = Vec::new();
        signed.extend_from_slice(&0u32.to_le_bytes()); // digests
        let mut cs = Vec::new();
        for c in certs {
            cs.extend_from_slice(&(c.len() as u32).to_le_bytes());
            cs.extend_from_slice(c);
        }
        signed.extend_from_slice(&(cs.len() as u32).to_le_bytes());
        signed.extend_from_slice(&cs);
        if v3 {
            signed.extend_from_slice(&[24, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F]);
        }
        signed.extend_from_slice(&0u32.to_le_bytes()); // attributes
        let mut signer = Vec::new();
        signer.extend_from_slice(&(signed.len() as u32).to_le_bytes());
        signer.extend_from_slice(&signed);
        if v3 {
            signer.extend_from_slice(&[24, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F]);
        }
        signer.extend_from_slice(&0u32.to_le_bytes()); // signatures
        signer.extend_from_slice(&0u32.to_le_bytes()); // public key
        let mut seq = (signer.len() as u32).to_le_bytes().to_vec();
        seq.extend_from_slice(&signer);
        let mut out = (seq.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(&seq);
        out
    }

    #[test]
    fn finds_v2_and_v3_and_counts_certificates() {
        let v2 = signer_block(&[b"cert-one", b"cert-two"], false);
        let v3 = signer_block(&[b"cert-three"], true);
        let blk = signing_block_bytes(&[(0x42726577, vec![0; 8]), (V2_KEY, v2), (V3_KEY, v3)]);
        let b = zip_of(&[("a", 0, b"x")], &blk);
        let src = MemSource(b);
        let sb = signing_block(&src);
        assert!(sb.flags_set && sb.v2 && sb.v3 && sb.error.is_none(), "{sb:?}");
        let (c2, e2) = signer_certificates(&read_block_value(&src, sb.v2_value.unwrap()).unwrap(), false);
        assert_eq!((c2, e2), (vec![b"cert-one".to_vec(), b"cert-two".to_vec()], None));
        let (c3, e3) = signer_certificates(&read_block_value(&src, sb.v3_value.unwrap()).unwrap(), true);
        assert_eq!((c3, e3), (vec![b"cert-three".to_vec()], None));
    }

    #[test]
    fn unsigned_and_broken_blocks() {
        let src = MemSource(zip_of(&[("a", 0, b"x")], &[0u8; 32]));
        let sb = signing_block(&src);
        assert!(sb.flags_set && !sb.v2 && !sb.v3 && sb.error.is_none());
        // Sizes at both ends disagree.
        let mut blk = signing_block_bytes(&[(V2_KEY, vec![1, 2, 3])]);
        blk[0] ^= 1;
        let sb = signing_block(&MemSource(zip_of(&[("a", 0, b"x")], &blk)));
        assert!(sb.flags_set && !sb.v2 && sb.error.unwrap().contains("Sizes"));
        // A sequence size that doesn't match: an error, nothing parsed.
        let (c, e) = signer_certificates(&[9, 0, 0, 0, 1, 2], false);
        assert!(c.is_empty() && e.unwrap().contains("does not match"));
        // Truncated signer: the certificates read before the error stay.
        let mut s = signer_block(&[b"abc"], false);
        let l = s.len();
        s.truncate(l - 4);
        let n = (s.len() - 4) as u32;
        s[..4].copy_from_slice(&n.to_le_bytes());
        let (c, e) = signer_certificates(&s, false);
        assert!(c.is_empty() && e.is_some());
    }

    #[test]
    fn decode_ignore_drops_invalid_bytes() {
        assert_eq!(decode_ignore(b"a\xffb\xe2\x82c\xef\xbf\xbd"), "abc\u{fffd}");
    }
}
