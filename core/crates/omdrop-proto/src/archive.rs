//! AirDrop's `/Upload` archives: a CPIO archive in DVZip framing.
//!
//! sharingd (macOS 15, iOS 26) sends `/Upload` as `application/x-dvzip`, not
//! the plain `x-cpio` older AirDrop implementations take; answering 406 to it
//! makes the sender report a failed transfer. A DVZip body is a sequence of
//! blocks, each a 4-byte big-endian header (low 31 bits: payload length; high
//! bit: stored) followed by a zlib stream or the raw bytes. sharingd stores a
//! block when zlib does not shrink it (measured 215526Z: a 22 MB video was 20
//! zlib blocks, then 151 stored ones). A body that starts with the gzip magic
//! is one gzip member instead, as OpenDrop-style senders send it. Inside is a
//! CPIO archive: odc (`070707`, what libarchive's `cpio` writer and Apple
//! produce) or newc (`070701`/`070702`).
//!
//! Decoding is streaming and bounded: [`extract`] reads the body once, never
//! holds it in memory or on disk, and stops at the first byte past a ceiling.
//! Only regular files are written; directories, symlinks, devices and FIFOs
//! are skipped, never created, and every name is reduced to one sanitised
//! component by [`safe_name`], so nothing can land outside the download
//! directory. Files are written under hidden temporary names and given their
//! real names only once the whole archive has checked out: a failed upload
//! leaves nothing behind.

use std::cell::Cell;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Mutex;

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use unicode_normalization::UnicodeNormalization;

/// Read and write granularity.
pub const IO_CHUNK_BYTES: usize = 64 * 1024;
/// The DVZip block size sharingd and the Python sender use.
pub const DVZIP_BLOCK_BYTES: usize = 1 << 16;
/// High bit of a DVZip block header: the payload is stored, not zlib.
pub const DVZIP_STORED: u32 = 0x8000_0000;
/// Members (of any type) one archive may hold.
pub const MAX_ARCHIVE_MEMBERS: usize = 512;
/// Longest member path accepted, in bytes.
pub const MAX_PATH_BYTES: usize = 4096;
/// Free space is re-checked after this many bytes written to one file.
pub const DISK_CHECK_INTERVAL: u64 = 16 * 1024 * 1024;
/// Longest file name a Linux file system takes, in bytes.
pub const MAX_FILE_NAME_BYTES: usize = 255;
/// Prefix of the hidden files an upload is written to before it checks out.
pub const PARTIAL_PREFIX: &str = ".omdrop-partial-";

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const ODC_MAGIC: &[u8; 6] = b"070707";
const NEWC_MAGIC: &[u8; 6] = b"070701";
const NEWC_CRC_MAGIC: &[u8; 6] = b"070702";
const TRAILER: &str = "TRAILER!!!";
const ODC_MAX_SIZE: u64 = 0o777_7777_7777;
const ODC_MAX_SHORT: u64 = 0o777_777;

/// Why an archive was refused.
#[derive(Debug)]
pub enum ArchiveError {
    /// A byte, member or free-space ceiling was reached.
    Limit(String),
    /// Not a valid DVZip/gzip body or CPIO archive.
    Invalid(String),
    /// Reading the body or writing a file failed. Errors raised by the body
    /// reader (timeouts, framing) arrive here unchanged, for the caller to
    /// classify.
    Io(io::Error),
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveError::Limit(m) | ArchiveError::Invalid(m) => f.write_str(m),
            ArchiveError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ArchiveError {}

impl From<io::Error> for ArchiveError {
    /// An `ArchiveError` that travelled through a `Read` impl comes back out
    /// as itself; anything else is `Io`.
    fn from(e: io::Error) -> Self {
        if e.get_ref().is_some_and(|inner| inner.is::<ArchiveError>()) {
            match e.into_inner().map(|inner| inner.downcast::<ArchiveError>()) {
                Some(Ok(inner)) => *inner,
                _ => ArchiveError::Invalid("internal error unwrapping an archive error".into()),
            }
        } else {
            ArchiveError::Io(e)
        }
    }
}

impl ArchiveError {
    fn into_io(self) -> io::Error {
        match self {
            ArchiveError::Io(e) => e,
            other => io::Error::other(other),
        }
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    ArchiveError::Invalid(message.into()).into_io()
}

/// Read until `buf` is full or the source ends; the number of bytes read.
pub(crate) fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

// ------------------------------------------------------------------ DVZip

type Sniffed<R> = BufReader<io::Chain<io::Cursor<Vec<u8>>, Source<R>>>;

/// The body, remembering whether it failed: flate2 wraps its own verdicts in
/// custom errors too, so only this tells a body-reader error (a timeout, bad
/// framing) from a bad gzip stream. Any byte it delivers clears `clean_end`.
struct Source<R> {
    inner: R,
    failed: bool,
    clean_end: Rc<Cell<bool>>,
}

impl<R: Read> Read for Source<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = self.inner.read(buf);
        match &result {
            Ok(n) if *n > 0 => self.clean_end.set(false),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => self.failed = true,
        }
        result
    }
}

enum Block {
    Header,
    Stored { left: usize },
    Compressed { left: usize, zlib: Box<Decompress> },
    Done,
}

enum Body<R: Read> {
    Gzip(Box<flate2::bufread::GzDecoder<Sniffed<R>>>),
    Blocks { inner: Sniffed<R>, block: Block },
}

/// Streams the CPIO bytes out of a DVZip or gzip body.
///
/// Truncated and malformed bodies are errors, never a short archive: a block
/// header cut short, a block whose bytes run out, a zlib stream that ends
/// before its block does (trailing data) or a block that ends before its
/// stream does.
///
/// Its clean-end flag is true only while it waits for body bytes at a point
/// where the body may end: between DVZip blocks, or after a gzip member's
/// footer. A body that stops anywhere else is truncated.
pub struct DvzipDecoder<R: Read> {
    body: Body<R>,
    clean_end: Rc<Cell<bool>>,
}

impl<R: Read> DvzipDecoder<R> {
    /// Sniffs the first two bytes to tell gzip from DVZip.
    pub fn new(source: R) -> io::Result<Self> {
        Self::with_clean_end(source, Rc::default())
    }

    /// As [`new`](Self::new), keeping its clean-end flag in `clean_end`.
    fn with_clean_end(mut source: R, clean_end: Rc<Cell<bool>>) -> io::Result<Self> {
        let mut magic = [0u8; 2];
        let n = read_full(&mut source, &mut magic)?;
        let prefix = magic.get(..n).unwrap_or_default().to_vec();
        let source = Source {
            inner: source,
            failed: false,
            clean_end: clean_end.clone(),
        };
        let inner = BufReader::with_capacity(IO_CHUNK_BYTES, io::Cursor::new(prefix).chain(source));
        let body = if n == 2 && magic == GZIP_MAGIC {
            Body::Gzip(Box::new(flate2::bufread::GzDecoder::new(inner)))
        } else {
            Body::Blocks {
                inner,
                block: Block::Header,
            }
        };
        Ok(DvzipDecoder { body, clean_end })
    }
}

impl<R: Read> Read for DvzipDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match &mut self.body {
            Body::Gzip(decoder) => match decoder.read(buf) {
                Ok(0) => {
                    // The member's footer is in: the body may end here.
                    self.clean_end.set(decoder.get_ref().buffer().is_empty());
                    if decoder.get_mut().fill_buf()?.is_empty() {
                        Ok(0)
                    } else {
                        Err(invalid("gzip body has trailing data"))
                    }
                }
                Ok(n) => Ok(n),
                Err(e) if decoder.get_ref().get_ref().get_ref().1.failed => Err(e),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    Err(invalid("truncated gzip body"))
                }
                Err(e) => Err(invalid(format!("invalid gzip body: {e}"))),
            },
            Body::Blocks { inner, block } => read_blocks(inner, block, buf, &self.clean_end),
        }
    }
}

fn read_blocks<R: Read>(
    inner: &mut BufReader<R>,
    block: &mut Block,
    buf: &mut [u8],
    clean_end: &Cell<bool>,
) -> io::Result<usize> {
    loop {
        match block {
            Block::Done => return Ok(0),
            Block::Header => {
                // Between blocks: the body may end here, unless part of the
                // next header is already buffered.
                clean_end.set(inner.buffer().is_empty());
                let mut header = [0u8; 4];
                match read_full(inner, &mut header)? {
                    0 => {
                        *block = Block::Done;
                        return Ok(0);
                    }
                    4 => {}
                    n => return Err(invalid(format!("truncated DVZip block header: {n} bytes"))),
                }
                let value = u32::from_be_bytes(header);
                let left = (value & !DVZIP_STORED) as usize;
                *block = if value & DVZIP_STORED != 0 {
                    Block::Stored { left }
                } else {
                    Block::Compressed {
                        left,
                        zlib: Box::new(Decompress::new(true)),
                    }
                };
            }
            Block::Stored { left } => {
                if *left == 0 {
                    *block = Block::Header;
                    continue;
                }
                let want = buf.len().min(*left);
                let n = inner.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(invalid(format!(
                        "truncated stored block: {left} bytes missing"
                    )));
                }
                *left -= n;
                return Ok(n);
            }
            Block::Compressed { left, zlib } => {
                let available = if *left > 0 {
                    let available = inner.fill_buf()?;
                    if available.is_empty() {
                        return Err(invalid(format!(
                            "truncated compressed block: {left} bytes missing"
                        )));
                    }
                    available
                        .get(..available.len().min(*left))
                        .unwrap_or_default()
                } else {
                    &[]
                };
                let (in_before, out_before) = (zlib.total_in(), zlib.total_out());
                let status = zlib
                    .decompress(available, buf, FlushDecompress::None)
                    .map_err(|e| invalid(format!("invalid compressed block: {e}")))?;
                let consumed = (zlib.total_in() - in_before) as usize;
                let produced = (zlib.total_out() - out_before) as usize;
                inner.consume(consumed);
                *left -= consumed;
                if status == Status::StreamEnd {
                    if *left > 0 {
                        return Err(invalid("compressed block has trailing data"));
                    }
                    *block = Block::Header;
                } else if produced == 0 && consumed == 0 {
                    return Err(invalid("truncated compressed block"));
                }
                if produced > 0 {
                    return Ok(produced);
                }
            }
        }
    }
}

/// Writes DVZip: 64 KiB blocks, each zlib level 6, or stored when zlib does
/// not shrink it, as sharingd does. Call [`finish`](Self::finish): dropping
/// the encoder loses the last block. `flush` flushes the inner writer only, so
/// block boundaries never depend on how the caller writes.
pub struct DvzipEncoder<W: Write> {
    inner: W,
    block: Vec<u8>,
    compressed: Vec<u8>,
    zlib: Compress,
}

impl<W: Write> DvzipEncoder<W> {
    pub fn new(inner: W) -> Self {
        DvzipEncoder {
            inner,
            block: Vec::with_capacity(DVZIP_BLOCK_BYTES),
            compressed: Vec::with_capacity(DVZIP_BLOCK_BYTES + 1024),
            zlib: Compress::new(Compression::new(6), true),
        }
    }

    fn emit(&mut self) -> io::Result<()> {
        if self.block.is_empty() {
            return Ok(());
        }
        self.zlib.reset();
        self.compressed.clear();
        loop {
            if self.compressed.len() == self.compressed.capacity() {
                self.compressed.reserve(DVZIP_BLOCK_BYTES / 4);
            }
            let consumed = self.zlib.total_in() as usize;
            let rest = self.block.get(consumed..).unwrap_or_default();
            let status = self
                .zlib
                .compress_vec(rest, &mut self.compressed, FlushCompress::Finish)
                .map_err(io::Error::other)?;
            if status == Status::StreamEnd {
                break;
            }
        }
        if self.compressed.len() < self.block.len() {
            self.inner
                .write_all(&(self.compressed.len() as u32).to_be_bytes())?;
            self.inner.write_all(&self.compressed)?;
        } else {
            self.inner
                .write_all(&(DVZIP_STORED | self.block.len() as u32).to_be_bytes())?;
            self.inner.write_all(&self.block)?;
        }
        self.block.clear();
        Ok(())
    }

    /// Writes the last block and returns the inner writer, flushed.
    pub fn finish(mut self) -> io::Result<W> {
        self.emit()?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for DvzipEncoder<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let room = DVZIP_BLOCK_BYTES - self.block.len();
        let take = data.len().min(room);
        self.block
            .extend_from_slice(data.get(..take).unwrap_or_default());
        if self.block.len() == DVZIP_BLOCK_BYTES {
            self.emit()?;
        }
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ------------------------------------------------------------------- CPIO

/// One member's header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpioEntry {
    /// The stored path, lossily UTF-8.
    pub path: String,
    pub mode: u32,
    pub size: u64,
}

impl CpioEntry {
    /// A regular file: the only kind ever written out.
    pub fn is_file(&self) -> bool {
        self.mode & 0o170_000 == 0o100_000
    }
}

/// Reads odc and newc CPIO archives member by member, enforcing exact member
/// sizes. The archive must end with its `TRAILER!!!` member; what follows the
/// trailer is not read. An empty stream is an empty archive.
pub struct CpioReader<R: Read> {
    inner: R,
    left: u64,
    pad: u64,
    newc: bool,
    started: bool,
    done: bool,
    magic: Vec<u8>,
}

fn field(raw: &[u8], radix: u32, what: &str) -> io::Result<u64> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| invalid(format!("cpio {what} field is not a number")))?;
    if !text.chars().all(|c| c.is_digit(radix)) {
        return Err(invalid(format!(
            "cpio {what} field {text:?} is not a number"
        )));
    }
    u64::from_str_radix(text, radix)
        .map_err(|_| invalid(format!("cpio {what} field {text:?} is not a number")))
}

impl<R: Read> CpioReader<R> {
    pub fn new(inner: R) -> Self {
        CpioReader {
            inner,
            left: 0,
            pad: 0,
            newc: false,
            started: false,
            done: false,
            magic: Vec::new(),
        }
    }

    /// The first six bytes of the archive, for the log.
    pub fn magic(&self) -> &[u8] {
        &self.magic
    }

    /// The next member, or `None` after the trailer. Skips whatever the
    /// caller left unread of the previous member.
    pub fn next_entry(&mut self) -> Result<Option<CpioEntry>, ArchiveError> {
        if self.done {
            return Ok(None);
        }
        let skip = self.left + self.pad;
        if skip > 0 {
            let skipped = io::copy(&mut (&mut self.inner).take(skip), &mut io::sink())?;
            if skipped < skip {
                return Err(ArchiveError::Invalid("truncated cpio member data".into()));
            }
            self.left = 0;
            self.pad = 0;
        }
        let mut magic = [0u8; 6];
        let n = read_full(&mut self.inner, &mut magic)?;
        if n == 0 && !self.started {
            self.done = true;
            return Ok(None);
        }
        if !self.started {
            self.magic = magic.get(..n).unwrap_or_default().to_vec();
            self.started = true;
        }
        if n < magic.len() {
            return Err(ArchiveError::Invalid("truncated cpio header".into()));
        }
        let (mode, namesize, size) = match &magic {
            ODC_MAGIC => {
                let mut h = [0u8; 70];
                if read_full(&mut self.inner, &mut h)? < h.len() {
                    return Err(ArchiveError::Invalid("truncated cpio header".into()));
                }
                self.newc = false;
                (
                    field(&h[12..18], 8, "mode")?,
                    field(&h[53..59], 8, "name size")?,
                    field(&h[59..70], 8, "file size")?,
                )
            }
            NEWC_MAGIC | NEWC_CRC_MAGIC => {
                let mut h = [0u8; 104];
                if read_full(&mut self.inner, &mut h)? < h.len() {
                    return Err(ArchiveError::Invalid("truncated cpio header".into()));
                }
                self.newc = true;
                (
                    field(&h[8..16], 16, "mode")?,
                    field(&h[88..96], 16, "name size")?,
                    field(&h[48..56], 16, "file size")?,
                )
            }
            _ => {
                return Err(ArchiveError::Invalid(format!(
                    "not a cpio archive (magic {})",
                    py_bytes_repr(magic.get(..n).unwrap_or_default())
                )));
            }
        };
        let namesize = usize::try_from(namesize).unwrap_or(usize::MAX);
        if namesize == 0 || namesize > MAX_PATH_BYTES + 1 {
            return Err(ArchiveError::Invalid(format!(
                "cpio member name of {namesize} bytes"
            )));
        }
        let mut name = vec![0u8; namesize];
        if read_full(&mut self.inner, &mut name)? < namesize {
            return Err(ArchiveError::Invalid("truncated cpio member name".into()));
        }
        if name.last() != Some(&0) {
            return Err(ArchiveError::Invalid(
                "cpio member name is not NUL-terminated".into(),
            ));
        }
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let path = String::from_utf8_lossy(name.get(..end).unwrap_or_default()).into_owned();
        if self.newc {
            let header_pad = (4 - (110 + namesize) % 4) % 4;
            let mut pad = [0u8; 3];
            if read_full(&mut self.inner, &mut pad[..header_pad])? < header_pad {
                return Err(ArchiveError::Invalid("truncated cpio header".into()));
            }
        }
        if path == TRAILER {
            self.done = true;
            return Ok(None);
        }
        self.left = size;
        self.pad = if self.newc { (4 - size % 4) % 4 } else { 0 };
        Ok(Some(CpioEntry {
            path,
            mode: mode as u32,
            size,
        }))
    }

    /// Reads the current member's data; `Ok(0)` at its end.
    pub fn read_data(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        if want == 0 {
            return Ok(0);
        }
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(invalid("truncated cpio member data"));
        }
        self.left -= n as u64;
        Ok(n)
    }

    /// The underlying reader, positioned after the last header read.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Writes an odc (`070707`) CPIO archive, as libarchive's `cpio` writer does:
/// inode numbers are synthesized (1, 2, ...) and every member is a single
/// link, so no reader can take two members for hard links of each other.
pub struct CpioWriter<W: Write> {
    inner: W,
    next_ino: u64,
}

impl<W: Write> CpioWriter<W> {
    pub fn new(inner: W) -> Self {
        CpioWriter { inner, next_ino: 0 }
    }

    /// Appends a regular file stored as `name` (a bare base name, as
    /// sharingd sends). `meta` gives its mode, owner, mtime, device and size;
    /// `data` must yield exactly `meta.len()` bytes, or the file changed while
    /// it was being sent and this fails.
    pub fn append_file(
        &mut self,
        name: &str,
        meta: &Metadata,
        data: &mut impl Read,
    ) -> io::Result<()> {
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name}: not a regular file"),
            ));
        }
        let fields = OdcFields {
            dev: meta.dev(),
            mode: u64::from(meta.mode()),
            uid: u64::from(meta.uid()),
            gid: u64::from(meta.gid()),
            mtime: u64::try_from(meta.mtime()).unwrap_or(0),
            size: meta.len(),
        };
        self.write_entry(name.as_bytes(), &fields, data)
    }

    /// Appends a member with an arbitrary mode (a symlink, a device, a
    /// directory), for tools and tests that need to build what a hostile
    /// sender could.
    pub fn append_raw(&mut self, name: &[u8], mode: u32, data: &[u8]) -> io::Result<()> {
        let fields = OdcFields {
            dev: 0,
            mode: u64::from(mode),
            uid: 0,
            gid: 0,
            mtime: 0,
            size: data.len() as u64,
        };
        self.write_entry(name, &fields, &mut &data[..])
    }

    fn write_entry(&mut self, name: &[u8], f: &OdcFields, data: &mut impl Read) -> io::Result<()> {
        let shown = String::from_utf8_lossy(name);
        if name.is_empty() || name.contains(&0) || name.len() + 1 > ODC_MAX_SHORT as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{shown}: unusable archive member name"),
            ));
        }
        if f.size > ODC_MAX_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{shown}: {} bytes is too large for the cpio format (8 GiB limit)",
                    f.size
                ),
            ));
        }
        self.next_ino += 1;
        if self.next_ino > ODC_MAX_SHORT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many files for one cpio archive",
            ));
        }
        let short = |v: u64| v.min(ODC_MAX_SHORT);
        let header = format!(
            "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
            short(f.dev),
            self.next_ino,
            f.mode & ODC_MAX_SHORT,
            short(f.uid),
            short(f.gid),
            1,
            0,
            f.mtime.min(ODC_MAX_SIZE),
            name.len() + 1,
            f.size,
        );
        self.inner.write_all(header.as_bytes())?;
        self.inner.write_all(name)?;
        self.inner.write_all(&[0])?;
        let copied = io::copy(&mut data.take(f.size), &mut self.inner)?;
        if copied < f.size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "{shown}: file shrank while it was being sent ({copied} of {} bytes)",
                    f.size
                ),
            ));
        }
        let mut probe = [0u8; 1];
        if read_full(data, &mut probe)? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{shown}: file grew while it was being sent"),
            ));
        }
        Ok(())
    }

    /// Writes the `TRAILER!!!` member and returns the inner writer, flushed.
    pub fn finish(mut self) -> io::Result<W> {
        let header = format!(
            "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            TRAILER.len() + 1,
            0
        );
        self.inner.write_all(header.as_bytes())?;
        self.inner.write_all(TRAILER.as_bytes())?;
        self.inner.write_all(&[0])?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

struct OdcFields {
    dev: u64,
    mode: u64,
    uid: u64,
    gid: u64,
    mtime: u64,
    size: u64,
}

// ------------------------------------------------------------------ names

/// Path separators, NUL, C0/C1 controls and the format characters a name could
/// use to lie about itself: bidi overrides (`"gpj.<U+202E>exe"` renders as
/// `"exe.jpg"`), isolates, zero-width characters and the BOM; and the line
/// and paragraph separators, which the receiver's log escapes, so a name
/// holding one would be logged as a name no file has and never announced.
/// Shared by received file names and the receiver name we advertise.
pub fn is_unsafe_char(c: char) -> bool {
    matches!(c,
        '/' | '\\' | '\0'
        | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}'
        | '\u{200b}'..='\u{200f}'
        | '\u{2028}' | '\u{2029}'
        | '\u{feff}'
        | '\u{01}'..='\u{1f}'
        | '\u{7f}'..='\u{9f}')
}

/// Python's `os.path.splitext` for a name with no separators: the extension
/// starts at the last dot that has a non-dot before it.
pub fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(dot)
            if name
                .get(..dot)
                .is_some_and(|stem| stem.chars().any(|c| c != '.')) =>
        {
            name.split_at(dot)
        }
        _ => (name, ""),
    }
}

/// One non-hidden file name from sender-controlled text: the last path
/// component (`/` or `\`), NFC, unsafe characters removed, whitespace trimmed,
/// leading dots removed, and the stem shortened until the name fits 255
/// bytes. `fallback` when nothing is left, or when only the extension would
/// be (a hidden name, which the start-up sweep could even take for an
/// unfinished upload).
pub fn safe_name(name: &str, fallback: &str) -> String {
    let last = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let cleaned: String = last.nfc().filter(|&c| !is_unsafe_char(c)).collect();
    let trimmed = cleaned.trim().trim_start_matches('.');
    let (stem, ext) = split_ext(trimmed);
    let mut stem = stem.to_string();
    while stem.len() + ext.len() > MAX_FILE_NAME_BYTES && stem.pop().is_some() {}
    if stem.is_empty() {
        return fallback.to_string();
    }
    let out = stem + ext;
    if out.len() > MAX_FILE_NAME_BYTES || out.starts_with('.') {
        fallback.to_string()
    } else {
        out
    }
}

/// `name`, then `stem-1.ext`, `stem-2.ext`, ... (the stem shortened so each
/// fits 255 bytes), up to 10000 candidates.
pub fn candidate_names(name: &str) -> impl Iterator<Item = String> + '_ {
    let (stem, ext) = split_ext(name);
    (0..10_000u32).map(move |i| {
        if i == 0 {
            return name.to_string();
        }
        let suffix = format!("-{i}{ext}");
        let mut stem = stem.to_string();
        while stem.len() + suffix.len() > MAX_FILE_NAME_BYTES && stem.pop().is_some() {}
        stem + &suffix
    })
}

/// Create `dest/name` (or the first free [`candidate_names`] variant)
/// exclusively, never following a symlink and never replacing a file. Mode
/// 0644 less the umask. Returns the name used and the open file.
pub fn open_new(dest: &Path, name: &str) -> io::Result<(String, File)> {
    for candidate in candidate_names(name) {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dest.join(&candidate))
        {
            Ok(file) => return Ok((candidate, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("{name}: no free name"),
    ))
}

/// `repr()` of a Python `str`, for log lines and messages that keep the
/// Python receiver's text.
pub fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if !py_printable(c) => {
                let n = c as u32;
                if n <= 0xff {
                    out.push_str(&format!("\\x{n:02x}"));
                } else if n <= 0xffff {
                    out.push_str(&format!("\\u{n:04x}"));
                } else {
                    out.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `repr()` of Python `bytes`.
pub fn py_bytes_repr(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from("b");
    out.push(quote);
    for &byte in b {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            c if char::from(c) == quote => {
                out.push('\\');
                out.push(quote);
            }
            0x20..=0x7e => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push(quote);
    out
}

/// Close to Python's `str.isprintable`: controls, format characters,
/// separators other than space, surrogates and private use are not.
fn py_printable(c: char) -> bool {
    !(c.is_control()
        || matches!(c,
            '\u{a0}' | '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}' | '\u{1680}'
            | '\u{180e}' | '\u{2000}'..='\u{200f}' | '\u{2028}'..='\u{202f}' | '\u{205f}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}' | '\u{3000}' | '\u{e000}'..='\u{f8ff}' | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}' | '\u{f0000}'..='\u{10ffff}'))
}

// ------------------------------------------------------------- extraction

/// Hidden files of uploads in progress, so a stopping receiver can remove
/// them: a process that exits does not run destructors.
#[derive(Default)]
pub struct Partials(Mutex<Vec<PathBuf>>);

impl Partials {
    pub const fn new() -> Self {
        Partials(Mutex::new(Vec::new()))
    }

    fn add(&self, path: &Path) {
        if let Ok(mut paths) = self.0.lock() {
            paths.push(path.to_path_buf());
        }
    }

    fn forget(&self, path: &Path) {
        if let Ok(mut paths) = self.0.lock() {
            paths.retain(|p| p != path);
        }
    }

    /// Unlink every file still in progress.
    pub fn remove_all(&self) {
        let paths = match self.0.lock() {
            Ok(mut paths) => std::mem::take(&mut *paths),
            Err(_) => return,
        };
        for path in paths {
            let _ = fs::remove_file(path);
        }
    }
}

/// Remove `.omdrop-partial-*` regular files this user owns in `dest`: what a
/// receiver killed mid-upload (SIGKILL, power loss) left. Returns how many.
/// An entry that cannot be read (it vanished mid-sweep) is skipped.
pub fn sweep_partials(dest: &Path) -> io::Result<usize> {
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let mut removed = 0;
    for entry in fs::read_dir(dest)?.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(PARTIAL_PREFIX)
        {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if meta.file_type().is_file() && meta.uid() == uid && fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Ceilings for one upload.
#[derive(Clone, Copy, Debug)]
pub struct ExtractLimits {
    /// Bytes allowed for the decoded archive, for any one file, and for all
    /// files together.
    pub byte_limit: u64,
    /// Members of any type.
    pub max_members: usize,
    /// Free space a file being written must leave on the download disk.
    pub min_free_bytes: u64,
}

/// What an upload became.
#[derive(Debug)]
pub struct Extracted {
    /// The stored names, in archive order.
    pub names: Vec<String>,
    /// CPIO bytes decoded from the body.
    pub decoded_bytes: u64,
    /// The archive's first six bytes.
    pub magic: Vec<u8>,
    /// The body never sent its end (a chunked body's closing chunk): it went
    /// quiet after the archive was whole, and was taken as ended there
    /// ([`crate::http::Patience`]).
    pub unterminated: bool,
}

/// How far an extraction got, readable after it fails. An upload that stalls
/// is diagnosed from this: a stall after the CPIO trailer means every file
/// arrived and only the request's end did not (DVZip has no end marker; the
/// body's end is the archive's end), while a stall before it means file data
/// was still missing.
#[derive(Debug, Default)]
pub struct ExtractProgress {
    decoded: Cell<u64>,
    trailer_seen: Cell<bool>,
    clean_end: Rc<Cell<bool>>,
}

impl ExtractProgress {
    pub fn new() -> Self {
        Self::default()
    }

    /// CPIO bytes decoded so far.
    pub fn decoded(&self) -> u64 {
        self.decoded.get()
    }

    /// Whether the archive's `TRAILER!!!` member was reached.
    pub fn trailer_seen(&self) -> bool {
        self.trailer_seen.get()
    }

    /// Whether the body could end right now with nothing lost: the archive
    /// is past its `TRAILER!!!`, and the decoder is waiting for body bytes
    /// between DVZip blocks or after the gzip footer. Past the trailer but
    /// inside a block or the footer, the body is truncated, not whole.
    pub fn whole(&self) -> bool {
        self.trailer_seen.get() && self.clean_end.get()
    }
}

struct Limited<'p, R> {
    inner: R,
    total: u64,
    limit: u64,
    progress: &'p ExtractProgress,
}

impl<R: Read> Read for Limited<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Ask for at most one byte past the ceiling: a zip bomb is stopped
        // after limit + 1 decoded bytes, not after a whole buffer.
        let room =
            usize::try_from((self.limit - self.total).saturating_add(1)).unwrap_or(usize::MAX);
        let want = buf.len().min(room);
        let n = self.inner.read(&mut buf[..want])?;
        self.total += n as u64;
        self.progress.decoded.set(self.total);
        if self.total > self.limit {
            return Err(ArchiveError::Limit(format!(
                "decompressed archive exceeds {}-byte limit",
                self.limit
            ))
            .into_io());
        }
        Ok(n)
    }
}

/// A member written in full: only its path is kept, not an open file, so a
/// 512-member upload holds no file descriptors while the rest arrives.
struct Partial<'a> {
    temp: Option<tempfile::TempPath>,
    path: PathBuf,
    partials: &'a Partials,
}

impl Drop for Partial<'_> {
    fn drop(&mut self) {
        // TempPath unlinks on drop; only the registry needs telling.
        self.temp.take();
        self.partials.forget(&self.path);
    }
}

#[allow(clippy::useless_conversion, reason = "u32 fields on 32-bit targets")]
fn free_bytes(file: &File) -> io::Result<u64> {
    use std::os::fd::AsRawFd;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the fd is open for the duration of the call and `st` is a valid
    // out-pointer to a statvfs.
    let rc = unsafe { libc::fstatvfs(file.as_raw_fd(), st.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatvfs returned 0, so it initialised `st`.
    let st = unsafe { st.assume_init() };
    // fsblkcnt_t and c_ulong are u64 here and u32 on 32-bit targets.
    Ok(u64::from(st.f_bavail).saturating_mul(u64::from(st.f_frsize)))
}

fn write_member<R: Read>(
    cpio: &mut CpioReader<R>,
    file: &mut File,
    label: &str,
    min_free: u64,
) -> Result<(), ArchiveError> {
    let mut buf = vec![0u8; IO_CHUNK_BYTES];
    let mut until_disk_check = 0u64;
    loop {
        let n = cpio.read_data(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        if n as u64 >= until_disk_check {
            if free_bytes(file)? < min_free.saturating_add(DISK_CHECK_INTERVAL) {
                return Err(ArchiveError::Limit(format!(
                    "{label} stopped to preserve {min_free} bytes free"
                )));
            }
            until_disk_check = DISK_CHECK_INTERVAL;
        }
        file.write_all(buf.get(..n).unwrap_or_default())?;
        until_disk_check = until_disk_check.saturating_sub(n as u64);
    }
}

/// Decode a DVZip or gzip body and store the regular files of the CPIO archive
/// inside it in `dest`, under [`safe_name`]s that never replace an existing
/// file. Skips everything else, and AppleDouble `._*` files. All or nothing:
/// on any error no file is left behind. The body is read to its end, so
/// truncation anywhere in it is an error even after the CPIO trailer.
/// `progress` records how far it got, for diagnosing a failure.
pub fn extract<R: Read>(
    body: R,
    dest: &Path,
    limits: &ExtractLimits,
    partials: &Partials,
    progress: &ExtractProgress,
) -> Result<Extracted, ArchiveError> {
    let decoder = DvzipDecoder::with_clean_end(body, progress.clean_end.clone())?;
    let mut cpio = CpioReader::new(Limited {
        inner: decoder,
        total: 0,
        limit: limits.byte_limit,
        progress,
    });
    let mut pending: Vec<(String, Partial)> = Vec::new();
    let mut members = 0usize;
    let mut output_bytes = 0u64;
    while let Some(entry) = cpio.next_entry()? {
        members += 1;
        if members > limits.max_members {
            return Err(ArchiveError::Limit(format!(
                "archive exceeds {}-member limit",
                limits.max_members
            )));
        }
        if !entry.is_file() {
            continue;
        }
        if entry
            .path
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .starts_with("._")
        {
            continue;
        }
        if entry.size > limits.byte_limit {
            return Err(ArchiveError::Limit(format!(
                "file {} declares {} bytes",
                py_repr(&entry.path),
                entry.size
            )));
        }
        if output_bytes + entry.size > limits.byte_limit {
            return Err(ArchiveError::Limit(format!(
                "archive declares more than {} output bytes",
                limits.byte_limit
            )));
        }
        output_bytes += entry.size;
        let name = safe_name(&entry.path, "file");
        let mut file = tempfile::Builder::new()
            .prefix(PARTIAL_PREFIX)
            .permissions(fs::Permissions::from_mode(0o644))
            .tempfile_in(dest)?;
        let path = file.path().to_path_buf();
        partials.add(&path);
        // Declared after `file`, so on an error it is dropped first.
        let mut partial = Partial {
            temp: None,
            path,
            partials,
        };
        write_member(
            &mut cpio,
            file.as_file_mut(),
            &format!("file {}", py_repr(&name)),
            limits.min_free_bytes,
        )?;
        // Closes the file.
        partial.temp = Some(file.into_temp_path());
        pending.push((name, partial));
    }
    progress.trailer_seen.set(true);
    let magic = cpio.magic().to_vec();
    let mut rest = cpio.into_inner();
    // Read the rest of the body to its end. A body that goes quiet once the
    // archive is whole, with its closing chunk never sent, ends here too.
    let unterminated = match io::copy(&mut rest, &mut io::sink()) {
        Ok(_) => false,
        Err(e) if crate::http::is_complete(&e) => true,
        Err(e) => return Err(e.into()),
    };
    let decoded_bytes = rest.total;
    drop(rest);

    let mut stored: Vec<String> = Vec::with_capacity(pending.len());
    let result = (|| -> io::Result<()> {
        for (name, mut partial) in pending {
            let Some(mut temp) = partial.temp.take() else {
                continue;
            };
            let mut placed = None;
            for candidate in candidate_names(&name) {
                match temp.persist_noclobber(dest.join(&candidate)) {
                    Ok(()) => {
                        placed = Some(candidate);
                        break;
                    }
                    Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => temp = e.path,
                    Err(e) => return Err(e.error),
                }
            }
            drop(partial);
            match placed {
                Some(candidate) => stored.push(candidate),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("{name}: no free name"),
                    ));
                }
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        for name in stored.iter().rev() {
            let _ = fs::remove_file(dest.join(name));
        }
        return Err(ArchiveError::Io(e));
    }
    Ok(Extracted {
        names: stored,
        decoded_bytes,
        magic,
        unterminated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpio(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = CpioWriter::new(Vec::new());
        for (name, data) in files {
            w.append_raw(name.as_bytes(), 0o100_644, data).unwrap();
        }
        w.finish().unwrap()
    }

    fn dvzip(data: &[u8]) -> Vec<u8> {
        let mut e = DvzipEncoder::new(Vec::new());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn stored(payload: &[u8]) -> Vec<u8> {
        let mut out = (DVZIP_STORED | payload.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    fn decode(body: &[u8]) -> Result<Vec<u8>, ArchiveError> {
        let mut out = Vec::new();
        DvzipDecoder::new(body)?.read_to_end(&mut out)?;
        Ok(out)
    }

    fn limits(byte_limit: u64) -> ExtractLimits {
        ExtractLimits {
            byte_limit,
            max_members: MAX_ARCHIVE_MEMBERS,
            min_free_bytes: 0,
        }
    }

    fn store(body: &[u8], dest: &Path, l: ExtractLimits) -> Result<Vec<String>, ArchiveError> {
        extract(body, dest, &l, &Partials::new(), &ExtractProgress::new()).map(|e| e.names)
    }

    fn listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), Compression::new(6));
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn dvzip_round_trips_compressible_and_incompressible_data() {
        let mut data = vec![b'a'; 200_000];
        let mut x = 0x1234_5678u32;
        for _ in 0..150_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            data.push(x as u8);
        }
        let body = dvzip(&data);
        // Both block kinds occur: zlib for the run, stored for the noise.
        let mut kinds = (false, false);
        let mut rest = &body[..];
        while rest.len() >= 4 {
            let v = u32::from_be_bytes(rest[..4].try_into().unwrap());
            if v & DVZIP_STORED != 0 {
                kinds.1 = true
            } else {
                kinds.0 = true
            }
            rest = &rest[4 + (v & !DVZIP_STORED) as usize..];
        }
        assert_eq!(kinds, (true, true));
        assert_eq!(decode(&body).unwrap(), data);
        assert_eq!(decode(&dvzip(b"")).unwrap(), b"");
    }

    #[test]
    fn python_sender_blocks_decode() {
        // airdrop-send.py's dvzip_encode: zlib.compress(block, 6), length header.
        let block = zlib(b"hello hello hello hello");
        let mut body = (block.len() as u32).to_be_bytes().to_vec();
        body.extend(block);
        body.extend(stored(b" world"));
        assert_eq!(decode(&body).unwrap(), b"hello hello hello hello world");
    }

    #[test]
    fn gzip_bodies_decode_and_reject_trailing_or_truncated_data() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&[b'x'; 1000]).unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(decode(&gz).unwrap(), vec![b'x'; 1000]);
        let mut trailing = gz.clone();
        trailing.push(0);
        assert!(
            matches!(decode(&trailing), Err(ArchiveError::Invalid(m)) if m.contains("trailing"))
        );
        for cut in [3, gz.len() / 2, gz.len() - 4] {
            assert!(
                matches!(decode(&gz[..cut]), Err(ArchiveError::Invalid(_))),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn malformed_dvzip_is_refused() {
        let block = zlib(b"payload");
        let mut good = (block.len() as u32).to_be_bytes().to_vec();
        good.extend(&block);
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (vec![0, 0, 0], "truncated DVZip block header: 3 bytes"),
            (
                stored(b"abc")[..5].to_vec(),
                "truncated stored block: 2 bytes missing",
            ),
            (
                good[..good.len() - 2].to_vec(),
                "truncated compressed block: 2 bytes missing",
            ),
            // The block claims two more bytes than its zlib stream uses.
            (
                [
                    ((block.len() + 2) as u32).to_be_bytes().to_vec(),
                    block.clone(),
                    vec![1, 2],
                ]
                .concat(),
                "trailing data",
            ),
            // The block ends before its zlib stream does.
            (
                [
                    ((block.len() - 3) as u32).to_be_bytes().to_vec(),
                    block[..block.len() - 3].to_vec(),
                ]
                .concat(),
                "truncated compressed block",
            ),
            (vec![0, 0, 0, 0], "truncated compressed block"),
            (
                [vec![0, 0, 0, 4], b"junk".to_vec()].concat(),
                "invalid compressed block",
            ),
        ];
        for (body, want) in cases {
            match decode(&body) {
                Err(ArchiveError::Invalid(m)) => assert!(m.contains(want), "{m:?} lacks {want:?}"),
                other => panic!("{want}: {other:?}"),
            }
        }
    }

    #[test]
    fn decompression_stops_at_the_ceiling() {
        // A zip bomb: 32 MiB of zeros in a skipped member, a few KiB on the wire.
        let mut w = CpioWriter::new(Vec::new());
        w.append_raw(b"./._bomb", 0o100_644, &vec![0u8; 32 << 20])
            .unwrap();
        let body = dvzip(&w.finish().unwrap());
        assert!(body.len() < 200_000);
        let dest = tempfile::tempdir().unwrap();
        let err = store(&body, dest.path(), limits(1 << 20)).unwrap_err();
        assert!(
            matches!(&err, ArchiveError::Limit(m) if m == "decompressed archive exceeds 1048576-byte limit"),
            "{err}"
        );
        let progress = ExtractProgress::new();
        let mut limited = Limited {
            inner: DvzipDecoder::new(&body[..]).unwrap(),
            total: 0,
            limit: 31,
            progress: &progress,
        };
        assert!(io::copy(&mut limited, &mut io::sink()).is_err());
        assert_eq!(limited.total, 32);
    }

    #[test]
    fn cpio_round_trips_and_reads_newc() {
        let archive = cpio(&[("one.txt", b"one"), ("two.txt", b"")]);
        assert_eq!(&archive[..6], b"070707");
        let mut r = CpioReader::new(&archive[..]);
        let one = r.next_entry().unwrap().unwrap();
        assert_eq!(
            (one.path.as_str(), one.size, one.is_file()),
            ("one.txt", 3, true)
        );
        let mut data = Vec::new();
        let mut buf = [0u8; 2];
        loop {
            let n = r.read_data(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        assert_eq!(data, b"one");
        assert_eq!(r.next_entry().unwrap().unwrap().path, "two.txt");
        assert!(r.next_entry().unwrap().is_none());

        // newc, hand-built: header, name padded to 4, data padded to 4.
        let mut newc = Vec::new();
        for (name, data) in [("a.txt", &b"hello"[..]), ("TRAILER!!!", &b""[..])] {
            let mode = if data.is_empty() { 0 } else { 0o100_644 };
            newc.extend(format!(
                "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
                1, mode, 0, 0, 1, 0, data.len(), 0, 0, 0, 0, name.len() + 1, 0
            ).bytes());
            newc.extend(name.bytes());
            newc.push(0);
            while newc.len() % 4 != 0 {
                newc.push(0)
            }
            newc.extend(data);
            while newc.len() % 4 != 0 {
                newc.push(0)
            }
        }
        let dest = tempfile::tempdir().unwrap();
        assert_eq!(
            store(&stored(&newc), dest.path(), limits(1 << 20)).unwrap(),
            ["a.txt"]
        );
        assert_eq!(fs::read(dest.path().join("a.txt")).unwrap(), b"hello");
    }

    #[test]
    fn cpio_writer_takes_real_files_and_refuses_changed_ones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("photo.jpg");
        fs::write(&path, b"jpeg bytes").unwrap();
        let meta = fs::metadata(&path).unwrap();
        let mut w = CpioWriter::new(Vec::new());
        w.append_file("photo.jpg", &meta, &mut File::open(&path).unwrap())
            .unwrap();
        assert!(w.append_file("short", &meta, &mut &b"jpeg"[..]).is_err());
        let mut w = CpioWriter::new(Vec::new());
        assert!(
            w.append_file("long", &meta, &mut &b"jpeg bytes and more"[..])
                .is_err()
        );
        assert!(
            w.append_file("dir", &fs::metadata(dir.path()).unwrap(), &mut io::empty())
                .is_err()
        );
    }

    #[test]
    fn files_are_stored_and_everything_else_skipped() {
        let mut w = CpioWriter::new(Vec::new());
        w.append_raw(b".", 0o040_755, b"").unwrap();
        w.append_raw(b"./Folder", 0o040_755, b"").unwrap();
        w.append_raw(b"./Folder/a.txt", 0o100_644, b"A").unwrap();
        w.append_raw(b"./link", 0o120_777, b"/etc/passwd").unwrap();
        w.append_raw(b"./dev", 0o020_644, b"").unwrap();
        w.append_raw(b"./fifo", 0o010_644, b"").unwrap();
        w.append_raw(b"./._a.txt", 0o100_644, b"appledouble")
            .unwrap();
        w.append_raw(b"./a.txt", 0o100_644, b"B").unwrap();
        let dest = tempfile::tempdir().unwrap();
        let names = store(&dvzip(&w.finish().unwrap()), dest.path(), limits(1 << 20)).unwrap();
        assert_eq!(names, ["a.txt", "a-1.txt"]);
        assert_eq!(listing(dest.path()), ["a-1.txt", "a.txt"]);
        assert_eq!(fs::read(dest.path().join("a-1.txt")).unwrap(), b"B");
    }

    #[test]
    fn traversal_names_stay_inside_the_destination() {
        let outer = tempfile::tempdir().unwrap();
        let dest = outer.path().join("dest");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("existing.txt"), b"keep").unwrap();
        std::os::unix::fs::symlink(outer.path().join("escaped"), dest.join("trap")).unwrap();
        let archive = cpio(&[
            ("../../escape.txt", b"1"),
            ("/etc/cron.d/x", b"2"),
            ("..\\..\\win.txt", b"3"),
            ("..", b"4"),
            (".hidden", b"5"),
            ("existing.txt", b"6"),
            ("trap", b"7"),
            ("gpj.\u{202e}exe", b"8"),
            ("e\u{301}t\u{e9}.txt", b"9"),
        ]);
        let names = store(&stored(&archive), &dest, limits(1 << 20)).unwrap();
        assert_eq!(
            names,
            [
                "escape.txt",
                "x",
                "win.txt",
                "file",
                "hidden",
                "existing-1.txt",
                "trap-1",
                "gpj.exe",
                "\u{e9}t\u{e9}.txt"
            ]
        );
        assert_eq!(fs::read(dest.join("existing.txt")).unwrap(), b"keep");
        assert!(!outer.path().join("escaped").exists());
        assert_eq!(listing(outer.path()), ["dest"]);
    }

    #[test]
    fn member_limit_leaves_nothing_behind() {
        let dest = tempfile::tempdir().unwrap();
        let mut l = limits(1 << 20);
        l.max_members = 1;
        let err = store(
            &stored(&cpio(&[("one.txt", b"one"), ("two.txt", b"two")])),
            dest.path(),
            l,
        )
        .unwrap_err();
        assert!(
            matches!(&err, ArchiveError::Limit(m) if m == "archive exceeds 1-member limit"),
            "{err}"
        );
        assert!(listing(dest.path()).is_empty());
    }

    #[test]
    fn per_file_and_total_limits_leave_nothing_behind() {
        // A member header alone, declaring `size` bytes that never follow.
        fn header(name: &str, size: u64) -> Vec<u8> {
            let mut h = format!(
                "070707000000000001100644000000000000000001000000{:011o}{:06o}{size:011o}",
                0,
                name.len() + 1
            )
            .into_bytes();
            h.extend(name.bytes());
            h.push(0);
            h
        }
        let dest = tempfile::tempdir().unwrap();
        let err = store(
            &stored(&cpio(&[("large.bin", b"four")])),
            dest.path(),
            limits(3),
        )
        .unwrap_err();
        assert!(matches!(err, ArchiveError::Limit(_)), "{err}");
        let err = store(&stored(&header("./big", 1000)), dest.path(), limits(500)).unwrap_err();
        assert!(
            matches!(&err, ArchiveError::Limit(m) if m == "file './big' declares 1000 bytes"),
            "{err}"
        );
        let mut first = header("one", 200);
        first.extend([b'1'; 200]);
        first.extend(header("two", 250));
        let err = store(&stored(&first), dest.path(), limits(400)).unwrap_err();
        assert!(
            matches!(&err, ArchiveError::Limit(m) if m == "archive declares more than 400 output bytes"),
            "{err}"
        );
        assert!(listing(dest.path()).is_empty());
    }

    #[test]
    fn invalid_archives_are_not_saved() {
        let dest = tempfile::tempdir().unwrap();
        let archive = cpio(&[("one.txt", b"one")]);
        let no_trailer = &archive[..archive.len() - 87];
        let cases: Vec<Vec<u8>> = vec![
            stored(b"not an archive"),
            stored(&archive[..archive.len() - 5]),
            stored(no_trailer),
            stored(&archive[..80]),
            stored(&b"0707070000000000000100644000000000000000010000000000000000000000000ZZZZZZ00000000000"[..]),
            [stored(&archive), vec![0, 0]].concat(),
        ];
        for body in cases {
            let err = store(&body, dest.path(), limits(1 << 20)).unwrap_err();
            assert!(matches!(err, ArchiveError::Invalid(_)), "{err}");
            assert!(listing(dest.path()).is_empty());
        }
        assert_eq!(
            store(b"", dest.path(), limits(1 << 20)).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_failure_while_writing_removes_partial_files() {
        // The body fails after the first member is complete.
        struct FailAfter<'a>(&'a [u8]);
        impl Read for FailAfter<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "stalled"));
                }
                let n = buf.len().min(self.0.len()).min(7);
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let archive = stored(&cpio(&[("one.txt", b"one"), ("two.txt", b"two")]));
        let dest = tempfile::tempdir().unwrap();
        let partials = Partials::new();
        let err = extract(
            FailAfter(&archive[..archive.len() - 10]),
            dest.path(),
            &limits(1 << 20),
            &partials,
            &ExtractProgress::new(),
        )
        .unwrap_err();
        assert!(
            matches!(&err, ArchiveError::Io(e) if e.kind() == io::ErrorKind::TimedOut),
            "{err}"
        );
        assert!(listing(dest.path()).is_empty());
        assert!(partials.0.lock().is_ok_and(|p| p.is_empty()));
    }

    /// The R6 iPhone video (2026-10-14): a 67.5 MB upload went quiet and was
    /// refused with 408, and nothing in the log said whether its files had
    /// all arrived. The progress says which side of the trailer it stopped on.
    #[test]
    fn a_stalled_body_reports_whether_every_file_had_arrived() {
        struct StallAfter<'a>(&'a [u8]);
        impl Read for StallAfter<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "stalled"));
                }
                let n = buf.len().min(self.0.len()).min(512);
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let data = vec![7u8; 5000];
        let raw = cpio(&[("clip.mov", &data)]);
        let archive = stored(&raw);
        for (cut, trailer_seen) in [(archive.len(), true), (archive.len() / 2, false)] {
            let dest = tempfile::tempdir().unwrap();
            let progress = ExtractProgress::new();
            let err = extract(
                StallAfter(&archive[..cut]),
                dest.path(),
                &limits(1 << 20),
                &Partials::new(),
                &progress,
            )
            .unwrap_err();
            assert!(
                matches!(&err, ArchiveError::Io(e) if e.kind() == io::ErrorKind::TimedOut),
                "{err}"
            );
            assert_eq!(progress.trailer_seen(), trailer_seen, "cut at {cut}");
            if trailer_seen {
                assert_eq!(progress.decoded(), raw.len() as u64);
            } else {
                assert!(
                    progress.decoded() < data.len() as u64,
                    "{}",
                    progress.decoded()
                );
            }
            assert!(listing(dest.path()).is_empty());
        }
    }

    #[test]
    fn stale_partials_are_swept() {
        let dest = tempfile::tempdir().unwrap();
        fs::write(dest.path().join(".omdrop-partial-abc"), b"x").unwrap();
        fs::write(dest.path().join("keep.txt"), b"x").unwrap();
        assert_eq!(sweep_partials(dest.path()).unwrap(), 1);
        assert_eq!(listing(dest.path()), ["keep.txt"]);
    }

    #[test]
    fn written_members_hold_no_open_files() {
        // Counts this process's descriptors open on files in `dest` at every
        // body read; a member must be closed once it is written, or two
        // 512-member uploads exhaust the 1024-descriptor default.
        struct Counting<'a> {
            inner: &'a [u8],
            dest: PathBuf,
            most: usize,
        }
        impl Read for Counting<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let open = fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .flatten()
                    .filter(|fd| fs::read_link(fd.path()).is_ok_and(|t| t.starts_with(&self.dest)))
                    .count();
                self.most = self.most.max(open);
                self.inner.read(buf)
            }
        }
        let names: Vec<String> = (0..300).map(|i| format!("f{i}.txt")).collect();
        let files: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"x"[..])).collect();
        let body = stored(&cpio(&files));
        let dest = tempfile::tempdir().unwrap();
        let dest_path = fs::canonicalize(dest.path()).unwrap();
        let mut source = Counting {
            inner: &body,
            dest: dest_path.clone(),
            most: 0,
        };
        let out = extract(
            &mut source,
            &dest_path,
            &limits(1 << 20),
            &Partials::new(),
            &ExtractProgress::new(),
        )
        .unwrap();
        assert_eq!(out.names.len(), 300);
        assert!(source.most <= 1, "{} files open at once", source.most);
    }

    #[test]
    fn safe_name_matches_the_python_receiver() {
        let long = "a".repeat(300) + ".txt";
        let cases: &[(&str, &str)] = &[
            ("../../etc/passwd", "passwd"),
            ("dir\\sub\\x.jpg", "x.jpg"),
            ("..", "fallback"),
            ("...hidden.txt", "hidden.txt"),
            ("  spaced  ", "spaced"),
            ("a\u{0}b\u{7}c\u{9b}d", "abcd"),
            ("bidi\u{202e}txt.exe", "biditxt.exe"),
            ("zw\u{200b}j\u{feff}", "zwj"),
            ("line\u{2028}para\u{2029}.txt", "linepara.txt"),
            ("", "fallback"),
            (" .x", "x"),
            (". .x", " .x"),
        ];
        for (input, want) in cases {
            assert_eq!(safe_name(input, "fallback"), *want, "{input:?}");
        }
        let cut = safe_name(&long, "f");
        assert_eq!(cut.len(), 255);
        assert!(cut.ends_with(".txt"));
        assert_eq!(safe_name(&format!("a.{}", "b".repeat(300)), "file"), "file");
        // An extension of exactly 255 bytes: what is left would be hidden.
        assert_eq!(safe_name(&format!("a.{}", "b".repeat(254)), "file"), "file");
        assert_eq!(
            safe_name(&format!("x.omdrop-partial-{}", "b".repeat(239)), "file"),
            "file"
        );
        let multibyte = safe_name(&("é".repeat(200) + ".png"), "f");
        assert!(multibyte.len() <= 255 && multibyte.ends_with(".png"));
        assert_eq!(split_ext("archive.tar.gz"), ("archive.tar", ".gz"));
        assert_eq!(split_ext("noext"), ("noext", ""));
        assert_eq!(split_ext("trailing."), ("trailing", "."));
    }

    #[test]
    fn open_new_never_replaces_or_follows() {
        let dest = tempfile::tempdir().unwrap();
        fs::write(dest.path().join("a.txt"), b"old").unwrap();
        std::os::unix::fs::symlink("/nonexistent-target", dest.path().join("a-1.txt")).unwrap();
        let (name, _) = open_new(dest.path(), "a.txt").unwrap();
        assert_eq!(name, "a-2.txt");
        assert_eq!(fs::read(dest.path().join("a.txt")).unwrap(), b"old");
        let long = "n".repeat(255);
        fs::write(dest.path().join(&long), b"").unwrap();
        let (name, _) = open_new(dest.path(), &long).unwrap();
        assert_eq!(name.len(), 255);
        assert!(name.ends_with("-1"));
    }

    #[test]
    fn python_reprs() {
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("a\u{202e}b\n"), "'a\\u202eb\\n'");
        assert_eq!(py_repr("café"), "'café'");
        assert_eq!(py_bytes_repr(b"070707"), "b'070707'");
        assert_eq!(py_bytes_repr(b"\x1f\x8b'"), "b\"\\x1f\\x8b'\"");
    }
}
