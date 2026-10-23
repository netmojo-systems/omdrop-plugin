//! Property lists from untrusted peers, parsed under limits.
//!
//! `plist::Value::from_reader` is not safe on a peer's bytes. A binary plist
//! may reference one object many times, and the `plist` crate expands every
//! reference into a fresh copy (Python's plistlib shares the object instead):
//! a few hundred bytes of `[A, A]`, `[[A, A], [A, A]]`, ... decode to billions
//! of values, and a 1 MiB body of one 850 KB data object referenced 199 000
//! times decodes to 169 GB. And a deeply nested array is dropped recursively,
//! so 100 000 levels overflow the stack and abort the process. This builds the
//! value from the event stream itself, refusing more than [`MAX_EVENTS`]
//! events, collections deeper than [`MAX_DEPTH`], or more decoded bytes than
//! [`byte_budget`] allows. A binary plist's collections are walked first,
//! without decoding, because the reader allocates for a collection's members
//! before its first event.

use std::fmt;
use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use plist::stream::{Event, Reader};
use plist::{Dictionary, Value};

/// Values (and collection ends) one plist may hold. A real Ask with 512 files
/// is well under 10 000.
pub const MAX_EVENTS: usize = 200_000;
/// Collections inside collections. AirDrop plists are three deep.
pub const MAX_DEPTH: usize = 32;
/// What a value other than data or a string counts against the byte budget.
const VALUE_OVERHEAD: usize = 16;
/// The byte budget never goes below this.
const MIN_BYTE_BUDGET: usize = 4 << 20;

/// Decoded bytes a plist of `input_len` bytes may produce: data and string
/// lengths, plus [`VALUE_OVERHEAD`] per other value, at most four times the
/// input or 4 MiB, whichever is more. An honest plist decodes to about its
/// own size.
pub fn byte_budget(input_len: usize) -> usize {
    input_len.saturating_mul(4).max(MIN_BYTE_BUDGET)
}

#[derive(Debug, PartialEq, Eq)]
pub enum PlistError {
    /// Not a property list.
    Invalid(String),
    /// Over [`MAX_EVENTS`], [`MAX_DEPTH`] or [`byte_budget`].
    TooComplex,
}

impl fmt::Display for PlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlistError::Invalid(m) => f.write_str(m),
            PlistError::TooComplex => write!(
                f,
                "property list deeper than {MAX_DEPTH}, larger than {MAX_EVENTS} values, \
                 or larger than four times its own size decoded"
            ),
        }
    }
}

impl std::error::Error for PlistError {}

enum Frame {
    Array(Vec<Value>),
    Dict(Dictionary, Option<String>),
}

/// A binary plist ends with this many bytes of trailer.
const TRAILER_LEN: usize = 32;

fn malformed() -> PlistError {
    PlistError::Invalid("malformed binary property list".into())
}

/// A big-endian unsigned integer of 1 to 8 bytes.
fn be_uint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0, |n, &b| n << 8 | u64::from(b))
}

/// One collection open on the walk: where its references start, how many it
/// declared, and how many have been followed.
struct Open {
    refs: usize,
    len: u64,
    next: u64,
}

/// Walk a binary plist's collections the way the `plist` crate's reader does,
/// holding one position per open collection, before that reader runs.
///
/// The reader allocates eight bytes for each member a collection declares as
/// soon as it meets the collection, and keeps them until the collection ends,
/// so every open collection holds its whole reference list. It checks a
/// declared count only against the bytes before the trailer, and those bytes
/// can serve as every collection's reference list at once: 120 KB of nested
/// arrays, each declaring 60 000 two-byte references over the same bytes,
/// held 16 MB before [`MAX_DEPTH`] stopped the 33rd. Each declared member becomes at
/// least one event, so a plist whose collections declare more than
/// [`MAX_EVENTS`] members in all could never parse; refusing it here bounds
/// what the reader allocates to that many references. The object table,
/// which the reader also widens to eight bytes an entry, is held to
/// [`MAX_EVENTS`] objects for the same reason: an encoder writes each object
/// once, so an honest plist has no more objects than values.
///
/// What the walk cannot follow is refused as malformed. The reader refuses
/// it too, except for a reference list or length running into the trailer,
/// which no encoder writes.
fn check_binary(data: &[u8]) -> Result<(), PlistError> {
    if !data.starts_with(b"bplist00") {
        return Ok(());
    }
    let Some(end) = data.len().checked_sub(TRAILER_LEN).filter(|&e| e >= 8) else {
        return Err(malformed());
    };
    let trailer = &data[end..];
    let offset_size = usize::from(trailer[6]);
    let ref_size = usize::from(trailer[7]);
    if !matches!(offset_size, 1..=4 | 8) || !matches!(ref_size, 1 | 2 | 4 | 8) {
        return Err(malformed());
    }
    let objects = be_uint(&trailer[8..16]);
    let root = be_uint(&trailer[16..24]);
    let table = be_uint(&trailer[24..32]);
    if objects > MAX_EVENTS as u64 {
        return Err(PlistError::TooComplex);
    }
    // Only the bytes before the trailer hold objects, lengths and references.
    let uint_at = |pos: usize, size: usize| -> Result<u64, PlistError> {
        let bytes = pos
            .checked_add(size)
            .filter(|&stop| stop <= end)
            .and_then(|stop| data.get(pos..stop))
            .ok_or_else(malformed)?;
        Ok(be_uint(bytes))
    };
    let table = usize::try_from(table).map_err(|_| malformed())?;
    // `objects` is at most MAX_EVENTS, so neither product overflows.
    if table.saturating_add(objects as usize * offset_size) > end {
        return Err(malformed());
    }
    let mut open: Vec<Open> = Vec::new();
    let mut declared = 0u64;
    let mut object = Some(root);
    loop {
        if let Some(index) = object.take() {
            if index >= objects {
                return Err(malformed());
            }
            let at = uint_at(table + index as usize * offset_size, offset_size)?;
            let at = usize::try_from(at).map_err(|_| malformed())?;
            let marker = uint_at(at, 1)? as u8;
            let per_member = match marker >> 4 {
                0xa => 1,
                0xd => 2,
                _ => 0,
            };
            if per_member > 0 {
                // The reader's object length: the low four bits, or 0xF and
                // an integer object of 1, 2, 4 or 8 bytes after the marker.
                let (len, refs) = if marker & 0x0f == 0x0f {
                    let size = 1usize << (uint_at(at + 1, 1)? & 0x03);
                    (uint_at(at + 2, size)?, at + 2 + size)
                } else {
                    (u64::from(marker & 0x0f), at + 1)
                };
                let members = len.checked_mul(per_member).ok_or(PlistError::TooComplex)?;
                declared = declared.saturating_add(members);
                if declared > MAX_EVENTS as u64 {
                    return Err(PlistError::TooComplex);
                }
                if open.len() >= MAX_DEPTH {
                    return Err(PlistError::TooComplex);
                }
                // `members` is at most MAX_EVENTS here.
                if refs.saturating_add(members as usize * ref_size) > end {
                    return Err(malformed());
                }
                open.push(Open {
                    refs,
                    len: members,
                    next: 0,
                });
            }
        }
        let Some(top) = open.last_mut() else {
            return Ok(());
        };
        if top.next < top.len {
            object = Some(uint_at(top.refs + top.next as usize * ref_size, ref_size)?);
            top.next += 1;
        } else {
            open.pop();
        }
    }
}

/// Parse an XML or binary property list.
pub fn parse(data: &[u8]) -> Result<Value, PlistError> {
    check_binary(data)?;
    let mut stack: Vec<Frame> = Vec::new();
    let mut root: Option<Value> = None;
    let budget = byte_budget(data.len());
    let mut decoded = 0usize;
    for (count, event) in Reader::new(Cursor::new(data)).enumerate() {
        if count >= MAX_EVENTS {
            return Err(PlistError::TooComplex);
        }
        let event = event.map_err(|e| PlistError::Invalid(e.to_string()))?;
        decoded = decoded.saturating_add(match &event {
            Event::Data(d) => d.len(),
            Event::String(s) => s.len(),
            _ => VALUE_OVERHEAD,
        });
        if decoded > budget {
            return Err(PlistError::TooComplex);
        }
        let value = match event {
            Event::StartArray(_) | Event::StartDictionary(_) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(PlistError::TooComplex);
                }
                stack.push(match event {
                    Event::StartArray(_) => Frame::Array(Vec::new()),
                    _ => Frame::Dict(Dictionary::new(), None),
                });
                continue;
            }
            Event::EndCollection => match stack.pop() {
                Some(Frame::Array(items)) => Value::Array(items),
                Some(Frame::Dict(dict, None)) => Value::Dictionary(dict),
                _ => return Err(PlistError::Invalid("unbalanced collection".into())),
            },
            Event::Boolean(b) => Value::Boolean(b),
            Event::Data(d) => Value::Data(d.into_owned()),
            Event::Date(d) => Value::Date(in_range(d)?),
            Event::Integer(i) => Value::Integer(i),
            Event::Real(r) => Value::Real(r),
            Event::String(s) => Value::String(s.into_owned()),
            Event::Uid(u) => Value::Uid(u),
            _ => return Err(PlistError::Invalid("unknown plist event".into())),
        };
        match stack.last_mut() {
            None if root.is_none() => root = Some(value),
            None => return Err(PlistError::Invalid("more than one root value".into())),
            Some(Frame::Array(items)) => items.push(value),
            Some(Frame::Dict(_, key @ None)) => match value {
                Value::String(k) => *key = Some(k),
                _ => return Err(PlistError::Invalid("dictionary key is not a string".into())),
            },
            Some(Frame::Dict(dict, key @ Some(_))) => {
                if let Some(k) = key.take() {
                    dict.insert(k, value);
                }
            }
        }
    }
    match (root, stack.is_empty()) {
        (Some(value), true) => Ok(value),
        _ => Err(PlistError::Invalid("truncated property list".into())),
    }
}

/// 0001-01-01T00:00:00Z and the second after 9999-12-31T23:59:59Z, from the
/// Unix epoch: Python's `datetime` range, so plistlib refuses the same dates.
const DATE_MIN_BEFORE_EPOCH: Duration = Duration::from_secs(62_135_596_800);
const DATE_END_AFTER_EPOCH: Duration = Duration::from_secs(253_402_300_800);

/// A date the `plist` crate can format. It accepts any finite binary date and
/// any RFC 3339 XML date, but its `Debug`, XML and serde output panic outside
/// years 0001-9999 (cargo-fuzz, `safeplist` target), and the receiver formats
/// an Ask's odd values with `Debug`.
fn in_range(d: plist::Date) -> Result<plist::Date, PlistError> {
    let ok = match SystemTime::from(d).duration_since(UNIX_EPOCH) {
        Ok(after) => after < DATE_END_AFTER_EPOCH,
        Err(before) => before.duration() <= DATE_MIN_BEFORE_EPOCH,
    };
    if ok {
        Ok(d)
    } else {
        Err(PlistError::Invalid("date outside years 0001-9999".into()))
    }
}

/// [`parse`], then the root dictionary; `None` for anything else.
pub fn parse_dict(data: &[u8]) -> Option<Dictionary> {
    parse(data).ok().and_then(Value::into_dictionary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binary(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        value.to_writer_binary(&mut out).unwrap();
        out
    }

    #[test]
    fn ordinary_plists_parse() {
        let mut d = Dictionary::new();
        d.insert(
            "Files".into(),
            Value::Array(vec![
                Value::Dictionary(Dictionary::new()),
                Value::Integer(3.into()),
            ]),
        );
        d.insert("SenderRecordData".into(), Value::Data(vec![1, 2, 3]));
        let v = Value::Dictionary(d);
        assert_eq!(parse(&binary(&v)).unwrap(), v);
        let mut xml = Vec::new();
        v.to_writer_xml(&mut xml).unwrap();
        assert_eq!(parse(&xml).unwrap(), v);
        assert!(parse(b"not a plist").is_err());
        assert!(parse(b"").is_err());
        assert_eq!(parse_dict(&binary(&Value::Array(vec![]))), None);
    }

    fn xml_date(date: &str) -> Vec<u8> {
        format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><date>{date}</date></plist>")
            .into_bytes()
    }

    #[test]
    fn dates_outside_years_0001_to_9999_are_refused_not_a_panic() {
        // Found by cargo-fuzz: the plist crate formats these with a panic,
        // and the receiver formats an Ask's odd values with Debug.
        let far = UNIX_EPOCH + DATE_END_AFTER_EPOCH;
        let refused = [
            binary(&Value::Date(far.into())),
            binary(&Value::Date((far + Duration::from_secs(1 << 40)).into())),
            xml_date("0000-12-31T23:59:59Z"),
            xml_date("0000-01-01T00:00:00+01:00"),
        ];
        for data in refused {
            assert!(
                matches!(parse(&data), Err(PlistError::Invalid(_))),
                "{data:?}"
            );
        }
        // The range's ends still parse, and format.
        let first = UNIX_EPOCH - DATE_MIN_BEFORE_EPOCH;
        let last = UNIX_EPOCH + DATE_END_AFTER_EPOCH - Duration::from_secs(1);
        for data in [
            binary(&Value::Date(first.into())),
            binary(&Value::Date(last.into())),
            xml_date("0001-01-01T00:00:00Z"),
            xml_date("9999-12-31T23:59:59Z"),
        ] {
            let value = parse(&data).unwrap();
            assert!(format!("{value:?}").contains("Date"));
        }
    }

    #[test]
    fn deep_nesting_is_refused_not_a_stack_overflow() {
        let depth = 200_000;
        let xml = format!(
            "<?xml version=\"1.0\"?><plist version=\"1.0\">{}{}</plist>",
            "<array>".repeat(depth),
            "</array>".repeat(depth)
        );
        assert_eq!(parse(xml.as_bytes()), Err(PlistError::TooComplex));
    }

    #[test]
    fn shared_references_cannot_expand_exponentially() {
        // A hand-built binary plist, five levels deep: object 0 is an empty
        // array, object k an array of 200 references to object k-1. About
        // 1 KB describes 200^4 = 1.6 billion values.
        let n = 5u8;
        let mut body = b"bplist00".to_vec();
        let mut offsets: Vec<u16> = vec![body.len() as u16];
        body.push(0xa0);
        for k in 1..n {
            offsets.push(body.len() as u16);
            body.extend([0xaf, 0x10, 200]);
            body.extend(std::iter::repeat_n(k - 1, 200));
        }
        let table = body.len();
        body.extend(offsets.iter().flat_map(|o| o.to_be_bytes()));
        body.extend([0u8; 6]);
        body.extend([2u8, 1]);
        body.extend(u64::from(n).to_be_bytes());
        body.extend(u64::from(n - 1).to_be_bytes());
        body.extend((table as u64).to_be_bytes());
        assert!(body.len() < 1024);
        assert_eq!(parse(&body), Err(PlistError::TooComplex));
        // The same shape, small enough, decodes: the bytes are a valid plist.
        let mut small = body.clone();
        let top = small.len() - 16;
        small[top..top + 8].copy_from_slice(&1u64.to_be_bytes());
        assert!(matches!(parse(&small), Ok(Value::Array(a)) if a.len() == 200));
    }

    /// A binary plist: object 0 is `size` bytes of data, object 1 (the root)
    /// an array of `refs` references to it.
    fn shared_data(size: u32, refs: u32) -> Vec<u8> {
        let mut body = b"bplist00".to_vec();
        let mut offsets: Vec<u32> = vec![body.len() as u32];
        body.extend([0x4f, 0x12]);
        body.extend(size.to_be_bytes());
        body.extend(std::iter::repeat_n(0x41, size as usize));
        offsets.push(body.len() as u32);
        body.extend([0xaf, 0x12]);
        body.extend(refs.to_be_bytes());
        body.extend(std::iter::repeat_n(0u8, refs as usize));
        let table = body.len();
        body.extend(offsets.iter().flat_map(|o| o.to_be_bytes()));
        body.extend([0u8; 6]);
        body.extend([4u8, 1]);
        body.extend(2u64.to_be_bytes());
        body.extend(1u64.to_be_bytes());
        body.extend((table as u64).to_be_bytes());
        body
    }

    #[test]
    fn shared_data_cannot_expand_past_the_byte_budget() {
        // Under 1 MiB on the wire, 167 GB decoded.
        let bomb = shared_data(840_000, 199_000);
        assert!(bomb.len() < 1 << 20);
        let started = std::time::Instant::now();
        assert_eq!(parse(&bomb), Err(PlistError::TooComplex));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // Three references to the same object are within budget: the shape
        // itself is valid.
        let fine = parse(&shared_data(840_000, 3)).unwrap();
        assert!(matches!(fine, Value::Array(a) if a.len() == 3));
    }

    #[test]
    fn the_walk_passes_large_honest_plists_and_refuses_broken_tables() {
        // An Ask at its 512-file limit, every file a dictionary of 8 keys.
        let file: Dictionary = (0..8)
            .map(|k| (format!("Key{k}"), Value::String(format!("value {k}"))))
            .collect();
        let mut ask = Dictionary::new();
        ask.insert(
            "Files".into(),
            Value::Array(vec![Value::Dictionary(file); 512]),
        );
        let ask = Value::Dictionary(ask);
        let data = binary(&ask);
        assert_eq!(check_binary(&data), Ok(()));
        assert_eq!(parse(&data).unwrap(), ask);
        // A dictionary's keys and values both count: 100 001 pairs are over.
        let mut big = b"bplist00".to_vec();
        big.extend([0xdf, 0x12]);
        big.extend(100_001u32.to_be_bytes());
        big.extend(std::iter::repeat_n(0u8, 200_002));
        let table = big.len() as u64;
        big.push(8);
        big.extend([0u8; 6]);
        big.extend([1u8, 1]);
        big.extend(1u64.to_be_bytes());
        big.extend(0u64.to_be_bytes());
        big.extend(table.to_be_bytes());
        assert_eq!(check_binary(&big), Err(PlistError::TooComplex));
        // An object table, root or reference outside the file.
        let mut cut = data.clone();
        let n = cut.len();
        cut[n - 8..].copy_from_slice(&(n as u64).to_be_bytes());
        assert!(matches!(check_binary(&cut), Err(PlistError::Invalid(_))));
        let mut rootless = data.clone();
        rootless[n - 16..n - 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(
            check_binary(&rootless),
            Err(PlistError::Invalid(_))
        ));
        assert!(matches!(
            check_binary(b"bplist00"),
            Err(PlistError::Invalid(_))
        ));
        // XML is the reader's alone.
        assert_eq!(check_binary(b"<plist><array/></plist>"), Ok(()));
    }
}
