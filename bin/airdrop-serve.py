#!/usr/bin/env python3
"""Serve AirDrop's HTTPS endpoints (/Discover, /Ask, /Upload) on awdl0.

The receiving half only: the driver package's radio helper hand-builds the
AWDL service announcements that actually reach the Macs (an ordinary
multicast rarely makes it to the air; its 40-frame bursts do), so this serves
under the identity that helper advertises -- instance <awdl0 MAC hex>, port
8771 -- and registers nothing over mDNS itself.

Runs as the invoking user, never root: it needs no privilege, and received
files belong to the user without a chown.
"""
import argparse
import errno
import io
import ipaddress
import json
import logging
import socket
import os
import plistlib
import pwd
import re
import signal
import ssl
import stat as stat_mod
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import zlib

import libarchive
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import contacts  # noqa: E402  -- sibling module, found via the line above
import debugdump  # noqa: E402
import identity  # noqa: E402
import safeplist  # noqa: E402

# The identity's key is loaded into this process for the life of the window;
# keep it out of core dumps and away from same-UID ptrace.
identity.not_dumpable()


# Path separators, NUL, control characters (Cc) and format characters (Cf:
# bidi overrides, zero-width joiners) -- the last because a name like
# "gpj.<U+202E>exe" renders as "exe.jpg" in a file manager. Used for received
# file names and for the receiver name we advertise.
UNSAFE_CHAR = re.compile(r'[/\\\x00]|[\u202a-\u202e\u2066-\u2069\u200b-\u200f\ufeff]|[\x01-\x1f\x7f-\x9f]')
# The config file is the source of truth: ~/.config/airdrop/config.toml,
# written by `omdrop setup` and the configuration commands in `omdrop`.
# CLI flags override individual keys, so the file can be absent entirely.
# Validation lives here, never in whatever writes the file: a GUI is a
# convenience for writing a value, not what makes it safe. Reload = restart.
CONFIG_PATH = os.path.join(os.environ.get('XDG_CONFIG_HOME') or os.path.join(pwd.getpwuid(os.getuid()).pw_dir, '.config'),
                           'airdrop', 'config.toml')
CONFIG_KEYS = ('name', 'model', 'download_dir', 'max_receive_percent')
STRING_CONFIG_KEYS = ('name', 'model', 'download_dir')
DEFAULT_MAX_RECEIVE_PERCENT = 30


def default_receiver_name():
    """What the Mac sheet draws under our tile when config.toml says nothing:
    the short hostname, as the user already knows this machine."""
    return socket.gethostname().split('.')[0] or 'omdrop'


def load_config(path):
    """Read the TOML; unknown keys are an error (a typo must not silently fall
    back to a default), missing file is fine (defaults apply)."""
    try:
        import tomllib
    except ModuleNotFoundError:  # Python < 3.11: same API from the tomli package
        import tomli as tomllib
    try:
        with open(path, 'rb') as f:
            cfg = tomllib.load(f)
    except FileNotFoundError:
        return {}
    except tomllib.TOMLDecodeError as e:
        raise SystemExit(f'{path}: {e}')
    bad = sorted(set(cfg) - set(CONFIG_KEYS))
    if bad:
        raise SystemExit(f'{path}: unknown key(s) {", ".join(bad)}; known: {", ".join(CONFIG_KEYS)}')
    for k in STRING_CONFIG_KEYS:
        if k in cfg and (not isinstance(cfg[k], str) or not cfg[k].strip()):
            raise SystemExit(f'{path}: {k} must be a non-empty string')
    if 'max_receive_percent' in cfg:
        validate_receive_percent(cfg['max_receive_percent'])
    return cfg


MODEL_RE = re.compile(r'^[A-Za-z]+[0-9]+,[0-9]+$')  # MacBookPro18,3 / iMac21,1 / Macmini9,1


def validate_name(name):
    # What the Mac sheet will draw. No control/format characters, bounded length.
    if UNSAFE_CHAR.search(name) or len(name) > 63:
        raise SystemExit(f'name {name!r}: 1-63 characters, no path separators or control/format characters')
    return name


def validate_model(model):
    if not MODEL_RE.match(model):
        raise SystemExit(f'model {model!r}: must be an Apple model identifier such as MacBookPro18,3')
    return model


def validate_receive_percent(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 90:
        raise SystemExit('max_receive_percent must be an integer from 1 to 90')
    return value


def validate_download_dir(path):
    """Resolved once; must exist, be a directory, and be owned by this user --
    received files land here as this user, so a directory we do not own is a
    misconfiguration, not something to create or chown our way out of."""
    dest = os.path.realpath(os.path.expanduser(path))
    try:
        st = os.stat(dest)
    except FileNotFoundError:
        raise SystemExit(f'download_dir {path!r} -> {dest}: does not exist')
    if not stat_mod.S_ISDIR(st.st_mode):
        raise SystemExit(f'download_dir {dest}: not a directory')
    if st.st_uid != os.getuid():
        raise SystemExit(f'download_dir {dest}: owned by uid {st.st_uid}, not us ({os.getuid()})')
    return dest


ap = argparse.ArgumentParser(
    description=f'AirDrop receiver. Config: {CONFIG_PATH} '
                '(name, model, download_dir, max_receive_percent); flags override.')
ap.add_argument('--iface', default='awdl0')
ap.add_argument('--port', type=int, default=8771)
ap.add_argument('--name', default=None,
                help='ReceiverComputerName: the label under the tile in the Mac sheet (config: name)')
ap.add_argument('--model', default=None,
                help='ReceiverModelName: Apple model identifier; picks the device glyph the sheet draws (config: model)')
ap.add_argument('--keys', default=None,
                help='replace ~/.omdrop for the identity files: DIR/keys holds the on-disk '
                     'identity and the self-signed pair (see docs/identity-contract.md)')
ap.add_argument('--outdir', default=None,
                help='where received files go (config: download_dir)')
ap.add_argument('--max-receive-percent', type=int, default=None,
                help='maximum transfer size as a percentage of currently free output disk space')
ap.add_argument('--config', default=CONFIG_PATH, help='config file path')
args = ap.parse_args()

_cfg = load_config(args.config)
NAME = validate_name(args.name if args.name is not None else _cfg.get('name') or default_receiver_name())
MODEL = validate_model(args.model if args.model is not None else _cfg.get('model', 'MacBookPro18,3'))
_outdir = args.outdir if args.outdir is not None else _cfg.get('download_dir', os.path.join(pwd.getpwuid(os.getuid()).pw_dir, 'Downloads'))
# Resolved once; never chdir -- cwd is process-global and the server is threaded.
DEST = validate_download_dir(_outdir)
MAX_RECEIVE_PERCENT = validate_receive_percent(
    args.max_receive_percent if args.max_receive_percent is not None
    else _cfg.get('max_receive_percent', DEFAULT_MAX_RECEIVE_PERCENT))

# Longest log message, in bytes, as in omdrop-core (log::MAX_MESSAGE_BYTES).
# journald splits a stdout line longer than its LineMax (48 KiB by default)
# into several entries, and with `-o cat` a fragment would read as a line of
# its own, starting with whatever text a peer placed at the cut.
MAX_LOG_MESSAGE_BYTES = 32 * 1024
# What omdrop-core's log::escape() escapes: C0 and C1 controls (newlines
# included) as \xNN; line and paragraph separators, zero-width characters,
# bidi controls and the BOM as \uNNNN. Lone surrogates, which only a Python
# string can hold (a name decoded with surrogateescape), go as \uNNNN too
# rather than failing the write.
LOG_ESCAPE = re.compile('[\x00-\x1f\x7f-\x9f]|'
                        '[\u2028\u2029\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff\ud800-\udfff]')


def escape_log(message):
    """message as one bounded log line, the way omdrop-core writes it."""
    out = LOG_ESCAPE.sub(lambda m: f'\\x{ord(m[0]):02x}' if ord(m[0]) < 0xa0
                         else f'\\u{ord(m[0]):04x}', message)
    data = out.encode('utf-8')
    if len(data) <= MAX_LOG_MESSAGE_BYTES:
        return out
    cut = MAX_LOG_MESSAGE_BYTES
    while (data[cut] & 0xc0) == 0x80:     # back to a character boundary
        cut -= 1
    return f'{data[:cut].decode("utf-8")} [... {len(data) - cut} more bytes]'


class EscapingFormatter(logging.Formatter):
    """Every record as one escaped, bounded line. Peers write into this log
    (names, file names, headers, request lines), and `omdrop watch` acts on
    what it reads here, so no peer text may start a line of its own. A
    traceback belongs to its record and is escaped with it."""

    def format(self, record):
        text = record.getMessage()
        if record.exc_info:
            text += '\n' + self.formatException(record.exc_info)
        if record.stack_info:
            text += '\n' + self.formatStack(record.stack_info)
        record.message = escape_log(text)
        record.asctime = self.formatTime(record, self.datefmt)
        return self.formatMessage(record)


_log_handler = logging.StreamHandler(sys.stdout)
_log_handler.setFormatter(EscapingFormatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
logging.basicConfig(level=logging.DEBUG, handlers=[_log_handler])

with open(f'/sys/class/net/{args.iface}/address') as f:
    sid = f.read().strip().replace(':', '')


# Threaded because sharingd opens several connections at once; a
# single-threaded server would hold /Discover behind a stalled one.
class ThreadingHTTPServerV6(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    allow_reuse_address = True

    # A connection that opens and then carries no request is the signature of a
    # sender that gave up or a TLS handshake we lost -- invisible in the
    # request log, which only fires once a request line parses.
    def __init__(self, *a, **k):
        # Sessions still open at shutdown, so stopping can free the port.
        self.live = set()
        super().__init__(*a, **k)

    def process_request(self, request, client_address):
        logging.info('connection from [%s]:%s', client_address[0], client_address[1])
        self.live.add(request)
        super().process_request(request, client_address)

    def shutdown_request(self, request):
        self.live.discard(request)
        super().shutdown_request(request)

    def reset_sessions(self):
        for sock in list(self.live):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack('ii', 1, 0))
                sock.close()
            except OSError:
                pass
            self.live.discard(sock)

    def handle_error(self, request, client_address):
        # sharingd closes the keep-alive TLS session with a RST once the
        # transfer is done (211010Z); the resulting ECONNRESET on the next
        # readline is the normal end of a session, not a fault.
        if isinstance(sys.exc_info()[1], (ConnectionResetError, HandshakeFailed)):
            return
        # Into the log rather than socketserver's traceback on stderr: an
        # exception's text can carry what a peer sent, and only the log
        # escapes it.
        logging.error('exception while serving [%s]:%s', client_address[0],
                      client_address[1], exc_info=True)


# Raised by Handler.setup once a failed handshake is logged, so handle_error
# does not add a traceback for what is usually a sender leaving the link.
class HandshakeFailed(Exception):
    pass


KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB

# Metadata, framing, member count, and idle time have fixed ceilings. Transfer
# bytes use a percentage of free space computed when the upload starts; users
# configure that percentage with `omdrop limit`.
READ_IDLE_TIMEOUT_SECONDS = 30
INITIAL_READ_SECONDS = 60
# How long an accepted Ask waits for its Upload on the same connection. The
# sender uploads straight after the Ask is answered, but a poor AWDL link can
# delay that request past the idle limit; 60 s covers the roughly 45 s a Mac
# sender has been seen waiting. Only the wait for the next request line gets
# this: its headers and body go back to READ_IDLE_TIMEOUT_SECONDS, and no
# upload slot is held meanwhile.
UPLOAD_WAIT_SECONDS = 60
MIN_READ_BYTES_PER_SECOND = 64 * KIB
DRAIN_QUIET_SECONDS = 1         # after an upload answered without its closing
DRAIN_LIMIT_SECONDS = 10        # chunk: see drain_before_close
MAX_METADATA_BYTES = 1 * MIB
MAX_ARCHIVE_MEMBERS = 512
MIN_FREE_BYTES = 1 * GIB
DISK_CHECK_INTERVAL = 16 * MIB
IO_CHUNK_BYTES = 64 * KIB
MAX_CHUNK_LINE_BYTES = 128
MAX_TRAILER_BYTES = 8 * KIB
MAX_CONCURRENT_UPLOADS = 2
UPLOAD_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_UPLOADS)


class RequestBodyError(ValueError):
    status = 400


class BodyTooLarge(RequestBodyError):
    status = 413


class UploadLimitError(ValueError):
    pass


class ReceiveBudget:
    """Byte budget for one upload, based on current free output-disk space."""

    def __init__(self, dest, percent):
        fs = os.statvfs(dest)
        self.free_bytes = fs.f_bavail * fs.f_frsize
        percent_bytes = self.free_bytes * percent // 100
        reservable = max(0, self.free_bytes - MIN_FREE_BYTES)
        self.byte_limit = min(percent_bytes, reservable)
        self.percent = percent
        if self.byte_limit <= 0:
            raise UploadLimitError(
                f'not enough free space while preserving {MIN_FREE_BYTES} bytes')


class ReadRateTimeout(socket.timeout):
    """The body is still arriving, but slower than the minimum read rate."""


class ReadDeadline:
    """Require sustained progress as well as an idle-socket timeout."""

    def __init__(self):
        self.started = time.monotonic()
        self.transferred = 0

    def note(self, size):
        self.transferred += size
        allowed = INITIAL_READ_SECONDS + (
            self.transferred / MIN_READ_BYTES_PER_SECOND)
        if time.monotonic() > self.started + allowed:
            raise ReadRateTimeout('request body did not meet minimum read rate')

    def stall_report(self, error, expected):
        """How far a timed-out body got, so a stall reads plainly in the log.

        A stopped transfer and a slow one call for different fixes: a radio
        that stopped carrying the upload (issue 13) is not helped by a longer
        timeout, and the byte count and elapsed time are what tell them apart.
        """
        why = (f'slower than {MIN_READ_BYTES_PER_SECOND} bytes/s'
               if isinstance(error, ReadRateTimeout)
               else f'nothing arrived for {READ_IDLE_TIMEOUT_SECONDS} s')
        of = f' of {expected}' if expected is not None else ''
        return (f'request body read timed out, {why}: {self.transferred}{of} '
                f'bytes in {time.monotonic() - self.started:.1f} s')


class LimitedWriter:
    """Count writes, enforce a byte ceiling, and preserve free disk space."""

    def __init__(self, target, limit, label, limit_error=UploadLimitError,
                 check_disk=False):
        self.target = target
        self.limit = limit
        self.label = label
        self.limit_error = limit_error
        self.check_disk = check_disk
        self.total = 0
        self._until_disk_check = 0

    @property
    def remaining(self):
        return self.limit - self.total

    def write(self, data):
        if not data:
            return 0
        size = len(data)
        if size > self.remaining:
            raise self.limit_error(
                f'{self.label} exceeds {self.limit}-byte limit')
        if self.check_disk and size >= self._until_disk_check:
            fs = os.fstatvfs(self.target.fileno())
            free = fs.f_bavail * fs.f_frsize
            if free < MIN_FREE_BYTES + DISK_CHECK_INTERVAL:
                raise UploadLimitError(
                    f'{self.label} stopped to preserve {MIN_FREE_BYTES} bytes free')
            self._until_disk_check = DISK_CHECK_INTERVAL
        written = self.target.write(data)
        if written != size:
            raise OSError(f'short write for {self.label}: {written} of {size} bytes')
        self.total += written
        self._until_disk_check -= written
        return written


def body_plan(headers, limit):
    """Validate framing before sending 100 Continue or reading any body."""
    transfer = headers.get('Transfer-Encoding', '')
    if transfer:
        encodings = [part.strip().lower() for part in transfer.split(',')]
        if encodings != ['chunked']:
            raise RequestBodyError(f'unsupported Transfer-Encoding: {transfer!r}')
        return 'chunked', None
    value = headers.get('Content-Length')
    if value is None:
        raise RequestBodyError('request body needs Content-Length or chunked encoding')
    try:
        length = int(value)
    except (TypeError, ValueError):
        raise RequestBodyError(f'invalid Content-Length: {value!r}') from None
    if length < 0:
        raise RequestBodyError(f'invalid Content-Length: {value!r}')
    if length > limit:
        raise BodyTooLarge(f'request body exceeds {limit}-byte limit')
    return 'length', length


def _copy_exact(source, writer, size, truncated, deadline):
    # read1 hands back whatever has arrived rather than waiting for a full
    # chunk, so a stalled body is counted to the byte instead of to the last
    # complete 64 KiB it managed.
    read = getattr(source, 'read1', source.read)
    left = size
    while left:
        data = read(min(left, IO_CHUNK_BYTES))
        if not data:
            raise RequestBodyError(truncated)
        deadline.note(len(data))
        writer.write(data)
        left -= len(data)


def _read_chunked(rfile, writer, deadline):
    while True:
        line = rfile.readline(MAX_CHUNK_LINE_BYTES + 1)
        deadline.note(len(line))
        if not line or len(line) > MAX_CHUNK_LINE_BYTES or not line.endswith(b'\n'):
            raise RequestBodyError('invalid or overlong chunk-size line')
        token = line.split(b';', 1)[0].strip()
        try:
            size = int(token, 16)
        except ValueError:
            raise RequestBodyError(f'invalid chunk size: {token[:40]!r}') from None
        if size < 0:
            raise RequestBodyError('negative chunk size')
        if size == 0:
            trailers = 0
            while True:
                line = rfile.readline(MAX_CHUNK_LINE_BYTES + 1)
                deadline.note(len(line))
                trailers += len(line)
                if (not line or len(line) > MAX_CHUNK_LINE_BYTES
                        or trailers > MAX_TRAILER_BYTES):
                    raise RequestBodyError('invalid or overlong chunk trailers')
                if line in (b'\r\n', b'\n'):
                    return
        if size > writer.remaining:
            raise BodyTooLarge(
                f'request body exceeds {writer.limit}-byte limit')
        _copy_exact(rfile, writer, size, 'truncated chunk data', deadline)
        ending = rfile.read(2)
        deadline.note(len(ending))
        if ending != b'\r\n':
            raise RequestBodyError('chunk data missing CRLF')


def patient_reader(rfile, sock, is_complete):
    """PatientReader over rfile, or rfile itself (main's behaviour: wait out
    the idle timeout) when this Python's SocketIO isn't the one it expects."""
    if not PatientReader.supported(rfile):
        logging.warning('socket reader lacks _timeout_occurred; stalled uploads '
                        'will not be checked for completeness')
        return rfile
    return PatientReader(rfile, sock, is_complete)


class BodyComplete(Exception):
    """The upload went quiet, but what arrived is already a whole archive."""


def archive_is_complete(raw, byte_limit):
    """True when raw, from its start, decodes to a CPIO archive that reads to
    its end. Used on a stalled upload only, so a full decode is affordable."""
    pos = raw.tell()
    try:
        raw.flush()
        with tempfile.TemporaryFile(dir=DEST) as cpio:
            decode_dvzip(raw, cpio, byte_limit)
            # Only an archive that reached CPIO's end-of-archive entry is
            # whole. libarchive reads an empty stream, or one cut cleanly
            # between members, as a valid archive, and accepting either would
            # silently drop the files that never arrived.
            size = cpio.tell()
            cpio.seek(max(0, size - 1024))
            if b'TRAILER!!!' not in cpio.read():
                return False
            cpio.seek(0)
            members = 0
            with libarchive.stream_reader(cpio) as archive:
                for entry in archive:
                    members += 1
                    for _ in entry.get_blocks():
                        pass
        return members > 0
    except Exception:
        return False
    finally:
        raw.seek(pos)


class PatientReader:
    """rfile, read in short waits so a stall can be looked at while it lasts.

    Over exclusive-mode AWDL (Intel Wi-Fi) the iPhone sometimes delivers every
    byte of an upload and then never sends the chunked body's closing "0"
    chunk: its progress bar sits full, and the upload used to die on the idle
    timeout 25 KB "short" (2026-10-10, 4 of 7 receives of a 34 MB video). When
    the wait for the next chunk-size line goes quiet for STEP seconds, this
    asks is_complete(); when the archive is whole it raises BodyComplete so the
    upload is stored and answered. Otherwise it keeps waiting, up to
    READ_IDLE_TIMEOUT_SECONDS of silence as before.

    Each check decodes everything received so far, so it runs only at a chunk
    boundary (where the missing closing chunk would be) and at most MAX_CHECKS
    times per upload: a sender that keeps pausing mid-body cannot make the
    receiver decode it over and over."""

    STEP = 3
    MAX_CHECKS = 2

    def __init__(self, rfile, sock, is_complete):
        self.rfile = rfile
        self.sock = sock
        self.is_complete = is_complete
        self.checks_left = self.MAX_CHECKS

    @staticmethod
    def supported(rfile):
        """Whether rfile is the CPython SocketIO this relies on. Its private
        _timeout_occurred flag must be cleared after a timeout; if a Python
        version renames it, every read after the first stall would fail."""
        return hasattr(getattr(rfile, 'raw', None), '_timeout_occurred')

    def _call(self, fn, *args, may_check=False):
        idle = 0
        checked = not may_check
        self.sock.settimeout(self.STEP)
        try:
            while True:
                try:
                    return fn(*args)
                except socket.timeout:
                    # SocketIO refuses every read after a timeout. Nothing was
                    # consumed by the read that timed out, so clear the flag
                    # and carry on (CPython socket.SocketIO, private).
                    self.rfile.raw._timeout_occurred = False
                    idle += self.STEP
                    if not checked and self.checks_left > 0:
                        checked = True
                        self.checks_left -= 1
                        if self.is_complete():
                            raise BodyComplete()
                    if idle >= READ_IDLE_TIMEOUT_SECONDS:
                        raise
        finally:
            self.sock.settimeout(READ_IDLE_TIMEOUT_SECONDS)

    # readline and read are built on peek, never on rfile's own: those lose
    # the bytes they had gathered when a wait times out partway (tested), and
    # peek only fills the buffer, so a timed-out wait consumes nothing.
    def _take(self, size, stop_at_newline):
        out = b''
        while len(out) < size:
            # Only the first byte of a chunk-size line marks a chunk boundary.
            ready = self._call(self.rfile.peek, 1,
                               may_check=stop_at_newline and not out)
            if not ready:
                break
            want = size - len(out)
            if stop_at_newline:
                i = ready.find(b'\n', 0, want)
                if i >= 0:
                    out += self.rfile.read(i + 1)
                    break
            out += self.rfile.read(min(len(ready), want))
        return out

    def readline(self, size=-1):
        return self._take(size if size >= 0 else 1 << 30, True)

    def read(self, size):
        return self._take(size, False)

    def read1(self, size):
        return self._call(self.rfile.read1, size)


def read_request_body(rfile, headers, target, limit, *, check_disk=False,
                      plan=None, deadline=None):
    """Stream one framed request body into target under byte and time limits."""
    mode, length = plan or body_plan(headers, limit)
    deadline = deadline or ReadDeadline()
    writer = LimitedWriter(target, limit, 'request body', BodyTooLarge,
                           check_disk)
    if mode == 'chunked':
        _read_chunked(rfile, writer, deadline)
    else:
        _copy_exact(rfile, writer, length, 'truncated request body', deadline)
    return writer.total


def read_small_body(rfile, headers, limit=MAX_METADATA_BYTES):
    body = io.BytesIO()
    read_request_body(rfile, headers, body, limit)
    return body.getvalue()


def _inflate(decoder, data, writer):
    while data:
        output = decoder.decompress(
            data, min(IO_CHUNK_BYTES, writer.remaining + 1))
        writer.write(output)
        if decoder.unconsumed_tail:
            data = decoder.unconsumed_tail
        else:
            return


def _decode_compressed_block(source, size, writer, *, wbits=zlib.MAX_WBITS):
    decoder = zlib.decompressobj(wbits)
    left = size
    while left:
        data = source.read(min(left, IO_CHUNK_BYTES))
        if not data:
            raise ValueError(f'truncated compressed block: {left} bytes missing')
        left -= len(data)
        _inflate(decoder, data, writer)
        if decoder.unused_data:
            raise ValueError('compressed block has trailing data')
    writer.write(decoder.flush())
    if not decoder.eof:
        raise ValueError('truncated compressed block')


def decode_dvzip(source, target, byte_limit):
    """Stream a gzip or block-framed DVZip body into a bounded CPIO stream."""
    writer = LimitedWriter(target, byte_limit,
                           'decompressed archive', check_disk=True)
    source.seek(0)
    magic = source.read(2)
    source.seek(0)
    if magic == b'\x1f\x8b':
        decoder = zlib.decompressobj(31)
        while True:
            data = source.read(IO_CHUNK_BYTES)
            if not data:
                break
            _inflate(decoder, data, writer)
            if decoder.unused_data:
                raise ValueError('gzip body has trailing data')
        writer.write(decoder.flush())
        if not decoder.eof:
            raise ValueError('truncated gzip body')
        return writer.total

    while True:
        header = source.read(4)
        if not header:
            return writer.total
        if len(header) != 4:
            raise ValueError(f'truncated DVZip block header: {len(header)} bytes')
        value = int.from_bytes(header, 'big')
        size = value & 0x7fffffff
        if value & 0x80000000:
            left = size
            while left:
                data = source.read(min(left, IO_CHUNK_BYTES))
                if not data:
                    raise ValueError(f'truncated stored block: {left} bytes missing')
                writer.write(data)
                left -= len(data)
        else:
            _decode_compressed_block(source, size, writer)


def safe_name(name, fallback):
    """Return one non-hidden filesystem component from sender-controlled text."""
    name = unicodedata.normalize('NFC', name.replace('\\', '/').rsplit('/', 1)[-1])
    name = UNSAFE_CHAR.sub('', name).strip().lstrip('.')
    stem, ext = os.path.splitext(name)
    while len((stem + ext).encode('utf-8')) > 255 and stem:
        stem = stem[:-1]
    return (stem + ext) or fallback


def open_new(dest, name):
    """Create dest/name atomically without clobbering an existing file."""
    stem, ext = os.path.splitext(name)
    for i in range(10000):
        cand = name if i == 0 else f'{stem}-{i}{ext}'
        try:
            fd = os.open(os.path.join(dest, cand),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            continue
        return cand, os.fdopen(fd, 'wb')
    raise FileExistsError(name)


class ExtractionBudget:
    def __init__(self, byte_limit):
        self.byte_limit = byte_limit
        self.members = 0
        self.output_bytes = 0

    def count_member(self):
        self.members += 1
        if self.members > MAX_ARCHIVE_MEMBERS:
            raise UploadLimitError(
                f'archive exceeds {MAX_ARCHIVE_MEMBERS}-member limit')


class ExtractedFileWriter(LimitedWriter):
    def __init__(self, target, budget, name):
        super().__init__(target, budget.byte_limit, f'file {name!r}',
                         check_disk=True)
        self.budget = budget

    def write(self, data):
        if self.budget.output_bytes + len(data) > self.budget.byte_limit:
            raise UploadLimitError(
                f'archive output exceeds {self.budget.byte_limit}-byte limit')
        written = super().write(data)
        self.budget.output_bytes += written
        return written


def store_upload(raw, dest, tid, receive_budget):
    """Decode and extract regular files, removing every output on failure."""
    created = []
    written = []
    try:
        with tempfile.TemporaryFile(dir=dest) as cpio:
            decoded = decode_dvzip(raw, cpio, receive_budget.byte_limit)
            # The wire copy is no longer needed. Release its blocks before the
            # extracted files begin consuming space.
            raw.seek(0)
            raw.truncate(0)
            cpio.seek(0)
            magic = cpio.read(6)
            cpio.seek(0)
            logging.info('upload %s: decoded to %d bytes, magic %r',
                         tid, decoded, magic)
            budget = ExtractionBudget(receive_budget.byte_limit)
            with libarchive.stream_reader(cpio) as archive:
                for entry in archive:
                    budget.count_member()
                    if not entry.isfile:
                        continue
                    if os.path.basename(entry.pathname).startswith('._'):
                        continue
                    declared = getattr(entry, 'size', 0)
                    if declared > budget.byte_limit:
                        raise UploadLimitError(
                            f'file {entry.pathname!r} declares {declared} bytes')
                    if budget.output_bytes + max(declared, 0) > budget.byte_limit:
                        raise UploadLimitError(
                            f'archive declares more than {budget.byte_limit} output bytes')
                    base = safe_name(entry.pathname, 'file')
                    name, output = open_new(dest, base)
                    created.append(name)
                    with output:
                        sink = ExtractedFileWriter(output, budget, name)
                        for block in entry.get_blocks():
                            sink.write(block)
                    written.append(name)
    except Exception:
        for name in reversed(created):
            try:
                os.unlink(os.path.join(dest, name))
            except FileNotFoundError:
                pass
        raise
    return written


def store_link(url, dest):
    """Write a received URL into dest as an inert .url shortcut and return the
    stored name. INI form ([InternetShortcut]) because it is plain text, needs
    no execute bit, and is what browsers and file managers already open -- a
    .desktop Type=Link would be the freedesktop spelling but invites the
    executable-desktop-entry class of problem for no gain.

    The name comes from the URL's host and last path segment, sanitised the
    same way an uploaded filename is; the URL itself is written as a value, not
    interpreted, and nothing here launches anything."""
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    stem = '-'.join(p for p in (parts.netloc, parts.path.rstrip('/').rsplit('/', 1)[-1]) if p)
    name, f = open_new(dest, safe_name(stem, 'link') + '.url')
    with f:
        f.write(f'[InternetShortcut]\nURL={url}\n'.encode('utf-8'))
    return name


# ReceiverMediaCapabilities, sent in both the Discover and the Ask answer.
# Version 3 codec/profile table captured from a MacBook Pro response; keeping
# the captured payload avoids advertising the codec-free legacy-format stub.
MEDIA_CAPABILITIES = b'{"SupportsAdjustmentBaseResources":true,"Version":3,"Codecs":{"hvc1":{"Profiles":{"VTIsHDRAllowedOnDevice":true,"VTSupportedProfiles":[1,2,3,4],"VTDoViIsHardwareAccelerated":true,"VTDoViSupportedLevels":["01","02","03","04","05","06","07","08","09"],"VTPerProfileSupport":{"3":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"1":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"4":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"2":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186}},"VTDoViSupportedProfiles":["05","08"]}},"CodecSupport":{"VTIsHDRAllowedOnDevice":true,"VTCodecSupportDict":{"apcs":{"VTIsHardwareAccelerated":true},"hvc1":{"VTIsHDRAllowedOnDevice":true,"VTPerProfileSupport":{"3":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"1":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"4":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"2":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186}},"VTSupportedProfiles":[1,2,3,4]},"apcn":{"VTIsHardwareAccelerated":true},"apch":{"VTIsHardwareAccelerated":true},"apco":{"VTIsHardwareAccelerated":true},"ap4x":{"VTIsHardwareAccelerated":true},"ap4h":{"VTIsHardwareAccelerated":true}}}},"ContainerFormats":{"public.heif-standard":{"HeifSubtypes":["public.avci","public.avif","public.heic","public.heics","public.heif"]}},"Vendor":{"com.apple":{"LivePhotoFormatVersion":"1","AssetBundleFormatVersion":"1"}}}'


class Handler(BaseHTTPRequestHandler):
    """AirDrop's receiving endpoints, as sharingd (AirDrop/1.0, macOS 15) and
    iOS actually send them:
    - /Discover and /Ask arrive `Transfer-Encoding: chunked` with no
      Content-Length, so their bodies go through the same bounded reader as
      an upload's, never int(Content-Length). Each body is read from rfile
      exactly once, in place: Ask and Upload share one TLS connection, and a
      swapped-out rfile once made the keep-alive loop see EOF.
    - /Upload arrives as application/x-dvzip, not the plain x-cpio older
      AirDrop implementations take (answering 406 to it makes the sender
      report a failed transfer). Decode it. Older iOS still sends x-cpio
      (seen from iOS 16): its compressed body decodes to the same CPIO
      archive, and refusing it failed every transfer from that phone.
    Anything else POSTed is answered 400, GET and HEAD a bare 200, and every
    other method the stock 501.
    """

    protocol_version = 'HTTP/1.1'
    # Set once an accepted Ask expects an Upload on this connection, and
    # cleared when the next request's first byte arrives.
    awaiting_upload = False

    def setup(self):
        # Applies to the TLS handshake, request headers and every body read. A
        # peer that stops transmitting cannot hold one server thread forever.
        self.request.settimeout(READ_IDLE_TIMEOUT_SECONDS)
        # The handshake runs here, on this connection's own thread, not in
        # accept(): there, one sender that dropped off the link mid-handshake
        # stopped every later connection from being accepted for the rest of
        # the window (2026-09-30 17:13Z: backlog full, iPhone never answered).
        try:
            self.request.do_handshake()
        except OSError as e:
            logging.info('TLS handshake with [%s]:%s failed: %s',
                         self.client_address[0], self.client_address[1], e)
            raise HandshakeFailed from e
        super().setup()

    def handle_one_request(self):
        # The Upload wait covers only the gap before the next request starts.
        # Its first byte ends it, so a request line, headers or body that stall
        # get the ordinary idle limit. peek() blocks for that byte, counts any
        # already buffered, and consumes nothing.
        try:
            if self.awaiting_upload:
                try:
                    self.rfile.peek(1)
                except TimeoutError:
                    logging.warning('no Upload within %d s of an accepted Ask; closing the connection',
                                    UPLOAD_WAIT_SECONDS)
                    self.close_connection = True
                    return
                self.awaiting_upload = False
                self.request.settimeout(READ_IDLE_TIMEOUT_SECONDS)
            super().handle_one_request()
        except (ConnectionError, ssl.SSLError) as e:
            self.peer_disconnected(str(e))

    def handle_expect_100(self):
        # BaseHTTPRequestHandler would acknowledge an upload before its framing
        # and disk-relative limit are validated. Defer only Upload; the other
        # endpoints still need the normal automatic acknowledgement.
        if self.path == '/Upload':
            return True
        return super().handle_expect_100()

    def peer_disconnected(self, reason):
        self.close_connection = True
        logging.info('%s peer disconnected: %s',
                     getattr(self, 'path', 'request'), reason)

    def reject(self, status, reason):
        logging.warning('%s rejected: %s', self.path, reason)
        self.send_response(status)
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True

    def answer(self, body):
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self.answer(b'\n')

    def do_POST(self):
        logging.debug('POST %s, headers:\n%s', self.path, self.headers)
        if PEERCERT_DIR:
            # Research instrumentation must never be able to fail a transfer.
            # It did once: a capture bug raised inside do_POST and killed three
            # real iPhone connections before /Ask was ever parsed, which looked
            # exactly like a receiver that refused them.
            try:
                _capture_peer_cert(self.connection)
            except Exception:
                logging.exception('peer certificate capture failed; continuing')
        if self.path == '/Upload':
            self.handle_upload()
            return
        if self.path not in ('/Discover', '/Ask'):
            self.send_response(400)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        try:
            body = read_small_body(self.rfile, self.headers)
        except socket.timeout:
            self.reject(408, 'request body read timed out')
            return
        except RequestBodyError as e:
            self.reject(e.status, str(e))
            return
        logging.debug('buffered bounded %d-byte body for %s', len(body), self.path)
        if self.path == '/Discover':
            self.handle_discover(body)
        else:
            self.handle_ask(body)

    # Contacts Only should mean a stranger does not see this machine at all,
    # which is what Apple's mode does and what the name implies. Until now it
    # only refused the transfer: an unknown Mac received a full /Discover
    # answer, tiled in its own share sheet, and was turned away at /Ask
    # (measured 2026-09-20, 403 in 23 ms). Presence leaked -- name, model and
    # the fact the machine exists.
    #
    # This hides us from an HONEST stranger and nothing more. /Discover carries
    # SenderRecordData (3718 bytes from a real Mac, 2026-09-20) but no client
    # certificate, so the record cannot be bound to the connection and a replay
    # of a contact's record would still be answered. That is acceptable for
    # deciding who sees a tile and NEVER acceptable for deciding who may send,
    # which is why the transfer gate in handle_ask is untouched and still does
    # the full cert-bound check.
    #
    # Silence rather than an error: a 403 here would tell the stranger the
    # machine is there, which is the thing being hidden.
    def handle_discover(self, body):
        if contacts.visibility() == 'contacts':
            try:
                record = (safeplist.loads(body) or {}).get('SenderRecordData')
            except Exception:
                record = None
            outcome, detail = contacts.decide_discovery(record)
            if outcome != contacts.ACCEPT:
                logging.info('discovery withheld (contacts only): %s%s',
                             contacts.WHY[outcome], f' [{detail}]' if detail else '')
                self.send_response(401)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
        write_debug(body, 'receive_discover_request.plist')
        answer = {
            'ReceiverModelName': MODEL,
            'ReceiverComputerName': NAME,
            'ReceiverMediaCapabilities': MEDIA_CAPABILITIES,
            'IsAirDropable': True,
        }
        # The Apple ID validation record, when this machine has one, is what
        # lets a Contacts Only sender recognise us.
        if RECORD_DATA:
            answer['ReceiverRecordData'] = RECORD_DATA
        resp = plistlib.dumps(answer, fmt=plistlib.FMT_BINARY)
        write_debug(resp, 'receive_discover_response.plist')
        self.answer(resp)

    # 2026-09-12, iPhone on iOS 26, two link transfers: /Discover 200, /Ask 200
    # for a 108-byte `x-com.webloc`, then NO /Upload at all while the phone's
    # UI reported "Sent". The Ask was answered with the two name keys only
    # (OpenDrop's answer); the Discover answer (and a Mac's, 043402Z) also
    # carries ReceiverMediaCapabilities, which is how the sender learns what
    # the receiver will take. Answer the Ask with the same three keys and log
    # what was asked for: that log line is what separates "the sender never
    # uploaded" from "the upload failed on our side".
    def handle_ask(self, body):
        write_debug(body, 'receive_ask_request.plist')
        try:
            # Never plistlib.loads: the log line below walks every reference
            # in a binary plist, and a sub-MiB body can name one entry
            # hundreds of thousands of times. Over safeplist's limits, the
            # Ask is undecodable, as in omdrop-core.
            ask = safeplist.loads(body)
        except Exception as e:
            logging.error('ask: undecodable %d-byte body: %r', len(body), e)
            ask = {}
        files = ask.get('Files') or []
        logging.info('ask from %s (%s): type %s, %d item(s): %s',
                     ask.get('SenderComputerName'), ask.get('SenderModelName'),
                     ','.join(ask.get('TransferType') or {}) or '?', len(files),
                     '; '.join(f"{f.get('FileName')} {f.get('FileType')} {f.get('FileSize')}B"
                               for f in files) or (ask.get('Items') or '-'))
        items = ask.get('Items') or []
        if len(items) > MAX_ARCHIVE_MEMBERS:
            self.reject(413, f'Ask exceeds {MAX_ARCHIVE_MEMBERS}-item limit')
            return
        # Contacts Only is enforced here rather than at /Discover, for two
        # reasons measured on 2026-09-18: a sender presents its Apple-issued
        # client certificate on /Ask and never on /Discover, and /Ask is the
        # moment a transfer is actually proposed. Refusing here costs the
        # sender a clear error instead of an unexplained disappearance.
        mode = contacts.visibility()
        if mode == 'contacts':
            peer_cert = None
            try:
                peer_cert = self.connection.getpeercert(binary_form=True)
            except (AttributeError, ValueError):
                pass
            outcome, detail = contacts.decide(ask.get('SenderRecordData'), peer_cert)
            if outcome != contacts.ACCEPT:
                # No identifier is logged: the record's hashes are reversible
                # to a phone number by brute force.
                logging.warning('ask REFUSED (contacts only): %s%s',
                                contacts.WHY[outcome],
                                f' [{detail}]' if detail else '')
                self.send_response(403)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            logging.info('ask accepted: %s', contacts.WHY[outcome])
            # Remembered per connection: Ask and Upload share one TLS session,
            # so an Upload that never passed an Ask has nothing vouching for it.
            self._contacts_ok = True

        # A `links` transfer is Ask-only: with SUPPORTS_URL (0x01) advertised,
        # iOS puts the URL straight into Items and sends no /Upload at all, so
        # accepting the Ask IS the transfer. Store it, or the link is lost.
        # NEVER open it: in Everyone mode any device in range could otherwise
        # make this machine visit an arbitrary URL. A file the user clicks is
        # the whole interaction we are willing to offer.
        if 'links' in (ask.get('TransferType') or {}):
            for item in items:
                if not isinstance(item, str) or not item.startswith(('http://', 'https://')):
                    logging.warning('ask: ignoring non-http item %.80r', item)
                    continue
                stored = store_link(item, DEST)
                logging.info('link stored as %s -> %s', stored, item)
        resp = plistlib.dumps({
            'ReceiverModelName': MODEL,
            'ReceiverComputerName': NAME,
            'ReceiverMediaCapabilities': MEDIA_CAPABILITIES,
            'IsAirDropable': True,
        }, fmt=plistlib.FMT_BINARY)
        write_debug(resp, 'receive_ask_response.plist')
        self.answer(resp)
        # A links Ask is the whole transfer; every other kind is followed by
        # an Upload on this connection.
        if 'links' not in (ask.get('TransferType') or {}):
            self.awaiting_upload = True
            self.request.settimeout(UPLOAD_WAIT_SECONDS)

    def handle_upload(self):
        # An Upload that never passed an Ask has nothing vouching for it, and
        # the Upload itself carries no validation record to judge.
        if contacts.visibility() == 'contacts' and not getattr(self, '_contacts_ok', False):
            self.reject(403, 'contacts-only upload has no accepted Ask')
            return
        ctype = self.headers.get('Content-Type', '').split(';')[0].strip().lower()
        if ctype not in ('application/x-dvzip', 'application/x-cpio'):
            self.reject(415, f'unsupported Content-Type {ctype!r}')
            return
        if not UPLOAD_SLOTS.acquire(blocking=False):
            self.reject(503, 'too many uploads in progress')
            return
        tid = safe_name(self.headers.get('TransferID', ''), 'upload')
        deadline = ReadDeadline()
        plan = None
        ended_early = False
        try:
            receive_budget = ReceiveBudget(DEST, MAX_RECEIVE_PERCENT)
            plan = body_plan(self.headers, receive_budget.byte_limit)
            logging.info(
                'upload %s: %d%% of %d free bytes allows %d bytes',
                tid, receive_budget.percent, receive_budget.free_bytes,
                receive_budget.byte_limit)
            if self.headers.get('Expect', '').lower() == '100-continue':
                self.send_response_only(100)
                self.end_headers()
            with tempfile.TemporaryFile(dir=DEST) as raw:
                patient = patient_reader(
                    self.rfile, self.request,
                    lambda: archive_is_complete(raw, receive_budget.byte_limit))
                try:
                    wire_bytes = read_request_body(
                        patient, self.headers, raw, receive_budget.byte_limit,
                        check_disk=True, plan=plan, deadline=deadline)
                except BodyComplete:
                    raw.flush()
                    wire_bytes = raw.tell()
                    # The closing chunk never came, so this connection's
                    # framing is unknown: answer, then close it.
                    self.close_connection = True
                    ended_early = True
                    logging.warning('upload %s: no closing chunk after %d s, but the '
                                    'archive is complete; storing it', tid, PatientReader.STEP)
                raw.seek(0)
                logging.info('upload %s: %d bytes dvzip (TotalBytes %s)',
                             tid, wire_bytes, self.headers.get('TotalBytes'))
                written = store_upload(raw, DEST, tid, receive_budget)
            logging.info('upload %s: stored %s', tid, ', '.join(written))
        except socket.timeout as e:
            # Chunked framing announces no length, so there is none to name.
            expected = plan[1] if plan else None
            self.reject(408, f'upload {tid}: {deadline.stall_report(e, expected)}')
            return
        except (BodyTooLarge, UploadLimitError) as e:
            self.reject(413, str(e))
            return
        except RequestBodyError as e:
            self.reject(e.status, str(e))
            return
        except (ConnectionError, ssl.SSLError) as e:
            # Socket errors are OSErrors too. They do not mean storage failed,
            # and replying 507 on the dead socket just raises BrokenPipeError.
            # The temporary file and upload slot are released by with/finally.
            self.peer_disconnected(
                f'upload {tid}: {e}; {deadline.transferred} HTTP body/framing '
                f'bytes read in {time.monotonic() - deadline.started:.1f} s')
            return
        except OSError as e:
            self.reject(507, f'storage failed: {e}')
            return
        except Exception as e:
            self.reject(422, f'upload is not a valid bounded DVZip archive: {e}')
            return
        finally:
            UPLOAD_SLOTS.release()
        self.send_response(200)
        self.send_header('Content-Length', '0')
        # Finish the transfer now rather than waiting for the idle timeout.
        self.send_header('Connection', 'close')
        self.end_headers()
        if ended_early:
            self.drain_before_close()

    def drain_before_close(self):
        """Read what the sender still has in flight before closing.

        A Mac's sharingd sends the closing chunk only after it has our answer.
        Closing with that chunk unread, or with it still on the way, makes the
        kernel send a TCP RST, and a Mac that sees the reset reports the stored
        transfer as failed (sharingd: unexpected-NSPOSIXErrorDomain-54). An
        iPhone instead keeps the connection open and waits for us to close.
        So read until the sender closes or goes quiet for DRAIN_QUIET_SECONDS,
        and never for longer than DRAIN_LIMIT_SECONDS in all.
        """
        try:
            self.wfile.flush()
        except OSError:
            return
        end = time.monotonic() + DRAIN_LIMIT_SECONDS
        try:
            while (left := end - time.monotonic()) > 0:
                self.request.settimeout(min(DRAIN_QUIET_SECONDS, left))
                if not self.rfile.read1(IO_CHUNK_BYTES):
                    return              # the sender closed: so can we
        except (OSError, ValueError):   # quiet (socket.timeout), or gone
            return

    def log_message(self, fmt, *a):
        logging.info('%s %s', self.client_address[0], fmt % a)


# ------------------------------------------------------------------ identity
#
# The certificate this machine presents and the Apple ID validation record
# that lets a Contacts Only sender recognise it. Chosen once, at start, by the
# rules in docs/identity-contract.md, which the driver's sender follows too:
# from the 1Password cache, the files in ~/.omdrop/keys, or the self-signed
# pair, which is created here if it is missing. Within a window the choice is
# the window's; if that identity is unavailable this refuses to start rather
# than presenting a different one.
USER = identity.User(keys_dir=args.keys)
try:
    IDENTITY = identity.resolve(USER, name=NAME)
except identity.IdentityError as e:
    raise SystemExit(f'no usable identity: {e}')
for warning in IDENTITY.warnings:
    logging.warning('identity: %s', warning)
RECORD_DATA = IDENTITY.record
logging.info('identity: %s%s', IDENTITY.kind,
             f', Apple ID validation record {len(RECORD_DATA)} bytes' if RECORD_DATA else '')


def write_debug(data, name):
    """The latest exchange of each kind, for when a device misbehaves; opt-in."""
    debugdump.dump(name, data)


APPLE_ROOT = contacts.apple_root_ca()
if APPLE_ROOT is None:
    raise SystemExit(f'Apple root CA certificate missing: {contacts.APPLE_ROOT_CA}')

# ----------------------------------------------------------------------- TLS
#
# The base context is what AirDrop peers expect of each other: this machine's
# certificate, TLS 1.0 refused (Python's own floor, TLS 1.2 today, stands when
# higher), and CERT_NONE, because senders present self-signed certificates as
# a matter of course.
#
# On top of that, ask the peer for a client certificate. Required for Contacts
# Only, because that certificate is what binds a sender's Apple-signed
# validation record to the live connection; a record on its own is handed to
# any prober that asks and would otherwise be replayable. CERT_NONE never
# asks, and so never sees one.
#
# Two things this has to get right, both learned the hard way on 2026-09-19:
#
# CERT_OPTIONAL means "a certificate may be absent", NOT "a certificate is
# tolerated". A peer that does present one has it verified, and a failure
# aborts the handshake with unknown_ca before any request is read. The base
# context trusts only Apple's root, while an Apple leaf is issued by the
# "Apple Application Integration Certification Authority" intermediate, so
# every Apple sender failed to chain and was refused at TLS. The intermediates
# vendored beside contacts.py are the missing link; certificate_account()
# already passes them for the same chain.
#
# Everyone mode goes back to CERT_NONE. Requesting a certificate there buys
# nothing -- no code consults it -- and it can only turn a sender whose
# certificate does not chain to Apple, such as a stock opendrop peer, into a
# handshake failure. The old comment claimed Everyone mode was unaffected;
# that was true of intent and false of behaviour.
#
# Measured scope of the defect, 2026-09-19: a Mac verified successfully against
# a root-only store before this fix, which is only possible if it supplied the
# intermediate, so macOS senders were never affected. iOS was measured directly
# and sends a 2-certificate chain, leaf + AAI intermediate. What broke was any
# sender presenting a bare leaf, which includes this project's own sender --
# and therefore every loopback test of the Contacts Only gate.
#
# OMDROP_PEERCERT saves what arrives, for research; it keeps the certificate
# request alive in Everyone mode so a capture run still sees one.
PEERCERT_DIR = os.environ.get('OMDROP_PEERCERT')


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = max(ctx.minimum_version, ssl.TLSVersion.TLSv1_1)
    identity.load_into(ctx, IDENTITY)
    ctx.load_verify_locations(cafile=APPLE_ROOT)
    ctx.verify_mode = ssl.CERT_NONE
    if contacts.visibility() != 'contacts' and not PEERCERT_DIR:
        return ctx
    for intermediate in contacts.apple_intermediates():
        try:
            ctx.load_verify_locations(cafile=intermediate)
        except (OSError, ssl.SSLError):
            logging.warning('could not load Apple intermediate %s; a sender '
                            'presenting an Apple certificate may be refused '
                            'at TLS', os.path.basename(intermediate))
    ctx.verify_mode = ssl.CERT_OPTIONAL
    return ctx


if PEERCERT_DIR:
    os.makedirs(PEERCERT_DIR, exist_ok=True)

    def _capture_peer_cert(conn):
        try:
            der = conn.getpeercert(binary_form=True)
        except (AttributeError, ValueError):
            return
        path = os.path.join(PEERCERT_DIR,
                            f'client-{time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())}.der')
        if der:
            with open(path, 'wb') as fh:
                fh.write(der)
            logging.warning('captured %d-byte client certificate -> %s', len(der), path)
            # getpeercert() returns the LEAF only, so it cannot say whether the
            # sender supplied its issuing intermediates. That distinction
            # decides whether a receiver trusting only Apple's root can build
            # the chain at all, which is exactly what the unknown_ca defect
            # turned on.
            try:
                chain = conn.get_unverified_chain() or []
            except (AttributeError, ValueError, NotImplementedError):
                chain = []
            if chain:
                logging.warning('client sent a %d-certificate chain', len(chain))
                for depth, cert in enumerate(chain):
                    # get_unverified_chain() yields DER bytes on this build;
                    # older/other builds yield Certificate objects. Accept both,
                    # and never let a research capture break a live transfer.
                    blob = cert if isinstance(cert, (bytes, bytearray)) else \
                        cert.public_bytes(ssl.DER)
                    with open(f'{path[:-4]}-depth{depth}.der', 'wb') as fh:
                        fh.write(blob)
            else:
                logging.warning('client chain unavailable; leaf only')
        else:
            logging.warning('peer presented NO client certificate')

# ------------------------------------------------------------------- serving

def interface_ipv6(iface):
    """The first IPv6 address the kernel lists on iface, or None."""
    try:
        with open('/proc/net/if_inet6') as f:
            rows = [line.split() for line in f]
    except OSError:
        return None
    for row in rows:
        if len(row) == 6 and row[5] == iface:
            return ipaddress.IPv6Address(bytes.fromhex(row[0]))
    return None


# The socket is the IPv6 wildcard, but an interface with no address yet is one
# no peer can reach, so refuse to start and let the unit try again.
IFACE_ADDR = interface_ipv6(args.iface)
if IFACE_ADDR is None:
    raise SystemExit(f'interface {args.iface} has no IPv6 address yet; is the AWDL radio up?')


# A busy port is waited out, never side-stepped. opendrop quietly moved to the
# next one, which nothing advertises -- a receiver nobody can reach. Waiting is
# what the user wants instead: the usual reason is the previous run's socket
# still unwinding, which clears in seconds now that stopping resets its
# sessions.
def bind_server(attempts=5, pause=2):
    for attempt in range(1, attempts + 1):
        try:
            return ThreadingHTTPServerV6(('::', args.port), Handler)
        except OSError as e:
            if e.errno != errno.EADDRINUSE:
                raise
        logging.warning('port %d still held; retry %d of %d', args.port,
                        attempt, attempts)
        time.sleep(pause)
    return None


server = bind_server()
if server is None:
    logging.error('port %d is still held by something else after waiting; '
                  'the announcer only ever names %d', args.port, args.port)
    sys.exit(1)
server.socket = tls_context().wrap_socket(server.socket, server_side=True,
                                          do_handshake_on_connect=False)
logging.info('config %s: %s', args.config, ', '.join(f'{k}={v!r}' for k, v in sorted(_cfg.items())) or 'absent (defaults)')
logging.info('serving %s._airdrop._tcp.local as %s (%s) on [%s]:%d, receiving into %s',
             sid, NAME, MODEL, IFACE_ADDR, args.port, DEST)

# systemd stops this unit with SIGTERM, whose default action skips every
# cleanup below -- including the session reset that frees the port.
def on_term(signum, frame):
    raise KeyboardInterrupt


signal.signal(signal.SIGTERM, on_term)
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    server.reset_sessions()
    server.server_close()
