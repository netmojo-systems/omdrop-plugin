"""Opt-in dumps of AirDrop requests and answers, per docs/identity-contract.md.

Off unless OMDROP_DEBUG=1 (redacted) or OMDROP_DEBUG_SENSITIVE=1 (verbatim).
They land in $XDG_RUNTIME_DIR/omdrop/debug, never the home directory: a
request carries validation records, ours and the sender's.
"""
import os
import plistlib

import safeplist

_REDACT_SUFFIXES = ('RecordData', 'Certificate')


def _enabled():
    sensitive = os.environ.get('OMDROP_DEBUG_SENSITIVE') == '1'
    return sensitive or os.environ.get('OMDROP_DEBUG') == '1', sensitive


def _redact(value):
    if isinstance(value, dict):
        return {k: (f'<redacted {len(v)} bytes>' if isinstance(k, str)
                    and k.endswith(_REDACT_SUFFIXES) and isinstance(v, (bytes, bytearray, str))
                    else _redact(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def directory():
    runtime = os.environ.get('XDG_RUNTIME_DIR') or f'/run/user/{os.getuid()}'
    return os.path.join(runtime, 'omdrop', 'debug')


def dump(name, data):
    """Write one exchange's body under `name`, if dumps are on. Never raises."""
    on, sensitive = _enabled()
    if not on:
        return
    try:
        if sensitive:
            out = data
        else:
            try:
                out = plistlib.dumps(_redact(safeplist.loads(data)), fmt=plistlib.FMT_XML)
            except Exception:
                out = f'<opaque {len(data)} bytes>'.encode()
        path = os.path.join(directory(), name)
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        # mkstemp, not a pid-based name: the receiver is threaded, and two
        # exchanges at once would otherwise share one temporary file.
        import tempfile
        fd, tmp = tempfile.mkstemp(prefix=f'.{name}.', dir=os.path.dirname(path))
        try:
            os.write(fd, out)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except OSError:
        pass
