"""Property lists from untrusted peers, decoded under limits.

A binary plist may reference one object many times. plistlib shares that
object rather than copying it, so decoding stays cheap, but everything that
walks the result -- a log line, a repr, an XML dump -- visits every reference.
A 960 KB /Ask whose Files array names one 60 KB entry 900 000 times decodes in
milliseconds and then needs 54 GB to log. So the decoded value is measured as
if each reference were a copy, and refused past the limits omdrop-core's
safeplist.rs applies while it parses: MAX_EVENTS values, MAX_DEPTH nested
collections, and byte_budget() decoded bytes. A reference cycle, which a
binary plist can also express, fails the depth limit.
"""
import plistlib

# Values (and collection ends) one plist may hold. A real Ask with 512 files
# is well under 10 000.
MAX_EVENTS = 200_000
# Collections inside collections. AirDrop plists are three deep.
MAX_DEPTH = 32
# What a value other than data or a string counts against the byte budget.
VALUE_OVERHEAD = 16
# The byte budget never goes below this.
MIN_BYTE_BUDGET = 4 << 20


class TooComplex(ValueError):
    def __init__(self):
        super().__init__(
            f'property list deeper than {MAX_DEPTH}, larger than {MAX_EVENTS} values, '
            'or larger than four times its own size decoded')


def byte_budget(input_len):
    """Decoded bytes a plist of `input_len` bytes may produce: four times the
    input or 4 MiB, whichever is more. An honest plist decodes to about its
    own size."""
    return max(input_len * 4, MIN_BYTE_BUDGET)


def _size(value):
    if isinstance(value, (str, bytes, bytearray)):
        return len(value)
    return VALUE_OVERHEAD


def _measure(root, budget):
    # Iterative, with every reference walked as a copy. A collection's
    # members are counted before they are queued, so one huge array is
    # refused without queueing it.
    events, decoded = 1, 0
    stack = [(root, 0)]
    while stack:
        value, depth = stack.pop()
        decoded += _size(value)
        if isinstance(value, (dict, list)):
            if depth >= MAX_DEPTH:
                raise TooComplex()
            # The collection's end, and each member (a dict entry is a key
            # and a value).
            events += 1 + len(value) * (2 if isinstance(value, dict) else 1)
            decoded += VALUE_OVERHEAD
            if events > MAX_EVENTS:
                raise TooComplex()
            if isinstance(value, dict):
                for key, member in value.items():
                    decoded += _size(key)
                    stack.append((member, depth + 1))
            else:
                stack.extend((member, depth + 1) for member in value)
        if decoded > budget:
            raise TooComplex()


def loads(data):
    """plistlib.loads, refusing a value whose references expand past the
    limits above with TooComplex (a ValueError)."""
    value = plistlib.loads(data)
    _measure(value, byte_budget(len(data)))
    return value
