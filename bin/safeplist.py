"""Property lists from untrusted peers, decoded under limits.

A binary plist may reference one object many times, or give one object many
IDs. plistlib shares an object referenced by one ID, so walking the result --
a log line, a printed name, an XML dump -- visits every reference, and it
builds an object afresh for each ID, so decoding itself can allocate far more
than the input. Both are bounded by the limits omdrop-core's safeplist.rs
applies while it parses: MAX_EVENTS values, MAX_DEPTH nested collections, and
byte_budget() decoded bytes, with every reference counted as a copy. A binary
plist is stopped while it is decoded; a reference cycle fails the depth limit.
The same module is omdrop-awdl's userspace/awdl_plist.py.
"""
import io
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


class _BoundedBinaryParser(plistlib._BinaryPlistParser):
    """plistlib's binary parser, stopped as soon as the plist it is building
    passes the limits, rather than measured afterwards.

    plistlib caches a decoded object by its ID, but a binary plist can give
    one object many IDs: 1000 IDs naming one 200 000-member array make
    plistlib build 1000 separate lists (1.6 GB) from a 400 KB input. And it
    reads a collection's whole reference list before its first member, at
    every nesting level: 34 nested arrays whose reference lists overlap held
    13 MB of pending references for a 21 KB input. So every reference is
    charged as a value when its list is read, before plistlib builds the
    list, and every object's size when it is built: nothing is allocated
    past MAX_EVENTS references or the byte budget."""

    def __init__(self, input_len):
        super().__init__(dict_type=dict)
        self._input_len = input_len
        self._budget = byte_budget(input_len)
        self._events = 1  # the top object, which no reference names
        self._decoded = self._depth = 0
        self.too_complex = False

    def _refuse(self):
        # parse() turns every ValueError into InvalidFileException; the flag
        # lets loads() say which it was.
        self.too_complex = True
        raise TooComplex()

    def _read_ints(self, n, size):
        # n is the peer's count. Before 3.13, plistlib builds a struct format n
        # characters long before checking that the bytes are there.
        if n * size > self._input_len:
            raise plistlib.InvalidFileException()
        return super()._read_ints(n, size)

    def _read_refs(self, n):
        # A collection's members (a dictionary reads its keys and its values
        # as two lists), charged before the list exists. Each is read later
        # by _read_object, from the cache or not, so each costs one value.
        self._events += n
        if self._events > MAX_EVENTS:
            self._refuse()
        return super()._read_refs(n)

    def _read_object(self, ref):
        # One past MAX_DEPTH: the exact depth limit is _measure's, after.
        if self._depth > MAX_DEPTH:
            self._refuse()
        self._depth += 1
        try:
            value = super()._read_object(ref)
        finally:
            self._depth -= 1
        self._decoded += _size(value)
        if self._decoded > self._budget:
            self._refuse()
        return value


def loads(data):
    """plistlib.loads, refusing a value whose references expand past the
    limits above with TooComplex (a ValueError). A binary plist is refused
    while it is decoded; an XML one, which cannot share objects, decodes to
    about its own size and is measured after."""
    if data[:8] == b'bplist00':
        parser = _BoundedBinaryParser(len(data))
        try:
            value = parser.parse(io.BytesIO(data))
        except plistlib.InvalidFileException:
            if parser.too_complex:
                raise TooComplex() from None
            raise
    else:
        value = plistlib.loads(data)
    # Exact limits, the same for both formats, and a reference cycle, which
    # the parser returns from its cache, fails the depth limit.
    _measure(value, byte_budget(len(data)))
    return value
