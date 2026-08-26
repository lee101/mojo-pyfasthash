"""Small, intentionally straightforward reference implementations for parity tests."""

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1


def _rot32(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK32


def _rot64(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64


def fnv(data, seed, bits, alternate=False):
    mask, prime = (MASK32, 0x1000193) if bits == 32 else (MASK64, 0x100000001B3)
    h = seed & mask
    for byte in data:
        h = ((h ^ byte) * prime if alternate else (h * prime) ^ byte) & mask
    return h


def murmur2_32(data, seed=0):
    h, i = (seed ^ len(data)) & MASK32, 0
    while i + 4 <= len(data):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * 0x5BD1E995) & MASK32
        k ^= k >> 24
        k = (k * 0x5BD1E995) & MASK32
        h = ((h * 0x5BD1E995) ^ k) & MASK32
        i += 4
    tail = data[i:]
    if tail:
        h ^= int.from_bytes(tail, "little")
        h = (h * 0x5BD1E995) & MASK32
    h ^= h >> 13
    h = (h * 0x5BD1E995) & MASK32
    return (h ^ (h >> 15)) & MASK32


def murmur3_32(data, seed=0):
    h, i = seed & MASK32, 0
    while i + 4 <= len(data):
        k = int.from_bytes(data[i:i + 4], "little")
        k = _rot32((k * 0xCC9E2D51) & MASK32, 15)
        h ^= (k * 0x1B873593) & MASK32
        h = (_rot32(h, 13) * 5 + 0xE6546B64) & MASK32
        i += 4
    tail = int.from_bytes(data[i:], "little")
    if tail:
        h ^= (_rot32((tail * 0xCC9E2D51) & MASK32, 15) * 0x1B873593) & MASK32
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & MASK32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & MASK32
    return (h ^ (h >> 16)) & MASK32


def xx32(data, seed=0):
    p1, p2, p3, p4, p5 = 0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1
    def round_(acc, value):
        return (_rot32((acc + value * p2) & MASK32, 13) * p1) & MASK32
    i = 0
    if len(data) >= 16:
        v1, v2, v3, v4 = (seed + p1 + p2) & MASK32, (seed + p2) & MASK32, seed & MASK32, (seed - p1) & MASK32
        while i + 16 <= len(data):
            v1, v2 = round_(v1, int.from_bytes(data[i:i + 4], "little")), round_(v2, int.from_bytes(data[i + 4:i + 8], "little"))
            v3, v4 = round_(v3, int.from_bytes(data[i + 8:i + 12], "little")), round_(v4, int.from_bytes(data[i + 12:i + 16], "little"))
            i += 16
        h = (_rot32(v1, 1) + _rot32(v2, 7) + _rot32(v3, 12) + _rot32(v4, 18)) & MASK32
    else:
        h = (seed + p5) & MASK32
    h = (h + len(data)) & MASK32
    while i + 4 <= len(data):
        h = (_rot32((h + int.from_bytes(data[i:i + 4], "little") * p3) & MASK32, 17) * p4) & MASK32
        i += 4
    for byte in data[i:]:
        h = (_rot32((h + byte * p5) & MASK32, 11) * p1) & MASK32
    h ^= h >> 15
    h = (h * p2) & MASK32
    h ^= h >> 13
    h = (h * p3) & MASK32
    return (h ^ (h >> 16)) & MASK32


def xx64(data, seed=0):
    p1, p2, p3, p4, p5 = 0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9, 0x85EBCA77C2B2AE63, 0x27D4EB2F165667C5
    def round_(acc, value):
        return (_rot64((acc + value * p2) & MASK64, 31) * p1) & MASK64
    i = 0
    if len(data) >= 32:
        v1, v2, v3, v4 = (seed + p1 + p2) & MASK64, (seed + p2) & MASK64, seed & MASK64, (seed - p1) & MASK64
        while i + 32 <= len(data):
            v1, v2 = round_(v1, int.from_bytes(data[i:i + 8], "little")), round_(v2, int.from_bytes(data[i + 8:i + 16], "little"))
            v3, v4 = round_(v3, int.from_bytes(data[i + 16:i + 24], "little")), round_(v4, int.from_bytes(data[i + 24:i + 32], "little"))
            i += 32
        h = (_rot64(v1, 1) + _rot64(v2, 7) + _rot64(v3, 12) + _rot64(v4, 18)) & MASK64
        for value in (v1, v2, v3, v4):
            h = ((h ^ round_(0, value)) * p1 + p4) & MASK64
    else:
        h = (seed + p5) & MASK64
    h = (h + len(data)) & MASK64
    while i + 8 <= len(data):
        h = (_rot64(h ^ round_(0, int.from_bytes(data[i:i + 8], "little")), 27) * p1 + p4) & MASK64
        i += 8
    if i + 4 <= len(data):
        h = (_rot64((h ^ (int.from_bytes(data[i:i + 4], "little") * p1)) & MASK64, 23) * p2 + p3) & MASK64
        i += 4
    for byte in data[i:]:
        h = (_rot64((h ^ (byte * p5)) & MASK64, 11) * p1) & MASK64
    h ^= h >> 33
    h = (h * p2) & MASK64
    h ^= h >> 29
    h = (h * p3) & MASK64
    return (h ^ (h >> 32)) & MASK64
