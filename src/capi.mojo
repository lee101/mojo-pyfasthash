"""Non-cryptographic byte hashes exposed through a small C ABI."""

comptime BytePtr = UnsafePointer[UInt8, AnyOrigin[mut=True]]
comptime U64Ptr = UnsafePointer[UInt64, AnyOrigin[mut=True]]


def bytes_at(addr: Int) -> BytePtr:
    return BytePtr(unsafe_from_address=addr)


def output_at(addr: Int) -> U64Ptr:
    return U64Ptr(unsafe_from_address=addr)


def read32(p: BytePtr, i: Int) -> UInt32:
    return UInt32(p[i]) | (UInt32(p[i + 1]) << 8) | (UInt32(p[i + 2]) << 16) | (UInt32(p[i + 3]) << 24)


def read64(p: BytePtr, i: Int) -> UInt64:
    return UInt64(p[i]) | (UInt64(p[i + 1]) << 8) | (UInt64(p[i + 2]) << 16) | (UInt64(p[i + 3]) << 24) | (UInt64(p[i + 4]) << 32) | (UInt64(p[i + 5]) << 40) | (UInt64(p[i + 6]) << 48) | (UInt64(p[i + 7]) << 56)


def rotl32(x: UInt32, n: Int) -> UInt32:
    return (x << UInt32(n)) | (x >> UInt32(32 - n))


def rotl64(x: UInt64, n: Int) -> UInt64:
    return (x << UInt64(n)) | (x >> UInt64(64 - n))


def fnv1_32_impl(p: BytePtr, n: Int, seed: UInt32) -> UInt32:
    var h = seed
    var i = 0
    while i < n:
        h = (h * UInt32(16777619)) ^ UInt32(p[i])
        i += 1
    return h


def fnv1a_32_impl(p: BytePtr, n: Int, seed: UInt32) -> UInt32:
    var h = seed
    var i = 0
    while i < n:
        h = (h ^ UInt32(p[i])) * UInt32(16777619)
        i += 1
    return h


def fnv1_64_impl(p: BytePtr, n: Int, seed: UInt64) -> UInt64:
    var h = seed
    var i = 0
    while i < n:
        h = (h * UInt64(1099511628211)) ^ UInt64(p[i])
        i += 1
    return h


def fnv1a_64_impl(p: BytePtr, n: Int, seed: UInt64) -> UInt64:
    var h = seed
    var i = 0
    while i < n:
        h = (h ^ UInt64(p[i])) * UInt64(1099511628211)
        i += 1
    return h


def murmur2_32_impl(p: BytePtr, n: Int, seed: UInt32) -> UInt32:
    var h = seed ^ UInt32(n)
    var i = 0
    while i + 16 <= n:
        var k0 = read32(p, i)
        var k1 = read32(p, i + 4)
        var k2 = read32(p, i + 8)
        var k3 = read32(p, i + 12)
        k0 *= UInt32(0x5BD1E995)
        k1 *= UInt32(0x5BD1E995)
        k2 *= UInt32(0x5BD1E995)
        k3 *= UInt32(0x5BD1E995)
        k0 ^= k0 >> 24
        k1 ^= k1 >> 24
        k2 ^= k2 >> 24
        k3 ^= k3 >> 24
        k0 *= UInt32(0x5BD1E995)
        k1 *= UInt32(0x5BD1E995)
        k2 *= UInt32(0x5BD1E995)
        k3 *= UInt32(0x5BD1E995)
        h = h * UInt32(0x5BD1E995) ^ k0
        h = h * UInt32(0x5BD1E995) ^ k1
        h = h * UInt32(0x5BD1E995) ^ k2
        h = h * UInt32(0x5BD1E995) ^ k3
        i += 16
    while i + 4 <= n:
        var k = read32(p, i)
        k *= UInt32(0x5BD1E995)
        k ^= k >> 24
        k *= UInt32(0x5BD1E995)
        h *= UInt32(0x5BD1E995)
        h ^= k
        i += 4
    if n - i == 3:
        h ^= UInt32(p[i + 2]) << 16
        h ^= UInt32(p[i + 1]) << 8
        h ^= UInt32(p[i])
        h *= UInt32(0x5BD1E995)
    elif n - i == 2:
        h ^= UInt32(p[i + 1]) << 8
        h ^= UInt32(p[i])
        h *= UInt32(0x5BD1E995)
    elif n - i == 1:
        h ^= UInt32(p[i])
        h *= UInt32(0x5BD1E995)
    h ^= h >> 13
    h *= UInt32(0x5BD1E995)
    h ^= h >> 15
    return h


def murmur3_32_impl(p: BytePtr, n: Int, seed: UInt32) -> UInt32:
    var h = seed
    var i = 0
    while i + 16 <= n:
        var k0 = read32(p, i)
        var k1 = read32(p, i + 4)
        var k2 = read32(p, i + 8)
        var k3 = read32(p, i + 12)
        k0 *= UInt32(0xCC9E2D51)
        k1 *= UInt32(0xCC9E2D51)
        k2 *= UInt32(0xCC9E2D51)
        k3 *= UInt32(0xCC9E2D51)
        k0 = rotl32(k0, 15)
        k1 = rotl32(k1, 15)
        k2 = rotl32(k2, 15)
        k3 = rotl32(k3, 15)
        k0 *= UInt32(0x1B873593)
        k1 *= UInt32(0x1B873593)
        k2 *= UInt32(0x1B873593)
        k3 *= UInt32(0x1B873593)
        h ^= k0
        h = rotl32(h, 13) * UInt32(5) + UInt32(0xE6546B64)
        h ^= k1
        h = rotl32(h, 13) * UInt32(5) + UInt32(0xE6546B64)
        h ^= k2
        h = rotl32(h, 13) * UInt32(5) + UInt32(0xE6546B64)
        h ^= k3
        h = rotl32(h, 13) * UInt32(5) + UInt32(0xE6546B64)
        i += 16
    while i + 4 <= n:
        var k = read32(p, i)
        k *= UInt32(0xCC9E2D51)
        k = rotl32(k, 15)
        k *= UInt32(0x1B873593)
        h ^= k
        h = rotl32(h, 13)
        h = h * UInt32(5) + UInt32(0xE6546B64)
        i += 4
    var tail = UInt32(0)
    if n - i == 3:
        tail ^= UInt32(p[i + 2]) << 16
        tail ^= UInt32(p[i + 1]) << 8
        tail ^= UInt32(p[i])
    elif n - i == 2:
        tail ^= UInt32(p[i + 1]) << 8
        tail ^= UInt32(p[i])
    elif n - i == 1:
        tail ^= UInt32(p[i])
    if n - i != 0:
        tail *= UInt32(0xCC9E2D51)
        tail = rotl32(tail, 15)
        tail *= UInt32(0x1B873593)
        h ^= tail
    h ^= UInt32(n)
    h ^= h >> 16
    h *= UInt32(0x85EBCA6B)
    h ^= h >> 13
    h *= UInt32(0xC2B2AE35)
    h ^= h >> 16
    return h


def xx32_round(acc: UInt32, input: UInt32) -> UInt32:
    var v = acc + input * UInt32(0x85EBCA77)
    v = rotl32(v, 13)
    return v * UInt32(0x9E3779B1)


def xx32_merge(acc: UInt32, val: UInt32) -> UInt32:
    var h = acc ^ xx32_round(UInt32(0), val)
    return h * UInt32(0x9E3779B1) + UInt32(0x27D4EB2F)


def xx32_impl(p: BytePtr, n: Int, seed: UInt32) -> UInt32:
    var i = 0
    var h: UInt32
    if n >= 16:
        var v1 = seed + UInt32(0x9E3779B1) + UInt32(0x85EBCA77)
        var v2 = seed + UInt32(0x85EBCA77)
        var v3 = seed
        var v4 = seed - UInt32(0x9E3779B1)
        while i + 16 <= n:
            v1 = xx32_round(v1, read32(p, i))
            v2 = xx32_round(v2, read32(p, i + 4))
            v3 = xx32_round(v3, read32(p, i + 8))
            v4 = xx32_round(v4, read32(p, i + 12))
            i += 16
        h = rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18)
        h = xx32_merge(h, v1)
        h = xx32_merge(h, v2)
        h = xx32_merge(h, v3)
        h = xx32_merge(h, v4)
    else:
        h = seed + UInt32(0x165667B1)
    h += UInt32(n)
    while i + 4 <= n:
        h += read32(p, i) * UInt32(0xC2B2AE3D)
        h = rotl32(h, 17) * UInt32(0x27D4EB2F)
        i += 4
    while i < n:
        h += UInt32(p[i]) * UInt32(0x165667B1)
        h = rotl32(h, 11) * UInt32(0x9E3779B1)
        i += 1
    h ^= h >> 15
    h *= UInt32(0x85EBCA77)
    h ^= h >> 13
    h *= UInt32(0xC2B2AE3D)
    h ^= h >> 16
    return h


def xx64_round(acc: UInt64, input: UInt64) -> UInt64:
    var v = acc + input * UInt64(0xC2B2AE3D27D4EB4F)
    v = rotl64(v, 31)
    return v * UInt64(0x9E3779B185EBCA87)


def xx64_merge(acc: UInt64, val: UInt64) -> UInt64:
    var h = acc ^ xx64_round(UInt64(0), val)
    return h * UInt64(0x9E3779B185EBCA87) + UInt64(0x85EBCA77C2B2AE63)


def xx64_impl(p: BytePtr, n: Int, seed: UInt64) -> UInt64:
    var i = 0
    var h: UInt64
    if n >= 32:
        var v1 = seed + UInt64(0x9E3779B185EBCA87) + UInt64(0xC2B2AE3D27D4EB4F)
        var v2 = seed + UInt64(0xC2B2AE3D27D4EB4F)
        var v3 = seed
        var v4 = seed - UInt64(0x9E3779B185EBCA87)
        while i + 32 <= n:
            v1 = xx64_round(v1, read64(p, i))
            v2 = xx64_round(v2, read64(p, i + 8))
            v3 = xx64_round(v3, read64(p, i + 16))
            v4 = xx64_round(v4, read64(p, i + 24))
            i += 32
        h = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18)
        h = xx64_merge(h, v1)
        h = xx64_merge(h, v2)
        h = xx64_merge(h, v3)
        h = xx64_merge(h, v4)
    else:
        h = seed + UInt64(0x27D4EB2F165667C5)
    h += UInt64(n)
    while i + 8 <= n:
        var k = xx64_round(UInt64(0), read64(p, i))
        h ^= k
        h = rotl64(h, 27) * UInt64(0x9E3779B185EBCA87) + UInt64(0x85EBCA77C2B2AE63)
        i += 8
    if i + 4 <= n:
        h ^= UInt64(read32(p, i)) * UInt64(0x9E3779B185EBCA87)
        h = rotl64(h, 23) * UInt64(0xC2B2AE3D27D4EB4F) + UInt64(0x165667B19E3779F9)
        i += 4
    while i < n:
        h ^= UInt64(p[i]) * UInt64(0x27D4EB2F165667C5)
        h = rotl64(h, 11) * UInt64(0x9E3779B185EBCA87)
        i += 1
    h ^= h >> 33
    h *= UInt64(0xC2B2AE3D27D4EB4F)
    h ^= h >> 29
    h *= UInt64(0x165667B19E3779F9)
    h ^= h >> 32
    return h


@export("mph_fnv1_32")
def mph_fnv1_32(addr: Int, n: Int, seed: Int, result: Int) abi("C"):
    output_at(result)[0] = UInt64(fnv1_32_impl(bytes_at(addr), n, UInt32(seed)))


@export("mph_fnv1a_32")
def mph_fnv1a_32(addr: Int, n: Int, seed: Int, result: Int) abi("C"):
    output_at(result)[0] = UInt64(fnv1a_32_impl(bytes_at(addr), n, UInt32(seed)))


@export("mph_fnv1_64")
def mph_fnv1_64(addr: Int, n: Int, seed: Int, result: Int) abi("C"):
    output_at(result)[0] = fnv1_64_impl(bytes_at(addr), n, UInt64(seed))


@export("mph_fnv1a_64")
def mph_fnv1a_64(addr: Int, n: Int, seed: Int, result: Int) abi("C"):
    output_at(result)[0] = fnv1a_64_impl(bytes_at(addr), n, UInt64(seed))


@export("mph_murmur2_32")
def mph_murmur2_32(addr: Int, n: Int, seed: Int, result: Int) abi("C"):
    output_at(result)[0] = UInt64(murmur2_32_impl(bytes_at(addr), n, UInt32(seed)))


@export("mph_murmur3_32")
def mph_murmur3_32(addr: Int, n: Int, seed: Int, result: Int) abi("C"):
    output_at(result)[0] = UInt64(murmur3_32_impl(bytes_at(addr), n, UInt32(seed)))


@export("mph_xx_32")
def mph_xx_32(addr: Int, n: Int, seed: Int, result: Int) abi("C"):
    output_at(result)[0] = UInt64(xx32_impl(bytes_at(addr), n, UInt32(seed)))


@export("mph_xx_64")
def mph_xx_64(addr: Int, n: Int, seed: Int, result: Int) abi("C"):
    output_at(result)[0] = xx64_impl(bytes_at(addr), n, UInt64(seed))
