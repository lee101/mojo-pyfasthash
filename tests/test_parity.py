import os

import numpy as np
import pytest

import pyhash
from pyhash._lib import _ReadonlyBuffer, byte_address
from reference import fnv, murmur2_32, murmur3_32, xx32, xx64


UPSTREAM_TEST_VECTORS = {
    "fnv1_32": (3698262380, 660137056, 3910690890),
    "fnv1a_32": (1858026756, 1357873952, 996945022),
    "fnv1_64": (17151984479173897804, 6349570372626520864, 14017453969697934794),
    "fnv1a_64": (11830222609977404196, 8858165303110309728, 14494269412771327550),
    "murmur2_32": (403862830, 1257009171, 2308212514),
    "murmur3_32": (3127628307, 1973649836, 1351191292),
    "xx_32": (1042293711, 1018767936, 2783988247),
    "xx_64": (5754696928334414137, 12934826212537126916, 16125048496228390453),
}


@pytest.mark.parametrize("name, expected", UPSTREAM_TEST_VECTORS.items())
def test_upstream_pyhash_test_vectors(name, expected):
    hasher = getattr(pyhash, name)()
    byte_hash, seeded_hash, unicode_hash = expected
    assert hasher(b"test") == byte_hash
    assert hasher(b"test", seed=byte_hash) == seeded_hash
    assert hasher(b"test", b"test") == seeded_hash
    assert hasher("test") == unicode_hash


REFERENCE = {
    "fnv1_32": lambda data, seed: fnv(data, seed, 32),
    "fnv1a_32": lambda data, seed: fnv(data, seed, 32, alternate=True),
    "fnv1_64": lambda data, seed: fnv(data, seed, 64),
    "fnv1a_64": lambda data, seed: fnv(data, seed, 64, alternate=True),
    "murmur2_32": murmur2_32,
    "murmur3_32": murmur3_32,
    "xx_32": xx32,
    "xx_64": xx64,
}


@pytest.mark.parametrize("name", REFERENCE)
def test_random_binary_inputs_match_pure_python_reference(name):
    hasher, reference = getattr(pyhash, name)(), REFERENCE[name]
    mask = (1 << hasher._bits) - 1
    for n in range(65):
        data = os.urandom(n)
        seed = int.from_bytes(os.urandom(8), "little") & mask
        assert hasher(data, seed=seed) == reference(data, seed)


def test_seed_attribute_and_memoryview_inputs():
    h = pyhash.xx_64(7)
    data = bytearray(range(32))
    assert h(memoryview(data)) == xx64(bytes(data), 7)
    h.seed = 11
    assert h(data) == xx64(bytes(data), 11)


def test_seed_requires_an_integer_without_silent_narrowing():
    with pytest.raises(TypeError):
        pyhash.xx_64(1.5)
    with pytest.raises(TypeError):
        pyhash.xx_64()(b"data", seed=1.5)


def test_contiguous_non_byte_dtype_hashes_its_complete_raw_buffer():
    data = np.array([0x1020, 0x3040, 0x5060], dtype=np.uint16)
    assert pyhash.xx_64()(data) == xx64(data.tobytes())


def test_empty_and_non_contiguous_input_behaviour():
    assert pyhash.murmur3_32()(b"") == murmur3_32(b"")
    with pytest.raises(ValueError, match="contiguous"):
        pyhash.xx_32()(memoryview(bytearray(range(8)))[::2])


def test_readonly_numpy_input_stays_zero_copy():
    data = np.arange(257, dtype=np.uint8)
    data.setflags(write=False)
    address, nbytes, owner = byte_address(data)
    try:
        assert address == data.ctypes.data
        assert nbytes == data.nbytes
    finally:
        if isinstance(owner, _ReadonlyBuffer):
            owner.close()
    assert pyhash.xx_64()(data) == xx64(data.tobytes())


@pytest.mark.parametrize("name", ("murmur2_32", "murmur3_32"))
@pytest.mark.parametrize("tail", range(4))
def test_staged_murmur_blocks_match_reference_at_tails(name, tail):
    data = bytes(range(256)) * 16 + bytes(range(tail))
    seed = 0x12345678
    assert getattr(pyhash, name)(seed)(data) == REFERENCE[name](data, seed)


@pytest.mark.parametrize("name", ("murmur2_32", "murmur3_32", "xx_32", "xx_64"))
@pytest.mark.parametrize("length", (15, 16, 17, 31, 32, 33, 63, 64, 65))
def test_word_loop_boundaries_and_unaligned_tails(name, length):
    backing = bytearray(range(length + 1))
    data = memoryview(backing)[1:]
    seed = 0x12345678
    assert getattr(pyhash, name)(seed)(data) == REFERENCE[name](data, seed)


@pytest.mark.parametrize(
    "length, expected",
    (
        (15, 1070822502),
        (16, 2672565993),
        (17, 3096662848),
        (31, 4097334608),
        (32, 3183402826),
        (33, 3789564615),
        (63, 1473379930),
        (64, 1662533714),
        (65, 2194161156),
    ),
)
def test_xx32_long_input_matches_upstream(length, expected):
    assert pyhash.xx_32(0x12345678)(bytes(range(length))) == expected


def test_xx32_large_input_matches_upstream():
    data = bytes(range(256)) * (32 * 4096)
    assert pyhash.xx_32(0x12345678)(data) == 4095641633


def test_public_api_contains_only_implemented_hashers():
    assert set(pyhash.__hasher__) == set(REFERENCE)
    assert pyhash.build_with_int128 is False
