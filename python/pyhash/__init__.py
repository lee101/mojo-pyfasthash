"""A Mojo implementation of pyfasthash's most-used non-cryptographic hashes."""

from __future__ import annotations

import operator

from ._lib import build, hash_bytes

__version__ = "0.1.0"
build_with_int128 = False


class _Hasher:
    _symbol = ""
    _bits = 64

    def __init__(self, seed: int = 0):
        self.seed = operator.index(seed) & ((1 << self._bits) - 1)

    def __call__(self, *args: object, seed: int | None = None) -> int:
        if not args:
            raise TypeError("missed self argument")
        value = self.seed if seed is None else operator.index(seed) & ((1 << self._bits) - 1)
        for arg in args:
            value = hash_bytes(self._symbol, arg, value)
        return value & ((1 << self._bits) - 1)


class fnv1_32(_Hasher):
    _symbol, _bits = "mph_fnv1_32", 32


class fnv1a_32(_Hasher):
    _symbol, _bits = "mph_fnv1a_32", 32


class fnv1_64(_Hasher):
    _symbol, _bits = "mph_fnv1_64", 64


class fnv1a_64(_Hasher):
    _symbol, _bits = "mph_fnv1a_64", 64


class murmur2_32(_Hasher):
    _symbol, _bits = "mph_murmur2_32", 32


class murmur3_32(_Hasher):
    _symbol, _bits = "mph_murmur3_32", 32


class xx_32(_Hasher):
    _symbol, _bits = "mph_xx_32", 32


class xx_64(_Hasher):
    _symbol, _bits = "mph_xx_64", 64


__hasher__ = {
    cls.__name__: cls
    for cls in (fnv1_32, fnv1a_32, fnv1_64, fnv1a_64, murmur2_32, murmur3_32, xx_32, xx_64)
}

__all__ = ["build", "build_with_int128", "__hasher__", *__hasher__]
