# mojo-pyfasthash

`mojo-pyfasthash` is a standalone Mojo port of the compute-bound, fixed-width
hashes exposed by Flier Lu's `pyfasthash` project (published on PyPI as
[`pyhash`](https://pypi.org/project/pyhash/)). It provides a drop-in `pyhash`
module for the covered subset. These are fast non-cryptographic hashes: do not
use them for passwords, signatures, or adversarial inputs.

## Covered API

The constructors, `seed` attribute, `__call__(*buffers, seed=...)`, binary
buffer support, and Python `str` handling match upstream for these algorithms:

- `fnv1_32`, `fnv1a_32`, `fnv1_64`, `fnv1a_64`
- `murmur2_32`, `murmur3_32`
- `xx_32`, `xx_64`

The wider upstream catalogue is deliberately not represented: CityHash,
FarmHash, MetroHash, SpookyHash, lookup3, SuperFastHash, T1HA, wyhash,
MumHash, HighwayHash, XXH3, and all 128-bit/256-bit return types are not yet
covered. `build_with_int128` is therefore `False`.

The original project is called `pyhash` on PyPI, not `pyfasthash`. Tests use
its published test vectors plus independent pure-Python reference
implementations over randomized inputs.

## Install and use

```bash
pixi install
pixi run build
pixi run python -c 'import pyhash; print(pyhash.xx_64()(b"hello world"))'
```

```python
import pyhash

hasher = pyhash.murmur3_32()
digest = hasher(b"first chunk", b"second chunk")
assert digest == hasher(b"second chunk", seed=hasher(b"first chunk"))
print(digest)
```

The package lives at `python/pyhash`; Pixi adds `python/` to `PYTHONPATH`.
For deployment, point `MOJO_PYFASTHASH_LIB` at a prebuilt shared library to
disable import-time rebuilding. Contiguous buffer-protocol inputs are hashed
as their complete raw byte representation; non-contiguous inputs are rejected.

## Benchmark

Measured with `pixi run bench` on this machine. Results are best of three runs
on one deterministic byte buffer. The reference is the portable pure-Python
implementation used by the parity suite; these are not claims against upstream
`pyhash`.

| kernel | Mojo | pure Python reference | speedup |
|---|---:|---:|---:|
| fnv1_32 | 2.95 ms | 302.23 ms | 102.48x |
| fnv1a_32 | 3.05 ms | 303.05 ms | 99.27x |
| fnv1_64 | 3.11 ms | 328.25 ms | 105.67x |
| fnv1a_64 | 3.04 ms | 330.94 ms | 108.71x |
| murmur2_32 | 0.76 ms | 447.13 ms | 586.92x |
| murmur3_32 | 0.97 ms | 629.54 ms | 650.91x |
| xx_32 | 0.39 ms | 441.08 ms | 1120.01x |
| xx_64 | 0.20 ms | 228.06 ms | 1166.75x |

Run the benchmark through Pixi only: its task takes a machine-wide lock so
other repository jobs cannot distort the measurements.

GPU execution is intentionally not provided. Each supported API call produces
one ordered digest, so its accumulator dependency prevents useful data-parallel
work; host-device transfer and reduction would lose to the CPU kernels.

## How it works

All kernels are in one Mojo compilation unit, compiled with `mojo build --emit
shared-lib` into `dist/libmojo-pyfasthash.so`. ctypes sends each input as an
address plus byte count; the Mojo C ABI rebuilds an `UnsafePointer[UInt8,
AnyOrigin[mut=True]]` internally. A caller-owned `uint64` output slot avoids
signed 64-bit return-value ambiguity. Buffer exporters are retained for the
whole native call, so their data remains valid while Mojo reads it.
`str` values are encoded as UTF-16 little-endian before crossing FFI, matching
the upstream Python 3 representation.

## Development

```bash
pixi run build && pixi run test && pixi run bench
```
