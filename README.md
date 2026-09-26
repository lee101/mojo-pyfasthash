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
| fnv1_32 | 3.11 ms | 307.58 ms | 98.79x |
| fnv1a_32 | 2.93 ms | 299.24 ms | 102.17x |
| fnv1_64 | 3.29 ms | 317.99 ms | 96.76x |
| fnv1a_64 | 3.07 ms | 309.20 ms | 100.86x |
| murmur2_32 | 0.71 ms | 422.49 ms | 594.60x |
| murmur3_32 | 0.82 ms | 613.18 ms | 751.41x |
| xx_32 | 0.61 ms | 441.49 ms | 724.21x |
| xx_64 | 0.18 ms | 215.12 ms | 1220.50x |

For target selection, upstream `pyhash` 0.9.4 was also built from its current
source with its hash kernels unchanged and measured under the same lock. The
Python 3.13 build used a current pybind11 and disabled unrelated 128-bit
bindings. These results are best of seven calls on the same 2 MiB input:

| kernel | Mojo | upstream pyhash | Mojo / upstream |
|---|---:|---:|---:|
| fnv1_32 | 3.74 ms | 5.71 ms | 1.52x |
| fnv1a_32 | 3.07 ms | 4.71 ms | 1.53x |
| fnv1_64 | 2.78 ms | 5.26 ms | 1.89x |
| fnv1a_64 | 2.92 ms | 5.17 ms | 1.77x |
| murmur2_32 | 0.72 ms | 0.77 ms | 1.08x |
| murmur3_32 | 0.76 ms | 0.88 ms | 1.15x |
| xx_32 | 0.66 ms | 0.33 ms | 0.50x |
| xx_64 | 0.19 ms | 0.17 ms | 0.87x |

The original long-input XXH32 path included XXH64-style merge rounds and did
not match upstream. Removing them restores parity; the table reports the
corrected kernel rather than the faster wrong result. Mojo lowers the four
XXH32 recurrence lanes to packed SIMD on this AVX2 host. A hand-written Mojo
SIMD version was measured and removed because it was slower. XXH32 is the only
kernel here with independent work to spare: its four recurrence lanes, about one
multiply and one rotate per 4 bytes loaded, are interleaved onto a single core.
That is roughly one operation per byte, below the roughly two per byte where
splitting across threads can pay, so the 32 MiB threshold and the separate
four-lane implementation that fed it are gone. `xx_32` now always runs the
interleaved kernel, which reads the input once in order instead of four times
with a stride of 16 bytes. It sustains 2.8 Gop/s from 1 MiB to 64 MiB and runs
32 MiB in 11.91 ms, which is the same figure the removed eight-worker path was
credited with, so the split was not buying anything. The two implementations
are byte-for-byte identical on every input the test suite covers, including its
32 MiB case that used to take the removed path.

Run the benchmark through Pixi only: its task takes a machine-wide lock so
other repository jobs cannot distort the measurements.

GPU execution is intentionally not provided. These kernels perform only a few
integer operations per 4 or 8 bytes loaded, below the arithmetic-intensity
threshold where device transfer can pay off. Most also have an ordered
accumulator dependency, so only XXH32's four lanes are independent and they are
already interleaved on one core.

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
