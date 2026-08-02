"""ctypes access to the Mojo hashing kernels."""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "src")
LIB = os.environ.get("MOJO_PYFASTHASH_LIB") or os.path.join(
    ROOT, "dist", "libmojo-pyfasthash.so"
)

# The Mojo ABI uses `Int` here, which is a signed pointer-width integer on the
# supported 64-bit target.  Keep pointer, length, and output arguments typed
# distinctly so ctypes cannot narrow a length or output address implicitly.
I = ctypes.c_int64
P = ctypes.c_void_p
N = ctypes.c_ssize_t


class _PyBuffer(ctypes.Structure):
    _fields_ = [
        ("buf", ctypes.c_void_p),
        ("obj", ctypes.c_void_p),
        ("len", ctypes.c_ssize_t),
        ("itemsize", ctypes.c_ssize_t),
        ("readonly", ctypes.c_int),
        ("ndim", ctypes.c_int),
        ("format", ctypes.c_char_p),
        ("shape", ctypes.POINTER(ctypes.c_ssize_t)),
        ("strides", ctypes.POINTER(ctypes.c_ssize_t)),
        ("suboffsets", ctypes.POINTER(ctypes.c_ssize_t)),
        ("internal", ctypes.c_void_p),
    ]


_PyObject_GetBuffer = ctypes.pythonapi.PyObject_GetBuffer
_PyObject_GetBuffer.argtypes = (ctypes.py_object, ctypes.POINTER(_PyBuffer), ctypes.c_int)
_PyObject_GetBuffer.restype = ctypes.c_int
_PyBuffer_Release = ctypes.pythonapi.PyBuffer_Release
_PyBuffer_Release.argtypes = (ctypes.POINTER(_PyBuffer),)
_PyBuffer_Release.restype = None


class _ReadonlyBuffer:
    def __init__(self, view: memoryview):
        self.view = view
        self.export = _PyBuffer()
        _PyObject_GetBuffer(view, ctypes.byref(self.export), 0)

    def close(self) -> None:
        if self.export.obj:
            _PyBuffer_Release(ctypes.byref(self.export))
            self.export.obj = None


_SIGNATURES = {
    "mph_fnv1_32": ([P, N, I, P], None),
    "mph_fnv1a_32": ([P, N, I, P], None),
    "mph_fnv1_64": ([P, N, I, P], None),
    "mph_fnv1a_64": ([P, N, I, P], None),
    "mph_murmur2_32": ([P, N, I, P], None),
    "mph_murmur3_32": ([P, N, I, P], None),
    "mph_xx_32": ([P, N, I, P], None),
    "mph_xx_64": ([P, N, I, P], None),
}


class BuildError(RuntimeError):
    pass


def _mojo_command() -> list[str]:
    override = os.environ.get("MOJO_PYFASTHASH_MOJO")
    if override:
        return override.split()
    found = shutil.which("mojo")
    if found:
        return [found]
    pixi = shutil.which("pixi") or os.path.expanduser("~/.pixi/bin/pixi")
    if os.path.exists(pixi):
        return [pixi, "run", "--manifest-path", os.path.join(ROOT, "pixi.toml"), "mojo"]
    raise BuildError("mojo not found; set MOJO_PYFASTHASH_MOJO=/path/to/mojo")


def build(force: bool = False) -> str:
    """Compile the shared library when it is missing or stale."""
    if os.environ.get("MOJO_PYFASTHASH_LIB") and os.path.exists(LIB) and not force:
        return LIB
    sources = [
        os.path.join(path, name)
        for path, _, names in os.walk(SRC)
        for name in names
        if name.endswith(".mojo")
    ]
    if not force and os.path.exists(LIB):
        if os.path.getmtime(LIB) >= max(map(os.path.getmtime, sources)):
            return LIB
    os.makedirs(os.path.dirname(LIB), exist_ok=True)
    proc = subprocess.run(
        _mojo_command() + ["build", "--emit", "shared-lib", os.path.join(SRC, "capi.mojo"), "-o", LIB],
        capture_output=True,
        text=True,
        timeout=1800,
    )
    if proc.returncode or not os.path.exists(LIB):
        raise BuildError((proc.stderr or proc.stdout).strip()[:4000])
    return LIB


_library: ctypes.CDLL | None = None


def lib() -> ctypes.CDLL:
    global _library
    if _library is None:
        _library = ctypes.CDLL(build())
        for name, (argtypes, restype) in _SIGNATURES.items():
            fn = getattr(_library, name)
            fn.argtypes = argtypes
            fn.restype = restype
    return _library


def byte_address(value: object) -> tuple[int, int, object]:
    """Return a byte address, size, and owner that keeps the input alive."""
    if isinstance(value, str):
        value = value.encode("utf-16-le")
    if isinstance(value, bytes):
        if not value:
            holder = ctypes.c_ubyte(0)
            return ctypes.addressof(holder), 0, holder
        holder = ctypes.c_char_p(value)
        return ctypes.cast(holder, ctypes.c_void_p).value, len(value), holder
    try:
        view = memoryview(value)
    except TypeError as exc:
        raise TypeError("unsupported argument type") from exc
    if not view.c_contiguous:
        raise ValueError("only support contiguous buffer")
    if not view.nbytes:
        holder = ctypes.c_ubyte(0)
        return ctypes.addressof(holder), 0, holder
    if view.readonly:
        holder = _ReadonlyBuffer(view)
        return holder.export.buf, view.nbytes, holder
    holder = ctypes.c_ubyte.from_buffer(view)
    return ctypes.addressof(holder), view.nbytes, (view, holder)


def hash_bytes(symbol: str, value: object, seed: int) -> int:
    address, nbytes, owner = byte_address(value)
    result = ctypes.c_uint64()
    lib_fn = getattr(lib(), symbol)
    try:
        lib_fn(address, nbytes, ctypes.c_int64(seed).value, ctypes.addressof(result))
    finally:
        if isinstance(owner, _ReadonlyBuffer):
            owner.close()
    return result.value
