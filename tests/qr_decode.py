"""A self-contained QR decoder, used only by the tests.

``utils.qr`` must produce a PNG that a phone can actually scan, and the only way
to assert that is to read the payload back out of the pixels. Every off-the-shelf
decoder was a bad trade for this repo: ``pyzbar`` is 32 KB of Python over a
``libzbar0`` shared library that CI would need a new apt step to install (the
workflow installs *only* ``pip install --require-hashes``), and
``opencv-python-headless`` is a 61 MB wheel to check one image. So the decode is
done here, from the spec.

This is a genuine independent decode, not a re-encode compared against itself:
it samples the module grid out of the PNG, reads the mask pattern from the format
information, unmasks, walks the two-column zigzag, de-interleaves the RS blocks
and parses the mode-segment chain. The only things borrowed from ``qrcode`` are
two static spec tables — alignment-pattern centres and the RS block structure —
which are constants of the standard, not encoding logic.

Error correction is deliberately NOT applied: the input is a freshly rendered
PNG with no damage, so a payload that needs correcting means the encoder is
broken and the test should fail rather than quietly repair it.
"""

from __future__ import annotations

import io

from PIL import Image
from qrcode.base import rs_blocks
from qrcode.util import pattern_position

_FORMAT_XOR = 0x5412
_ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

_MASKS = (
    lambda i, j: (i + j) % 2 == 0,
    lambda i, j: i % 2 == 0,
    lambda i, j: j % 3 == 0,
    lambda i, j: (i + j) % 3 == 0,
    lambda i, j: (i // 2 + j // 3) % 2 == 0,
    lambda i, j: (i * j) % 2 + (i * j) % 3 == 0,
    lambda i, j: ((i * j) % 2 + (i * j) % 3) % 2 == 0,
    lambda i, j: ((i + j) % 2 + (i * j) % 3) % 2 == 0,
)


def _count_bits(mode: int, version: int) -> int:
    tier = 0 if version <= 9 else (1 if version <= 26 else 2)
    return {
        0b0001: (10, 12, 14),
        0b0010: (9, 11, 13),
        0b0100: (8, 16, 16),
        0b1000: (8, 10, 12),
    }[mode][tier]


def _modules(png: bytes, box_size: int, border: int) -> list[list[bool]]:
    image = Image.open(io.BytesIO(png)).convert("L")
    width, height = image.size
    if width != height:
        raise ValueError(f"QR image is not square: {width}x{height}")
    size = width // box_size - 2 * border
    pixels = image.load()
    return [
        [
            pixels[(border + col) * box_size + box_size // 2, (border + row) * box_size + box_size // 2] < 128
            for col in range(size)
        ]
        for row in range(size)
    ]


def _function_modules(size: int, version: int) -> list[list[bool]]:
    reserved = [[False] * size for _ in range(size)]

    def fill(row0: int, col0: int, height: int, width: int) -> None:
        for row in range(max(0, row0), min(size, row0 + height)):
            for col in range(max(0, col0), min(size, col0 + width)):
                reserved[row][col] = True

    for row0, col0 in ((0, 0), (0, size - 8), (size - 8, 0)):
        fill(row0, col0, 8, 8)
    fill(6, 0, 1, size)
    fill(0, 6, size, 1)
    fill(8, 0, 1, 9)
    fill(0, 8, 9, 1)
    fill(8, size - 8, 1, 8)
    fill(size - 8, 8, 8, 1)
    centres = pattern_position(version)
    skip = {(6, 6), (6, size - 7), (size - 7, 6)}
    for row in centres:
        for col in centres:
            if (row, col) not in skip:
                fill(row - 2, col - 2, 5, 5)
    if version >= 7:
        fill(size - 11, 0, 3, 6)
        fill(0, size - 11, 6, 3)
    return reserved


def _mask_pattern(modules: list[list[bool]], size: int) -> int:
    bits = 0
    for i in range(8):
        if modules[8][size - 1 - i]:
            bits |= 1 << i
    for i in range(8, 15):
        if modules[size - 15 + i][8]:
            bits |= 1 << i
    return ((bits ^ _FORMAT_XOR) >> 10) & 0b111


def _data_bits(modules: list[list[bool]], reserved: list[list[bool]], size: int, mask: int) -> list[int]:
    unmask = _MASKS[mask]
    bits: list[int] = []
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        for i in range(size):
            row = size - 1 - i if upward else i
            for c in (col, col - 1):
                if not reserved[row][c]:
                    bit = modules[row][c]
                    bits.append(int(bit != unmask(row, c)))
        col -= 2
        upward = not upward
    return bits


def _data_codewords(bits: list[int], version: int, error_correction: int) -> bytes:
    codewords = [int("".join(map(str, bits[i : i + 8])), 2) for i in range(0, len(bits) - 7, 8)]
    counts = [block.data_count for block in rs_blocks(version, error_correction)]
    blocks: list[list[int]] = [[] for _ in counts]
    index = 0
    for i in range(max(counts)):
        for block, count in zip(blocks, counts, strict=True):
            if i < count:
                block.append(codewords[index])
                index += 1
    return bytes(byte for block in blocks for byte in block)


class _BitReader:
    def __init__(self, payload: bytes) -> None:
        self._bits = "".join(f"{byte:08b}" for byte in payload)
        self._at = 0

    def read(self, count: int) -> int:
        if self._at + count > len(self._bits):
            raise ValueError("QR bitstream ended mid-segment")
        chunk = self._bits[self._at : self._at + count]
        self._at += count
        return int(chunk, 2)

    @property
    def remaining(self) -> int:
        return len(self._bits) - self._at


def _segments(payload: bytes, version: int) -> bytes:
    """Read the mode-segment chain ``qrcode``'s optimizer emits."""
    reader = _BitReader(payload)
    out = bytearray()
    while reader.remaining >= 4:
        mode = reader.read(4)
        if mode == 0b0000:
            break
        count = reader.read(_count_bits(mode, version))
        if mode == 0b0100:
            out.extend(reader.read(8) for _ in range(count))
        elif mode == 0b0010:
            for _ in range(0, count - 1, 2):
                pair = reader.read(11)
                out.extend(f"{_ALNUM[pair // 45]}{_ALNUM[pair % 45]}".encode())
            if count % 2:
                out.extend(_ALNUM[reader.read(6)].encode())
        elif mode == 0b0001:
            for _ in range(0, count - 2, 3):
                out.extend(f"{reader.read(10):03d}".encode())
            rest = count % 3
            if rest == 2:
                out.extend(f"{reader.read(7):02d}".encode())
            elif rest == 1:
                out.extend(f"{reader.read(4):01d}".encode())
        else:
            raise ValueError(f"unsupported QR mode 0b{mode:04b}")
    return bytes(out)


def decode_qr(png: bytes, *, error_correction: int, box_size: int = 8, border: int = 4) -> str:
    modules = _modules(png, box_size, border)
    size = len(modules)
    if size % 4 != 1 or not 21 <= size <= 177:
        raise ValueError(f"not a QR module grid: {size}x{size}")
    version = (size - 17) // 4
    reserved = _function_modules(size, version)
    mask = _mask_pattern(modules, size)
    bits = _data_bits(modules, reserved, size, mask)
    payload = _data_codewords(bits, version, error_correction)
    return _segments(payload, version).decode("utf-8")
