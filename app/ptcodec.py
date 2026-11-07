#!/usr/bin/env python3
"""
ptcodec — расшифровка / зашифровка файлов Cisco Packet Tracer (.pkt, .pka, .pkz).

Формат (PT 7+), по реверсу проекта pka2xml:
  файл = obf1( TwofishEAX( obf2( size_be32 + zlib(xml) ) ) )
  obf1: reverse + XOR (len - i*len)
  obf2: XOR (len - i)
  Twofish-EAX: key = 0x89*16, nonce = 0x10*16, tag 16 байт в конце.
Старый формат (PT 5.x): obf2 + zlib, без шифрования.
.pkz — zip-архив, внутри .pkt/.pka (+ вложения).

Без внешних зависимостей: Twofish и EAX реализованы здесь.

Использование:
  ptcodec.py decode  input.pkt  output.xml
  ptcodec.py encode  input.xml  output.pkt
  ptcodec.py info    input.pkt
  ptcodec.py selftest
"""
import struct
import sys
import zipfile
import zlib
import io

# ----------------------------------------------------------------- Twofish ---

_Q0T = [
    [0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4],
    [0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD],
    [0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1],
    [0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA],
]
_Q1T = [
    [0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5],
    [0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8],
    [0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF],
    [0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA],
]


def _ror4(x, n):
    return ((x >> n) | (x << (4 - n))) & 0xF


def _qperm(t, x):
    a0, b0 = x >> 4, x & 0xF
    a1 = a0 ^ b0
    b1 = a0 ^ _ror4(b0, 1) ^ ((8 * a0) & 0xF)
    a2, b2 = t[0][a1], t[1][b1]
    a3 = a2 ^ b2
    b3 = a2 ^ _ror4(b2, 1) ^ ((8 * a2) & 0xF)
    a4, b4 = t[2][a3], t[3][b3]
    return (b4 << 4) | a4


Q0 = [_qperm(_Q0T, x) for x in range(256)]
Q1 = [_qperm(_Q1T, x) for x in range(256)]


def _gfmul(a, b, poly):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return r


_MDS = [[0x01, 0xEF, 0x5B, 0x5B],
        [0x5B, 0xEF, 0xEF, 0x01],
        [0xEF, 0x5B, 0x01, 0xEF],
        [0xEF, 0x01, 0xEF, 0x5B]]
_RS = [[0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
       [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
       [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
       [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03]]
M32 = 0xFFFFFFFF


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def _ror(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def _mds_col(j, b):
    """Вклад байта b в столбец j матрицы MDS -> 32-битное слово (little-endian)."""
    w = 0
    for i in range(4):
        w |= _gfmul(_MDS[i][j], b, 0x169) << (8 * i)
    return w


_MDSTAB = [[_mds_col(j, b) for b in range(256)] for j in range(4)]



def _sbox_bytes(b, L):
    """Ключезависимые S-боксы h-функции (без MDS). L — список k слов."""
    k = len(L)
    lb = [[(w >> (8 * i)) & 0xFF for i in range(4)] for w in L]
    y = list(b)
    if k == 4:
        y[0] = Q1[y[0]] ^ lb[3][0]
        y[1] = Q0[y[1]] ^ lb[3][1]
        y[2] = Q0[y[2]] ^ lb[3][2]
        y[3] = Q1[y[3]] ^ lb[3][3]
    if k >= 3:
        y[0] = Q1[y[0]] ^ lb[2][0]
        y[1] = Q1[y[1]] ^ lb[2][1]
        y[2] = Q0[y[2]] ^ lb[2][2]
        y[3] = Q0[y[3]] ^ lb[2][3]
    y[0] = Q1[Q0[Q0[y[0]] ^ lb[1][0]] ^ lb[0][0]]
    y[1] = Q0[Q0[Q1[y[1]] ^ lb[1][1]] ^ lb[0][1]]
    y[2] = Q1[Q1[Q0[y[2]] ^ lb[1][2]] ^ lb[0][2]]
    y[3] = Q0[Q1[Q1[y[3]] ^ lb[1][3]] ^ lb[0][3]]
    return y


def _h(x, L):
    y = _sbox_bytes([(x >> (8 * i)) & 0xFF for i in range(4)], L)
    return (_MDSTAB[0][y[0]] ^ _MDSTAB[1][y[1]] ^
            _MDSTAB[2][y[2]] ^ _MDSTAB[3][y[3]])


class Twofish:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("bad key length")
        k = len(key) // 8
        words = struct.unpack("<%dI" % (2 * k), key)
        me, mo = list(words[0::2]), list(words[1::2])
        s = []
        for i in range(k):
            chunk = key[8 * i:8 * i + 8]
            w = 0
            for r in range(4):
                v = 0
                for c in range(8):
                    v ^= _gfmul(_RS[r][c], chunk[c], 0x14D)
                w |= v << (8 * r)
            s.append(w)
        s = s[::-1]  # S = (S_{k-1}, ..., S_0)
        rho = 0x01010101
        self.K = []
        for i in range(20):
            a = _h(2 * i * rho, me)
            b = _rol(_h((2 * i + 1) * rho, mo), 8)
            self.K.append((a + b) & M32)
            self.K.append(_rol((a + 2 * b) & M32, 9))
        # таблицы g-функции с ключом S
        self.T = [[0] * 256 for _ in range(4)]
        for x in range(256):
            y = _sbox_bytes([x, x, x, x], s)
            for j in range(4):
                self.T[j][x] = _MDSTAB[j][y[j]]

    def _g(self, x):
        T = self.T
        return (T[0][x & 0xFF] ^ T[1][(x >> 8) & 0xFF] ^
                T[2][(x >> 16) & 0xFF] ^ T[3][x >> 24])

    def encrypt_block(self, blk: bytes) -> bytes:
        K = self.K
        T0, T1, T2, T3 = self.T
        r0, r1, r2, r3 = struct.unpack("<4I", blk)
        r0 ^= K[0]; r1 ^= K[1]; r2 ^= K[2]; r3 ^= K[3]
        for rnd in range(16):
            t0 = (T0[r0 & 0xFF] ^ T1[(r0 >> 8) & 0xFF] ^
                  T2[(r0 >> 16) & 0xFF] ^ T3[r0 >> 24])
            x = ((r1 << 8) | (r1 >> 24)) & M32
            t1 = (T0[x & 0xFF] ^ T1[(x >> 8) & 0xFF] ^
                  T2[(x >> 16) & 0xFF] ^ T3[x >> 24])
            f0 = (t0 + t1 + K[2 * rnd + 8]) & M32
            f1 = (t0 + 2 * t1 + K[2 * rnd + 9]) & M32
            r2 = _ror(r2 ^ f0, 1)
            r3 = _rol(r3, 1) ^ f1
            r0, r1, r2, r3 = r2, r3, r0, r1
        return struct.pack("<4I", r2 ^ K[4], r3 ^ K[5], r0 ^ K[6], r1 ^ K[7])


# --------------------------------------------------------------------- EAX ---

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _dbl(b):
    n = int.from_bytes(b, "big") << 1
    if n >> 128:
        n = (n ^ 0x87) & ((1 << 128) - 1)
    return n.to_bytes(16, "big")


class EAX:
    def __init__(self, cipher):
        self.c = cipher
        L = cipher.encrypt_block(bytes(16))
        self.k1 = _dbl(L)
        self.k2 = _dbl(self.k1)

    def _cmac(self, data: bytes) -> bytes:
        enc = self.c.encrypt_block
        n = max(1, (len(data) + 15) // 16)
        x = bytes(16)
        for i in range(n - 1):
            x = enc(_xor(x, data[16 * i:16 * i + 16]))
        last = data[16 * (n - 1):]
        if len(last) == 16:
            last = _xor(last, self.k1)
        else:
            last = _xor(last + b"\x80" + bytes(15 - len(last)), self.k2)
        return enc(_xor(x, last))

    def _omac(self, t, data):
        return self._cmac(bytes(15) + bytes([t]) + data)

    def _ctr(self, nonce_mac, data):
        enc = self.c.encrypt_block
        ctr = int.from_bytes(nonce_mac, "big")
        out = bytearray(len(data))
        mask = (1 << 128) - 1
        for i in range(0, len(data), 16):
            ks = enc(ctr.to_bytes(16, "big"))
            chunk = data[i:i + 16]
            out[i:i + len(chunk)] = _xor(chunk, ks)
            ctr = (ctr + 1) & mask
        return bytes(out)

    def encrypt(self, nonce, data, header=b""):
        n = self._omac(0, nonce)
        h = self._omac(1, header)
        c = self._ctr(n, data)
        tag = _xor(_xor(n, h), self._omac(2, c))
        return c + tag

    def decrypt(self, nonce, data, header=b""):
        c, tag = data[:-16], data[-16:]
        n = self._omac(0, nonce)
        h = self._omac(1, header)
        if _xor(_xor(n, h), self._omac(2, c)) != tag:
            raise ValueError("EAX tag mismatch (файл повреждён или другой формат)")
        return self._ctr(n, c)


# ------------------------------------------------------------ Packet Tracer ---

KEY_PKT, IV_PKT = bytes([137]) * 16, bytes([16]) * 16


def _obf_outer_decode(data: bytes) -> bytes:
    L = len(data)
    return bytes(data[L - 1 - i] ^ ((L - i * L) & 0xFF) for i in range(L))


def _obf_outer_encode(data: bytes) -> bytes:
    L = len(data)
    out = bytearray(L)
    for i in range(L):
        out[L - 1 - i] = data[i] ^ ((L - i * L) & 0xFF)
    return bytes(out)


def _obf_inner(data: bytes) -> bytes:  # симметрична
    L = len(data)
    return bytes(data[i] ^ ((L - i) & 0xFF) for i in range(L))


def _unpack_zlib(data: bytes) -> bytes:
    size = int.from_bytes(data[:4], "big")
    out = zlib.decompress(data[4:])
    if len(out) != size:
        raise ValueError("размер после распаковки не совпал")
    return out


def _pack_zlib(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + zlib.compress(data)


def extract_from_pkz(raw: bytes):
    """Если это .pkz (zip) — вернуть (имя, байты) вложенного .pkt/.pka."""
    if raw[:2] != b"PK":
        return None
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        for name in z.namelist():
            if name.lower().endswith((".pkt", ".pka")):
                return name, z.read(name)
    raise ValueError("в .pkz не найден .pkt/.pka")


def decrypt(raw: bytes) -> bytes:
    """байты .pkt/.pka/.pkz -> XML (bytes)."""
    inner = extract_from_pkz(raw)
    if inner:
        raw = inner[1]
    try:
        stage1 = _obf_outer_decode(raw)
        stage2 = EAX(Twofish(KEY_PKT)).decrypt(IV_PKT, stage1)
        return _unpack_zlib(_obf_inner(stage2))
    except ValueError:
        # старый формат PT 5.x
        return _unpack_zlib(_obf_inner(raw))


def encrypt(xml: bytes) -> bytes:
    """XML -> байты .pkt (формат PT 7+)."""
    data = _obf_inner(_pack_zlib(xml))
    data = EAX(Twofish(KEY_PKT)).encrypt(IV_PKT, data)
    return _obf_outer_encode(data)


# --------------------------------------------------------------- self-test ---

def selftest():
    # Официальные тест-векторы Twofish (128 bit)
    tf = Twofish(bytes(16))
    assert tf.encrypt_block(bytes(16)).hex().upper() == \
        "9F589F5CF6122C32B6BFEC2F2AE8C35A", "twofish vector 1"
    # итеративный вектор: 49 итераций -> 5D9D4EEFFA9151575524F115815A12E0
    k, p = bytes(16), bytes(16)
    for _ in range(49):
        c = Twofish(k).encrypt_block(p)
        k, p = p, c
    assert c.hex().upper() == "5D9D4EEFFA9151575524F115815A12E0", "twofish vector 2"
    # EAX roundtrip
    e = EAX(Twofish(KEY_PKT))
    msg = bytes(range(200))
    assert e.decrypt(IV_PKT, e.encrypt(IV_PKT, msg)) == msg
    # полный roundtrip формата
    xml = b"<PACKETTRACER5><VERSION>8.2.2.0400</VERSION></PACKETTRACER5>"
    assert decrypt(encrypt(xml)) == xml
    print("selftest OK")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    cmd = argv[1]
    if cmd == "selftest":
        selftest()
    elif cmd == "decode" and len(argv) == 4:
        with open(argv[2], "rb") as f:
            xml = decrypt(f.read())
        with open(argv[3], "wb") as f:
            f.write(xml)
        print("OK: %d байт XML" % len(xml))
    elif cmd == "encode" and len(argv) == 4:
        with open(argv[2], "rb") as f:
            out = encrypt(f.read())
        with open(argv[3], "wb") as f:
            f.write(out)
        print("OK: %d байт" % len(out))
    elif cmd == "info" and len(argv) == 3:
        import re
        with open(argv[2], "rb") as f:
            xml = decrypt(f.read())
        ver = re.search(rb"<VERSION>([^<]*)</VERSION>", xml)
        print("версия PT:", ver.group(1).decode() if ver else "?")
        print("размер XML:", len(xml))
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
