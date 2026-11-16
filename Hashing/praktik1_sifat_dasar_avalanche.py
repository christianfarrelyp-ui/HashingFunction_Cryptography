"""
Praktikum Kriptografi Minggu 6
Praktik 1: Sifat Dasar Hash dan Avalanche Effect

Tujuan:
- Mengamati sifat deterministik dan panjang output tetap
- Membandingkan panjang digest MD5, SHA-1, SHA-2, SHA-3, dan SHAKE (XOF)
- Mengukur avalanche effect secara statistik (1.000 percobaan)
- Membandingkan hash kriptografis dengan fungsi 'hash' buatan yang lemah
"""

import hashlib
import random
import statistics

SEED = 2026          # Seed tetap agar hasil eksperimen konsisten dan dapat direproduksi
JUMLAH_UJI = 1000    # Jumlah percobaan avalanche secara statistik


def bit_beda(a: bytes, b: bytes) -> int:
    """Hitung jumlah bit yang berbeda antara dua digest berpanjang sama."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def balik_satu_bit(data: bytes, posisi_bit: int) -> bytes:
    """Kembalikan salinan data dengan tepat satu bit dibalik."""
    hasil = bytearray(data)
    hasil[posisi_bit // 8] ^= 1 << (posisi_bit % 8)
    return bytes(hasil)


def hash_lemah(data: bytes) -> bytes:
    """
    Fungsi 'hash' buatan yang TIDAK aman, hanya sebagai pembanding:
    jumlah seluruh byte, modulo 2^32, menghasilkan output 4 byte (32 bit).
    """
    return (sum(data) % 2**32).to_bytes(4, "big")


def garis(judul: str) -> None:
    print()
    print("=" * 64)
    print(judul)
    print("=" * 64)


if __name__ == "__main__":
    # =========================================================================
    # BAGIAN 1: Deterministik dan panjang output tetap
    # =========================================================================
    garis("BAGIAN 1. Deterministik dan panjang output tetap")

    teks = b"Keamanan Data"
    print(f"\nInput: {teks.decode()!r}, dihitung tiga kali dengan SHA-256:")
    for i in range(1, 4):
        print(f"  Run {i}: {hashlib.sha256(teks).hexdigest()}")

    data_besar = random.Random(SEED).randbytes(5 * 1024 * 1024)  # 5 MB
    print(
        f"\nInput kecil: {len(teks):>9,} byte -> SHA-256 "
        f"{len(hashlib.sha256(teks).hexdigest())} karakter heksadesimal"
    )
    print(
        f"Input besar: {len(data_besar):>9,} byte -> SHA-256 "
        f"{len(hashlib.sha256(data_besar).hexdigest())} karakter heksadesimal"
    )

    print("\nPanjang digest berbagai algoritma untuk input yang sama:")
    print(f"  {'Algoritma':<12} {'Bit':>5}  Digest (16 karakter pertama)")
    for nama in ["md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512"]:
        h = hashlib.new(nama, teks)
        print(f"  {nama:<12} {h.digest_size * 8:>5}  {h.hexdigest()[:16]}...")

    print("\nSHAKE256 adalah XOF: panjang output dipilih oleh pemakai.")
    for panjang_byte in (16, 32, 64):
        out = hashlib.shake_256(teks).hexdigest(panjang_byte)
        print(f"  SHAKE256, {panjang_byte * 8:>4} bit: {out}")

    # =========================================================================
    # BAGIAN 2: Avalanche effect, satu contoh
    # =========================================================================
    garis("BAGIAN 2. Avalanche effect, satu contoh")

    pasangan = [
        (b"hello", b"hfllo"),
        (b"Data penting", b"Data pentIng"),
    ]
    for asli, ubah in pasangan:
        h1 = hashlib.sha256(asli).digest()
        h2 = hashlib.sha256(ubah).digest()
        beda = bit_beda(h1, h2)
        print(f"\n  {asli.decode()!r:<16} -> {h1.hex()}")
        print(f"  {ubah.decode()!r:<16} -> {h2.hex()}")
        print(f"  Bit berbeda: {beda} dari 256 ({beda / 256 * 100:.1f}%)")

    print("\nCatatan: satu contoh belum membuktikan apa pun secara statistik.")
    print("Bagian 3 mengulang percobaan ini sebanyak", JUMLAH_UJI, "kali.")

    # =========================================================================
    # BAGIAN 3: Avalanche effect secara statistik
    # =========================================================================
    garis(f"BAGIAN 3. Avalanche effect secara statistik ({JUMLAH_UJI} percobaan)")
    print("\nSetiap percobaan: pesan acak 32 byte, balik TEPAT 1 bit,")
    print("lalu hitung berapa persen bit digest yang ikut berubah.")

    rng = random.Random(SEED)
    fungsi = {
        "SHA-256": lambda d: hashlib.sha256(d).digest(),
        "SHA3-256": lambda d: hashlib.sha3_256(d).digest(),
        "hash_lemah": hash_lemah,
    }
    hasil = {nama: [] for nama in fungsi}

    for _ in range(JUMLAH_UJI):
        pesan = rng.randbytes(32)
        pesan_ubah = balik_satu_bit(pesan, rng.randrange(256))
        for nama, f in fungsi.items():
            d1, d2 = f(pesan), f(pesan_ubah)
            hasil[nama].append(bit_beda(d1, d2) / (len(d1) * 8) * 100)

    print(f"\n  {'Fungsi':<11} {'Rata-rata':>10} {'Std dev':>9} {'Min':>7} {'Maks':>7}")
    for nama, nilai in hasil.items():
        print(
            f"  {nama:<11} {statistics.mean(nilai):>9.1f}% "
            f"{statistics.stdev(nilai):>8.1f}% {min(nilai):>6.1f}% {max(nilai):>6.1f}%"
        )

    batas = [
        (0, 10), (10, 20), (20, 30), (30, 40), (40, 45),
        (45, 50), (50, 55), (55, 60), (60, 101)
    ]
    for nama in ("SHA-256", "hash_lemah"):
        print(f"\nSebaran persentase bit berubah, {nama} (panjang bar relatif):")
        hitung = [sum(b <= v < a for v in hasil[nama]) for b, a in batas]
        skala = max(hitung) / 40
        for (bawah, atas), n in zip(batas, hitung):
            label = f"{bawah}-{min(atas, 100)}%"
            print(f"  {label:>8} | {'#' * round(n / skala):<40} {n}")

    print("\nOBSERVASI:")
    print("  -> SHA-256 dan SHA3-256 berpusat di sekitar 50% dengan sebaran sempit.")
    print("  -> hash_lemah hanya mengubah sedikit bit: hubungan input dan output")
    print("     mudah ditebak, sehingga tidak layak dipakai untuk keamanan.")
    print("  -> Avalanche effect adalah karakteristik desain yang penting, tetapi")
    print("     tidak sama dengan preimage atau collision resistance.")