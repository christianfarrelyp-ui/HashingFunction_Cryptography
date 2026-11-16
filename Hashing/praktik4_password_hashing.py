"""
Praktikum Kriptografi Minggu 6
Praktik 4: Password Hashing - SHA-256, Salt, bcrypt, dan Argon2id

Tujuan:
- Menunjukkan masalah SHA-256 tanpa salt untuk password
- Menunjukkan bahwa salt saja belum cukup karena SHA-256 terlalu cepat
- Membandingkan bcrypt dan Argon2id (rekomendasi utama OWASP)
- Membuktikan bahwa algoritma lambat TIDAK menyelamatkan password lemah
- Mengamati batas 72 byte pada bcrypt

Instalasi: pip install bcrypt argon2-cffi
"""

import hashlib
import os
import time
import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

PASSWORD = "admin123"

# Daftar kata sandi umum (versi mini dari wordlist seperti rockyou.txt)
WORDLIST = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball", "abc123",
    "football", "monkey", "letmein", "696969", "shadow", "master", "666666",
    "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321",
    "superman", "1qaz2wsx", "7777777", "admin123", "indonesia", "bismillah",
]


def garis(judul: str) -> None:
    print()
    print("=" * 64)
    print(judul)
    print("=" * 64)


def ukur(fungsi, ulang: int = 1) -> float:
    """Kembalikan rata-rata waktu (detik) satu pemanggilan fungsi."""
    mulai = time.perf_counter()
    for _ in range(ulang):
        fungsi()
    return (time.perf_counter() - mulai) / ulang


if __name__ == "__main__":
    # =========================================================================
    # BAGIAN 1: SHA-256 tanpa salt
    # =========================================================================
    garis("BAGIAN 1. SHA-256 tanpa salt")

    pengguna = {"andi": PASSWORD, "budi": PASSWORD, "citra": "Kopi!Pagi#2026"}
    print("\nIsi tabel users (password disimpan sebagai SHA-256):")
    for nama, pw in pengguna.items():
        print(f"  {nama:<6} {hashlib.sha256(pw.encode()).hexdigest()}")

    print("\nOBSERVASI:")
    print("  -> andi dan budi memiliki hash identik: penyerang langsung tahu")
    print("     keduanya memakai password yang sama.")
    print("  -> Hash deterministik dapat dicari di tabel pre-computed (rainbow table)")
    print("     tanpa menghitung ulang.")

    # =========================================================================
    # BAGIAN 2: SHA-256 dengan salt
    # =========================================================================
    garis("BAGIAN 2. SHA-256 dengan salt acak per pengguna")
    print()
    for nama, pw in pengguna.items():
        salt = os.urandom(16)
        h = hashlib.sha256(salt + pw.encode()).hexdigest()
        print(f"  {nama:<6} salt={salt.hex()[:12]}... hash={h[:32]}...")

    waktu_sha = ukur(
        lambda: hashlib.sha256(os.urandom(16) + PASSWORD.encode()).digest(),
        200_000,
    )
    print(f"\nKecepatan SHA-256 (Python, 1 core CPU): ~{1 / waktu_sha:,.0f} hash/detik")
    print("GPU dengan hashcat dapat menghitung MILIARAN SHA-256 per detik.")

    print("\nOBSERVASI:")
    print("  -> Salt membuat hash andi dan budi berbeda dan menggagalkan rainbow table.")
    print("  -> Namun SHA-256 tetap terlalu cepat: penyerang tetap dapat mencoba")
    print("     miliaran tebakan per detik untuk setiap salt.")

    # =========================================================================
    # BAGIAN 3: bcrypt dan Argon2id
    # =========================================================================
    garis("BAGIAN 3. bcrypt dan Argon2id")

    pw = PASSWORD.encode()
    print("\nbcrypt, password yang sama di-hash tiga kali:")
    for i in range(3):
        print(f"  {bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode()}")

    contoh_bcrypt = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode()
    print("\nStruktur string bcrypt:")
    print(f"  {contoh_bcrypt}")
    print(f"  versi: {contoh_bcrypt[1:3]}  (karakter ke-2 sampai 3)")
    print(f"  cost : {contoh_bcrypt[4:6]}  (2^cost iterasi)")
    print(f"  salt : {contoh_bcrypt[7:29]}  (22 karakter, karakter ke-8 sampai 29)")
    print(f"  hash : {contoh_bcrypt[29:]}  (31 karakter)")

    ph = PasswordHasher()  # Parameter default argon2-cffi
    contoh_argon = ph.hash(PASSWORD)
    print("\nArgon2id (argon2-cffi, parameter default):")
    print(f"  {contoh_argon}")
    print(
        f"  memori = {ph.memory_cost:,} KiB, iterasi = {ph.time_cost}, "
        f"paralelisme = {ph.parallelism}"
    )

    print("\nWaktu per hash (rata-rata 3 kali):")
    waktu = {}
    for cost in (10, 12, 14):
        waktu[f"bcrypt cost {cost}"] = ukur(
            lambda c=cost: bcrypt.hashpw(pw, bcrypt.gensalt(rounds=c)), 3
        )
    waktu["Argon2id default"] = ukur(lambda: ph.hash(PASSWORD), 3)

    for nama, t in waktu.items():
        print(
            f"  {nama:<18} {t * 1000:>8.0f} ms "
            f"(~{t / waktu_sha:,.0f}x lebih lambat dari SHA-256)"
        )

    print("\nVerifikasi login:")
    print(f"  bcrypt.checkpw('admin123') -> {bcrypt.checkpw(pw, contoh_bcrypt.encode())}")
    print(f"  bcrypt.checkpw('salah123') -> {bcrypt.checkpw(b'salah123', contoh_bcrypt.encode())}")
    print(f"  argon2 verify('admin123')  -> {ph.verify(contoh_argon, PASSWORD)}")
    try:
        ph.verify(contoh_argon, "salah123")
    except VerifyMismatchError:
        print("  argon2 verify('salah123')  -> VerifyMismatchError (ditolak)")

    print("\nOBSERVASI:")
    print("  -> Setiap kenaikan cost bcrypt sebesar 1 menggandakan waktu.")
    print("  -> Argon2id juga memakai banyak MEMORI per tebakan (memory-hard),")
    print("     sehingga serangan dengan GPU/ASIC menjadi jauh lebih mahal.")

    # =========================================================================
    # BAGIAN 4: Serangan kamus terhadap hash yang bocor
    # =========================================================================
    garis("BAGIAN 4. Serangan kamus: apakah algoritma lambat cukup?")

    salt = os.urandom(16)
    bocor_sha = hashlib.sha256(salt + pw).digest()
    bocor_bcrypt = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12))
    bocor_argon = ph.hash(PASSWORD)

    def _argon_cocok(w: str) -> bool:
        try:
            return ph.verify(bocor_argon, w)
        except VerifyMismatchError:
            return False

    uji = {
        "SHA-256 + salt": lambda w: hashlib.sha256(salt + w.encode()).digest() == bocor_sha,
        "bcrypt cost 12": lambda w: bcrypt.checkpw(w.encode(), bocor_bcrypt),
        "Argon2id": lambda w: _argon_cocok(w),
    }

    print(f"\nWordlist: {len(WORDLIST)} kata sandi umum. Target: hash bocor milik 'andi'.\n")
    for nama, cek in uji.items():
        mulai = time.perf_counter()
        ketemu = None
        for i, kata in enumerate(WORDLIST, 1):
            if cek(kata):
                ketemu = (i, kata)
                break
        durasi = time.perf_counter() - mulai
        print(
            f"  {nama:<15} ditemukan '{ketemu[1]}' pada tebakan ke-{ketemu[0]} "
            f"dalam {durasi:.3f} detik"
        )

    print("\nEkstrapolasi untuk wordlist 14 juta kata (seukuran rockyou.txt), 1 core:")
    for nama, t in [
        ("SHA-256 + salt", waktu_sha),
        ("bcrypt cost 12", waktu["bcrypt cost 12"]),
        ("Argon2id default", waktu["Argon2id default"]),
    ]:
        detik = 14_000_000 * t
        teks = f"{detik:,.0f} detik" if detik < 3600 else f"{detik / 86400:,.1f} hari"
        print(f"  {nama:<17} ~{teks}")

    print("\nOBSERVASI:")
    print("  -> Password lemah tetap ditemukan oleh SEMUA algoritma.")
    print("  -> Algoritma lambat hanya memperbesar biaya per tebakan. Keamanan")
    print("     tetap bergantung pada kekuatan password, salt unik, dan cost yang tepat.")

    # =========================================================================
    # BAGIAN 5: Batas 72 byte pada bcrypt
    # =========================================================================
    garis("BAGIAN 5. Batas input 72 byte pada bcrypt")

    pw_panjang_1 = b"A" * 72 + b"-akhiran-pertama"
    pw_panjang_2 = b"A" * 72 + b"-akhiran-berbeda"

    print(f"\nPanjang password uji: {len(pw_panjang_1)} byte")
    print(f"Versi library bcrypt: {bcrypt.__version__}")

    try:
        h = bcrypt.hashpw(pw_panjang_1, bcrypt.gensalt(rounds=4))
        sama = bcrypt.checkpw(pw_panjang_2, h)
        print("Library memotong input secara diam-diam.")
        print(f"Password lain dengan 72 byte awal yang sama diterima: {sama}")
    except ValueError as e:
        print(f"Library menolak input: ValueError: {e}")

    print("\nOBSERVASI:")
    print("  -> bcrypt hanya memproses 72 byte pertama. Versi lama memotong")
    print("     diam-diam, versi 5.0 ke atas menolak dengan ValueError.")
    print("  -> Argon2id tidak memiliki batas ini. Alasan utama OWASP memilih")
    print("     Argon2id tetap sifat memory-hard; batas 72 byte adalah")
    print("     keterbatasan bcrypt yang wajib diketahui pengembang.")