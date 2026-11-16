"""
Praktikum Kriptografi Minggu 6
Praktik 3: Verifikasi Integritas File, Batas Hash Biasa, dan HMAC

Tujuan:
- Membuat file integrity checker yang membaca file per potongan (chunk)
- Menunjukkan kapan hash biasa berhasil dan kapan gagal
- Menunjukkan bahwa HMAC menambahkan autentikasi melalui secret key
- Membedakan kebutuhan hash, HMAC, dan digital signature
"""

import hashlib
import hmac
import os
import secrets
import tempfile


def sha256_file(path: str, ukuran_chunk: int = 64 * 1024) -> str:
    """Hitung SHA-256 file per potongan, seperti Get-FileHash / sha256sum."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while potongan := f.read(ukuran_chunk):
            h.update(potongan)
    return h.hexdigest()


def hmac_file(key: bytes, path: str, ukuran_chunk: int = 64 * 1024) -> str:
    """Hitung HMAC-SHA-256 file per potongan."""
    m = hmac.new(key, digestmod=hashlib.sha256)
    with open(path, "rb") as f:
        while potongan := f.read(ukuran_chunk):
            m.update(potongan)
    return m.hexdigest()


def garis(judul: str) -> None:
    print()
    print("=" * 64)
    print(judul)
    print("=" * 64)


def status(cocok: bool) -> str:
    return "LOLOS (dianggap asli)" if cocok else "GAGAL (perubahan terdeteksi)"


if __name__ == "__main__":
    folder = tempfile.mkdtemp(prefix="praktik3_")
    file_rilis = os.path.join(folder, "aplikasi_v1.2.bin")

    # Simulasi file rilis ~3 MB
    with open(file_rilis, "wb") as f:
        f.write(b"MZ" + bytes(range(256)) * 12_000)

    # =========================================================================
    # BAGIAN 1: Publisher mempublikasikan digest
    # =========================================================================
    garis("BAGIAN 1. Publisher mempublikasikan SHA-256")

    digest_resmi = sha256_file(file_rilis)
    print(
        f"\nFile         : {os.path.basename(file_rilis)} "
        f"({os.path.getsize(file_rilis):,} byte)"
    )
    print(f"SHA-256 resmi: {digest_resmi}")
    print("\nPerintah setara di sistem operasi:")
    print("  Windows: Get-FileHash aplikasi_v1.2.bin -Algorithm SHA256")
    print("  Linux  : sha256sum aplikasi_v1.2.bin")

    # =========================================================================
    # BAGIAN 2: Skenario A, file rusak atau diubah saat distribusi
    # =========================================================================
    garis("BAGIAN 2. Skenario A: file diubah, digest resmi tidak tersentuh")

    with open(file_rilis, "r+b") as f:
        f.seek(1_000_000)
        f.write(b"\x90")  # Satu byte diubah di tengah file

    digest_unduhan = sha256_file(file_rilis)
    print(f"\nSHA-256 resmi   : {digest_resmi}")
    print(f"SHA-256 unduhan : {digest_unduhan}")
    print(f"Hasil verifikasi: {status(digest_unduhan == digest_resmi)}")

    # =========================================================================
    # BAGIAN 3: Skenario B, penyerang menguasai server
    # =========================================================================
    garis("BAGIAN 3. Skenario B: penyerang mengganti file DAN digest")

    with open(file_rilis, "ab") as f:
        f.write(b"<payload berbahaya>")

    digest_palsu = sha256_file(file_rilis)  # Siapa pun dapat menghitung SHA-256

    print("\nPenyerang menyisipkan payload, lalu menghitung SHA-256 baru dan")
    print("mengganti digest yang tertera di halaman unduhan.")
    print(f"\nSHA-256 di halaman (palsu): {digest_palsu}")
    print(f"SHA-256 file unduhan      : {sha256_file(file_rilis)}")
    print(f"Hasil verifikasi          : {status(sha256_file(file_rilis) == digest_palsu)}")

    print("\nOBSERVASI:")
    print("  -> Hash biasa tidak memakai kunci. Siapa pun yang dapat mengubah file")
    print("     juga dapat menghitung digest baru. Hash membuktikan integritas")
    print("     HANYA jika digest diperoleh dari saluran yang tepercaya.")

    # =========================================================================
    # BAGIAN 4: HMAC
    # =========================================================================
    garis("BAGIAN 4. HMAC-SHA-256: hash + secret key")

    # Kembalikan file ke kondisi asli
    with open(file_rilis, "wb") as f:
        f.write(b"MZ" + bytes(range(256)) * 12_000)

    kunci = secrets.token_bytes(32)  # Dibagi antara pengirim dan penerima saja
    tag_resmi = hmac_file(kunci, file_rilis)
    print(f"\nKunci rahasia (contoh): {kunci.hex()[:16]}... (32 byte)")
    print(f"Tag HMAC resmi        : {tag_resmi}")

    # Penyerang mengubah file dan mencoba membuat tag dengan kunci tebakan
    with open(file_rilis, "ab") as f:
        f.write(b"<payload berbahaya>")

    kunci_tebakan = secrets.token_bytes(32)
    tag_penyerang = hmac_file(kunci_tebakan, file_rilis)
    tag_dihitung_penerima = hmac_file(kunci, file_rilis)

    print("\nPenyerang mengubah file dan membuat tag dengan kunci tebakan.")
    print(f"Tag dari penyerang    : {tag_penyerang}")
    print(f"Tag dihitung penerima : {tag_dihitung_penerima}")

    cocok = hmac.compare_digest(tag_dihitung_penerima, tag_penyerang)
    print(f"Hasil verifikasi      : {status(cocok)}")

    print("\nOBSERVASI:")
    print("  -> Tanpa kunci, penyerang tidak dapat membuat tag yang valid.")
    print("  -> Perbandingan memakai hmac.compare_digest (waktu konstan), bukan '=='")
    print("     agar waktu perbandingan tidak membocorkan informasi tentang tag.")
    print("  -> HMAC menuntut kunci yang SAMA di kedua pihak. Untuk distribusi")
    print("     software ke publik, pengguna tidak boleh memegang kunci rahasia")
    print("     publisher, sehingga solusinya adalah digital signature.")

    # Bersihkan file sementara
    os.remove(file_rilis)
    os.rmdir(folder)

    print("\nRINGKASAN:")
    print(f"  {'Mekanisme':<20} {'Integritas':<12} {'Autentikasi':<13} {'Kunci'}")
    print(f"  {'-' * 20} {'-' * 12} {'-' * 13} {'-' * 22}")
    print(f"  {'SHA-256':<20} {'ya*':<12} {'tidak':<13} {'tidak ada'}")
    print(f"  {'HMAC-SHA-256':<20} {'ya':<12} {'ya':<13} {'rahasia bersama'}")
    print(f"  {'Digital signature':<20} {'ya':<12} {'ya':<13} {'privat / publik'}")
    print("  * hanya jika digest diperoleh dari saluran tepercaya")