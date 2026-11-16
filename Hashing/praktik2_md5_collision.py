"""
Praktikum Kriptografi Minggu 6
Praktik 2: Kegagalan Collision Resistance pada MD5

Tujuan:
- Menunjukkan dua data berbeda dengan MD5 identik (collision nyata)
- Membuktikan mengapa satu collision dapat 'diperpanjang' menjadi banyak file
- Membedakan collision identical-prefix dan chosen-prefix
- Menghubungkan kegagalan collision resistance dengan serangan nyata

Sumber data:
Dua blok 128 byte di bawah adalah pasangan collision MD5 identical-prefix
yang dipublikasikan oleh Xiaoyun Wang dan Hongbo Yu (2004; Eurocrypt 2005,
"How to Break MD5 and Other Hash Functions").
"""

import hashlib

BLOK_A = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a"
    "085125e8f7cdc99fd91dbdf280373c5b"
    "960b1dd1dc417b9ce4d897f45a6555d5"
    "35739ac7f0ebfd0c3029f166d109b18f"
    "75277f7930d55ceb22e8adba79cc155c"
    "ed74cbdd5fc5d36db19b0ad835cca7e3"
)

BLOK_B = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a"
    "085125e8f7cdc99fd91dbd7280373c5b"
    "960b1dd1dc417b9ce4d897f45a6555d5"
    "35739a47f0ebfd0c3029f166d109b18f"
    "75277f7930d55ceb22e8adba794c155c"
    "ed74cbdd5fc5d36db19b0a5835cca7e3"
)

assert len(BLOK_A) == len(BLOK_B) == 128  # Dua blok MD5 @ 64 byte


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def garis(judul: str) -> None:
    print()
    print("=" * 64)
    print(judul)
    print("=" * 64)


if __name__ == "__main__":
    # =========================================================================
    # BAGIAN 1: Collision MD5
    # =========================================================================
    garis("BAGIAN 1. Dua data berbeda, MD5 identik")

    posisi_beda = [i for i, (a, b) in enumerate(zip(BLOK_A, BLOK_B)) if a != b]
    print(f"\nPanjang masing-masing blok: {len(BLOK_A)} byte")
    print(f"Jumlah byte yang berbeda  : {len(posisi_beda)}")
    print("Posisi byte yang berbeda  :", posisi_beda)
    for p in posisi_beda:
        print(f"  byte ke-{p:<3}: A=0x{BLOK_A[p]:02x}  B=0x{BLOK_B[p]:02x}")

    print(f"\nMD5(A) = {md5(BLOK_A)}")
    print(f"MD5(B) = {md5(BLOK_B)}")
    print(f"\nData sama: {BLOK_A == BLOK_B}")
    print(f"MD5 sama : {md5(BLOK_A) == md5(BLOK_B)}")

    print("\nOBSERVASI:")
    print("  -> Ini collision identical-prefix: kedua pesan berawal dari kondisi")
    print("     yang sama (di sini: IV standar MD5), lalu blok collision dihitung")
    print("     secara sengaja. Bukan kebetulan dan bukan hasil brute force.")

    # =========================================================================
    # BAGIAN 2: Satu collision, banyak file
    # =========================================================================
    garis("BAGIAN 2. Satu collision dapat diperpanjang")
    print("\nMD5 memproses data per blok 64 byte (konstruksi Merkle-Damgard).")
    print("Setelah A dan B diproses, state internal MD5 sudah IDENTIK.")
    print("Akibatnya, menambahkan sufiks yang sama tetap menghasilkan collision.\n")

    sufiks_list = [
        b"",
        b" Transfer ke rekening 1234567890 sebesar Rp 1.000.000",
        b" " + b"X" * 1000,
    ]
    for s in sufiks_list:
        ma, mb = md5(BLOK_A + s), md5(BLOK_B + s)
        print(f"  sufiks {len(s):>4} byte -> MD5 sama: {ma == mb} ({ma})")

    print("\nSebaliknya, jika PREFIKS diubah, state awal berbeda dan collision hilang:\n")
    for p in [b"", b"Z", b"Header dokumen v2\n"]:
        ma, mb = md5(p + BLOK_A), md5(p + BLOK_B)
        print(f"  prefiks {len(p):>3} byte -> MD5 sama: {ma == mb}")

    print("\nOBSERVASI:")
    print("  -> Penyerang cukup menemukan satu collision, lalu dapat menempelkan")
    print("     isi apa pun di belakangnya. Inilah dasar pembuatan dua program atau")
    print("     dua dokumen berbeda dengan MD5 yang sama.")
    print("  -> Collision identical-prefix mensyaratkan prefiks yang sama.")
    print("     Varian yang lebih kuat, chosen-prefix collision (Stevens, Lenstra,")
    print("     de Weger, 2007), mengizinkan dua prefiks BERBEDA pilihan penyerang.")

    # =========================================================================
    # BAGIAN 3: Algoritma lain pada data yang sama
    # =========================================================================
    garis("BAGIAN 3. Data yang sama pada SHA-1, SHA-256, SHA3-256")

    for nama in ["md5", "sha1", "sha256", "sha3_256"]:
        ha = hashlib.new(nama, BLOK_A).hexdigest()
        hb = hashlib.new(nama, BLOK_B).hexdigest()
        print(f"\n  {nama:<9} A: {ha}")
        print(f"  {'':<9} B: {hb}")
        print(f"  {'':<9} sama: {ha == hb}")

    print("\nOBSERVASI:")
    print("  -> Blok collision ini dirancang khusus untuk struktur internal MD5,")
    print("     sehingga tidak berlaku pada algoritma lain.")
    print("  -> Hasil ini TIDAK membuktikan SHA-256 bebas collision. Hasil ini")
    print("     hanya menunjukkan bahwa serangan tersebut spesifik terhadap MD5.")

    # =========================================================================
    # BAGIAN 4: Kasus nyata
    # =========================================================================
    garis("BAGIAN 4. Kasus nyata kegagalan collision resistance")

    kasus = [
        (
            "2008",
            "Rogue CA certificate (MD5, chosen-prefix)",
            "Sotirov, Stevens, dkk. memperoleh sertifikat dari CA komersial yang\n"
            "         masih memakai MD5, lalu membuat sertifikat CA palsu dengan\n"
            "         tanda tangan yang tetap valid. CA palsu dapat menerbitkan\n"
            "         sertifikat untuk domain apa pun.",
        ),
        (
            "2012",
            "Malware Flame (MD5, chosen-prefix)",
            "Penyerang memalsukan sertifikat code-signing yang berantai ke root\n"
            "         Microsoft, lalu menyebarkan malware bertanda tangan 'sah' melalui\n"
            "         mekanisme Windows Update palsu di jaringan lokal.",
        ),
        (
            "2017",
            "SHAttered (SHA-1, identical-prefix)",
            "Google dan CWI menghasilkan dua file PDF berbeda dengan SHA-1 identik.\n"
            "         Collision praktis pertama untuk SHA-1.",
        ),
        (
            "2020",
            "SHA-1 is a Shambles (SHA-1, chosen-prefix)",
            "Leurent dan Peyrin mendemonstrasikan chosen-prefix collision SHA-1\n"
            "         dan memakainya untuk memalsukan identitas pada PGP Web of Trust.",
        ),
    ]

    for tahun, judul, isi in kasus:
        print(f"\n  [{tahun}] {judul}")
        print(f"         {isi}")

    print("\nCatatan tentang Git:")
    print("  Git masih memakai SHA-1 secara default, tetapi sejak versi 2.13 (2017)")
    print("  memakai SHA-1DC yang mendeteksi pola serangan collision yang dikenal.")
    print("  Format objek SHA-256 sudah tersedia dan direncanakan menjadi default")
    print("  di Git 3.0. Belum ada serangan collision nyata terhadap repository Git.")

    print("\nKESIMPULAN:")
    print("  MD5 dan SHA-1 tidak layak untuk keperluan yang membutuhkan collision")
    print("  resistance: sertifikat, tanda tangan digital, dan verifikasi software.")
    print("  Untuk aplikasi baru gunakan SHA-2 atau SHA-3.")