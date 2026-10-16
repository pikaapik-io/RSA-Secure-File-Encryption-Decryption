#!/usr/bin/env python3

import os  # Dipakai untuk mengambil angka/byte acak dari sistem operasi.
import sys  # Dipakai kalau program dijalankan lewat terminal.

# Angka ini adalah eksponen publik yang umum dipakai di RSA.
# 65537 = 2^16 + 1, jadi masih cukup aman dan perhitungannya juga relatif cepat.
E_DEFAULT = 65537


# ---------------------------------------------------------------
# 0. UTILITAS DASAR
# ---------------------------------------------------------------
def random_bits(bits):
    """Membuat bilangan acak dengan panjang tepat ``bits`` bit.

    Kandidat prima harus memiliki panjang bit yang sesuai dengan target.
    Kalau bit paling kiri tidak dipaksa bernilai 1, angka acak yang dihasilkan
    bisa saja lebih pendek dari ukuran yang diminta dan ukuran kunci akhirnya
    tidak konsisten.
    """
    # Satu byte isinya 8 bit. Pembagian ini dibulatkan ke atas supaya jumlah
    # byte-nya cukup untuk menampung bit yang diminta.
    nbytes = (bits + 7) // 8
    x = int.from_bytes(os.urandom(nbytes), "big")
    # Kalau bit yang didapat kebanyakan, bagian paling kiri dipotong.
    x >>= nbytes * 8 - bits
    # Bit paling kiri dibuat 1 supaya panjang angkanya benar-benar sesuai.
    # Bit kedua ikut dibuat 1 agar kandidat tidak terlalu kecil, dan bit terakhir
    # dibuat 1 supaya kandidatnya ganjil (bilangan genap bukan prima, kecuali 2).
    x |= (1 << (bits - 1)) | (1 << (bits - 2))
    x |= 1
    return x


def random_range(low, high):
    """Menghasilkan bilangan acak di rentang inklusif [low, high]."""
    # Karena batas bawah dan atas ikut dihitung, jumlah kemungkinan angkanya
    # adalah high - low + 1.
    span = high - low + 1
    # Ambil angka acak yang cukup besar, lalu masukkan ke rentang yang diminta
    # dengan modulo.
    nbytes = (span.bit_length() + 7) // 8 + 1
    return low + int.from_bytes(os.urandom(nbytes), "big") % span


def mod_pow(base, exp, mod):
    """Menghitung ``base^exp mod mod`` dengan square-and-multiply.

    RSA sering menggunakan pangkat yang sangat besar. Menghitung ``base**exp``
    terlebih dahulu akan boros memori, sehingga perpangkatan dilakukan sambil
    terus mengambil modulo. Secara matematis, langkah ini tetap menghasilkan
    sisa yang sama, tetapi angka perantara tidak pernah membesar tanpa batas.
    """
    # Kalau base**exp dihitung langsung, angkanya bisa sangat besar.
    # Di sini hasilnya selalu langsung di-modulo agar angkanya tetap kecil.
    result = 1
    base %= mod
    while exp > 0:
        # Kalau bit terakhir exp adalah 1, base saat ini ikut dikalikan ke hasil.
        if exp & 1:
            result = (result * base) % mod
        # Geser exp ke kanan, sama seperti membagi exp dengan 2.
        exp >>= 1
        # Base dikuadratkan untuk dipakai pada langkah berikutnya.
        base = (base * base) % mod
    return result


def gcd(a, b):
    # FPB dibutuhkan untuk memastikan dua bilangan tidak memiliki faktor
    # persekutuan. Algoritma Euclid terus mengganti (a, b) menjadi
    # (b, a mod b); ketika b menjadi 0, a adalah FPB-nya.
    while b:
        a, b = b, a % b
    return a


def ext_gcd(a, b):
    """Mengembalikan ``(g, x, y)`` yang memenuhi ``a*x + b*y = g``.

    ``g`` adalah FPB(a, b). Koefisien ``x`` dan ``y`` inilah yang membuat
    algoritma Extended Euclid berguna untuk RSA: ketika ``g = 1``, persamaan
    tersebut bisa dipakai untuk menemukan invers modulo.
    """
    # Koefisien awal ini mewakili persamaan untuk a dan b sebelum proses
    # pembagian Euclid dimulai.
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        # q adalah hasil bagi pada langkah Euclid saat ini.
        q = a // b
        # Perbarui sisa pembagian dan pasangan bilangan yang sedang diproses.
        a, b = b, a - q * b
        # Koefisien ikut diperbarui agar hubungan a*x + b*y = gcd tetap terjaga.
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    # Pada akhir loop, a adalah FPB dan x0/y0 adalah koefisiennya.
    return a, x0, y0


def mod_inverse(e, phi):
    """Mencari ``d`` sehingga ``(e*d) mod phi = 1``.

    Dengan kata lain, d adalah invers modular dari e terhadap phi(n). Nilai d
    tidak dicari dengan pembagian biasa, karena hasilnya harus berupa bilangan
    bulat yang memenuhi persamaan modulo.
    """
    # d hanya bisa dicari kalau e dan phi tidak punya faktor persekutuan.
    g, x, _ = ext_gcd(e, phi)
    if g != 1:
        raise ValueError("e dan phi tidak koprima")
    # x bisa negatif. Modulo phi mengubahnya menjadi d versi positif yang
    # nilainya tetap setara.
    return x % phi


# ---------------------------------------------------------------
# 1. PEMBANGKITAN BILANGAN PRIMA
# ---------------------------------------------------------------
SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


def is_prime(n, rounds=40):
    """Menguji apakah n kemungkinan besar prima dengan Miller-Rabin.

    Miller-Rabin adalah uji probabilistik: angka komposit bisa saja lolos pada
    satu percobaan, tetapi peluangnya diperkecil setiap kali putaran diulang.
    Empat puluh putaran membuat peluang kandidat komposit yang lolos sangat
    kecil untuk kebutuhan demo implementasi RSA ini.
    """
    # Bilangan di bawah 2 bukan prima.
    if n < 2:
        return False
    # Pemeriksaan cepat ini menghindari Miller-Rabin untuk bilangan kecil dan
    # langsung menolak kandidat yang habis dibagi salah satu prima kecil.
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    # Di sini n-1 ditulis sebagai 2^s * d, dengan d harus ganjil.
    # Bentuk ini memang bagian dari cara kerja tes Miller-Rabin.
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        # a adalah angka penguji acak. Kalau satu kali saja gagal, n pasti
        # bukan prima. Kalau lolos semua percobaan, kemungkinan besar prima.
        a = random_range(2, n - 2)
        # Hitung a^d mod n sebagai langkah awal satu putaran pengujian.
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        # Kuadratkan berulang kali untuk mencari bukti bahwa kandidat mungkin
        # prima, sesuai deret pemeriksaan Miller-Rabin.
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False  # Berarti n terbukti bukan bilangan prima.
    return True  # Lolos 40 kali, jadi kemungkinan besar n memang prima.


def generate_prime(bits):
    # Tidak semua angka ganjil adalah prima, jadi kandidat dicoba berulang kali
    # sampai ada yang lolos uji Miller-Rabin.
    tries = 0
    while True:
        tries += 1
        cand = random_bits(bits)
        if is_prime(cand):
            return cand, tries


# ---------------------------------------------------------------
# 2. PEMBANGKITAN KUNCI
# ---------------------------------------------------------------
def generate_keys(bits=1024, verbose=True):
    """Membentuk pasangan kunci RSA ``((n, e), (n, d))``.

    Alurnya mengikuti rumus RSA:
    1. Pilih dua prima berbeda, p dan q.
    2. Hitung modulus ``n = p * q``.
    3. Hitung ``phi(n) = (p - 1) * (q - 1)``.
    4. Pilih e yang relatif prima terhadap phi(n).
    5. Cari d dengan ``e * d ≡ 1 (mod phi(n))``.

    Public key adalah (n, e), sedangkan private key adalah (n, d). Nilai p, q,
    dan phi tidak disimpan karena seharusnya dirahasiakan.
    """
    # Kunci kurang dari 512 bit terlalu lemah untuk tujuan pembelajaran ini.
    if bits < 512:
        raise ValueError("Ukuran kunci minimal 512 bit")
    # Loop ini juga menangani kasus langka ketika e tidak koprima dengan phi.
    while True:
        if verbose:
            print(f"\n[1] Membangkitkan prima p ({bits // 2} bit) ...")
        p, tp = generate_prime(bits // 2)
        if verbose:
            print(f"    p ditemukan setelah {tp} kandidat")
            print(f"[2] Membangkitkan prima q ({bits - bits // 2} bit) ...")
        q, tq = generate_prime(bits - bits // 2)
        # p dan q harus berbeda; jika sama, faktorisasi n menjadi mudah.
        while q == p:
            q, tq = generate_prime(bits - bits // 2)
        if verbose:
            print(f"    q ditemukan setelah {tq} kandidat")

        # Rumus pertama adalah n = p * q. Modulus ini dipakai oleh kedua kunci.
        # Keamanan RSA bertumpu pada sulitnya mencari kembali p dan q hanya dari
        # n ketika p dan q dibuat cukup besar.
        n = p * q
        # Untuk dua prima berbeda, banyak bilangan yang relatif prima terhadap n
        # dihitung dengan rumus phi(n) = (p - 1) * (q - 1). Nilai phi ini tidak
        # ikut dibagikan karena diperlukan saat membuat kunci privat.
        phi = (p - 1) * (q - 1)
        if verbose:
            print(f"[3] n = p * q            -> {n.bit_length()} bit")
            print(f"[4] phi = (p-1)*(q-1)    -> {phi.bit_length()} bit")

        # e harus relatif prima dengan phi agar invers modularnya ada. Kita
        # memakai 65537 karena merupakan pilihan umum: cukup kecil untuk cepat,
        # tetapi tetap memiliki bentuk biner yang efisien untuk perpangkatan.
        e = E_DEFAULT
        if gcd(e, phi) != 1:
            if verbose:
                print("    gcd(e, phi) != 1, ulangi pembangkitan prima")
            continue
        if verbose:
            print(f"[5] e = {e}  (gcd(e, phi) = 1 terpenuhi)")

        # Rumus kunci privat adalah e*d ≡ 1 (mod phi). Artinya, hasil e*d
        # ketika dibagi phi menyisakan 1. Syarat ini membuat pangkat e pada
        # enkripsi mempunyai pasangan pembalik, yaitu pangkat d pada dekripsi.
        d = mod_inverse(e, phi)
        if verbose:
            print(f"[6] d = e^-1 mod phi     -> {d.bit_length()} bit")
            print(f"[7] Verifikasi (e*d) mod phi = {(e * d) % phi}  (harus 1)")
        return (n, e), (n, d)


def save_key(path, key):
    # Format sengaja dibuat sederhana agar mudah dipelajari dan dipindahkan:
    # baris pertama berisi n, baris kedua berisi e (public) atau d (private).
    # Mode teks dipakai karena isi kunci hanya berupa bilangan desimal.
    with open(path, "w") as f:
        # Simpan n dan eksponen pada baris terpisah agar mudah dibaca manusia.
        f.write(f"{key[0]}\n{key[1]}\n")


def load_key(path):
    # split() menerima pemisah spasi maupun baris baru, jadi file kunci tetap
    # mudah dibaca dan bisa juga ditempel sebagai teks di antarmuka web.
    with open(path) as f:
        # Baca seluruh isi karena ukuran file kunci sangat kecil.
        lines = f.read().split()
    # Ubah dua teks angka kembali menjadi tuple integer yang dipakai RSA.
    return int(lines[0]), int(lines[1])


# ---------------------------------------------------------------
# 3. PADDING (mirip PKCS#1 v1.5, tipe 2)
#    EM = 0x00 || 0x02 || PS (acak, tidak nol, >= 8 byte) || 0x00 || DATA
#    Tanpa padding, RSA mentah akan deterministik: pesan yang sama selalu
#    menghasilkan ciphertext yang sama. Padding acak membuat setiap enkripsi
#    memiliki hasil berbeda dan sekaligus memberi batas yang jelas untuk data.
# ---------------------------------------------------------------
def pad_block(data, k):
    # k adalah ukuran modulus n dalam byte. Setiap blok hasil enkripsi harus
    # tepat k byte, sehingga data harus diberi padding sebelum diubah menjadi
    # bilangan dan dihitung dengan rumus RSA.
    ps_len = k - 3 - len(data)
    # bytearray memudahkan penambahan byte acak satu per satu.
    ps = bytearray()
    while len(ps) < ps_len:
        # Bagian PS diisi byte acak yang bukan 0. Nanti byte 0 dipakai sebagai
        # tanda batas antara padding dan data asli.
        for b in os.urandom(ps_len * 2):
            if b != 0:
                ps.append(b)
                if len(ps) == ps_len:
                    break
    return b"\x00\x02" + bytes(ps) + b"\x00" + data


def unpad_block(em):
    # Pemeriksaan ini penting: kunci yang salah atau ciphertext yang rusak
    # biasanya menghasilkan pola byte yang tidak sesuai.
    if len(em) < 11 or em[0] != 0 or em[1] != 2:
        raise ValueError("Padding tidak valid (kunci salah atau file rusak)")
    # Byte nol pertama setelah PS menjadi pemisah. Semua byte setelah pemisah
    # adalah data asli yang boleh dikembalikan ke pemanggil.
    idx = em.find(b"\x00", 2)
    if idx < 10:
        raise ValueError("Padding tidak valid (kunci salah atau file rusak)")
    return em[idx + 1:]


# ---------------------------------------------------------------
# 4. ENKRIPSI & DEKRIPSI FILE
# ---------------------------------------------------------------
def encrypt_file(in_path, out_path, pub_key, verbose=True):
    # Public key berisi modulus n dan eksponen publik e.
    n, e = pub_key
    # Ubah ukuran n dari bit ke byte. Ciphertext disusun dari blok-blok tetap
    # berukuran k byte agar batas antarblok selalu bisa dikenali saat dekripsi.
    k = (n.bit_length() + 7) // 8
    # Padding memakai 00 02, minimal 8 byte PS, dan 00 penutup. Setidaknya
    # 11 byte dipakai oleh struktur padding, sehingga isi data maksimal adalah
    # k - 11 byte per blok.
    max_data = k - 11

    with open(in_path, "rb") as f:
        # Mode biner menjaga semua byte file tetap utuh, termasuk byte nol.
        data = f.read()

    # Ini cara Python untuk membulatkan pembagian ke atas. max(1, ...) membuat
    # file kosong tetap menghasilkan satu blok.
    total_blocks = max(1, -(-len(data) // max_data))
    if verbose:
        print(f"\nUkuran file      : {len(data)} byte")
        print(f"Ukuran blok data : {max_data} byte -> blok cipher {k} byte")
        print(f"Jumlah blok      : {total_blocks}")

    # bytearray dipakai sebagai penampung ciphertext yang terdiri dari banyak
    # blok k-byte sebelum semuanya ditulis ke file.
    out = bytearray()
    for i in range(total_blocks):
        # Ambil potongan data sesuai kapasitas satu blok setelah padding.
        chunk = data[i * max_data:(i + 1) * max_data]
        em = pad_block(chunk, k)  # 1) Tambahkan padding ke potongan data.
        m = int.from_bytes(em, "big")  # 2) Ubah byte menjadi angka m.
        # RUMUS ENKRIPSI RSA: c = m^e mod n
        # m adalah angka dari blok yang sudah dipadding, e adalah bagian public
        # key, dan n adalah modulus. Hasil c inilah yang disimpan sebagai
        # ciphertext, bukan nilai m mentah.
        c = mod_pow(m, e, n)
        # Simpan c sebagai k byte supaya ukuran setiap blok tetap sama.
        out += c.to_bytes(k, "big")
        if verbose and i == 0:
            print("\n--- Contoh blok pertama ---")
            print(f"m (hex, 32 awal) : {hex(m)[2:34]}...")
            print(f"c (hex, 32 awal) : {hex(c)[2:34]}...")

    with open(out_path, "wb") as f:
        f.write(out)
    if verbose:
        print(f"\nEnkripsi selesai -> {out_path} ({len(out)} byte)")


def decrypt_file(in_path, out_path, priv_key, verbose=True):
    # Private key berisi modulus n yang sama dan eksponen privat d.
    n, d = priv_key
    # Ukuran blok harus dihitung dari n yang sama seperti saat enkripsi.
    k = (n.bit_length() + 7) // 8

    with open(in_path, "rb") as f:
        # Ciphertext dibaca sebagai bytes karena hasil RSA bukan teks biasa.
        cipher = f.read()
    if len(cipher) == 0 or len(cipher) % k != 0:
        raise ValueError("Ukuran file cipher tidak sesuai dengan kunci")

    blocks = len(cipher) // k
    if verbose:
        print(f"\nJumlah blok cipher : {blocks} (masing-masing {k} byte)")

    # Penampung ini berisi data asli setelah padding setiap blok dihapus.
    out = bytearray()
    for i in range(blocks):
        # Potong tepat satu blok ciphertext, lalu ubah dari bytes menjadi integer.
        c = int.from_bytes(cipher[i * k:(i + 1) * k], "big")  # 1) bytes -> int
        if c >= n:
            raise ValueError("Blok cipher tidak valid (c >= n)")
        # RUMUS DEKRIPSI RSA: m = c^d mod n
        # Jika c = m^e mod n, maka:
        #   c^d = (m^e)^d = m^(e*d) mod n
        # Karena e*d ≡ 1 (mod phi(n)), perpangkatan ini mengembalikan m
        # untuk blok yang valid. Setelah itu padding dibuang agar data asli
        # kembali persis seperti sebelum enkripsi.
        m = mod_pow(c, d, n)
        em = m.to_bytes(k, "big")  # 3) Kembalikan integer ke k byte.
        out += unpad_block(em)  # 4) Hapus header, PS, dan separator.
        if verbose and i == 0:
            print("\n--- Contoh blok pertama ---")
            print(f"c (hex, 32 awal) : {hex(c)[2:34]}...")
            print(f"m (hex, 32 awal) : {hex(m)[2:34]}...")

    with open(out_path, "wb") as f:
        f.write(out)
    if verbose:
        print(f"\nDekripsi selesai -> {out_path} ({len(out)} byte)")


# ---------------------------------------------------------------
# 5. ANTARMUKA MENU
# ---------------------------------------------------------------
def ask(prompt, default=None):
    # Menekan Enter tanpa mengetik apa pun berarti pengguna menerima nilai
    # bawaan, misalnya ukuran kunci 1024 bit atau nama file yang disarankan.
    # Tampilkan nilai default hanya jika memang tersedia.
    s = input(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    # Nilai kosong berarti gunakan default; selain itu gunakan input pengguna.
    return s or default


def main():
    # Ini versi menu terminal. Menu hanya menangani input dan output pengguna;
    # seluruh perhitungan RSA tetap memakai fungsi yang sama dengan web app.
    while True:
        # Menu ditampilkan kembali setelah satu operasi selesai agar program
        # terminal dapat dipakai untuk beberapa file dalam satu sesi.
        print("\n===== RSA FILE ENCRYPTION / DECRYPTION =====")
        print("1. Bangkitkan kunci (public.key & private.key)")
        print("2. Enkripsi file")
        print("3. Dekripsi file")
        print("0. Keluar")
        choice = input("Pilih: ").strip()
        try:
            if choice == "1":
                # Pilihan 1 membuat dan menyimpan pasangan kunci baru.
                bits = int(ask("Ukuran kunci (bit, min 512)", "1024"))
                pub, priv = generate_keys(bits)
                save_key("public.key", pub)
                save_key("private.key", priv)
                print("\nKunci tersimpan: public.key dan private.key")
                print("JAGA private.key, jangan dibagikan!")
            elif choice == "2":
                # Pilihan 2 membaca public key lalu mengenkripsi file sumber.
                src = ask("File yang dienkripsi")
                dst = ask("File hasil", src + ".enc")
                key = load_key(ask("File kunci publik", "public.key"))
                encrypt_file(src, dst, key)
            elif choice == "3":
                # Pilihan 3 membaca private key lalu mengembalikan file asli.
                src = ask("File terenkripsi (.enc)")
                dst = ask("File hasil dekripsi", "hasil_dekripsi.out")
                key = load_key(ask("File kunci privat", "private.key"))
                decrypt_file(src, dst, key)
            elif choice == "0":
                # break menghentikan loop dan menutup menu terminal.
                break
            else:
                print("Pilihan tidak dikenal.")
        # Bedakan error file supaya pesan yang ditampilkan lebih jelas.
        except FileNotFoundError as ex:
            print(f"Error: file tidak ditemukan -> {ex.filename}")
        except Exception as ex:
            print(f"Error: {ex}")


if __name__ == "__main__":
    main()
