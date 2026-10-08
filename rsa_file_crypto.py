#!/usr/bin/env python3

import os
import sys

E_DEFAULT = 65537  # eksponen publik standar


# ---------------------------------------------------------------
# 0. UTILITAS DASAR
# ---------------------------------------------------------------
def random_bits(bits):
    """Bilangan acak dengan panjang tepat 'bits' bit (bit atas & bawah = 1)."""
    nbytes = (bits + 7) // 8
    x = int.from_bytes(os.urandom(nbytes), "big")
    x >>= nbytes * 8 - bits           # potong ke 'bits' bit
    x |= (1 << (bits - 1)) | (1 << (bits - 2))  # 2 bit teratas = 1 (agar n panjangnya penuh)
    x |= 1                            # ganjil
    return x


def random_range(low, high):
    """Bilangan acak di rentang [low, high]."""
    span = high - low + 1
    nbytes = (span.bit_length() + 7) // 8 + 1
    return low + int.from_bytes(os.urandom(nbytes), "big") % span


def mod_pow(base, exp, mod):
    """Square-and-multiply: menghitung (base^exp) mod mod."""
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def ext_gcd(a, b):
    """Extended Euclid: mengembalikan (g, x, y) dengan a*x + b*y = g."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mod_inverse(e, phi):
    """Mencari d sehingga (e*d) mod phi = 1."""
    g, x, _ = ext_gcd(e, phi)
    if g != 1:
        raise ValueError("e dan phi tidak koprima")
    return x % phi


# ---------------------------------------------------------------
# 1. PEMBANGKITAN BILANGAN PRIMA
# ---------------------------------------------------------------
SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


def is_prime(n, rounds=40):
    """Uji keprimaan Miller-Rabin."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    # tulis n-1 = 2^s * d dengan d ganjil
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random_range(2, n - 2)
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False   # pasti komposit
    return True            # kemungkinan besar prima


def generate_prime(bits):
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
    if bits < 512:
        raise ValueError("Ukuran kunci minimal 512 bit")
    while True:
        if verbose:
            print(f"\n[1] Membangkitkan prima p ({bits // 2} bit) ...")
        p, tp = generate_prime(bits // 2)
        if verbose:
            print(f"    p ditemukan setelah {tp} kandidat")
            print(f"[2] Membangkitkan prima q ({bits - bits // 2} bit) ...")
        q, tq = generate_prime(bits - bits // 2)
        while q == p:
            q, tq = generate_prime(bits - bits // 2)
        if verbose:
            print(f"    q ditemukan setelah {tq} kandidat")

        n = p * q
        phi = (p - 1) * (q - 1)
        if verbose:
            print(f"[3] n = p * q            -> {n.bit_length()} bit")
            print(f"[4] phi = (p-1)*(q-1)    -> {phi.bit_length()} bit")

        e = E_DEFAULT
        if gcd(e, phi) != 1:
            if verbose:
                print("    gcd(e, phi) != 1, ulangi pembangkitan prima")
            continue
        if verbose:
            print(f"[5] e = {e}  (gcd(e, phi) = 1 terpenuhi)")

        d = mod_inverse(e, phi)
        if verbose:
            print(f"[6] d = e^-1 mod phi     -> {d.bit_length()} bit")
            print(f"[7] Verifikasi (e*d) mod phi = {(e * d) % phi}  (harus 1)")
        return (n, e), (n, d)


def save_key(path, key):
    with open(path, "w") as f:
        f.write(f"{key[0]}\n{key[1]}\n")


def load_key(path):
    with open(path) as f:
        lines = f.read().split()
    return int(lines[0]), int(lines[1])


# ---------------------------------------------------------------
# 3. PADDING (mirip PKCS#1 v1.5, tipe 2)
#    EM = 0x00 || 0x02 || PS (acak, tidak nol, >= 8 byte) || 0x00 || DATA
#    Tanpa padding, RSA mentah deterministik dan mudah diserang.
# ---------------------------------------------------------------
def pad_block(data, k):
    ps_len = k - 3 - len(data)
    ps = bytearray()
    while len(ps) < ps_len:
        for b in os.urandom(ps_len * 2):
            if b != 0:
                ps.append(b)
                if len(ps) == ps_len:
                    break
    return b"\x00\x02" + bytes(ps) + b"\x00" + data


def unpad_block(em):
    if len(em) < 11 or em[0] != 0 or em[1] != 2:
        raise ValueError("Padding tidak valid (kunci salah atau file rusak)")
    idx = em.find(b"\x00", 2)
    if idx < 10:
        raise ValueError("Padding tidak valid (kunci salah atau file rusak)")
    return em[idx + 1:]


# ---------------------------------------------------------------
# 4. ENKRIPSI & DEKRIPSI FILE
# ---------------------------------------------------------------
def encrypt_file(in_path, out_path, pub_key, verbose=True):
    n, e = pub_key
    k = (n.bit_length() + 7) // 8      # ukuran blok ciphertext (byte)
    max_data = k - 11                  # sisa ruang untuk data per blok

    with open(in_path, "rb") as f:
        data = f.read()

    total_blocks = max(1, -(-len(data) // max_data))
    if verbose:
        print(f"\nUkuran file      : {len(data)} byte")
        print(f"Ukuran blok data : {max_data} byte -> blok cipher {k} byte")
        print(f"Jumlah blok      : {total_blocks}")

    out = bytearray()
    for i in range(total_blocks):
        chunk = data[i * max_data:(i + 1) * max_data]
        em = pad_block(chunk, k)                   # 1) padding
        m = int.from_bytes(em, "big")              # 2) bytes -> integer
        c = mod_pow(m, e, n)                       # 3) c = m^e mod n
        out += c.to_bytes(k, "big")                # 4) integer -> bytes
        if verbose and i == 0:
            print("\n--- Contoh blok pertama ---")
            print(f"m (hex, 32 awal) : {hex(m)[2:34]}...")
            print(f"c (hex, 32 awal) : {hex(c)[2:34]}...")

    with open(out_path, "wb") as f:
        f.write(out)
    if verbose:
        print(f"\nEnkripsi selesai -> {out_path} ({len(out)} byte)")


def decrypt_file(in_path, out_path, priv_key, verbose=True):
    n, d = priv_key
    k = (n.bit_length() + 7) // 8

    with open(in_path, "rb") as f:
        cipher = f.read()
    if len(cipher) == 0 or len(cipher) % k != 0:
        raise ValueError("Ukuran file cipher tidak sesuai dengan kunci")

    blocks = len(cipher) // k
    if verbose:
        print(f"\nJumlah blok cipher : {blocks} (masing-masing {k} byte)")

    out = bytearray()
    for i in range(blocks):
        c = int.from_bytes(cipher[i * k:(i + 1) * k], "big")   # 1) bytes -> int
        if c >= n:
            raise ValueError("Blok cipher tidak valid (c >= n)")
        m = mod_pow(c, d, n)                                   # 2) m = c^d mod n
        em = m.to_bytes(k, "big")                              # 3) int -> bytes
        out += unpad_block(em)                                 # 4) hapus padding
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
    s = input(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    return s or default


def main():
    while True:
        print("\n===== RSA FILE ENCRYPTION / DECRYPTION =====")
        print("1. Bangkitkan kunci (public.key & private.key)")
        print("2. Enkripsi file")
        print("3. Dekripsi file")
        print("0. Keluar")
        choice = input("Pilih: ").strip()
        try:
            if choice == "1":
                bits = int(ask("Ukuran kunci (bit, min 512)", "1024"))
                pub, priv = generate_keys(bits)
                save_key("public.key", pub)
                save_key("private.key", priv)
                print("\nKunci tersimpan: public.key dan private.key")
                print("JAGA private.key, jangan dibagikan!")
            elif choice == "2":
                src = ask("File yang dienkripsi")
                dst = ask("File hasil", src + ".enc")
                key = load_key(ask("File kunci publik", "public.key"))
                encrypt_file(src, dst, key)
            elif choice == "3":
                src = ask("File terenkripsi (.enc)")
                dst = ask("File hasil dekripsi", "hasil_dekripsi.out")
                key = load_key(ask("File kunci privat", "private.key"))
                decrypt_file(src, dst, key)
            elif choice == "0":
                break
            else:
                print("Pilihan tidak dikenal.")
        except FileNotFoundError as ex:
            print(f"Error: file tidak ditemukan -> {ex.filename}")
        except Exception as ex:
            print(f"Error: {ex}")


if __name__ == "__main__":
    main()
