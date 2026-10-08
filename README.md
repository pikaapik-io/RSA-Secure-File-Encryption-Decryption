# RSA File Encryption / Decryption

Program ini merupakan implementasi enkripsi dan dekripsi file berbasis RSA yang dibuat secara manual tanpa menggunakan library kriptografi pihak ketiga. Program ini menggunakan operasi RSA secara langsung dengan:

- pembangkitan bilangan prima,
- pembuatan kunci publik dan privat,
- padding PKCS#1-like tipe 2,
- enkripsi/dekripsi per blok file.

## Fitur utama

- Membuat kunci RSA otomatis: `public.key` dan `private.key`
- Mengenkripsi file sumber menjadi file `.enc`
- Mendekripsi file terenkripsi kembali ke file asli
- Menggunakan menu interaktif di terminal

## Persyaratan

Pastikan Python sudah terinstal di komputer Anda.

Contoh menjalankan:

```bash
python rsa_file_crypto.py
```

atau:

```bash
py rsa_file_crypto.py
```

## Alur pemakaian

Saat program dijalankan, akan muncul menu:

```text
===== RSA FILE ENCRYPTION / DECRYPTION =====
1. Bangkitkan kunci (public.key & private.key)
2. Enkripsi file
3. Dekripsi file
0. Keluar
```

### 1) Membuat kunci RSA

Pilih menu `1`.

Program akan meminta:

```text
Ukuran kunci (bit, min 512) [1024]:
```

Masukkan ukuran bit, misalnya `1024` atau `2048`.

Setelah selesai, program akan otomatis menyimpan:

- `public.key`
- `private.key`

> Catatan penting: `private.key` harus dijaga kerahasiaannya. Jangan dibagikan ke siapapun.

---

### 2) Mengenkripsi file

Pilih menu `2`.

Program akan meminta input berikut:

```text
File yang dienkripsi: tes.txt
File hasil: tes.txt.enc
File kunci publik: public.key
```

Penjelasan:

- `File yang dienkripsi` = file asli yang ingin diamankan
- `File hasil` = nama file terenkripsi, biasanya ditulis dengan ekstensi `.enc`
- `File kunci publik` = file `public.key` yang telah dibuat sebelumnya

Contoh:

```text
File yang dienkripsi: tes.txt
File hasil: tes.txt.enc
File kunci publik: public.key
```

Setelah selesai, file hasil enkripsi akan dibuat, misalnya:

- `tes.txt.enc`

---

### 3) Mendekripsi file

Pilih menu `3`.

Program akan meminta:

```text
File terenkripsi (.enc): tes.txt.enc
File hasil dekripsi: hasil_dekripsi.out
File kunci privat: private.key
```

Penjelasan:

- `File terenkripsi` = file hasil enkripsi `.enc`
- `File hasil dekripsi` = lokasi file yang akan dikembalikan ke bentuk aslinya
- `File kunci privat` = file `private.key`

Contoh:

```text
File terenkripsi (.enc): tes.txt.enc
File hasil dekripsi: hasil_dekripsi.out
File kunci privat: private.key
```

Jika kunci privat valid, file hasil dekripsi akan dibuat dan isinya akan sama dengan file asli.

---

## Contoh alur lengkap

```bash
python rsa_file_crypto.py
```

Lalu:

1. Pilih `1` untuk membuat kunci
2. Pilih `2` untuk mengenkripsi `tes.txt`
3. Pilih `3` untuk mendekripsi `tes.txt.enc`

---

## Catatan keamanan

- Gunakan `public.key` untuk enkripsi.
- Gunakan `private.key` untuk dekripsi.
- Jangan membagikan `private.key`.
- Gunakan ukuran kunci minimal `512` bit, disarankan `1024` atau lebih.

## Struktur file yang umum dibuat

```text
RSA/
├── rsa_file_crypto.py
├── README.md
├── public.key
├── private.key
├── tes.txt
├── tes.txt.enc
└── hasil_dekripsi.out
```

## Troubleshooting

### Error: file tidak ditemukan

Pastikan file input benar-benar ada di folder yang sama dengan program.

### Error: padding tidak valid

Biasanya terjadi karena:

- file yang didekripsi bukan hasil enkripsi dari kunci yang sama,
- `private.key` tidak sesuai dengan `public.key`,
- file ciphertext rusak atau tidak lengkap.

### Error: ukuran file cipher tidak sesuai dengan kunci

File terenkripsi kemungkinan sudah rusak atau tidak dibuat dengan ukuran blok yang sesuai.

---

