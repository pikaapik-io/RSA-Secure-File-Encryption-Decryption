#!/usr/bin/env python3

"""Antarmuka web untuk program RSA.

File ini menjadi penghubung antara browser dan mesin kriptografi. Tugasnya
adalah menerima form atau upload, menyiapkan file sementara, memilih kunci yang
sesuai, lalu mengembalikan hasil sebagai respons JSON atau tautan download.
Rumus RSA dan pengolahan blok tetap berada di ``rsa_file_crypto.py`` supaya
logika kriptografi tidak bergantung pada jenis antarmukanya.
"""

from __future__ import annotations

import os  # Membaca pengaturan host, port, dan debug.
import base64  # Mengubah data biner menjadi teks yang bisa di-copy.
import shutil  # Menghapus folder sementara.
import tempfile  # Membuat folder sementara untuk satu proses.
import uuid  # Membuat ID dan token yang unik.
from pathlib import Path  # Memudahkan pengelolaan alamat file.
from typing import BinaryIO  # Menjelaskan tipe file upload.

from flask import Flask, jsonify, render_template, request, send_file  # Komponen Flask untuk route dan respons.
from werkzeug.utils import secure_filename  # Mencegah nama file berisi path traversal.

import rsa_file_crypto as rsa  # Mesin RSA yang dipakai oleh endpoint web.


# Gunakan folder file program sebagai titik awal. Dengan begitu, folder data
# tetap ditemukan dengan benar walaupun Flask dijalankan dari direktori lain.
BASE_DIR = Path(__file__).resolve().parent
# Semua file hasil dan kunci dikelompokkan di bawah folder data.
DATA_DIR = BASE_DIR / "data"
KEY_DIR = DATA_DIR / "keys"

# Batas upload 16 MiB. Batas ini mencegah satu request menghabiskan ruang
# penyimpanan atau memori server secara tidak terkontrol.
MAX_UPLOAD_BYTES = 16 * 1024 * 1024

app = Flask(__name__)  # Membuat objek aplikasi dan mendaftarkan route di bawahnya.
# Flask akan menolak request yang total ukurannya melewati batas ini.
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

# Browser cukup menerima token, bukan alamat file di server. Pemetaan ini juga
# membuat endpoint download tidak perlu mengekspos struktur folder internal.
DOWNLOADS: dict[str, Path] = {}


def _json_error(message: str, status: int = 400):
    # Semua error memakai bentuk yang sama agar JavaScript bisa menampilkan
    # pesan dengan konsisten tanpa menebak-nebak format respons.
    return jsonify({"ok": False, "error": message}), status


def _register_download(path: Path) -> str:
    # Token acak dipakai sebagai pengganti path asli pada URL download. UUID
    # juga mengurangi kemungkinan token mudah ditebak oleh pengguna lain.
    token = uuid.uuid4().hex
    # Simpan path absolut agar tetap tepat walaupun current working directory
    # berubah setelah request selesai.
    DOWNLOADS[token] = path.resolve()
    return token


def _save_upload(upload: BinaryIO, directory: Path, fallback: str) -> Path:
    # Nama file dari browser tidak boleh langsung dijadikan path. secure_filename
    # membuang bagian yang berbahaya seperti ../ sehingga upload tetap berada
    # di folder request yang sudah disiapkan.
    filename = secure_filename(upload.filename or "")
    if not filename:
        raise ValueError(f"Nama {fallback} tidak valid.")
    # Gabungkan nama yang sudah dibersihkan dengan folder request, bukan dengan
    # lokasi yang dikirim langsung oleh browser.
    path = directory / filename
    upload.save(path)  # Simpan isi upload ke folder kerja request.
    return path


def _key_from_request(directory: Path, field: str, key_type: str) -> tuple[int, int]:
    # Pengguna boleh memilih salah satu dari tiga cara: memakai key ID yang
    # tersimpan, menempelkan dua angka kunci sebagai teks, atau meng-upload
    # file kunci. Urutan di bawah ini menjaga ketiganya menghasilkan format
    # tuple yang sama untuk fungsi RSA.
    key_id = request.form.get(f"{key_type}_key_id", request.form.get("key_id", "")).strip()
    if key_id:
        # ID kunci dibuat dari UUID hex, sehingga bentuk yang diharapkan adalah
        # 32 karakter alfanumerik sebelum dipakai membentuk nama file.
        if not key_id.isalnum() or len(key_id) != 32:
            raise ValueError("ID kunci tidak valid.")
        suffix = "public" if key_type == "public" else "private"
        # Suffix dipilih dari jenis operasi agar public dan private key tidak
        # tertukar walaupun ID pasangannya sama.
        key_path = KEY_DIR / f"{key_id}.{suffix}.key"
        if not key_path.is_file():
            raise ValueError("Kunci tersimpan tidak ditemukan.")
    else:
        key_text = request.form.get(f"{key_type}_key_text", "").strip()
        if key_text:
            try:
                # Isi kunci mengikuti format sederhana di rsa_file_crypto.py:
                # dua angka, yaitu n dan e untuk public key atau n dan d untuk
                # private key. n adalah modulus yang dipakai kedua kunci.
                values = key_text.split()
                if len(values) != 2:
                    raise ValueError
                # Kembalikan lebih awal karena kunci teks tidak perlu dibaca
                # lagi dari file sementara.
                return int(values[0]), int(values[1])
            except ValueError as exc:
                raise ValueError(f"{key_type.title()} key text harus berisi dua angka: n dan e/d.") from exc
        upload = request.files.get(field)
        if upload is None or not upload.filename:
            raise ValueError(f"Pilih atau paste {key_type} key terlebih dahulu.")
        key_path = _save_upload(upload, directory, f"{key_type} key")
    try:
        return rsa.load_key(str(key_path))
    except (OSError, IndexError, ValueError) as exc:
        raise ValueError(f"{key_type.title()} key tidak valid.") from exc


@app.errorhandler(413)
def request_too_large(_error):
    # Flask memanggil handler ini sebelum endpoint memproses request yang
    # ukurannya melewati MAX_CONTENT_LENGTH.
    return _json_error("Ukuran upload melebihi batas 16 MB.", 413)


@app.get("/")
def index():
    # Kirim batas yang sama ke template agar informasi di halaman web tidak
    # berbeda dari aturan yang benar-benar diterapkan server.
    return render_template("index.html", max_upload_mb=MAX_UPLOAD_BYTES // (1024 * 1024))


@app.post("/api/keys")
def generate_key_pair():
    # Buat pasangan public-private key, simpan keduanya dengan ID yang sama,
    # lalu kirim salinan teksnya agar pengguna bisa menyimpan atau menyalin
    # kunci tersebut. Public key boleh dibagikan; private key harus dirahasiakan.
    try:
        # Parameter bits adalah target panjang modulus n = p * q. Di mesin RSA,
        # p dan q masing-masing kira-kira memakai setengah dari ukuran ini.
        bits = int(request.form.get("bits", "1024"))
        if bits < 512:
            raise ValueError("Ukuran kunci minimal 512 bit.")
        public_key, private_key = rsa.generate_keys(bits, verbose=False)
        # Pastikan folder penyimpanan tersedia sebelum dua file kunci dibuat.
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        key_id = uuid.uuid4().hex  # ID bersama untuk pasangan public dan private.
        public_path = KEY_DIR / f"{key_id}.public.key"
        private_path = KEY_DIR / f"{key_id}.private.key"
        # Kedua file memakai ID yang sama agar pasangan kuncinya mudah dicari.
        rsa.save_key(str(public_path), public_key)
        rsa.save_key(str(private_path), private_key)
        # Kunci juga dikirim sebagai teks supaya mudah langsung di-copy ke
        # form lain atau disimpan sebagai file dua baris.
        return jsonify(
            {
                "ok": True,
                "key_id": key_id,
                "public_key": {
                    "name": "public.key",
                    "text": f"{public_key[0]}\n{public_key[1]}",
                    "url": f"/download/{_register_download(public_path)}",
                },
                "private_key": {
                    "name": "private.key",
                    "text": f"{private_key[0]}\n{private_key[1]}",
                    "url": f"/download/{_register_download(private_path)}",
                },
            }
        )
    except (TypeError, ValueError) as exc:
        return _json_error(str(exc))


def _process_file(operation: str):
    # Enkripsi dan dekripsi memiliki alur web yang sama: siapkan input, baca
    # kunci, buat output, lalu berikan token download. Perbedaannya hanya pada
    # operasi RSA dan pasangan kunci yang dipakai.
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # Folder terpisah per request mencegah dua pengguna dengan nama file sama
    # saling menimpa file sementara.
    operation_dir = Path(tempfile.mkdtemp(prefix="rsa-operation-", dir=DATA_DIR))
    try:
        # Input selalu dinormalisasi menjadi path file, baik asalnya upload
        # maupun teks yang ditempel di browser.
        input_path = _input_path(request, operation_dir, operation)
        # Dalam RSA, enkripsi memakai public key (n, e) dengan rumus c = m^e
        # mod n, sedangkan dekripsi memakai private key (n, d) dengan rumus
        # m = c^d mod n. Pemilihan kunci dibuat eksplisit di sini agar tidak
        # tertukar ketika endpoint dipanggil.
        key_type = "public" if operation == "encrypt" else "private"
        key_field = "public_key" if operation == "encrypt" else "private_key"
        key = _key_from_request(operation_dir, key_field, key_type)

        # Nama output juga berasal dari pengguna, jadi perlakuannya harus sama
        # dengan nama file upload agar tidak bisa keluar dari folder request.
        requested_name = secure_filename(request.form.get("output_name", "").strip())
        if not requested_name:
            # Nama bawaan berbeda untuk enkripsi dan dekripsi agar hasil tidak
            # menimpa input secara tidak sengaja.
            requested_name = f"{input_path.name}.enc" if operation == "encrypt" else f"{input_path.stem}.decrypted"
        output_path = operation_dir / requested_name
        if output_path == input_path:
            raise ValueError("Nama file hasil harus berbeda dari file input.")

        if operation == "encrypt":
            # Fungsi ini membaca file input, memecahnya menjadi blok, lalu
            # menerapkan padding dan rumus c = m^e mod n.
            rsa.encrypt_file(str(input_path), str(output_path), key, verbose=False)
        else:
            # Fungsi ini menerapkan rumus m = c^d mod n lalu menghapus padding.
            rsa.decrypt_file(str(input_path), str(output_path), key, verbose=False)
        # Daftarkan output hanya setelah proses berhasil agar token tidak
        # mengarah ke file yang belum selesai atau gagal dibuat.
        token = _register_download(output_path)
        return jsonify(
            {
                "ok": True,
                "operation": operation,
                "input_name": input_path.name,
                "output_name": output_path.name,
                "download_url": f"/download/{token}",
                # Pada mode teks, isi hasil dikirim juga agar bisa ditampilkan
                # atau di-copy di browser. Hasil enkripsi berupa bytes, jadi
                # dikodekan Base64; hasil dekripsi teks dibaca sebagai UTF-8.
                # Untuk upload file biasa, hasil tetap diambil lewat download
                # agar isi biner tidak mengalami perubahan.
                "text_output": (
                    base64.b64encode(output_path.read_bytes()).decode("ascii")
                    if request.form.get("input_mode") == "text" and operation == "encrypt"
                    else output_path.read_text(encoding="utf-8")
                    if request.form.get("input_mode") == "text"
                    else None
                ),
            }
        )
    except (OSError, ValueError) as exc:
        # Kesalahan input, kunci, atau file dikembalikan sebagai JSON 400.
        return _json_error(str(exc))
    finally:
        # Hasil yang sukses tetap disimpan karena masih dibutuhkan saat URL
        # download dipanggil. Jika request gagal, tidak ada token yang menunjuk
        # ke folder ini sehingga folder sementara boleh dibersihkan.
        if not any(path.parent == operation_dir for path in DOWNLOADS.values()):
            shutil.rmtree(operation_dir, ignore_errors=True)


def _input_path(form_request, operation_dir: Path, operation: str) -> Path:
    # Teks diubah menjadi file sementara supaya enkripsi/dekripsi teks dan file
    # melewati fungsi RSA yang sama, bukan memiliki jalur kriptografi terpisah.
    if form_request.form.get("input_mode", "file") == "text":
        # Mode teks memakai field input_text; mode file memakai multipart file.
        text = form_request.form.get("input_text", "")
        if not text:
            raise ValueError("Masukkan teks terlebih dahulu.")
        input_path = operation_dir / "text-input.txt"
        if operation == "decrypt":
            # Ciphertext biner tidak aman ditempel langsung sebagai teks, maka
            # UI mengirimnya dalam Base64. validate=True menolak karakter atau
            # padding Base64 yang tidak valid sejak awal.
            try:
                input_path.write_bytes(base64.b64decode(text, validate=True))
            except (ValueError, UnicodeError) as exc:
                raise ValueError("Ciphertext text bukan Base64 yang valid.") from exc
        else:
            # Teks biasa disimpan UTF-8 sebelum masuk ke fungsi enkripsi.
            input_path.write_text(text, encoding="utf-8")
        return input_path
    upload = form_request.files.get("input_file")
    if upload is None or not upload.filename:
        raise ValueError("Pilih file yang akan diproses.")
    return _save_upload(upload, operation_dir, "input file")


@app.post("/api/encrypt")
def encrypt():
    # Endpoint ini hanya menentukan operasi; detail input, kunci, dan output
    # ditangani bersama oleh _process_file().
    return _process_file("encrypt")


@app.post("/api/decrypt")
def decrypt():
    # Endpoint pasangan enkripsi. Private key dipilih di dalam _process_file()
    # karena dekripsi tidak boleh menggunakan public key.
    return _process_file("decrypt")


@app.get("/download/<token>")
def download(token: str):
    # Download hanya dilayani untuk token yang dibuat server dan file yang masih
    # ada. Token yang tidak dikenal atau hasil yang sudah hilang dikembalikan
    # sebagai 404, bukan sebagai path file mentah.
    path = DOWNLOADS.get(token)
    # Pemeriksaan is_file mencegah server mengirim folder atau path yang sudah
    # tidak tersedia.
    if path is None or not path.is_file():
        return _json_error("File hasil tidak ditemukan atau tautan sudah tidak berlaku.", 404)
    return send_file(path, as_attachment=True, download_name=path.name)


if __name__ == "__main__":
    # Blok ini hanya berjalan ketika file dieksekusi langsung, bukan saat app
    # di-import oleh test atau server WSGI.
    DATA_DIR.mkdir(exist_ok=True)
    # Nilai konfigurasi dapat diubah lewat environment tanpa mengedit source.
    app.run(
        host=os.environ.get("RSA_HOST", "127.0.0.1"),
        port=int(os.environ.get("RSA_PORT", "5000")),
        debug=os.environ.get("RSA_DEBUG") == "1",
    )
