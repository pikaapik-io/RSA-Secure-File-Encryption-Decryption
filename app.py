#!/usr/bin/env python3

"""Bagian web dari program RSA.

File ini mengurus form, upload, download, lalu memanggil fungsi RSA di file
lain. Jadi, rumus RSA-nya ada di rsa_file_crypto.py, bukan di sini.
"""

from __future__ import annotations

import os  # Membaca pengaturan host, port, dan debug.
import base64  # Mengubah data biner menjadi teks yang bisa di-copy.
import shutil  # Menghapus folder sementara.
import tempfile  # Membuat folder sementara untuk satu proses.
import uuid  # Membuat ID dan token yang unik.
from pathlib import Path  # Memudahkan pengelolaan alamat file.
from typing import BinaryIO  # Menjelaskan tipe file upload.

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename  # Mencegah nama file berisi path traversal.

import rsa_file_crypto as rsa


# Mulai dari folder tempat file ini berada supaya lokasi data tetap benar
# walaupun program dijalankan dari folder lain.
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
KEY_DIR = DATA_DIR / "keys"

# Batas upload 16 MiB. Kalau tidak dibatasi, file besar bisa memenuhi server.
MAX_UPLOAD_BYTES = 16 * 1024 * 1024

app = Flask(__name__)  # Membuat aplikasi Flask.
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES  # Membatasi ukuran upload.

# Menyimpan token dan alamat file hasil. Browser cukup menerima tokennya saja.
DOWNLOADS: dict[str, Path] = {}


def _json_error(message: str, status: int = 400):
    # Semua error API dibuat dengan format yang sama agar mudah dibaca JavaScript.
    return jsonify({"ok": False, "error": message}), status


def _register_download(path: Path) -> str:
    # Token acak ini dipakai sebagai nama sementara di URL download.
    token = uuid.uuid4().hex
    DOWNLOADS[token] = path.resolve()
    return token


def _save_upload(upload: BinaryIO, directory: Path, fallback: str) -> Path:
    # Bersihkan nama file supaya input seperti ../file tidak bisa dipakai
    # untuk keluar dari folder kerja.
    filename = secure_filename(upload.filename or "")
    if not filename:
        raise ValueError(f"Nama {fallback} tidak valid.")
    path = directory / filename
    upload.save(path)  # Simpan isi upload ke folder kerja request.
    return path


def _key_from_request(directory: Path, field: str, key_type: str) -> tuple[int, int]:
    # Kunci bisa diambil dari server, ditempel sebagai teks, atau di-upload.
    key_id = request.form.get(f"{key_type}_key_id", request.form.get("key_id", "")).strip()
    if key_id:
        # ID kunci dibuat dari UUID hex, jadi bentuk yang diharapkan 32 karakter.
        if not key_id.isalnum() or len(key_id) != 32:
            raise ValueError("ID kunci tidak valid.")
        suffix = "public" if key_type == "public" else "private"
        key_path = KEY_DIR / f"{key_id}.{suffix}.key"
        if not key_path.is_file():
            raise ValueError("Kunci tersimpan tidak ditemukan.")
    else:
        key_text = request.form.get(f"{key_type}_key_text", "").strip()
        if key_text:
            try:
                # Isi kunci harus dua angka: n dan e untuk public, atau n dan d
                # untuk private.
                values = key_text.split()
                if len(values) != 2:
                    raise ValueError
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
    # Fungsi ini dipanggil Flask kalau ukuran upload melewati batas.
    return _json_error("Ukuran upload melebihi batas 16 MB.", 413)


@app.get("/")
def index():
    # Kirim batas ini ke halaman supaya tulisan di UI sesuai dengan server.
    return render_template("index.html", max_upload_mb=MAX_UPLOAD_BYTES // (1024 * 1024))


@app.post("/api/keys")
def generate_key_pair():
    # Buat pasangan public-private key dan simpan supaya bisa dipakai lagi.
    try:
        bits = int(request.form.get("bits", "1024"))  # Ukuran n dalam bit.
        if bits < 512:
            raise ValueError("Ukuran kunci minimal 512 bit.")
        public_key, private_key = rsa.generate_keys(bits, verbose=False)
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        key_id = uuid.uuid4().hex  # ID untuk mencari pasangan kunci ini.
        public_path = KEY_DIR / f"{key_id}.public.key"
        private_path = KEY_DIR / f"{key_id}.private.key"
        rsa.save_key(str(public_path), public_key)
        rsa.save_key(str(private_path), private_key)
        # Kunci juga dikirim sebagai teks supaya bisa langsung di-copy.
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
    # Enkripsi dan dekripsi memakai alur yang sama; yang berbeda hanya operasi
    # RSA dan jenis kuncinya.
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # Setiap request mendapat folder sendiri supaya nama file tidak bentrok.
    operation_dir = Path(tempfile.mkdtemp(prefix="rsa-operation-", dir=DATA_DIR))
    try:
        input_path = _input_path(request, operation_dir, operation)
        # Enkripsi pakai public key (n,e), dekripsi pakai private key (n,d).
        key_type = "public" if operation == "encrypt" else "private"
        key_field = "public_key" if operation == "encrypt" else "private_key"
        key = _key_from_request(operation_dir, key_field, key_type)

        # Nama file hasil juga harus dibersihkan.
        requested_name = secure_filename(request.form.get("output_name", "").strip())
        if not requested_name:
            requested_name = f"{input_path.name}.enc" if operation == "encrypt" else f"{input_path.stem}.decrypted"
        output_path = operation_dir / requested_name
        if output_path == input_path:
            raise ValueError("Nama file hasil harus berbeda dari file input.")

        if operation == "encrypt":
            rsa.encrypt_file(str(input_path), str(output_path), key, verbose=False)
        else:
            rsa.decrypt_file(str(input_path), str(output_path), key, verbose=False)
        token = _register_download(output_path)
        return jsonify(
            {
                "ok": True,
                "operation": operation,
                "input_name": input_path.name,
                "output_name": output_path.name,
                "download_url": f"/download/{token}",
                # Untuk mode teks, isi hasil dikirim juga. File biner diambil
                # lewat link download agar isinya tidak berubah.
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
        return _json_error(str(exc))
    finally:
        # Hasil yang sukses tetap disimpan karena masih dibutuhkan saat download.
        # Folder dari request yang gagal tidak punya token download, jadi aman
        # untuk langsung dihapus.
        if not any(path.parent == operation_dir for path in DOWNLOADS.values()):
            shutil.rmtree(operation_dir, ignore_errors=True)


def _input_path(form_request, operation_dir: Path, operation: str) -> Path:
    # Teks dibuat menjadi file sementara supaya alurnya sama seperti upload file.
    if form_request.form.get("input_mode", "file") == "text":
        text = form_request.form.get("input_text", "")
        if not text:
            raise ValueError("Masukkan teks terlebih dahulu.")
        input_path = operation_dir / "text-input.txt"
        if operation == "decrypt":
            # Hasil enkripsi yang ditempel di form berbentuk Base64.
            # validate=True memastikan teks Base64-nya benar.
            try:
                input_path.write_bytes(base64.b64decode(text, validate=True))
            except (ValueError, UnicodeError) as exc:
                raise ValueError("Ciphertext text bukan Base64 yang valid.") from exc
        else:
            input_path.write_text(text, encoding="utf-8")
        return input_path
    upload = form_request.files.get("input_file")
    if upload is None or not upload.filename:
        raise ValueError("Pilih file yang akan diproses.")
    return _save_upload(upload, operation_dir, "input file")


@app.post("/api/encrypt")
def encrypt():
    # Alamat API untuk proses enkripsi.
    return _process_file("encrypt")


@app.post("/api/decrypt")
def decrypt():
    # Alamat API untuk proses dekripsi.
    return _process_file("decrypt")


@app.get("/download/<token>")
def download(token: str):
    # Download hanya boleh dilakukan kalau token terdaftar dan file masih ada.
    path = DOWNLOADS.get(token)
    if path is None or not path.is_file():
        return _json_error("File hasil tidak ditemukan atau tautan sudah tidak berlaku.", 404)
    return send_file(path, as_attachment=True, download_name=path.name)


if __name__ == "__main__":
    # Bagian ini hanya jalan saat app.py dijalankan langsung.
    DATA_DIR.mkdir(exist_ok=True)
    app.run(
        host=os.environ.get("RSA_HOST", "127.0.0.1"),
        port=int(os.environ.get("RSA_PORT", "5000")),
        debug=os.environ.get("RSA_DEBUG") == "1",
    )
