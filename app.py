#!/usr/bin/env python3

"""Small web interface for the educational RSA implementation."""

from __future__ import annotations

import os
import base64
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import BinaryIO

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

import rsa_file_crypto as rsa


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
KEY_DIR = DATA_DIR / "keys"
MAX_UPLOAD_BYTES = 16 * 1024 * 1024

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
DOWNLOADS: dict[str, Path] = {}


def _json_error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


def _register_download(path: Path) -> str:
    token = uuid.uuid4().hex
    DOWNLOADS[token] = path.resolve()
    return token


def _save_upload(upload: BinaryIO, directory: Path, fallback: str) -> Path:
    filename = secure_filename(upload.filename or "")
    if not filename:
        raise ValueError(f"Nama {fallback} tidak valid.")
    path = directory / filename
    upload.save(path)
    return path


def _key_from_request(directory: Path, field: str, key_type: str) -> tuple[int, int]:
    key_id = request.form.get(f"{key_type}_key_id", request.form.get("key_id", "")).strip()
    if key_id:
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
    return _json_error("Ukuran upload melebihi batas 16 MB.", 413)


@app.get("/")
def index():
    return render_template("index.html", max_upload_mb=MAX_UPLOAD_BYTES // (1024 * 1024))


@app.post("/api/keys")
def generate_key_pair():
    try:
        bits = int(request.form.get("bits", "1024"))
        if bits < 512:
            raise ValueError("Ukuran kunci minimal 512 bit.")
        public_key, private_key = rsa.generate_keys(bits, verbose=False)
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        key_id = uuid.uuid4().hex
        public_path = KEY_DIR / f"{key_id}.public.key"
        private_path = KEY_DIR / f"{key_id}.private.key"
        rsa.save_key(str(public_path), public_key)
        rsa.save_key(str(private_path), private_key)
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
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    operation_dir = Path(tempfile.mkdtemp(prefix="rsa-operation-", dir=DATA_DIR))
    try:
        input_path = _input_path(request, operation_dir, operation)
        key_type = "public" if operation == "encrypt" else "private"
        key_field = "public_key" if operation == "encrypt" else "private_key"
        key = _key_from_request(operation_dir, key_field, key_type)

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
        # Keep successful output files available for downloads; failed requests
        # have no registered file and can be removed immediately.
        if not any(path.parent == operation_dir for path in DOWNLOADS.values()):
            shutil.rmtree(operation_dir, ignore_errors=True)


def _input_path(form_request, operation_dir: Path, operation: str) -> Path:
    if form_request.form.get("input_mode", "file") == "text":
        text = form_request.form.get("input_text", "")
        if not text:
            raise ValueError("Masukkan teks terlebih dahulu.")
        input_path = operation_dir / "text-input.txt"
        if operation == "decrypt":
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
    return _process_file("encrypt")


@app.post("/api/decrypt")
def decrypt():
    return _process_file("decrypt")


@app.get("/download/<token>")
def download(token: str):
    path = DOWNLOADS.get(token)
    if path is None or not path.is_file():
        return _json_error("File hasil tidak ditemukan atau tautan sudah tidak berlaku.", 404)
    return send_file(path, as_attachment=True, download_name=path.name)


if __name__ == "__main__":
    DATA_DIR.mkdir(exist_ok=True)
    app.run(
        host=os.environ.get("RSA_HOST", "127.0.0.1"),
        port=int(os.environ.get("RSA_PORT", "5000")),
        debug=os.environ.get("RSA_DEBUG") == "1",
    )
