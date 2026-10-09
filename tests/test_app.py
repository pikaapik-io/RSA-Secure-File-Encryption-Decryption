import io
import base64
import tempfile
import unittest
from pathlib import Path

import app
import rsa_file_crypto as rsa


class WebAppTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        app.DATA_DIR = Path(self.temp.name) / "data"
        app.KEY_DIR = app.DATA_DIR / "keys"
        app.DOWNLOADS.clear()
        self.client = app.app.test_client()
        self.public, self.private = rsa.generate_keys(512, verbose=False)
        app.KEY_DIR.mkdir(parents=True)
        self.public_path = app.KEY_DIR / "public.key"
        self.private_path = app.KEY_DIR / "private.key"
        rsa.save_key(str(self.public_path), self.public)
        rsa.save_key(str(self.private_path), self.private)

    def tearDown(self):
        self.temp.cleanup()

    def test_encrypt_and_decrypt_binary_file(self):
        payload = b"\x00\x01binary\xff" * 20
        encrypted = self.client.post("/api/encrypt", data={
            "input_file": (io.BytesIO(payload), "../notes.bin"),
            "public_key": (io.BytesIO(self.public_path.read_bytes()), "../public.key"),
        }, content_type="multipart/form-data")
        self.assertEqual(encrypted.status_code, 200)
        encrypted_data = encrypted.get_json()
        downloaded = self.client.get(encrypted_data["download_url"])
        decrypted = self.client.post("/api/decrypt", data={
            "input_file": (io.BytesIO(downloaded.data), "notes.bin.enc"),
            "private_key": (io.BytesIO(self.private_path.read_bytes()), "private.key"),
        }, content_type="multipart/form-data")
        self.assertEqual(decrypted.status_code, 200)
        restored = self.client.get(decrypted.get_json()["download_url"])
        self.assertEqual(restored.data, payload)

    def test_wrong_key_and_unknown_download_fail(self):
        other_public, _ = rsa.generate_keys(512, verbose=False)
        encrypted = self.client.post("/api/encrypt", data={
            "input_file": (io.BytesIO(b"secret"), "secret.txt"),
            "public_key": (io.BytesIO(self.public_path.read_bytes()), "public.key"),
        }, content_type="multipart/form-data").get_json()
        cipher = self.client.get(encrypted["download_url"]).data
        response = self.client.post("/api/decrypt", data={
            "input_file": (io.BytesIO(cipher), "secret.enc"),
            "private_key": (io.BytesIO(rsa_key_bytes(other_public)), "wrong.key"),
        }, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.get("/download/not-a-token").status_code, 404)

    def test_text_encrypt_and_decrypt(self):
        encrypted = self.client.post("/api/encrypt", data={
            "input_mode": "text",
            "input_text": "Pesan yang bisa di-copy.",
            "public_key": (io.BytesIO(self.public_path.read_bytes()), "public.key"),
        }, content_type="multipart/form-data")
        self.assertEqual(encrypted.status_code, 200)
        encoded = encrypted.get_json()["text_output"]
        base64.b64decode(encoded, validate=True)
        decrypted = self.client.post("/api/decrypt", data={
            "input_mode": "text",
            "input_text": encoded,
            "private_key": (io.BytesIO(self.private_path.read_bytes()), "private.key"),
        }, content_type="multipart/form-data")
        self.assertEqual(decrypted.status_code, 200)
        self.assertEqual(decrypted.get_json()["text_output"], "Pesan yang bisa di-copy.")

    def test_key_text_encrypt_and_decrypt(self):
        public_text = rsa_key_bytes(self.public).decode()
        private_text = rsa_key_bytes(self.private).decode()
        encrypted = self.client.post("/api/encrypt", data={
            "input_mode": "text",
            "input_text": "Key juga bisa dipaste.",
            "public_key_text": public_text,
        }, content_type="multipart/form-data")
        self.assertEqual(encrypted.status_code, 200)
        decrypted = self.client.post("/api/decrypt", data={
            "input_mode": "text",
            "input_text": encrypted.get_json()["text_output"],
            "private_key_text": private_text,
        }, content_type="multipart/form-data")
        self.assertEqual(decrypted.status_code, 200)
        self.assertEqual(decrypted.get_json()["text_output"], "Key juga bisa dipaste.")


def rsa_key_bytes(key):
    return f"{key[0]}\n{key[1]}\n".encode()


if __name__ == "__main__":
    unittest.main()
