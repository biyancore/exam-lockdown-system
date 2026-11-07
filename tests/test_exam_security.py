import io
import unittest

from cryptography.exceptions import InvalidTag
from PIL import Image

from modules.exam_security import (
    create_token, decrypt_pdf, embed_token, encrypt_pdf, extract_token, validate_token,
)


class ExamSecurityTests(unittest.TestCase):
    key = bytes(range(32))

    def cover(self, size=(100, 100), fmt="PNG"):
        buf = io.BytesIO()
        Image.new("RGB", size, "white").save(buf, format=fmt)
        return buf.getvalue()

    def test_pdf_roundtrip_randomness_and_tamper(self):
        pdf = b"%PDF-1.4\nconfidential exam\n%%EOF"
        encrypted = encrypt_pdf(pdf, self.key, 1)
        self.assertEqual(decrypt_pdf(encrypted, self.key, 1), pdf)
        self.assertNotIn(pdf, encrypted)
        self.assertNotEqual(encrypted, encrypt_pdf(pdf, self.key, 1))
        for data, key, exam in [
            (encrypted[:-1] + bytes([encrypted[-1] ^ 1]), self.key, 1),
            (encrypted, b"x" * 32, 1),
            (encrypted, self.key, 2),
        ]:
            with self.assertRaises(InvalidTag):
                decrypt_pdf(data, key, exam)

    def test_pdf_rejects_bad_header_and_size(self):
        for pdf in [b"not a PDF", b"%PDF-" + b"x" * (10 * 1024 * 1024)]:
            with self.assertRaises(ValueError):
                encrypt_pdf(pdf, self.key, 1)

    def test_token_is_bound_to_account_exam_and_expiry(self):
        token = create_token(self.key, 1, 2, 1000)
        self.assertIsNotNone(validate_token(token, self.key, 1, 2, now=999))
        self.assertIsNone(validate_token(token, self.key, 1, 2, now=1000))
        self.assertIsNone(validate_token(token, self.key, 1, 3, now=999))
        self.assertIsNone(validate_token(token, self.key, 2, 2, now=999))
        self.assertIsNone(validate_token(token, b"x" * 32, 1, 2, now=999))
        self.assertIsNone(validate_token("!" + token[1:], self.key, 1, 2, now=999))
        self.assertNotEqual(token, create_token(self.key, 1, 2, 1000))

    def test_png_roundtrip_and_pixel_change_limit(self):
        token = create_token(self.key, 1, 2, 1000)
        original = self.cover()
        png = embed_token(original, token)
        self.assertEqual(extract_token(png), token)
        before = Image.open(io.BytesIO(original)).tobytes()
        after = Image.open(io.BytesIO(png)).tobytes()
        self.assertTrue(all(abs(a - b) <= 1 for a, b in zip(before, after)))

    def test_rejects_ordinary_png_jpeg_and_tiny_cover(self):
        for data in [self.cover(), self.cover(fmt="JPEG"), b"not an image"]:
            with self.assertRaises(ValueError):
                extract_token(data)
        with self.assertRaises(ValueError):
            embed_token(self.cover(size=(8, 8)), create_token(self.key, 1, 2, 1000))


if __name__ == "__main__":
    unittest.main()
