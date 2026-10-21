from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


class DormCryptoTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows CNG is required")
    def test_matches_independent_windows_aes_ecb_pkcs7_vectors(self):
        from campus_net_assistant.dorm_crypto import encrypt_dorm_sso_value

        page_key = "AAECAwQFBgcICQoLDA0ODw=="
        self.assertEqual(encrypt_dorm_sso_value("test", page_key), "rzIqecVRld6ytjwJ6R5lRQ==")
        self.assertEqual(encrypt_dorm_sso_value("{}", page_key), "XjROMe16mC4WGbUXWRQLQA==")
        self.assertEqual(encrypt_dorm_sso_value("a中文", page_key), "sBH2AzHIY9sJ43P+jnnIyA==")

    def test_rejects_invalid_page_key_before_using_credentials(self):
        from campus_net_assistant.dorm_crypto import DormCryptoError, encrypt_dorm_sso_value

        with self.assertRaises(DormCryptoError):
            encrypt_dorm_sso_value("password", "not base64 !!!")
        with self.assertRaises(DormCryptoError):
            encrypt_dorm_sso_value("password", "a2V5")


if __name__ == "__main__":
    unittest.main()
