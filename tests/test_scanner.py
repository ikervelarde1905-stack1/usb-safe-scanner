import tempfile
import unittest
from pathlib import Path

import scanner


class ScannerTests(unittest.TestCase):
    def test_detects_eicar_test_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            test_file = Path(directory) / "eicar-test.txt"
            test_file.write_bytes(scanner.EICAR_SIGNATURE)

            result = scanner.scan(test_file, set())

            self.assertIsNotNone(result)
            self.assertEqual("eicar-test-signature", result["reason"])

    def test_clean_file_is_not_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            test_file = Path(directory) / "notes.txt"
            test_file.write_text("ordinary text", encoding="utf-8")

            result = scanner.scan(test_file, set())

            self.assertIsNone(result)

    def test_hash_list_match_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            test_file = Path(directory) / "listed.bin"
            test_file.write_bytes(b"known test data")
            file_hash = scanner.sha256_file(test_file)

            result = scanner.scan(test_file, {file_hash})

            self.assertIsNotNone(result)
            self.assertEqual("hash", result["reason"])


if __name__ == "__main__":
    unittest.main()
