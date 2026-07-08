import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from utils.file_inspector import inspect_file


class FileInspectorTests(unittest.TestCase):
    def test_unknown_extension_is_not_blocked_on_upload(self):
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as handle:
            handle.write(b'hello world')
            temp_path = handle.name

        try:
            result = inspect_file(temp_path)
            self.assertFalse(result['is_blocked'])
            self.assertTrue(result['upload_allowed'])
            self.assertFalse(result['download_blocked'])
        finally:
            os.remove(temp_path)

    def test_high_risk_extension_is_blocked_for_download(self):
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as handle:
            handle.write(b'hello world')
            temp_path = handle.name

        try:
            result = inspect_file(temp_path)
            self.assertFalse(result['is_blocked'])
            self.assertTrue(result['upload_allowed'])
            self.assertTrue(result['download_blocked'])
            self.assertEqual(result['risk_label'], 'HIGH')
        finally:
            os.remove(temp_path)


if __name__ == '__main__':
    unittest.main()
