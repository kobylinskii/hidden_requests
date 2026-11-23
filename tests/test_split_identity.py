import hashlib
import io
import unittest
import zipfile
from unittest.mock import patch
from trace import installed_identity


class SplitIdentityTests(unittest.TestCase):
    def test_base_and_configuration_split_are_verified(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            archive.writestr('lib/x86_64/example.so', b'native')
        payload = data.getvalue()
        digest = hashlib.sha256(payload).hexdigest()
        with patch('trace.subprocess.check_output', side_effect=[
            'package:/app/base.apk\npackage:/app/split_config.x86_64.apk\n',
            'a' * 64 + ' base.apk', digest + ' split.apk', payload,
        ]):
            build, inventory = installed_identity('demo', 'device')
        self.assertEqual(build, 'a' * 64)
        self.assertEqual(len(inventory), 2)
        self.assertEqual(inventory[1]['sha256'], digest)

    def test_code_split_requires_static_analysis_of_additional_code(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            archive.writestr('classes.dex', b'code')
        payload = data.getvalue()
        with patch('trace.subprocess.check_output', side_effect=[
            'package:/app/base.apk\npackage:/app/split_feature.apk\n',
            'a' * 64 + ' base.apk',
            hashlib.sha256(payload).hexdigest() + ' split.apk', payload,
        ]):
            self.assertEqual(installed_identity('demo', 'device'), (None, []))
