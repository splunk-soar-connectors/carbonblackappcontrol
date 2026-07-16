import json
import unittest
from pathlib import Path

from CBAC_security import safe_vault_filename


ROOT = Path(__file__).parent


class ManifestSecurityTests(unittest.TestCase):
    def test_tls_verification_defaults_on(self):
        manifest = json.loads((ROOT / "carbonblackappcontrol.json").read_text())

        self.assertIs(manifest["configuration"]["verify_server_cert"]["default"], True)
        self.assertIn(
            "config.get(phantom.APP_JSON_VERIFY, True)",
            (ROOT / "CBAC_connector.py").read_text(),
        )

    def test_upstream_filename_is_reduced_to_display_name(self):
        self.assertEqual(safe_vault_filename("../../etc/passwd"), "passwd")
        self.assertEqual(safe_vault_filename(r"..\..\payload.bin"), "payload.bin")

        for invalid in (None, "", ".", "..", "path/.."):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    safe_vault_filename(invalid)

    def test_download_uses_anonymous_binary_vault_staging(self):
        source = (ROOT / "CBAC_connector.py").read_text()

        self.assertIn("tempfile.NamedTemporaryFile(dir=vault_tmp_dir", source)
        self.assertIn("file.write(resp.content)", source)
        self.assertNotIn('vault_tmp_dir + "/" + filename', source)

    def test_computer_id_is_validated_before_path_construction(self):
        source = (ROOT / "CBAC_connector.py").read_text()
        validation = 'self._validate_integer(action_result, comp_id, "Computer ID")'
        endpoint = 'endpoint += f"/{comp_id}"'

        self.assertIn(validation, source)
        self.assertLess(source.index(validation), source.index(endpoint))


if __name__ == "__main__":
    unittest.main()
