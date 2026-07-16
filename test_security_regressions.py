import json
import unittest
from pathlib import Path


ROOT = Path(__file__).parent


class ManifestSecurityTests(unittest.TestCase):
    def test_tls_verification_defaults_on(self):
        manifest = json.loads((ROOT / "carbonblackappcontrol.json").read_text())

        self.assertIs(manifest["configuration"]["verify_server_cert"]["default"], True)
        self.assertIn(
            "config.get(phantom.APP_JSON_VERIFY, True)",
            (ROOT / "CBAC_connector.py").read_text(),
        )


if __name__ == "__main__":
    unittest.main()
