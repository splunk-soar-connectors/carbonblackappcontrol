import json
import unittest
from pathlib import Path

from CBAC_security import is_connector_owned_rule, is_global_rule_scope, is_report_only, redact_computer_credentials, safe_vault_filename


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

    def test_widget_escapes_hash_values_in_javascript(self):
        template = (ROOT / "hash_view.html").read_text()

        self.assertIn("result.param.hash_type|escapejs", template)
        self.assertIn("result.param.hash|escapejs", template)

    def test_computer_credentials_are_removed_from_results(self):
        original = {"id": 42, "CLIPassword": "secret", "name": "endpoint"}

        self.assertEqual(
            redact_computer_credentials(original),
            {"id": 42, "name": "endpoint"},
        )
        self.assertIn("CLIPassword", original)

        manifest = json.loads((ROOT / "carbonblackappcontrol.json").read_text())
        output_paths = {output["data_path"] for action in manifest["actions"] for output in action["output"]}
        self.assertNotIn("action_result.data.*.CLIPassword", output_paths)

    def test_vault_writing_action_is_not_read_only(self):
        manifest = json.loads((ROOT / "carbonblackappcontrol.json").read_text())
        get_file = next(action for action in manifest["actions"] if action["identifier"] == "get_file")

        self.assertIs(get_file["read_only"], False)
        self.assertEqual(get_file["type"], "generic")

    def test_file_rule_safety_classification(self):
        marker = "Added by Phantom"

        self.assertTrue(is_connector_owned_rule({"description": f"case note - {marker}"}, marker))
        self.assertFalse(is_connector_owned_rule({"description": "Created by an administrator"}, marker))
        for global_scope in (None, "", 0, "0", []):
            with self.subTest(global_scope=global_scope):
                self.assertTrue(is_global_rule_scope({"policyIds": global_scope}))
        self.assertFalse(is_global_rule_scope({"policyIds": [7]}))
        self.assertTrue(is_report_only({"reportOnly": True}))
        self.assertTrue(is_report_only({"reportOnly": "true"}))
        self.assertFalse(is_report_only({"reportOnly": False}))

    def test_file_rule_updates_enforce_ownership_and_scope(self):
        source = (ROOT / "CBAC_connector.py").read_text()

        self.assertGreaterEqual(source.count("is_connector_owned_rule(file_rule, self._comment)"), 2)
        self.assertGreaterEqual(source.count("is_global_rule_scope(file_rule)"), 2)
        self.assertGreaterEqual(source.count('file_rule["reportOnly"] = False'), 2)
        self.assertNotIn('file_rule["policyIds"] = 0  # 0 for global rule', source)


if __name__ == "__main__":
    unittest.main()
