# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import unittest

from CBAC_security import redact_computer_credentials


class RedactComputerCredentialsTest(unittest.TestCase):
    def test_removes_cli_password_case_insensitively(self):
        computer = {"id": 7, "CLIPassword": "secret", "clipassword": "also-secret"}  # pragma: allowlist secret

        self.assertEqual(redact_computer_credentials(computer), {"id": 7})

    def test_does_not_mutate_input(self):
        computer = {"id": 7, "CLIPassword": "secret"}  # pragma: allowlist secret

        redact_computer_credentials(computer)

        self.assertEqual(computer["CLIPassword"], "secret")


if __name__ == "__main__":
    unittest.main()
