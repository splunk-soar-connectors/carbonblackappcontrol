# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
from pathlib import Path

from CBAC_security import redact_cli_password


NON_READ_ONLY_ACTIONS = {
    "get_file",
    "get_fileinstances",
    "get_system_info",
    "hunt_file",
    "list_files",
    "list_policies",
}


def test_sensitive_actions_require_approval() -> None:
    manifest = json.loads(Path("carbonblackappcontrol.json").read_text())
    actions = {action["identifier"]: action for action in manifest["actions"]}

    assert all(actions[identifier]["read_only"] is False for identifier in NON_READ_ONLY_ACTIONS)
    assert actions["get_file"]["type"] == "generic"


def test_cli_password_is_removed_case_insensitively_and_recursively() -> None:
    response = {
        "id": 42,
        "CLIPassword": "top-level-secret",
        "nested": {
            "clipassword": "nested-secret",
            "safe": "value",
        },
        "items": [{"CliPassword": "list-secret", "name": "endpoint"}],
    }

    assert redact_cli_password(response) == {
        "id": 42,
        "nested": {"safe": "value"},
        "items": [{"name": "endpoint"}],
    }
