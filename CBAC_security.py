# File: CBAC_security.py
# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

from pathlib import PurePosixPath


def safe_vault_filename(value):
    """Reduce an upstream filename to a safe vault display name."""
    filename = PurePosixPath(str(value or "").replace("\\", "/")).name
    if filename in {"", ".", ".."}:
        raise ValueError("Invalid fileName returned by App Control")
    return filename


def redact_computer_credentials(computer):
    """Return a computer object without credential-bearing fields."""
    if not isinstance(computer, dict):
        return computer
    return {key: value for key, value in computer.items() if key.casefold() != "clipassword"}


def is_connector_owned_rule(rule, ownership_marker):
    """Return whether a file rule carries the connector ownership marker."""
    description = rule.get("description") if isinstance(rule, dict) else None
    return bool(description and ownership_marker.casefold() in description.casefold())


def is_global_rule_scope(rule):
    """Return whether a file rule applies globally rather than to selected policies."""
    policy_ids = rule.get("policyIds") if isinstance(rule, dict) else None
    return policy_ids in (None, "", 0, "0") or policy_ids == []


def is_report_only(rule):
    """Return whether a file rule reports matches without enforcing its state."""
    value = rule.get("reportOnly", False) if isinstance(rule, dict) else False
    return value is True or str(value).casefold() in {"1", "true"}
