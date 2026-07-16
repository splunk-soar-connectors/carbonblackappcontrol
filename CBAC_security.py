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
