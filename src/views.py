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
from soar_sdk.action_results import PermissiveActionOutput

from .app import app
from .helper import hash_type


@app.view_handler(template="hash_view.html")
def hash_view(outputs: list[PermissiveActionOutput]) -> dict:
    """Prepare hash action outputs for the legacy hash summary widget."""
    results = []
    for output in outputs:
        values = output.model_dump(by_alias=True, exclude_none=True)
        file_hash = values.get("view_hash", "")
        results.append(
            {
                "hash": file_hash,
                "hash_type": hash_type(file_hash) or "hash",
                "message": values.get("view_message", ""),
            }
        )
    return {"results": results}
