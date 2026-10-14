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
from soar_sdk.abstract import SOARClient

from ..app import Asset, app
from ..helper import execute_action, make_output_model, make_params_model

PARAM_FIELDS = [
    {
        "field_name": "file_id",
        "alias": "file_id",
        "data_type": "numeric",
        "description": "File ID",
        "required": True,
        "primary": True,
        "default": None,
        "value_list": None,
        "contains": ["carbon black file id"],
        "column_name": "File ID",
    },
]
OUTPUT_FIELDS = [
    {
        "field_name": "vault_id",
        "alias": "vault_id",
        "data_type": "string",
        "contains": ["sha1", "vault id"],
        "example_values": ["g23959171fbf8e5ff48d8eff7c0f456345d2444"],
        "column_name": "Vault ID",
    },
    {
        "field_name": "file_name",
        "alias": "file_name",
        "data_type": "string",
        "example_values": ["ReporterLog-test.log"],
        "column_name": "File Name",
    },
]
SUMMARY_FIELDS = [
    {
        "field_name": "sdk_status_column",
        "alias": "sdk_status_column",
        "data_type": "string",
        "column_name": "Status",
        "example_values": ["success", "failed"],
    },
    {
        "field_name": "vault_id",
        "alias": "vault_id",
        "data_type": "string",
        "contains": ["sha1", "vault id"],
        "example_values": ["g23959171fbf8e5ff48d8eff7c0f456345d2444"],
    },
]

Params = make_params_model("GetFileParams", PARAM_FIELDS)
Output = make_output_model("GetFileOutput", OUTPUT_FIELDS)
Summary = make_output_model("GetFileSummary", SUMMARY_FIELDS)


@app.action(
    identifier="get_file",
    description="Get the file from the controller and add it to the vault",
    verbose="This will only add the file in vault, whose <b>uploadStatus</b> is 3 (Completed).",
    action_type="investigate",
    read_only=True,
    params_class=Params,
    output_class=Output,
    summary_type=Summary,
    render_as="table",
)
def get_file(params: Params, soar: SOARClient, asset: Asset) -> list[Output]:
    """Get the file from the controller and add it to the vault"""
    return execute_action("get_file", params, soar, asset, Output, Summary)
