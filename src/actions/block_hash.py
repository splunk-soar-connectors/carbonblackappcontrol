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
from ..views import hash_view

PARAM_FIELDS = [
    {
        "field_name": "hash",
        "alias": "hash",
        "data_type": "string",
        "description": "File Hash to block/ban",
        "required": True,
        "primary": True,
        "default": None,
        "value_list": None,
        "contains": ["hash", "sha256", "sha1", "md5"],
    },
    {
        "field_name": "comment",
        "alias": "comment",
        "data_type": "string",
        "description": "Description to add to the block rule",
        "required": False,
        "primary": False,
        "default": None,
        "value_list": None,
        "contains": None,
    },
]
OUTPUT_FIELDS = [
    {"field_name": "clversion", "alias": "clVersion", "data_type": "numeric"},
    {"field_name": "createdby", "alias": "createdBy", "data_type": "string"},
    {"field_name": "createdbyuserid", "alias": "createdByUserId", "data_type": "numeric"},
    {"field_name": "datecreated", "alias": "dateCreated", "data_type": "string"},
    {"field_name": "datemodified", "alias": "dateModified", "data_type": "string"},
    {"field_name": "description", "alias": "description", "data_type": "string"},
    {"field_name": "filecatalogid", "alias": "fileCatalogId", "data_type": "numeric"},
    {"field_name": "filename", "alias": "fileName", "data_type": "string"},
    {"field_name": "fileruletype", "alias": "fileRuleType", "data_type": "string", "example_values": ["Ban"]},
    {"field_name": "filestate", "alias": "fileState", "data_type": "numeric"},
    {"field_name": "forceinstaller", "alias": "forceInstaller", "data_type": "boolean"},
    {"field_name": "forcenotinstaller", "alias": "forceNotInstaller", "data_type": "boolean"},
    {"field_name": "hash", "alias": "hash", "data_type": "string"},
    {"field_name": "id", "alias": "id", "data_type": "numeric"},
    {"field_name": "idunique", "alias": "idUnique", "data_type": "string", "example_values": ["7bea0dcd-585e-413d-8559-4d4a2a4c3b3a"]},
    {"field_name": "lazyapproval", "alias": "lazyApproval", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "modifiedby", "alias": "modifiedBy", "data_type": "string"},
    {"field_name": "modifiedbyuserid", "alias": "modifiedByUserId", "data_type": "numeric"},
    {"field_name": "name", "alias": "name", "data_type": "string"},
    {"field_name": "origidunique", "alias": "origIdUnique", "data_type": "string"},
    {"field_name": "platformflags", "alias": "platformFlags", "data_type": "numeric", "example_values": [0]},
    {"field_name": "policyflags", "alias": "policyFlags", "data_type": "string"},
    {"field_name": "policyids", "alias": "policyIds", "data_type": "string"},
    {"field_name": "policyids", "alias": "policyIds", "data_type": "string"},
    {"field_name": "reportonly", "alias": "reportOnly", "data_type": "boolean"},
    {"field_name": "reputationapprovalsenabled", "alias": "reputationApprovalsEnabled", "data_type": "boolean"},
    {"field_name": "sourceid", "alias": "sourceId", "data_type": "numeric"},
    {"field_name": "sourcetype", "alias": "sourceType", "data_type": "numeric"},
    {"field_name": "unifiedflag", "alias": "unifiedFlag", "data_type": "string"},
    {"field_name": "unifiedsource", "alias": "unifiedSource", "data_type": "string"},
    {"field_name": "version", "alias": "version", "data_type": "numeric", "example_values": [183563]},
    {"field_name": "visible", "alias": "visible", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "view_hash", "alias": "view_hash", "data_type": "string"},
    {"field_name": "view_message", "alias": "view_message", "data_type": "string"},
]
SUMMARY_FIELDS = []

Params = make_params_model("BlockHashParams", PARAM_FIELDS)
Output = make_output_model("BlockHashOutput", OUTPUT_FIELDS)
Summary = None


@app.action(
    name="block hash",
    identifier="_block_hash",
    description="Ban the file hash",
    verbose="This action requires the following permissions: <ul><li>View files</li><li>Manage files</li></ul>Sets the global state of the file hash to <b>ban</b> by adding or updating a <i>file rule</i>. If a file is found in the catalog, the action will use the catalog id in the rule. The action also appends the SOAR Installation ID to the description of the rule. This is the action's way of tagging rules that are created by the app. If the action finds the current state of the file as <i>banned</i> it does not attempt to set the state, this also results in the description of the rule remaining unchanged.",
    action_type="contain",
    read_only=False,
    params_class=Params,
    output_class=Output,
    view_handler=hash_view,
)
def block_hash(params: Params, soar: SOARClient, asset: Asset) -> list[Output]:
    """Ban the file hash"""
    return execute_action("_block_hash", params, soar, asset, Output, Summary)
