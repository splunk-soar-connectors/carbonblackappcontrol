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
        "field_name": "filecatalog_id",
        "alias": "filecatalog_id",
        "data_type": "numeric",
        "description": "Id of fileCatalog associated with this file instance",
        "required": True,
        "primary": True,
        "default": None,
        "value_list": None,
        "contains": ["carbon black filecatalog id"],
    },
    {
        "field_name": "computer_id",
        "alias": "computer_id",
        "data_type": "numeric",
        "description": "Id of computer associated with this file instance",
        "required": True,
        "primary": True,
        "default": None,
        "value_list": None,
        "contains": ["carbon black computer id"],
    },
]
OUTPUT_FIELDS = [
    {"field_name": "id", "alias": "id", "data_type": "numeric", "contains": ["carbon black fileinstance id"], "column_name": "File Instance ID"},
    {
        "field_name": "filecatalogid",
        "alias": "fileCatalogId",
        "data_type": "numeric",
        "contains": ["carbon black filecatalog id"],
        "column_name": "File Catalog ID",
    },
    {
        "field_name": "computerid",
        "alias": "computerId",
        "data_type": "numeric",
        "contains": ["carbon black computer id"],
        "column_name": "Computer ID",
    },
    {"field_name": "filename", "alias": "fileName", "data_type": "string", "column_name": "File Name"},
    {
        "field_name": "sdk_status_column",
        "alias": "sdk_status_column",
        "data_type": "string",
        "column_name": "Status",
        "example_values": ["success", "failed"],
    },
    {"field_name": "certificateid", "alias": "certificateId", "data_type": "numeric"},
    {"field_name": "datecreated", "alias": "dateCreated", "data_type": "string", "example_values": ["2017-04-11T20:28:45Z"]},
    {"field_name": "detachedcertificateid", "alias": "detachedCertificateId", "data_type": "string"},
    {"field_name": "detachedpublisherid", "alias": "detachedPublisherId", "data_type": "string"},
    {"field_name": "detailedlocalstate", "alias": "detailedLocalState", "data_type": "numeric", "example_values": [14]},
    {"field_name": "executed", "alias": "executed", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "fileinstancegroupid", "alias": "fileInstanceGroupId", "data_type": "numeric", "example_values": [433]},
    {"field_name": "initialized", "alias": "initialized", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "localstate", "alias": "localState", "data_type": "numeric"},
    {"field_name": "pathname", "alias": "pathName", "data_type": "string"},
    {"field_name": "policyid", "alias": "policyId", "data_type": "numeric", "example_values": [1]},
    {"field_name": "toplevel", "alias": "topLevel", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "unifiedsource", "alias": "unifiedSource", "data_type": "string"},
]
SUMMARY_FIELDS = []

Params = make_params_model("GetFileinstancesParams", PARAM_FIELDS)
Output = make_output_model("GetFileinstancesOutput", OUTPUT_FIELDS)
Summary = None


@app.action(
    name="get file instances",
    identifier="get_fileinstances",
    description="Searches for file instances",
    verbose="This action requires the following permission: <ul><li>View files</li></ul>",
    action_type="generic",
    read_only=True,
    params_class=Params,
    output_class=Output,
    render_as="table",
)
def get_fileinstances(params: Params, soar: SOARClient, asset: Asset) -> list[Output]:
    """Searches for file instances"""
    return execute_action("get_fileinstances", params, soar, asset, Output, Summary)
