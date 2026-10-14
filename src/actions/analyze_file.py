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
    {
        "field_name": "computer_id",
        "alias": "computer_id",
        "data_type": "numeric",
        "description": "Computer ID",
        "required": True,
        "primary": True,
        "default": None,
        "value_list": None,
        "contains": ["carbon black computer id"],
        "column_name": "Computer ID",
    },
    {
        "field_name": "connector_id",
        "alias": "connector_id",
        "data_type": "numeric",
        "description": "Connector ID",
        "required": True,
        "primary": True,
        "default": 1,
        "value_list": None,
        "contains": ["carbon black connector id"],
    },
    {
        "field_name": "target_type",
        "alias": "target_type",
        "data_type": "string",
        "description": "Analysis Target",
        "required": True,
        "primary": True,
        "default": "win7x64-sp1",
        "value_list": None,
        "contains": ["carbon black analysis target"],
    },
    {
        "field_name": "priority",
        "alias": "priority",
        "data_type": "numeric",
        "description": "Priority",
        "required": False,
        "primary": False,
        "default": 0,
        "value_list": [-2, -1, 0, 1, 2],
        "contains": None,
    },
]
OUTPUT_FIELDS = [
    {"field_name": "analysisresult", "alias": "analysisResult", "data_type": "numeric", "example_values": [0]},
    {"field_name": "analysisresult", "alias": "analysisResult", "data_type": "numeric", "example_values": [0]},
    {"field_name": "analysisstatus", "alias": "analysisStatus", "data_type": "numeric", "example_values": [0]},
    {"field_name": "analysisstatus", "alias": "analysisStatus", "data_type": "numeric", "example_values": [0]},
    {"field_name": "analysistarget", "alias": "analysisTarget", "data_type": "string", "example_values": ["win7x64-sp1"]},
    {"field_name": "analysistarget", "alias": "analysisTarget", "data_type": "string", "example_values": ["win7x64-sp1"]},
    {"field_name": "computerid", "alias": "computerId", "data_type": "numeric", "example_values": [1]},
    {"field_name": "computerid", "alias": "computerId", "data_type": "numeric", "example_values": [1]},
    {"field_name": "connectorid", "alias": "connectorId", "data_type": "numeric", "example_values": [1]},
    {"field_name": "connectorid", "alias": "connectorId", "data_type": "numeric", "example_values": [1]},
    {"field_name": "createdby", "alias": "createdBy", "data_type": "string", "example_values": ["admin"]},
    {"field_name": "createdby", "alias": "createdBy", "data_type": "string", "example_values": ["admin"]},
    {"field_name": "createdbyuserid", "alias": "createdByUserId", "data_type": "numeric", "example_values": [0]},
    {"field_name": "createdbyuserid", "alias": "createdByUserId", "data_type": "numeric", "example_values": [0]},
    {"field_name": "datecreated", "alias": "dateCreated", "data_type": "string", "example_values": ["2021-08-10T07:16:35.177Z"]},
    {"field_name": "datecreated", "alias": "dateCreated", "data_type": "string", "example_values": ["2020-07-09T21:14:53.937Z"]},
    {"field_name": "datemodified", "alias": "dateModified", "data_type": "string", "example_values": ["2021-08-10T07:16:35.19Z"]},
    {"field_name": "datemodified", "alias": "dateModified", "data_type": "string", "example_values": ["2020-07-09T23:13:46.96Z"]},
    {"field_name": "filecatalogid", "alias": "fileCatalogId", "data_type": "numeric", "example_values": [91]},
    {"field_name": "filecatalogid", "alias": "fileCatalogId", "data_type": "numeric", "example_values": [91]},
    {"field_name": "filename", "alias": "fileName", "data_type": "string", "example_values": ["4b1f58.rbf"]},
    {"field_name": "filename", "alias": "fileName", "data_type": "string", "example_values": ["4b1f58.rbf"]},
    {"field_name": "id", "alias": "id", "data_type": "numeric", "example_values": [12]},
    {"field_name": "id", "alias": "id", "data_type": "numeric", "example_values": [5]},
    {"field_name": "pathname", "alias": "pathName", "data_type": "string", "contains": ["file path"], "example_values": ["c:\\config.msi"]},
    {"field_name": "priority", "alias": "priority", "data_type": "numeric", "example_values": [0]},
    {"field_name": "priority", "alias": "priority", "data_type": "numeric", "example_values": [0]},
]
SUMMARY_FIELDS = [
    {
        "field_name": "analysis_status_desc",
        "alias": "analysis_status_desc",
        "data_type": "string",
        "example_values": ["Scheduled"],
        "column_name": "Analysis Status",
    },
    {
        "field_name": "sdk_status_column",
        "alias": "sdk_status_column",
        "data_type": "string",
        "column_name": "Status",
        "example_values": ["success", "failed"],
    },
    {"field_name": "analysis_status", "alias": "analysis_status", "data_type": "numeric", "example_values": [0]},
]

Params = make_params_model("AnalyzeFileParams", PARAM_FIELDS)
Output = make_output_model("AnalyzeFileOutput", OUTPUT_FIELDS)
Summary = make_output_model("AnalyzeFileSummary", SUMMARY_FIELDS)


@app.action(
    identifier="analyze_file",
    description="Analyze a file on a computer",
    verbose="This action requires the following permissions: <ul><li>View files</li><li>Submit files for analysis</li></ul>",
    action_type="investigate",
    read_only=False,
    params_class=Params,
    output_class=Output,
    summary_type=Summary,
    render_as="table",
)
def analyze_file(params: Params, soar: SOARClient, asset: Asset) -> list[Output]:
    """Analyze a file on a computer"""
    return execute_action("analyze_file", params, soar, asset, Output, Summary)
