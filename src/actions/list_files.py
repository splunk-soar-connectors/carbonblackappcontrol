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
        "field_name": "limit",
        "alias": "limit",
        "data_type": "numeric",
        "description": "Number of records to fetch in each response",
        "required": False,
        "primary": False,
        "default": None,
        "value_list": None,
        "contains": None,
    },
]
OUTPUT_FIELDS = [
    {
        "field_name": "id",
        "alias": "id",
        "data_type": "numeric",
        "contains": ["carbon black file id"],
        "example_values": [61],
        "column_name": "File ID",
    },
    {
        "field_name": "filename",
        "alias": "fileName",
        "data_type": "string",
        "example_values": ["agent disabled.msi.tmp"],
        "column_name": "File Name",
    },
    {"field_name": "uploadstatus", "alias": "uploadStatus", "data_type": "numeric", "example_values": [4], "column_name": "Upload Status"},
    {"field_name": "computerid", "alias": "computerId", "data_type": "numeric", "example_values": [1]},
    {"field_name": "count", "alias": "count", "data_type": "numeric", "example_values": [10]},
    {"field_name": "createdby", "alias": "createdBy", "data_type": "string", "example_values": ["apiuser"]},
    {"field_name": "createdbyuserid", "alias": "createdByUserId", "data_type": "numeric", "example_values": [1]},
    {"field_name": "datecreated", "alias": "dateCreated", "data_type": "string", "example_values": ["2017-05-28T00:05:07.213Z"]},
    {"field_name": "datemodified", "alias": "dateModified", "data_type": "string", "example_values": ["2017-05-28T00:05:07.213Z"]},
    {"field_name": "filecatalogid", "alias": "fileCatalogId", "data_type": "numeric", "example_values": [77575]},
    {
        "field_name": "pathname",
        "alias": "pathName",
        "data_type": "string",
        "example_values": ["c:\\program files (x86)\\bit9\\parity server\\hostpkg"],
    },
    {"field_name": "priority", "alias": "priority", "data_type": "numeric", "example_values": [0]},
    {"field_name": "uploadpath", "alias": "uploadPath", "data_type": "string", "example_values": ["/upload/path"]},
    {"field_name": "uploadedfilesize", "alias": "uploadedFileSize", "data_type": "numeric", "example_values": [0]},
]
SUMMARY_FIELDS = [
    {
        "field_name": "sdk_status_column",
        "alias": "sdk_status_column",
        "data_type": "string",
        "column_name": "Status",
        "example_values": ["success", "failed"],
    },
    {"field_name": "num_files", "alias": "num_files", "data_type": "numeric", "example_values": [10]},
    {"field_name": "total", "alias": "total", "data_type": "numeric", "example_values": [10]},
]

Params = make_params_model("ListFilesParams", PARAM_FIELDS)
Output = make_output_model("ListFilesOutput", OUTPUT_FIELDS)
Summary = make_output_model("ListFilesSummary", SUMMARY_FIELDS)


@app.action(
    identifier="list_files",
    description="List the files available on the controller",
    verbose="When provided -1 in limit parameter, it will return the count of the number of files available.",
    action_type="investigate",
    read_only=True,
    params_class=Params,
    output_class=Output,
    summary_type=Summary,
    render_as="table",
)
def list_files(params: Params, soar: SOARClient, asset: Asset) -> list[Output]:
    """List the files available on the controller"""
    return execute_action("list_files", params, soar, asset, Output, Summary)
