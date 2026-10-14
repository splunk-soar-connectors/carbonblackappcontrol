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
    {"field_name": "computerid", "alias": "computerId", "data_type": "numeric", "contains": ["carbon black computer id"]},
    {"field_name": "createdby", "alias": "createdBy", "data_type": "string"},
    {"field_name": "createdbyuserid", "alias": "createdByUserId", "data_type": "numeric"},
    {"field_name": "datecreated", "alias": "dateCreated", "data_type": "string"},
    {"field_name": "datemodified", "alias": "dateModified", "data_type": "string", "example_values": ["2017-05-28T00:05:07.213Z"]},
    {"field_name": "filecatalogid", "alias": "fileCatalogId", "data_type": "numeric"},
    {"field_name": "filename", "alias": "fileName", "data_type": "string"},
    {"field_name": "id", "alias": "id", "data_type": "numeric"},
    {"field_name": "pathname", "alias": "pathName", "data_type": "string", "contains": ["file path"]},
    {"field_name": "priority", "alias": "priority", "data_type": "numeric"},
    {"field_name": "uploadpath", "alias": "uploadPath", "data_type": "string"},
    {"field_name": "uploadstatus", "alias": "uploadStatus", "data_type": "numeric"},
    {"field_name": "uploadedfilesize", "alias": "uploadedFileSize", "data_type": "numeric", "example_values": [0]},
]
SUMMARY_FIELDS = [
    {"field_name": "upload_status_desc", "alias": "upload_status_desc", "data_type": "string", "column_name": "Upload Status"},
    {
        "field_name": "sdk_status_column",
        "alias": "sdk_status_column",
        "data_type": "string",
        "column_name": "Status",
        "example_values": ["success", "failed"],
    },
    {"field_name": "upload_status", "alias": "upload_status", "data_type": "numeric"},
]

Params = make_params_model("UploadFileParams", PARAM_FIELDS)
Output = make_output_model("UploadFileOutput", OUTPUT_FIELDS)
Summary = make_output_model("UploadFileSummary", SUMMARY_FIELDS)


@app.action(
    identifier="upload_file",
    description="Upload a file to a computer",
    verbose="This action requires the following permissions: <ul><li>View file uploads</li><li>Manage uploads of inventoried files</li></ul>It has been noticed that the default <b>admin</b> account does <i>not</i> have the required permissions to execute this action. Please create a new user with the required permissions for this app.",
    action_type="generic",
    read_only=False,
    params_class=Params,
    output_class=Output,
    summary_type=Summary,
    render_as="table",
)
def upload_file(params: Params, soar: SOARClient, asset: Asset) -> list[Output]:
    """Upload a file to a computer"""
    return execute_action("upload_file", params, soar, asset, Output, Summary)
