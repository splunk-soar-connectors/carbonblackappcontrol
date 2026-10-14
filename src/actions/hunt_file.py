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
        "field_name": "hash",
        "alias": "hash",
        "data_type": "string",
        "description": "Hash value of the file",
        "required": True,
        "primary": True,
        "default": None,
        "value_list": None,
        "contains": ["hash", "sha256", "sha1", "md5"],
    },
]
OUTPUT_FIELDS = [
    {"field_name": "id", "alias": "id", "data_type": "numeric", "contains": ["carbon black filecatalog id"], "column_name": "File Catalog ID"},
    {"field_name": "prevalence", "alias": "prevalence", "data_type": "numeric", "column_name": "Prevalence"},
    {
        "field_name": "computerid",
        "alias": "computerId",
        "data_type": "numeric",
        "contains": ["carbon black computer id"],
        "column_name": "Computer ID",
    },
    {"field_name": "filename", "alias": "fileName", "data_type": "string", "column_name": "File Name"},
    {"field_name": "company", "alias": "company", "data_type": "string", "column_name": "Company"},
    {"field_name": "acknowledged", "alias": "acknowledged", "data_type": "boolean", "example_values": [True]},
    {"field_name": "approvedbyreputation", "alias": "approvedByReputation", "data_type": "boolean"},
    {"field_name": "category", "alias": "category", "data_type": "string"},
    {"field_name": "certificateid", "alias": "certificateId", "data_type": "numeric"},
    {"field_name": "certificatestate", "alias": "certificateState", "data_type": "numeric"},
    {"field_name": "clversion", "alias": "clVersion", "data_type": "numeric", "example_values": [1301]},
    {"field_name": "datecreated", "alias": "dateCreated", "data_type": "string"},
    {"field_name": "datemodified", "alias": "dateModified", "data_type": "string", "example_values": ["2022-03-15T05:47:21.997Z"]},
    {
        "field_name": "description",
        "alias": "description",
        "data_type": "string",
        "example_values": ["Test Malware Protection Signature Update Stub"],
    },
    {"field_name": "dirtyprevalence", "alias": "dirtyPrevalence", "data_type": "string"},
    {"field_name": "effectivestate", "alias": "effectiveState", "data_type": "string"},
    {"field_name": "fileextension", "alias": "fileExtension", "data_type": "string"},
    {"field_name": "fileflags", "alias": "fileFlags", "data_type": "numeric"},
    {"field_name": "filesize", "alias": "fileSize", "data_type": "numeric"},
    {"field_name": "filestate", "alias": "fileState", "data_type": "numeric"},
    {"field_name": "filetype", "alias": "fileType", "data_type": "string"},
    {"field_name": "globalstatedetails", "alias": "globalStateDetails", "data_type": "string"},
    {"field_name": "initialized", "alias": "initialized", "data_type": "boolean", "example_values": [False]},
    {"field_name": "installedprogramname", "alias": "installedProgramName", "data_type": "string"},
    {"field_name": "md5", "alias": "md5", "data_type": "string"},
    {"field_name": "nodetype", "alias": "nodeType", "data_type": "numeric", "example_values": [2]},
    {"field_name": "pathname", "alias": "pathName", "data_type": "string"},
    {"field_name": "productname", "alias": "productName", "data_type": "string"},
    {"field_name": "productversion", "alias": "productVersion", "data_type": "string"},
    {"field_name": "publisher", "alias": "publisher", "data_type": "string"},
    {"field_name": "publisherid", "alias": "publisherId", "data_type": "numeric"},
    {"field_name": "publisherorcompany", "alias": "publisherOrCompany", "data_type": "string"},
    {"field_name": "publisherstate", "alias": "publisherState", "data_type": "numeric"},
    {"field_name": "reputationavailable", "alias": "reputationAvailable", "data_type": "boolean"},
    {"field_name": "reputationenabled", "alias": "reputationEnabled", "data_type": "boolean"},
    {"field_name": "sha1", "alias": "sha1", "data_type": "string"},
    {"field_name": "sha256", "alias": "sha256", "data_type": "string"},
    {"field_name": "sha256hashtype", "alias": "sha256HashType", "data_type": "numeric"},
    {"field_name": "statesource", "alias": "stateSource", "data_type": "string"},
    {"field_name": "threat", "alias": "threat", "data_type": "numeric"},
    {"field_name": "transactionid", "alias": "transactionId", "data_type": "string"},
    {"field_name": "trust", "alias": "trust", "data_type": "numeric"},
    {"field_name": "trustmessages", "alias": "trustMessages", "data_type": "string"},
    {"field_name": "unifiedsource", "alias": "unifiedSource", "data_type": "string"},
    {"field_name": "verdict", "alias": "verdict", "data_type": "string"},
]
SUMMARY_FIELDS = [
    {
        "field_name": "sdk_status_column",
        "alias": "sdk_status_column",
        "data_type": "string",
        "column_name": "Status",
        "example_values": ["success", "failed"],
    },
    {"field_name": "prevalence", "alias": "prevalence", "data_type": "numeric"},
]

Params = make_params_model("HuntFileParams", PARAM_FIELDS)
Output = make_output_model("HuntFileOutput", OUTPUT_FIELDS)
Summary = make_output_model("HuntFileSummary", SUMMARY_FIELDS)


@app.action(
    identifier="hunt_file",
    description="Searches for a particular file across all the endpoints",
    verbose="This action requires the following permission: <ul><li>View files</li></ul>",
    action_type="investigate",
    read_only=True,
    params_class=Params,
    output_class=Output,
    summary_type=Summary,
    render_as="table",
)
def hunt_file(params: Params, soar: SOARClient, asset: Asset) -> list[Output]:
    """Searches for a particular file across all the endpoints"""
    return execute_action("hunt_file", params, soar, asset, Output, Summary)
