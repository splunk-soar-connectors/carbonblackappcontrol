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
    {
        "field_name": "offset",
        "alias": "offset",
        "data_type": "numeric",
        "description": "Offset in query results",
        "required": False,
        "primary": False,
        "default": 0,
        "value_list": None,
        "contains": None,
    },
]
OUTPUT_FIELDS = [
    {
        "field_name": "id",
        "alias": "id",
        "data_type": "numeric",
        "contains": ["carbon black policy id"],
        "example_values": [1],
        "column_name": "Policy ID",
    },
    {"field_name": "name", "alias": "name", "data_type": "string", "example_values": ["Test Policy"], "column_name": "Policy Name"},
    {
        "field_name": "connectedcomputers",
        "alias": "connectedComputers",
        "data_type": "numeric",
        "contains": ["carbon black computer id"],
        "column_name": "Connected Computer",
    },
    {"field_name": "allowagentupgrades", "alias": "allowAgentUpgrades", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "atenforcementcomputers", "alias": "atEnforcementComputers", "data_type": "numeric"},
    {"field_name": "automatic", "alias": "automatic", "data_type": "boolean", "example_values": [True, False]},
    {
        "field_name": "automaticapprovalsontransition",
        "alias": "automaticApprovalsOnTransition",
        "data_type": "boolean",
        "example_values": [True, False],
    },
    {"field_name": "clversionmax", "alias": "clVersionMax", "data_type": "numeric"},
    {"field_name": "computerid", "alias": "computerId", "data_type": "numeric", "example_values": [1]},
    {"field_name": "createdbyuserid", "alias": "createdByUserId", "data_type": "numeric"},
    {"field_name": "customlogo", "alias": "customLogo", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "datecreated", "alias": "dateCreated", "data_type": "string", "example_values": ["2022-02-04T12:10:48.643Z"]},
    {"field_name": "datemodified", "alias": "dateModified", "data_type": "string", "example_values": ["2022-11-15T02:13:12.76Z"]},
    {"field_name": "description", "alias": "description", "data_type": "string", "example_values": ["This is test policy"]},
    {"field_name": "disconnectedenforcementlevel", "alias": "disconnectedEnforcementLevel", "data_type": "numeric", "example_values": [60]},
    {"field_name": "enforcementlevel", "alias": "enforcementLevel", "data_type": "numeric", "example_values": [60]},
    {"field_name": "filetrackingenabled", "alias": "fileTrackingEnabled", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "helpdeskurl", "alias": "helpDeskUrl", "data_type": "string"},
    {"field_name": "hidden", "alias": "hidden", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "imageurl", "alias": "imageUrl", "data_type": "string"},
    {"field_name": "loadagentinsafemode", "alias": "loadAgentInSafeMode", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "modifiedbyuserid", "alias": "modifiedByUserId", "data_type": "numeric"},
    {"field_name": "packagename", "alias": "packageName", "data_type": "string"},
    {"field_name": "readonly", "alias": "readOnly", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "reputationenabled", "alias": "reputationEnabled", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "totalcomputers", "alias": "totalComputers", "data_type": "numeric"},
]
SUMMARY_FIELDS = [
    {
        "field_name": "sdk_status_column",
        "alias": "sdk_status_column",
        "data_type": "string",
        "column_name": "Status",
        "example_values": ["success", "failed"],
    },
    {"field_name": "num_policies", "alias": "num_policies", "data_type": "numeric", "example_values": [10]},
]

Params = make_params_model("ListPoliciesParams", PARAM_FIELDS)
Output = make_output_model("ListPoliciesOutput", OUTPUT_FIELDS)
Summary = make_output_model("ListPoliciesSummary", SUMMARY_FIELDS)


@app.action(
    identifier="list_policies",
    description="List the policies",
    verbose="This action requires the following permissions: <ul><li>View policies</li></ul><p>When <b>limit</b> is set to '0' or not set then all the policies will be returned. If set to '-1' then only the result count will be returned, without actual results.</p>",
    action_type="investigate",
    read_only=True,
    params_class=Params,
    output_class=Output,
    summary_type=Summary,
    render_as="table",
)
def list_policies(params: Params, soar: SOARClient, asset: Asset) -> list[Output]:
    """List the policies"""
    return execute_action("list_policies", params, soar, asset, Output, Summary)
