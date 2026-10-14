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
        "field_name": "computer_id",
        "alias": "computer_id",
        "data_type": "numeric",
        "description": "Computer Object Id",
        "required": True,
        "primary": True,
        "default": None,
        "value_list": None,
        "contains": ["carbon black computer id"],
    },
    {
        "field_name": "prioritized",
        "alias": "prioritized",
        "data_type": "boolean",
        "description": "Priority of computer",
        "required": False,
        "primary": False,
        "default": None,
        "value_list": None,
        "contains": None,
    },
    {
        "field_name": "description",
        "alias": "description",
        "data_type": "string",
        "description": "Description about computer",
        "required": False,
        "primary": False,
        "default": None,
        "value_list": None,
        "contains": None,
    },
    {
        "field_name": "computer_tag",
        "alias": "computer_tag",
        "data_type": "string",
        "description": "Tags for computer",
        "required": False,
        "primary": False,
        "default": None,
        "value_list": None,
        "contains": None,
    },
    {
        "field_name": "policy_id",
        "alias": "policy_id",
        "data_type": "string",
        "description": "New Id of policy for this computer",
        "required": False,
        "primary": True,
        "default": None,
        "value_list": None,
        "contains": ["carbon black policy id"],
    },
]
OUTPUT_FIELDS = [
    {"field_name": "id", "alias": "id", "data_type": "numeric", "contains": ["carbon black computer id"], "column_name": "COMPUTER ID"},
    {"field_name": "name", "alias": "name", "data_type": "string", "column_name": "Computer Name"},
    {"field_name": "prioritized", "alias": "prioritized", "data_type": "boolean", "column_name": "Prioritized"},
    {"field_name": "description", "alias": "description", "data_type": "string", "column_name": "Description"},
    {"field_name": "enforcementlevel", "alias": "enforcementLevel", "data_type": "numeric", "column_name": "Enforcement Level"},
    {"field_name": "computertag", "alias": "computerTag", "data_type": "string", "column_name": "Computer Tag"},
    {"field_name": "policyid", "alias": "policyId", "data_type": "numeric", "example_values": [2], "column_name": "Policy ID"},
    {"field_name": "policyname", "alias": "policyName", "data_type": "string", "example_values": ["Test Policy"], "column_name": "Policy Name"},
    {
        "field_name": "sdk_status_column",
        "alias": "sdk_status_column",
        "data_type": "string",
        "column_name": "Status",
        "example_values": ["success", "failed"],
    },
    {"field_name": "clipassword", "alias": "CLIPassword", "data_type": "string"},
    {"field_name": "scepstatus", "alias": "SCEPStatus", "data_type": "numeric", "example_values": [0]},
    {"field_name": "activedebugflags", "alias": "activeDebugFlags", "data_type": "numeric", "example_values": [16]},
    {"field_name": "activedebuglevel", "alias": "activeDebugLevel", "data_type": "numeric", "example_values": [0]},
    {"field_name": "activekerneldebuglevel", "alias": "activeKernelDebugLevel", "data_type": "numeric", "example_values": [2]},
    {"field_name": "agentcachesize", "alias": "agentCacheSize", "data_type": "numeric", "example_values": [35486]},
    {"field_name": "agentmemorydumps", "alias": "agentMemoryDumps", "data_type": "numeric", "example_values": [0]},
    {"field_name": "agentqueuesize", "alias": "agentQueueSize", "data_type": "numeric", "example_values": [0]},
    {"field_name": "agentversion", "alias": "agentVersion", "data_type": "string", "example_values": ["7.2.2.1119"]},
    {"field_name": "automaticpolicy", "alias": "automaticPolicy", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "cbsensorflags", "alias": "cbSensorFlags", "data_type": "numeric", "example_values": [0]},
    {"field_name": "cbsensorid", "alias": "cbSensorId", "data_type": "numeric", "example_values": [0]},
    {"field_name": "cbsensorversion", "alias": "cbSensorVersion", "data_type": "string"},
    {"field_name": "ccflags", "alias": "ccFlags", "data_type": "numeric", "example_values": [0]},
    {"field_name": "cclevel", "alias": "ccLevel", "data_type": "numeric", "example_values": [0]},
    {"field_name": "clversion", "alias": "clVersion", "data_type": "numeric", "example_values": [1767]},
    {"field_name": "connected", "alias": "connected", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "datecreated", "alias": "dateCreated", "data_type": "string", "example_values": ["2016-06-24T22:01:59.563Z"]},
    {"field_name": "daysoffline", "alias": "daysOffline", "data_type": "numeric", "example_values": [1493]},
    {"field_name": "debugduration", "alias": "debugDuration", "data_type": "numeric", "example_values": [0]},
    {"field_name": "debugflags", "alias": "debugFlags", "data_type": "numeric", "example_values": [0]},
    {"field_name": "debuglevel", "alias": "debugLevel", "data_type": "numeric", "example_values": [-1]},
    {"field_name": "deleted", "alias": "deleted", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "disconnectedenforcementlevel", "alias": "disconnectedEnforcementLevel", "data_type": "numeric", "example_values": [60]},
    {"field_name": "forceupgrade", "alias": "forceUpgrade", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "hasduplicates", "alias": "hasDuplicates", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "hashealthcheckerrors", "alias": "hasHealthCheckErrors", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "initpercent", "alias": "initPercent", "data_type": "numeric", "example_values": [100]},
    {"field_name": "initializing", "alias": "initializing", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "ipaddress", "alias": "ipAddress", "data_type": "string", "example_values": ["10.16.0.171"]},
    {"field_name": "isactive", "alias": "isActive", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "kerneldebuglevel", "alias": "kernelDebugLevel", "data_type": "numeric", "example_values": [0]},
    {"field_name": "lastpolldate", "alias": "lastPollDate", "data_type": "string", "example_values": ["2018-05-23T22:33:46.303Z"]},
    {"field_name": "lastregisterdate", "alias": "lastRegisterDate", "data_type": "string", "example_values": ["2018-05-23T22:33:08.987Z"]},
    {"field_name": "localapproval", "alias": "localApproval", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "macaddress", "alias": "macAddress", "data_type": "string", "example_values": ["00:50:56:86:D9:3E"]},
    {"field_name": "machinemodel", "alias": "machineModel", "data_type": "string", "example_values": ["VMware Virtual Platform"]},
    {"field_name": "memorysize", "alias": "memorySize", "data_type": "numeric", "example_values": [4096]},
    {
        "field_name": "osname",
        "alias": "osName",
        "data_type": "string",
        "example_values": ["Test Server 2008 R2 x64 Server Standard Service Pack 1 (6.1.7601)"],
    },
    {"field_name": "osshortname", "alias": "osShortName", "data_type": "string", "example_values": ["Windows Server 2008"]},
    {"field_name": "platformid", "alias": "platformId", "data_type": "numeric", "example_values": [1]},
    {"field_name": "policystatus", "alias": "policyStatus", "data_type": "string", "example_values": ["Approvals out of date"]},
    {
        "field_name": "policystatusdetails",
        "alias": "policyStatusDetails",
        "data_type": "string",
        "example_values": ["Agent did not receive all the rules yet"],
    },
    {"field_name": "previouspolicyid", "alias": "previousPolicyId", "data_type": "numeric", "example_values": [6]},
    {"field_name": "processorcount", "alias": "processorCount", "data_type": "numeric", "example_values": [2]},
    {
        "field_name": "processormodel",
        "alias": "processorModel",
        "data_type": "string",
        "example_values": ["Intel(R) Xeon(R) Silver 4116 CPU @ 2.10GHz"],
    },
    {"field_name": "processorspeed", "alias": "processorSpeed", "data_type": "numeric", "example_values": [2100]},
    {"field_name": "refreshflags", "alias": "refreshFlags", "data_type": "numeric", "example_values": [0]},
    {"field_name": "supportedkernel", "alias": "supportedKernel", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "syncflags", "alias": "syncFlags", "data_type": "numeric", "example_values": [136]},
    {"field_name": "syncpercent", "alias": "syncPercent", "data_type": "numeric", "example_values": [100]},
    {"field_name": "systemmemorydumps", "alias": "systemMemoryDumps", "data_type": "numeric", "example_values": [0]},
    {"field_name": "tamperprotectionactive", "alias": "tamperProtectionActive", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "tdcount", "alias": "tdCount", "data_type": "numeric", "example_values": [0]},
    {"field_name": "template", "alias": "template", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "templateclonecleanupmode", "alias": "templateCloneCleanupMode", "data_type": "string"},
    {"field_name": "templateclonecleanuptime", "alias": "templateCloneCleanupTime", "data_type": "string"},
    {"field_name": "templateclonecleanuptimescale", "alias": "templateCloneCleanupTimeScale", "data_type": "string"},
    {"field_name": "templatecomputerid", "alias": "templateComputerId", "data_type": "numeric", "example_values": [0]},
    {"field_name": "templatedate", "alias": "templateDate", "data_type": "string"},
    {"field_name": "templatetrackmodsonly", "alias": "templateTrackModsOnly", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "uninstalled", "alias": "uninstalled", "data_type": "boolean", "example_values": [True, False]},
    {"field_name": "upgradeerror", "alias": "upgradeError", "data_type": "string"},
    {"field_name": "upgradeerrorcount", "alias": "upgradeErrorCount", "data_type": "numeric", "example_values": [0]},
    {"field_name": "upgradeerrortime", "alias": "upgradeErrorTime", "data_type": "string"},
    {"field_name": "upgradestatus", "alias": "upgradeStatus", "data_type": "string", "example_values": ["Up to date"]},
    {"field_name": "users", "alias": "users", "data_type": "string"},
    {"field_name": "virtualplatform", "alias": "virtualPlatform", "data_type": "string", "example_values": ["VMware"]},
    {"field_name": "virtualized", "alias": "virtualized", "data_type": "string", "example_values": ["Yes"]},
]
SUMMARY_FIELDS = []

Params = make_params_model("UpdateComputerParams", PARAM_FIELDS)
Output = make_output_model("UpdateComputerOutput", OUTPUT_FIELDS)
Summary = None


@app.action(
    identifier="update_computer",
    description="Change computer object details",
    verbose="This action requires the following permission:<ul><li>View Computers</li><li>Manage Computers</li></ul>The policyID is ignored if either localApproval is True or automaticPolicy is True.",
    action_type="generic",
    read_only=False,
    params_class=Params,
    output_class=Output,
    render_as="table",
)
def update_computer(params: Params, soar: SOARClient, asset: Asset) -> list[Output]:
    """Change computer object details"""
    return execute_action("update_computer", params, soar, asset, Output, Summary)
