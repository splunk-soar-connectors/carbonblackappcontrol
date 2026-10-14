from soar_sdk.abstract import SOARClient

from ..app import Asset, app
from ..helper import execute_action, make_output_model, make_params_model

PARAM_FIELDS = [
        {'field_name': 'ip_hostname', 'alias': 'ip_hostname', 'data_type': 'string', 'description': 'Hostname/IP address to get info of', 'required': False, 'primary': True, 'default': None, 'value_list': None, 'contains': ['ip', 'host name']},
        {'field_name': 'id', 'alias': 'id', 'data_type': 'numeric', 'description': 'Computer id', 'required': False, 'primary': True, 'default': None, 'value_list': None, 'contains': ['carbon black computer id']},
    ]
OUTPUT_FIELDS = [
        {'field_name': 'id', 'alias': 'id', 'data_type': 'numeric', 'contains': ['carbon black computer id'], 'column_name': 'ID'},
        {'field_name': 'name', 'alias': 'name', 'data_type': 'string', 'column_name': 'Name'},
        {'field_name': 'ipaddress', 'alias': 'ipAddress', 'data_type': 'string', 'contains': ['ip'], 'column_name': 'IP Address'},
        {'field_name': 'macaddress', 'alias': 'macAddress', 'data_type': 'string', 'column_name': 'MAC Address'},
        {'field_name': 'isactive', 'alias': 'isActive', 'data_type': 'boolean', 'column_name': 'Is Active'},
        {'field_name': 'osname', 'alias': 'osName', 'data_type': 'string', 'column_name': 'OS Name'},
        {'field_name': 'clipassword', 'alias': 'CLIPassword', 'data_type': 'string'},
        {'field_name': 'scepstatus', 'alias': 'SCEPStatus', 'data_type': 'numeric'},
        {'field_name': 'activedebugflags', 'alias': 'activeDebugFlags', 'data_type': 'numeric'},
        {'field_name': 'activedebuglevel', 'alias': 'activeDebugLevel', 'data_type': 'numeric'},
        {'field_name': 'activekerneldebuglevel', 'alias': 'activeKernelDebugLevel', 'data_type': 'numeric'},
        {'field_name': 'agentcachesize', 'alias': 'agentCacheSize', 'data_type': 'numeric'},
        {'field_name': 'agentmemorydumps', 'alias': 'agentMemoryDumps', 'data_type': 'numeric'},
        {'field_name': 'agentqueuesize', 'alias': 'agentQueueSize', 'data_type': 'numeric'},
        {'field_name': 'agentversion', 'alias': 'agentVersion', 'data_type': 'string'},
        {'field_name': 'automaticpolicy', 'alias': 'automaticPolicy', 'data_type': 'boolean'},
        {'field_name': 'cbsensorflags', 'alias': 'cbSensorFlags', 'data_type': 'numeric'},
        {'field_name': 'cbsensorid', 'alias': 'cbSensorId', 'data_type': 'numeric'},
        {'field_name': 'cbsensorversion', 'alias': 'cbSensorVersion', 'data_type': 'string', 'example_values': ['5.1.1.60603']},
        {'field_name': 'ccflags', 'alias': 'ccFlags', 'data_type': 'numeric'},
        {'field_name': 'cclevel', 'alias': 'ccLevel', 'data_type': 'numeric'},
        {'field_name': 'clversion', 'alias': 'clVersion', 'data_type': 'numeric'},
        {'field_name': 'computertag', 'alias': 'computerTag', 'data_type': 'string'},
        {'field_name': 'connected', 'alias': 'connected', 'data_type': 'boolean'},
        {'field_name': 'datecreated', 'alias': 'dateCreated', 'data_type': 'string'},
        {'field_name': 'daysoffline', 'alias': 'daysOffline', 'data_type': 'numeric'},
        {'field_name': 'debugduration', 'alias': 'debugDuration', 'data_type': 'numeric'},
        {'field_name': 'debugflags', 'alias': 'debugFlags', 'data_type': 'numeric'},
        {'field_name': 'debuglevel', 'alias': 'debugLevel', 'data_type': 'numeric'},
        {'field_name': 'deleted', 'alias': 'deleted', 'data_type': 'boolean'},
        {'field_name': 'description', 'alias': 'description', 'data_type': 'string'},
        {'field_name': 'disconnectedenforcementlevel', 'alias': 'disconnectedEnforcementLevel', 'data_type': 'numeric'},
        {'field_name': 'enforcementlevel', 'alias': 'enforcementLevel', 'data_type': 'numeric'},
        {'field_name': 'forceupgrade', 'alias': 'forceUpgrade', 'data_type': 'boolean'},
        {'field_name': 'hasduplicates', 'alias': 'hasDuplicates', 'data_type': 'boolean'},
        {'field_name': 'hashealthcheckerrors', 'alias': 'hasHealthCheckErrors', 'data_type': 'boolean'},
        {'field_name': 'initpercent', 'alias': 'initPercent', 'data_type': 'numeric'},
        {'field_name': 'initializing', 'alias': 'initializing', 'data_type': 'boolean'},
        {'field_name': 'kerneldebuglevel', 'alias': 'kernelDebugLevel', 'data_type': 'numeric'},
        {'field_name': 'lastpolldate', 'alias': 'lastPollDate', 'data_type': 'string'},
        {'field_name': 'lastregisterdate', 'alias': 'lastRegisterDate', 'data_type': 'string'},
        {'field_name': 'localapproval', 'alias': 'localApproval', 'data_type': 'boolean'},
        {'field_name': 'machinemodel', 'alias': 'machineModel', 'data_type': 'string'},
        {'field_name': 'memorysize', 'alias': 'memorySize', 'data_type': 'numeric'},
        {'field_name': 'osshortname', 'alias': 'osShortName', 'data_type': 'string'},
        {'field_name': 'platformid', 'alias': 'platformId', 'data_type': 'numeric'},
        {'field_name': 'policyid', 'alias': 'policyId', 'data_type': 'numeric'},
        {'field_name': 'policyname', 'alias': 'policyName', 'data_type': 'string'},
        {'field_name': 'policystatus', 'alias': 'policyStatus', 'data_type': 'string'},
        {'field_name': 'policystatusdetails', 'alias': 'policyStatusDetails', 'data_type': 'string'},
        {'field_name': 'previouspolicyid', 'alias': 'previousPolicyId', 'data_type': 'numeric'},
        {'field_name': 'prioritized', 'alias': 'prioritized', 'data_type': 'boolean'},
        {'field_name': 'processorcount', 'alias': 'processorCount', 'data_type': 'numeric'},
        {'field_name': 'processormodel', 'alias': 'processorModel', 'data_type': 'string'},
        {'field_name': 'processorspeed', 'alias': 'processorSpeed', 'data_type': 'numeric'},
        {'field_name': 'refreshflags', 'alias': 'refreshFlags', 'data_type': 'numeric'},
        {'field_name': 'supportedkernel', 'alias': 'supportedKernel', 'data_type': 'boolean'},
        {'field_name': 'syncflags', 'alias': 'syncFlags', 'data_type': 'numeric'},
        {'field_name': 'syncpercent', 'alias': 'syncPercent', 'data_type': 'numeric'},
        {'field_name': 'systemmemorydumps', 'alias': 'systemMemoryDumps', 'data_type': 'numeric'},
        {'field_name': 'tamperprotectionactive', 'alias': 'tamperProtectionActive', 'data_type': 'boolean'},
        {'field_name': 'tdcount', 'alias': 'tdCount', 'data_type': 'numeric'},
        {'field_name': 'template', 'alias': 'template', 'data_type': 'boolean'},
        {'field_name': 'templateclonecleanupmode', 'alias': 'templateCloneCleanupMode', 'data_type': 'string'},
        {'field_name': 'templateclonecleanuptime', 'alias': 'templateCloneCleanupTime', 'data_type': 'numeric'},
        {'field_name': 'templateclonecleanuptimescale', 'alias': 'templateCloneCleanupTimeScale', 'data_type': 'numeric'},
        {'field_name': 'templatecomputerid', 'alias': 'templateComputerId', 'data_type': 'numeric'},
        {'field_name': 'templatedate', 'alias': 'templateDate', 'data_type': 'string'},
        {'field_name': 'templatetrackmodsonly', 'alias': 'templateTrackModsOnly', 'data_type': 'boolean'},
        {'field_name': 'uninstalled', 'alias': 'uninstalled', 'data_type': 'boolean'},
        {'field_name': 'upgradeerror', 'alias': 'upgradeError', 'data_type': 'string'},
        {'field_name': 'upgradeerrorcount', 'alias': 'upgradeErrorCount', 'data_type': 'numeric'},
        {'field_name': 'upgradeerrortime', 'alias': 'upgradeErrorTime', 'data_type': 'string'},
        {'field_name': 'upgradestatus', 'alias': 'upgradeStatus', 'data_type': 'string'},
        {'field_name': 'users', 'alias': 'users', 'data_type': 'string'},
        {'field_name': 'virtualplatform', 'alias': 'virtualPlatform', 'data_type': 'string'},
        {'field_name': 'virtualized', 'alias': 'virtualized', 'data_type': 'string'},
    ]
SUMMARY_FIELDS = [
        {'field_name': 'sdk_status_column', 'alias': 'sdk_status_column', 'data_type': 'string', 'column_name': 'Status', 'example_values': ['success', 'failed']},
        {'field_name': 'total_endpoints', 'alias': 'total_endpoints', 'data_type': 'numeric'},
    ]

Params = make_params_model('GetSystemInfoParams', PARAM_FIELDS)
Output = make_output_model('GetSystemInfoOutput', OUTPUT_FIELDS)
Summary = make_output_model('GetSystemInfoSummary', SUMMARY_FIELDS)

@app.action(
    identifier='get_system_info',
    description='Get information about an endpoint',
    verbose='This action requires the following permission: <ul><li>View computers</li></ul>',
    action_type='investigate',
    read_only=True,
    params_class=Params,
    output_class=Output, summary_type=Summary, render_as="table"
)
def get_system_info(params: Params, soar: SOARClient, asset: Asset) -> list[Output]:
    """Get information about an endpoint"""
    return execute_action('get_system_info', params, soar, asset, Output, Summary)
