from soar_sdk.abstract import SOARClient

from ..app import Asset, app
from ..helper import execute_action, make_output_model, make_params_model
from ..views import hash_view

PARAM_FIELDS = [
        {'field_name': 'hash', 'alias': 'hash', 'data_type': 'string', 'description': 'File Hash to unblock', 'required': True, 'primary': True, 'default': None, 'value_list': None, 'contains': ['hash', 'sha256', 'sha1', 'md5']},
        {'field_name': 'file_state', 'alias': 'file_state', 'data_type': 'string', 'description': 'File state to set', 'required': False, 'primary': False, 'default': 'unapproved', 'value_list': ['unapproved', 'approved'], 'contains': None},
    ]
OUTPUT_FIELDS = [
        {'field_name': 'clversion', 'alias': 'clVersion', 'data_type': 'numeric'},
        {'field_name': 'createdby', 'alias': 'createdBy', 'data_type': 'string'},
        {'field_name': 'createdbyuserid', 'alias': 'createdByUserId', 'data_type': 'numeric'},
        {'field_name': 'datecreated', 'alias': 'dateCreated', 'data_type': 'string'},
        {'field_name': 'datemodified', 'alias': 'dateModified', 'data_type': 'string'},
        {'field_name': 'description', 'alias': 'description', 'data_type': 'string'},
        {'field_name': 'filecatalogid', 'alias': 'fileCatalogId', 'data_type': 'numeric'},
        {'field_name': 'filename', 'alias': 'fileName', 'data_type': 'string'},
        {'field_name': 'fileruletype', 'alias': 'fileRuleType', 'data_type': 'string', 'example_values': ['Unapproved']},
        {'field_name': 'filestate', 'alias': 'fileState', 'data_type': 'numeric'},
        {'field_name': 'forceinstaller', 'alias': 'forceInstaller', 'data_type': 'boolean'},
        {'field_name': 'forcenotinstaller', 'alias': 'forceNotInstaller', 'data_type': 'boolean'},
        {'field_name': 'hash', 'alias': 'hash', 'data_type': 'string'},
        {'field_name': 'id', 'alias': 'id', 'data_type': 'numeric'},
        {'field_name': 'idunique', 'alias': 'idUnique', 'data_type': 'string', 'example_values': ['502b2e2d-570f-4917-acc8-8f7083edfe66']},
        {'field_name': 'lazyapproval', 'alias': 'lazyApproval', 'data_type': 'boolean', 'example_values': [True, False]},
        {'field_name': 'modifiedby', 'alias': 'modifiedBy', 'data_type': 'string'},
        {'field_name': 'modifiedbyuserid', 'alias': 'modifiedByUserId', 'data_type': 'numeric'},
        {'field_name': 'name', 'alias': 'name', 'data_type': 'string'},
        {'field_name': 'origidunique', 'alias': 'origIdUnique', 'data_type': 'string'},
        {'field_name': 'platformflags', 'alias': 'platformFlags', 'data_type': 'numeric', 'example_values': [0]},
        {'field_name': 'policyids', 'alias': 'policyIds', 'data_type': 'string'},
        {'field_name': 'reportonly', 'alias': 'reportOnly', 'data_type': 'boolean'},
        {'field_name': 'reputationapprovalsenabled', 'alias': 'reputationApprovalsEnabled', 'data_type': 'boolean'},
        {'field_name': 'sourceid', 'alias': 'sourceId', 'data_type': 'numeric'},
        {'field_name': 'sourcetype', 'alias': 'sourceType', 'data_type': 'numeric'},
        {'field_name': 'unifiedflag', 'alias': 'unifiedFlag', 'data_type': 'string'},
        {'field_name': 'unifiedsource', 'alias': 'unifiedSource', 'data_type': 'string'},
        {'field_name': 'version', 'alias': 'version', 'data_type': 'numeric', 'example_values': [184467]},
        {'field_name': 'visible', 'alias': 'visible', 'data_type': 'boolean', 'example_values': [True, False]},
        {'field_name': 'view_hash', 'alias': 'view_hash', 'data_type': 'string'},
        {'field_name': 'view_message', 'alias': 'view_message', 'data_type': 'string'},
    ]
SUMMARY_FIELDS = [
    ]

Params = make_params_model('UnblockHashParams', PARAM_FIELDS)
Output = make_output_model('UnblockHashOutput', OUTPUT_FIELDS)
Summary = None

@app.action(
    name='unblock hash',
    identifier='_unblock_hash',
    description='Unblocks a particular hash',
    verbose='This action requires the following permissions: <ul><li>View files</li><li>Manage files</li></ul>Sets the global state of the hash to either <b>approved</b> or <b>unapproved</b> by updating the file rule. If the action does not find a rule for the hash, it will return an error. If the hash rule found by the action does not contain a description containing a matching SOAR Identification ID, it will return an error status without changing the state of the rule. This is to make sure the app only modifies rules that have been created or updated by itself.',
    action_type='correct',
    read_only=False,
    params_class=Params,
    output_class=Output, view_handler=hash_view
)
def unblock_hash(params: Params, soar: SOARClient, asset: Asset) -> list[Output]:
    """Unblocks a particular hash"""
    return execute_action('_unblock_hash', params, soar, asset, Output, Summary)
