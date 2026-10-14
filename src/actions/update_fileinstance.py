from soar_sdk.abstract import SOARClient

from ..app import Asset, app
from ..helper import execute_action, make_output_model, make_params_model

PARAM_FIELDS = [
        {'field_name': 'instance_id', 'alias': 'instance_id', 'data_type': 'numeric', 'description': 'File Instance Id', 'required': True, 'primary': True, 'default': None, 'value_list': None, 'contains': None},
        {'field_name': 'local_state', 'alias': 'local_state', 'data_type': 'string', 'description': 'Local state to set', 'required': True, 'primary': False, 'default': None, 'value_list': ['unapproved', 'approved'], 'contains': None},
    ]
OUTPUT_FIELDS = [
        {'field_name': 'id', 'alias': 'id', 'data_type': 'numeric', 'contains': ['carbon black fileinstance id'], 'column_name': 'File Instance ID'},
        {'field_name': 'filecatalogid', 'alias': 'fileCatalogId', 'data_type': 'numeric', 'contains': ['carbon black filecatalog id'], 'column_name': 'File Catalog ID'},
        {'field_name': 'computerid', 'alias': 'computerId', 'data_type': 'numeric', 'contains': ['carbon black computer id'], 'column_name': 'Computer ID'},
        {'field_name': 'filename', 'alias': 'fileName', 'data_type': 'string', 'column_name': 'File Name'},
        {'field_name': 'sdk_status_column', 'alias': 'sdk_status_column', 'data_type': 'string', 'column_name': 'Status', 'example_values': ['success', 'failed']},
        {'field_name': 'certificateid', 'alias': 'certificateId', 'data_type': 'numeric', 'example_values': [153]},
        {'field_name': 'datecreated', 'alias': 'dateCreated', 'data_type': 'string', 'example_values': ['2016-06-24T22:04:17Z']},
        {'field_name': 'detachedcertificateid', 'alias': 'detachedCertificateId', 'data_type': 'string'},
        {'field_name': 'detachedpublisherid', 'alias': 'detachedPublisherId', 'data_type': 'string'},
        {'field_name': 'detailedlocalstate', 'alias': 'detailedLocalState', 'data_type': 'numeric', 'example_values': [4]},
        {'field_name': 'executed', 'alias': 'executed', 'data_type': 'boolean', 'example_values': [True, False]},
        {'field_name': 'fileinstancegroupid', 'alias': 'fileInstanceGroupId', 'data_type': 'numeric', 'example_values': [31]},
        {'field_name': 'initialized', 'alias': 'initialized', 'data_type': 'boolean', 'example_values': [True, False]},
        {'field_name': 'localstate', 'alias': 'localState', 'data_type': 'numeric'},
        {'field_name': 'pathname', 'alias': 'pathName', 'data_type': 'string'},
        {'field_name': 'policyid', 'alias': 'policyId', 'data_type': 'numeric', 'example_values': [5]},
        {'field_name': 'toplevel', 'alias': 'topLevel', 'data_type': 'boolean', 'example_values': [True, False]},
        {'field_name': 'unifiedsource', 'alias': 'unifiedSource', 'data_type': 'string'},
    ]
SUMMARY_FIELDS = [
    ]

Params = make_params_model('UpdateFileinstanceParams', PARAM_FIELDS)
Output = make_output_model('UpdateFileinstanceOutput', OUTPUT_FIELDS)
Summary = None

@app.action(
    name='update file instance',
    identifier='update_fileinstance',
    description='Change local file instance state',
    verbose='This action requires the following permission:<ul><li>View files</li><li>Change local state</li></ul><p>Note that changed local state might not be reflected in the object immediately, but only after agent reports new state.</p>',
    action_type='generic',
    read_only=False,
    params_class=Params,
    output_class=Output, render_as="table"
)
def update_fileinstance(params: Params, soar: SOARClient, asset: Asset) -> list[Output]:
    """Change local file instance state"""
    return execute_action('update_fileinstance', params, soar, asset, Output, Summary)
