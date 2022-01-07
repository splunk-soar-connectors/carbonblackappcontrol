# File: bit9_connector.py
# Copyright (c) 2016-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom imports
# Other imports used by this connector
import json

import phantom.app as phantom
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# THIS Connector imports
from bit9_consts import *


class Bit9Connector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"
    ACTION_ID_HUNT_FILE = "hunt_file"
    ACTION_ID_WHITELIST = "whitelist"
    ACTION_ID_BLACKLIST = "blacklist"
    ACTION_ID_GET_SYSTEM_INFO = "get_system_info"
    ACTION_ID_UPLOAD_FILE = "upload_file"
    ACTION_ID_ANALYZE_FILE = "analyze_file"

    # This could be a list, but easier to read as a dictionary
    UPLOAD_STATUS_DESCS = {
            "0": "Queued",
            "1": "Initiated",
            "2": "Uploading",
            "3": "Completed",
            "4": "Error",
            "5": "Cancelled",
            "6": "Deleted"}

    ANALYSIS_STATUS_DESCS = {
            "0": "Scheduled",
            "1": "Submitted",
            "2": "Processed",
            "3": "Analyzed",
            "4": "Error",
            "5": "Cancelled"}

    def __init__(self):

        # Call the BaseConnectors init first
        super(Bit9Connector, self).__init__()

        self._base_url = None

    def initialize(self):

        config = self.get_config()

        self._headers = {'X-Auth-Token': config[BIT9_JSON_API_TOKEN], 'Content-Type': 'application/json'}
        self._base_url = "{0}{1}".format(config[BIT9_JSON_BASE_URL], BIT9_API_URI)
        self._comment = BIT9_ADDED_BY_PHANTOM.format(self.get_product_installation_id())

        return phantom.APP_SUCCESS

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):
        """ Function that makes the REST call to the device, generic function that can be called from various action handlers"""
        if headers is None:
            headers = {}

        # Get the config
        config = self.get_config()

        # Create the headers
        headers.update(self._headers)

        """
        if (method in ['put', 'post']):
            headers.update({'Content-Type': 'application/json'})
        """

        resp_json = None

        # get or post or put, whatever the caller asked us to use, if not specified the default will be 'get'
        request_func = getattr(requests, method)

        # handle the error in case the caller specified a non-existant method
        if not request_func:
            action_result.set_status(phantom.APP_ERROR, BIT9_ERR_API_UNSUPPORTED_METHOD, method=method)

        # Make the call
        try:
            r = request_func(self._base_url + endpoint,  # The complete url is made up of the base_url, the api url and the endpiont
                    data=json.dumps(data) if data else None,  # the data, converted to json string format if present, else just set to None
                    headers=headers,  # The headers to send in the HTTP call
                    verify=config[phantom.APP_JSON_VERIFY],  # should cert verification be carried out?
                    params=params)  # uri parameters if any
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, BIT9_ERR_SERVER_CONNECTION, e), resp_json)

        content_type = r.headers.get('content-type')

        if (content_type) and ('application/json' in content_type):
            # Try a json parse, since most REST API's give back the data in json, if the device does not return JSONs,
            # then need to implement parsing them some other manner
            try:
                resp_json = r.json()
            except Exception as e:
                # r.text is guaranteed to be NON None, it will be empty, but not None
                msg_string = BIT9_ERR_JSON_PARSE.format(raw_text=r.text)
                return (action_result.set_status(phantom.APP_ERROR, msg_string, e), resp_json)

        # Handle any special HTTP error codes here, many devices return an HTTP error code like 204. The requests module treats these as error,
        # so handle them here before anything else, uncomment the following lines in such cases
        # if (r.status_code == 201):
        #     return (phantom.APP_SUCCESS, resp_json)

        # Handle/process any errors that we get back from the device
        if 200 <= r.status_code <= 399:
            # Success
            return (phantom.APP_SUCCESS, resp_json)

        # Failure

        # init the string
        details = ""

        if resp_json:
            action_result.add_data(resp_json)
            details = json.dumps(resp_json).replace('{', '').replace('}', '')

        if r.status_code == 401:
            if details:
                details += ". "
            details += "Please verify the user has been configured with the required permissions as mentioned in the action documentation."

        return (action_result.set_status(phantom.APP_ERROR, BIT9_ERR_FROM_SERVER.format(status=r.status_code, detail=details)), resp_json)

    def _test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(param))

        self.save_progress("Testing the connection")
        self.save_progress("Making the API call to Carbon Black Protection")

        params = {'limit': -1}

        ret_val, resp_json = self._make_rest_call(FILE_CATALOG_ENDPOINT, action_result, params=params)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_hash_type(self, file_hash):

        if phantom.is_md5(file_hash):
            return "md5"

        if phantom.is_sha1(file_hash):
            return "sha1"

        if phantom.is_sha256(file_hash):
            return "sha256"

        return None

    def _get_file_catalog(self, file_hash, action_result):

        hash_type = self._get_hash_type(file_hash)

        if not hash_type:
            return action_result.set_status(phantom.APP_ERROR, "Unable to detect hash type")

        query = '{0}:{1}'.format(hash_type.upper(), file_hash)

        params = {'q': query}

        ret_val, resp_json = self._make_rest_call(FILE_CATALOG_ENDPOINT, action_result, params=params)

        if not ret_val:
            return (action_result.get_status(), None)

        if not resp_json:
            return (phantom.APP_SUCCESS, None)

        return (phantom.APP_SUCCESS, resp_json[0])

    def _unblock_hash(self, param):

        action_result = self.add_action_result(ActionResult(param))

        file_hash = param[phantom.APP_JSON_HASH]

        catalog_found = dict()

        # get rules for this hash
        ret_val, rules = self._get_rules_for_hash(file_hash, action_result, catalog_found)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not rules:
            return action_result.set_status(phantom.APP_ERROR, "No matching rules for the hash were found.")

        if len(rules) > 1:
            return action_result.set_status(phantom.APP_ERROR, "More than one rule matched for the hash. This is treated as an Error.")

        file_rule = rules[0]

        description = file_rule.get('description')

        if not description:
            return action_result.set_status(phantom.APP_ERROR, "Did not find a rule with Phantom tagged description to unblock")

        if self._comment.lower() not in description.lower():
            return action_result.set_status(phantom.APP_ERROR,
                                            "The rule for the given hash was not created by Phantom, cannot unblock the hash.")

        # check if the state of the file is what we wanted
        file_state = file_rule.get('fileState', BIT9_FILE_STATE_BANNED)

        unblock_state = BIT9_UNBLOCK_STATE_MAP[param.get(BIT9_JSON_UNBLOCK_STATE, BIT9_DEFAULT_UNBLOCK_STATE)]

        if str(file_state) == unblock_state:
            action_result.add_data(file_rule)
            return action_result.set_status(phantom.APP_SUCCESS, "State of file same as required")

        if (catalog_found) and ('id' in catalog_found):
            if file_rule.get('fileCatalogId', 0) == 0:
                file_rule['fileCatalogId'] = catalog_found['id']

        # set the file status to unblock
        file_rule['hash'] = file_hash

        if 'fileCatalogId' not in file_rule:
            file_rule['fileCatalogId'] = 0
        file_rule['policyIds'] = 0  # 0 for global rule
        file_rule['description'] = description

        file_rule['fileState'] = unblock_state

        ret_val, resp_json = self._make_rest_call(FILE_RULE_ENDPOINT, action_result, data=file_rule, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if resp_json:
            action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, "Updated rule successfully")

    def _get_rules_for_hash(self, file_hash, action_result, catalog_found=None):

        # Check if we can get a catalog id for this file
        ret_val, catalog = self._get_file_catalog(file_hash, action_result)

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)

        if catalog:
            if catalog_found is not None:
                catalog_found.update(catalog)

        # Try to find if there is already a rule with this specific hash
        params = {'q': 'hash:{0}'.format(file_hash)}
        ret_val, resp_json = self._make_rest_call(FILE_RULE_ENDPOINT, action_result, params=params)

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)

        if resp_json:
            self.save_progress("Found rule configured for Hash")
            # return it
            return (phantom.APP_SUCCESS, resp_json)

        # No rules for this hash, go the catalog way
        if not catalog:
            # No catalog, so no more rule finding catalog
            self.save_progress("File not found in Catalog")
            return (phantom.APP_SUCCESS, [])

        catalog_id = catalog.get('id')

        if not catalog_id:
            # No catalog, so no more rule finding catalog
            self.save_progress("File found in Catalog, but no ID")
            return (phantom.APP_SUCCESS, [])

        self.save_progress("Got Catalog ID: {0} for file".format(catalog_id))
        # got the catalog, now try to find the rules for this catalog
        params = {'q': 'fileCatalogId:{0}'.format(catalog_id)}

        ret_val, resp_json = self._make_rest_call(FILE_RULE_ENDPOINT, action_result, params=params)

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)

        return (phantom.APP_SUCCESS, resp_json)

    def _block_hash(self, param):

        action_result = self.add_action_result(ActionResult(param))

        file_hash = param[phantom.APP_JSON_HASH]

        catalog_found = dict()

        # get rules for this hash
        ret_val, rules = self._get_rules_for_hash(file_hash, action_result, catalog_found)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if len(rules) > 1:
            return action_result.set_status(phantom.APP_ERROR, "More than one rule matched for the hash. This is treated as an Error.")

        file_rule = {}

        if rules:
            self.save_progress("Got Rule for file")
            file_rule = rules[0]

        if (catalog_found) and ('id' in catalog_found):
            if file_rule.get('fileCatalogId', 0) == 0:
                file_rule['fileCatalogId'] = catalog_found['id']

        # check if the state of the file is what we wanted
        file_state = file_rule.get('fileState', BIT9_FILE_STATE_UNAPPROVED)

        if str(file_state) == BIT9_FILE_STATE_BANNED:
            action_result.add_data(file_rule)
            return action_result.set_status(phantom.APP_SUCCESS, "State of file same as required")

        # set the file status to Banned
        file_rule['hash'] = file_hash

        if 'fileCatalogId' not in file_rule:
            file_rule['fileCatalogId'] = 0
        file_rule['policyIds'] = 0  # 0 for global rule

        description = param.get(BIT9_JSON_DESCRIPTION)

        if description:
            description = "{0} - ".format(description)

        file_rule['description'] = "{0}{1}".format(description if description else '', self._comment)

        file_rule['fileState'] = BIT9_FILE_STATE_BANNED

        ret_val, resp_json = self._make_rest_call(FILE_RULE_ENDPOINT, action_result, data=file_rule, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if resp_json:
            action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, "Created/Updated rule successfully")

    def _hunt_file(self, param):

        action_result = self.add_action_result(ActionResult(param))

        file_hash = param[phantom.APP_JSON_HASH]

        # Check if we can get a catalog id for this file
        ret_val, catalog = self._get_file_catalog(file_hash, action_result)

        summary = action_result.update_summary({'prevalence': 0})

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not catalog:
            # No catalog, so no more rule finding catalog
            return action_result.set_status(phantom.APP_SUCCESS, "File not present in the catalog. Possibly not present in Enterprise.")

        catalog_id = catalog.get('id')

        if not catalog_id:
            # No catalog, so no more rule finding catalog
            return (phantom.APP_SUCCESS, [])

        summary['prevalence'] = catalog.get('prevalence', '0')

        action_result.add_data(catalog)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_system_info(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ip_hostname = param.get('ip_hostname')
        comp_id = param.get('id')

        if (not comp_id) and (not ip_hostname):
            return action_result.set_status(phantom.APP_ERROR,
                                            "Neither {0} nor {1} specified. Please specify at-least one of them".format('ip_hostname', 'id'))

        endpoint = '/computer'
        params = None

        if comp_id:
            endpoint += '/{0}'.format(comp_id)
        elif phantom.is_ip(ip_hostname):
            params = { 'q': 'ipAddress:*{0}*'.format(ip_hostname) }
        else:
            params = { 'q': 'name:*{0}*'.format(ip_hostname) }

        ret_val, resp_json = self._make_rest_call(endpoint, action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if type(resp_json) != list:
            resp_json = [resp_json]

        for curr_endpiont in resp_json:
            action_result.add_data(curr_endpiont)

        action_result.update_summary({'total_endpoints': len(resp_json)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _upload_file(self, param):

        action_result = self.add_action_result(ActionResult(param))

        comp_id = param['computer_id']
        file_id = param['file_id']

        endpoint = '/fileUpload'
        data = {'computerId': comp_id, 'fileCatalogId': file_id,
                'priority': param.get('priority', '0')}

        ret_val, resp_json = self._make_rest_call(endpoint, action_result, data=data, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if resp_json is None:
            return action_result.set_status(phantom.APP_ERROR, "File ID not found. Please provide a correct file ID")

        action_result.add_data(resp_json)

        upload_status = resp_json.get('uploadStatus')

        if upload_status is not None:
            summary = action_result.update_summary({'upload_status': upload_status})
            try:
                summary['upload_status_desc'] = self.UPLOAD_STATUS_DESCS[str(upload_status)]
            except:
                pass

        return action_result.set_status(phantom.APP_SUCCESS)

    def _analyze_file(self, param):

        action_result = self.add_action_result(ActionResult(param))

        comp_id = param['computer_id']
        file_id = param['file_id']
        target = param['target_type']
        connector_id = param['connector_id']

        endpoint = '/fileAnalysis'
        data = {'computerId': comp_id, 'fileCatalogId': file_id, 'connectorId': connector_id,
                'priority': param.get('priority', '0'),
                'analysisTarget': target}

        ret_val, resp_json = self._make_rest_call(endpoint, action_result, data=data, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if resp_json is None:
            return action_result.set_status(phantom.APP_ERROR, "File ID not found. Please provide a correct file ID")

        analysis_status = resp_json.get('analysisStatus')

        if type(resp_json) != list:
            resp_json = [resp_json]

        for curr_item in resp_json:
            action_result.add_data(curr_item)

        if analysis_status is not None:
            summary = action_result.update_summary({'analysis_status': analysis_status})
            try:
                summary['analysis_status_desc'] = self.ANALYSIS_STATUS_DESCS[str(analysis_status)]
            except:
                pass

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        """
        self.save_progress("Blocking on a breakpoint")
        import web_pdb
        web_pdb.set_trace()
        """

        result = None
        action = self.get_action_identifier()
        if action == self.ACTION_ID_WHITELIST:
            result = self._unblock_hash(param)

        elif action == self.ACTION_ID_TEST_CONNECTIVITY:
            result = self._test_connectivity(param)

        elif action == self.ACTION_ID_BLACKLIST:
            result = self._block_hash(param)

        elif action == self.ACTION_ID_HUNT_FILE:
            result = self._hunt_file(param)

        elif action == self.ACTION_ID_GET_SYSTEM_INFO:
            result = self._get_system_info(param)

        elif action == self.ACTION_ID_UPLOAD_FILE:
            result = self._upload_file(param)

        elif action == self.ACTION_ID_ANALYZE_FILE:
            result = self._analyze_file(param)

        return result


if __name__ == '__main__':

    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            login_url = BaseConnector._get_phantom_base_url() + 'login'
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = Bit9Connector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
