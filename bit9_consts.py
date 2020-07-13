# File: bit9_consts.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

ERROR_PARSING_JSON = "Error parsing the response as JSON"
BIT9_JSON_BASE_URL = "base_url"
BIT9_JSON_API_TOKEN = "api_token"
BIT9_JSON_DESCRIPTION = "comment"
BIT9_JSON_UNBLOCK_STATE = "file_state"

VERIFY_CERT = "verify_server_cert"
FILE_CATALOG_ENDPOINT = "/filecatalog"
FILE_RULE_ENDPOINT = "/fileRule"
CAT_ID_DATA = "fileCatalogId:%s"
APPEND_HASHES = "%s:%s"
LISTDECISION_MAP = {"white": "2", "black": "3"}
APPEND_NOT_POLICY = "%s%s"
B9FID = "id"
DECISION_MAP = {"local_approval": "localState", "global_approval": "fileState"}
BIT9_API_URI = "/api/bit9platform/v1"

BIT9_ERR_FROM_SERVER = "API failed, Status code: {status}, Detail: {detail}"
BIT9_ERR_JSON_PARSE = "Unable to parse reply as a Json, raw string reply: '{raw_text}'"
BIT9_ERR_JSON_PARSE = "Unable to parse reply as a Json, raw string reply: '{raw_text}'"
BIT9_ERR_API_UNSUPPORTED_METHOD = "Unsupported method"
BIT9_ERR_SERVER_CONNECTION = "Connection failed"

BIT9_FILE_STATE_UNAPPROVED = "1"
BIT9_FILE_STATE_APPROVED = "2"
BIT9_FILE_STATE_BANNED = "3"

BIT9_UNBLOCK_STATE_MAP = {"approved": BIT9_FILE_STATE_APPROVED, "unapproved": BIT9_FILE_STATE_UNAPPROVED}
BIT9_DEFAULT_UNBLOCK_STATE = "unapproved"
BIT9_ADDED_BY_PHANTOM = "Added by Phantom Installation ID: {0}"
