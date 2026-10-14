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
API_URI = "/api/bit9platform/v1"
FILE_CATALOG_ENDPOINT = "/filecatalog"
FILE_RULE_ENDPOINT = "/fileRule"
FILE_UPLOAD_ENDPOINT = "/fileUpload"
FILE_INSTANCE_ENDPOINT = "/fileInstance"
COMPUTER_OBJECT_ENDPOINT = "/computer"
POLICY_OBJECT_ENDPOINT = "/policy"
FILE_ANALYSIS_ENDPOINT = "/fileAnalysis"

FILE_STATE_UNAPPROVED = "1"
FILE_STATE_APPROVED = "2"
FILE_STATE_BANNED = "3"
LOCAL_STATE_UNAPPROVED = "1"
LOCAL_STATE_APPROVED = "2"
UNBLOCK_STATE_MAP = {"approved": FILE_STATE_APPROVED, "unapproved": FILE_STATE_UNAPPROVED}
UNBLOCK_LOCAL_STATE_MAP = {"approved": LOCAL_STATE_APPROVED, "unapproved": LOCAL_STATE_UNAPPROVED}
DEFAULT_UNBLOCK_STATE = "unapproved"
# TODO: The legacy connector also used this literal placeholder. Preserve it for
# compatibility until the SDK exposes a supported installation ID; then write
# the real ID and continue recognizing this legacy marker when unblocking rules.
ADDED_BY_PHANTOM = "Added by Phantom Installation ID: {0}"
UPLOAD_STATUS_DESCS = {"0": "Queued", "1": "Initiated", "2": "Uploading", "3": "Completed", "4": "Error", "5": "Cancelled", "6": "Deleted"}
ANALYSIS_STATUS_DESCS = {"0": "Scheduled", "1": "Submitted", "2": "Processed", "3": "Analyzed", "4": "Error", "5": "Cancelled"}
DEFAULT_TIMEOUT = 60
