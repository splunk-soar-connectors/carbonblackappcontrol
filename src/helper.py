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
import ipaddress
import json
import re
from typing import Any

from pydantic import create_model

from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from .consts import (
    ADDED_BY_PHANTOM,
    ANALYSIS_STATUS_DESCS,
    COMPUTER_OBJECT_ENDPOINT,
    DEFAULT_TIMEOUT,
    DEFAULT_UNBLOCK_STATE,
    FILE_ANALYSIS_ENDPOINT,
    FILE_CATALOG_ENDPOINT,
    FILE_INSTANCE_ENDPOINT,
    FILE_RULE_ENDPOINT,
    FILE_STATE_BANNED,
    FILE_STATE_UNAPPROVED,
    FILE_UPLOAD_ENDPOINT,
    LOCAL_STATE_UNAPPROVED,
    POLICY_OBJECT_ENDPOINT,
    UNBLOCK_LOCAL_STATE_MAP,
    UNBLOCK_STATE_MAP,
    UPLOAD_STATUS_DESCS,
    API_URI,
)

HTTP_SUCCESS_MIN = 200
HTTP_SUCCESS_MAX = 399
HTTP_UNAUTHORIZED = 401


def make_params_model(name: str, fields: list[dict[str, Any]]) -> type[Params]:
    """Create a Params model from manifest metadata kept alongside an action."""
    model_fields = {}
    for item in fields:
        field_type = {"string": str, "numeric": int, "boolean": bool, "password": str}[item["data_type"]]
        kwargs = {
            "description": item.get("description"),
            "required": item.get("required", False),
            "primary": item.get("primary", False),
            "default": item.get("default"),
            "value_list": item.get("value_list"),
            "cef_types": item.get("contains"),
            "column_name": item.get("column_name"),
            "alias": item.get("alias"),
        }
        is_optional = not item.get("required", False) and item.get("default") is None
        annotation = field_type | None if is_optional else field_type
        model_fields[item["field_name"]] = (annotation, Param(**kwargs))
    return create_model(name, __base__=Params, **model_fields)


def make_output_model(name: str, fields: list[dict[str, Any]]) -> type[ActionOutput]:
    """Create a permissive output model with converted manifest field metadata."""
    model_fields = {}
    used_names = set()
    for item in fields:
        if item["field_name"] in used_names:
            continue
        used_names.add(item["field_name"])
        field_type = {"string": str, "numeric": int, "boolean": bool, "password": str}.get(item["data_type"], str)
        kwargs = {
            "alias": item.get("alias"),
            "cef_types": item.get("contains"),
            "example_values": item.get("example_values"),
            "column_name": item.get("column_name"),
        }
        model_fields[item["field_name"]] = (field_type | None, OutputField(**kwargs))
    return create_model(name, __base__=PermissiveActionOutput, **model_fields)


def make_request(  # noqa: PLR0913
    asset: Any,
    endpoint: str,
    *,
    method: str = "GET",
    params: dict[str, Any] | None = None,
    data: Any = None,
    download: bool = False,
) -> Any:
    """Call the Carbon Black App Control API and raise readable errors."""
    import httpx
    from soar_sdk.auth import StaticTokenAuth

    url = f"{asset.base_url.rstrip('/')}{API_URI}{endpoint}"
    auth = StaticTokenAuth(asset.api_token, token_type="", header_name="X-Auth-Token")
    headers = {"Content-Type": "application/json"}
    try:
        with httpx.Client(
            auth=auth,
            verify=asset.verify_server_cert,
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=True,
        ) as client:
            response = client.request(method, url, params=params, json=data, headers=headers)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Connection failed: {exc}") from exc

    if not HTTP_SUCCESS_MIN <= response.status_code <= HTTP_SUCCESS_MAX:
        detail = response.text
        try:
            body = response.json()
            detail = json.dumps(body).replace("{", "").replace("}", "")
        except ValueError:
            pass
        if response.status_code == HTTP_UNAUTHORIZED:
            detail += ". Please verify the user has been configured with the required permissions as mentioned in the action documentation."
        raise RuntimeError(f"API failed, Status code: {response.status_code}, Detail: {detail}")

    if download:
        return response.content
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            return response.json()
        except ValueError as exc:
            raise RuntimeError(f"Unable to parse reply as a Json, raw string reply: '{response.text}'") from exc
    return response.text if response.text else None


def validate_integer(value: Any, name: str, *, allow_zero: bool = False, allow_minus_one_limit: bool = False) -> int | None:
    """Match the legacy connector's integer, non-negative, and non-zero checks."""
    if value is None:
        return None
    try:
        number = float(value)
        if not number.is_integer():
            raise ValueError
        number = int(number)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"Please provide a valid integer value in the {name}") from exc
    if allow_minus_one_limit and name == "Limit" and number == -1:
        return number
    if number < 0:
        raise ValueError(f"Please provide a valid non-negative integer value in the {name}")
    if not allow_zero and number == 0:
        raise ValueError(f"Please provide a non-zero positive integer in the {name}")
    return number


def hash_type(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "sha256"
    return None


def get_file_catalog(asset: Any, file_hash: str) -> dict[str, Any] | None:
    kind = hash_type(file_hash)
    if not kind:
        raise ValueError("Unable to detect hash type")
    result = make_request(asset, FILE_CATALOG_ENDPOINT, params={"q": f"{kind.upper()}:{file_hash}"})
    return result[0] if isinstance(result, list) and result else None


def get_rules_for_hash(asset: Any, file_hash: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    catalog = get_file_catalog(asset, file_hash)
    rules = make_request(asset, "/fileRule", params={"q": f"hash:{file_hash}"})
    if rules:
        return rules, catalog
    if not catalog or not catalog.get("id"):
        return [], catalog
    rules = make_request(asset, "/fileRule", params={"q": f"fileCatalogId:{catalog['id']}"})
    return rules or [], catalog


def _field_values(model: type[ActionOutput], values: dict[str, Any]) -> dict[str, Any]:
    """Filter values to fields declared by an ActionOutput model."""
    accepted = {}
    for field_name, field in model.model_fields.items():
        source_name = field.alias or field_name
        if field_name == "sdk_status_column":
            accepted[field_name] = "success"
        elif source_name in values:
            value = values[source_name]
            if isinstance(value, dict | list):
                value = json.dumps(value)
            accepted[field_name] = value
    return accepted


def _set_result(
    soar: Any,
    message: str,
    summary_cls: type[ActionOutput] | None,
    summary: dict[str, Any] | None,
) -> None:
    soar.set_message(message)
    if summary_cls is not None:
        soar.set_summary(summary_cls(**_field_values(summary_cls, summary or {})))


def _records(output_cls: type[ActionOutput], records: Any, *, status: str = "success") -> list[ActionOutput]:
    if records is None:
        return []
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list):
        records = [{"response": records}]
    outputs = []
    for record in records:
        record_values = {"response": record} if not isinstance(record, dict) else record
        values = dict(record_values)
        for field_name, value in _field_values(output_cls, record_values).items():
            field = output_cls.model_fields[field_name]
            values[field.alias or field_name] = value
        if "view_hash" in output_cls.model_fields:
            values["view_hash"] = record_values.get("view_hash", "")
            values["view_message"] = record_values.get("view_message", "")
        if "sdk_status_column" in output_cls.model_fields:
            values["sdk_status_column"] = status
        outputs.append(output_cls(**values))
    return outputs


def execute_action(  # noqa: PLR0912, PLR0913, PLR0915
    action_id: str,
    params: Params,
    soar: Any,
    asset: Any,
    output_cls: type[ActionOutput],
    summary_cls: type[ActionOutput] | None,
) -> list[ActionOutput]:
    """Execute one converted Carbon Black App Control action."""
    values = params.model_dump(by_alias=True, exclude_none=True)
    message = "Action completed successfully"
    summary: dict[str, Any] = {}
    records: Any = []

    if action_id == "hunt_file":
        file_hash = values["hash"]
        catalog = get_file_catalog(asset, file_hash)
        summary["prevalence"] = 0
        if not catalog:
            message = "File not present in the catalog. Possibly not present in Enterprise."
        else:
            summary["prevalence"] = catalog.get("prevalence", 0)
            records = [catalog]
            message = "Fetched file details successfully"

    elif action_id == "_unblock_hash":
        file_hash = values["hash"]
        rules, catalog = get_rules_for_hash(asset, file_hash)
        if not rules:
            raise ValueError("No matching rules for the hash were found.")
        if len(rules) > 1:
            raise ValueError("More than one rule matched for the hash. This is treated as an Error.")
        rule = dict(rules[0])
        description = rule.get("description")
        if not description:
            raise ValueError("Did not find a rule with Phantom tagged description to unblock")
        if ADDED_BY_PHANTOM.lower() not in description.lower():
            raise ValueError("The rule for the given hash was not created by Phantom, cannot unblock the hash.")
        file_state = rule.get("fileState", FILE_STATE_BANNED)
        requested_state = values.get("file_state", DEFAULT_UNBLOCK_STATE)
        try:
            unblock_state = UNBLOCK_STATE_MAP[requested_state]
        except KeyError as exc:
            raise ValueError("Invalid file state provided") from exc
        if str(file_state) == unblock_state:
            records = [rule]
            message = "State of file same as required"
        else:
            if catalog and rule.get("fileCatalogId", 0) == 0:
                rule["fileCatalogId"] = catalog.get("id")
            rule.update({"hash": file_hash, "policyIds": 0, "description": description, "fileState": unblock_state})
            response = make_request(asset, FILE_RULE_ENDPOINT, method="POST", data=rule)
            fallback = {**rule, "policyIds": str(rule["policyIds"])}
            records = [response or fallback]
            message = "Updated rule successfully"

    elif action_id == "_block_hash":
        file_hash = values["hash"]
        rules, catalog = get_rules_for_hash(asset, file_hash)
        if len(rules) > 1:
            raise ValueError("More than one rule matched for the hash. This is treated as an Error.")
        rule = dict(rules[0]) if rules else {}
        if catalog and rule.get("fileCatalogId", 0) == 0:
            rule["fileCatalogId"] = catalog.get("id")
        if str(rule.get("fileState", FILE_STATE_UNAPPROVED)) == FILE_STATE_BANNED:
            records = [rule]
            message = "State of file same as required"
        else:
            rule["hash"] = file_hash
            rule.setdefault("fileCatalogId", 0)
            rule["policyIds"] = 0
            comment = values.get("comment")
            rule["description"] = f"{comment} - {ADDED_BY_PHANTOM}" if comment else ADDED_BY_PHANTOM
            rule["fileState"] = FILE_STATE_BANNED
            response = make_request(asset, FILE_RULE_ENDPOINT, method="POST", data=rule)
            fallback = {**rule, "policyIds": str(rule["policyIds"])}
            records = [response or fallback]
            message = "Created/Updated rule successfully"

    elif action_id == "upload_file":
        comp_id = validate_integer(values["computer_id"], "Computer ID", allow_zero=True)
        file_id = validate_integer(values["file_id"], "File ID")
        response = make_request(
            asset,
            FILE_UPLOAD_ENDPOINT,
            method="POST",
            data={"computerId": comp_id, "fileCatalogId": file_id, "priority": values.get("priority", 0)},
        )
        if response is None:
            raise ValueError("File ID not found. Please provide a correct file ID")
        records = [response]
        upload_status = response.get("uploadStatus")
        if upload_status is not None:
            summary["upload_status"] = upload_status
            try:
                summary["upload_status_desc"] = UPLOAD_STATUS_DESCS[str(upload_status)]
            except KeyError as exc:
                raise ValueError(f"Unknown upload status: {upload_status}") from exc
        message = "File status is changed to upload state successfully"

    elif action_id == "list_files":
        limit = validate_integer(values.get("limit", 100), "Limit", allow_minus_one_limit=True)
        response = make_request(asset, FILE_UPLOAD_ENDPOINT, params={"limit": limit})
        if limit == -1:
            summary["total"] = response["count"]
            message = f"Total: {response['count']}"
        else:
            records = response or []
            summary["num_files"] = len(records)
            message = f"Number of files returned: {len(records)}"

    elif action_id == "get_file":
        file_id = validate_integer(values["file_id"], "File ID")
        endpoint = f"{FILE_UPLOAD_ENDPOINT}/{file_id}"
        info = make_request(asset, endpoint)
        if not isinstance(info, dict) or not info.get("fileName"):
            raise ValueError("File metadata did not include a file name")
        content = make_request(asset, endpoint, params={"downloadFile": True}, download=True)
        vault_id = soar.vault.create_attachment(
            container_id=soar.get_executing_container_id(),
            file_content=content,
            file_name=info["fileName"],
        )
        records = [{"vault_id": vault_id, "file_name": info["fileName"]}]
        summary["vault_id"] = vault_id
        message = f"Successfully added file to vault. Vault ID: {vault_id}"

    elif action_id == "analyze_file":
        comp_id = validate_integer(values["computer_id"], "Computer ID")
        file_id = validate_integer(values["file_id"], "File ID")
        connector_id = validate_integer(values["connector_id"], "Connector ID")
        response = make_request(
            asset,
            FILE_ANALYSIS_ENDPOINT,
            method="POST",
            data={
                "computerId": comp_id,
                "fileCatalogId": file_id,
                "connectorId": connector_id,
                "priority": values.get("priority", 0),
                "analysisTarget": values["target_type"],
            },
        )
        if response is None:
            raise ValueError("File ID not found. Please provide a correct file ID")
        response_records = response if isinstance(response, list) else [response]
        records = response_records
        if response_records and response_records[0].get("analysisStatus") is not None:
            analysis_status = response_records[0]["analysisStatus"]
            summary["analysis_status"] = analysis_status
            try:
                summary["analysis_status_desc"] = ANALYSIS_STATUS_DESCS[str(analysis_status)]
            except KeyError as exc:
                raise ValueError(f"Unknown analysis status: {analysis_status}") from exc

    elif action_id == "get_system_info":
        ip_hostname = values.get("ip_hostname")
        comp_id = values.get("id")
        if not comp_id and not ip_hostname:
            raise ValueError("Neither ip_hostname nor id specified. Please specify at-least one of them")
        params_q = None
        endpoint = COMPUTER_OBJECT_ENDPOINT
        if comp_id:
            endpoint += f"/{comp_id}"
        else:
            try:
                ipaddress.ip_address(ip_hostname)
                params_q = {"q": f"ipAddress:*{ip_hostname}*"}
            except ValueError:
                params_q = {"q": f"name:*{ip_hostname}*"}
        response = make_request(asset, endpoint, params=params_q)
        records = response if isinstance(response, list) else [response]
        summary["total_endpoints"] = len(records)

    elif action_id == "get_fileinstances":
        catalog_id = validate_integer(values["filecatalog_id"], "FileCatalog ID")
        computer_id = validate_integer(values["computer_id"], "Computer ID")
        records = (
            make_request(
                asset,
                FILE_INSTANCE_ENDPOINT,
                params={"q": [f"computerId:{computer_id}", f"fileCatalogId:{catalog_id}"]},
            )
            or []
        )

    elif action_id == "update_fileinstance":
        instance_id = validate_integer(values["instance_id"], "FileInstance ID")
        local_state_name = values["local_state"]
        if local_state_name not in UNBLOCK_LOCAL_STATE_MAP:
            raise ValueError("Invalid local state provided")
        endpoint = f"{FILE_INSTANCE_ENDPOINT}/{instance_id}"
        instance = make_request(asset, endpoint)
        if not instance:
            raise ValueError("No matching instance for the ID were found")
        if isinstance(instance, list):
            if len(instance) > 1:
                raise ValueError("More than one file instance matched for the id. This is treated as an error")
            instance = instance[0] if instance else None
        if instance is None:
            raise ValueError("No matching instance for the ID were found")
        state = UNBLOCK_LOCAL_STATE_MAP[local_state_name]
        if str(instance.get("localState", LOCAL_STATE_UNAPPROVED)) != state:
            instance["localState"] = state
            response = make_request(asset, endpoint, method="PUT", data=instance)
            instance = response or instance
            message = "Local state of file instance updated successfully"
        else:
            message = "Local state of file instance same as required"
        records = [instance]

    elif action_id == "update_computer":
        computer_id = validate_integer(values["computer_id"], "Computer ID")
        endpoint = f"{COMPUTER_OBJECT_ENDPOINT}/{computer_id}"
        computer = make_request(asset, endpoint)
        if not isinstance(computer, dict):
            raise ValueError(f"Unable to find computer object with id {computer_id}")
        computer["prioritized"] = values.get("prioritized", computer.get("prioritized", False))
        computer["computerTag"] = values.get("computer_tag", computer.get("computerTag", ""))
        computer["description"] = values.get("description", computer.get("description", ""))
        policy_id = values.get("policy_id", computer.get("policyId"))
        computer["policyId"] = policy_id
        policy = make_request(asset, f"{POLICY_OBJECT_ENDPOINT}/{policy_id}")
        if not policy:
            raise ValueError(f"Unable to find policy object with id {policy_id}")
        if values.get("policy_id") and computer.get("automaticPolicy"):
            raise ValueError(f"Can't update policy on computer {computer_id} if automaticPolicy set to True")  # noqa: S608
        if values.get("policy_id") and computer.get("localApproval"):
            raise ValueError(f"Can't update policy on computer {computer_id} if localApproval set to True")  # noqa: S608
        updated = make_request(asset, endpoint, method="PUT", data=computer)
        records = [updated or computer]
        message = "Computer object updated successfully"

    elif action_id == "list_policies":
        limit = validate_integer(values.get("limit"), "Limit", allow_zero=True, allow_minus_one_limit=True)
        offset = validate_integer(values.get("offset", 0), "Offset", allow_zero=True)
        query_params = {"limit": limit, "offset": offset}
        response = make_request(
            asset,
            POLICY_OBJECT_ENDPOINT,
            params={key: value for key, value in query_params.items() if value is not None},
        )
        if limit == -1:
            summary["total"] = response["count"]
            message = f"Total: {response['count']}"
        else:
            records = response or []
            summary["num_policies"] = len(records)
            message = f"Number of policies returned: {len(records)}"

    else:
        raise ValueError(f"Unsupported action identifier: {action_id}")

    _set_result(soar, message, summary_cls, summary)
    if action_id in {"_block_hash", "_unblock_hash"}:
        values = [{**record, "view_hash": params.hash, "view_message": message} for record in (records or [{}])]
        return _records(output_cls, values)
    return _records(output_cls, records)
