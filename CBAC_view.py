# File: CBAC_view.py
# Copyright (c) 2016-2025 Splunk Inc.
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
# import json
import phantom.app as phantom
import phantom.utils as util


def _get_hash_type(hash_value):
    if util.is_md5(hash_value):
        return phantom.APP_SUCCESS, "md5"

    if util.is_sha1(hash_value):
        return phantom.APP_SUCCESS, "sha1"

    if util.is_sha256(hash_value):
        return phantom.APP_SUCCESS, "sha256"

    return phantom.APP_ERROR, None


def get_ctx_result(result):
    ctx_result = {}

    param = result.get_param()

    if "hash" in param:
        hash_val = param.get("hash")
        ret_val, param["hash_type"] = _get_hash_type(hash_val)

    ctx_result["param"] = param

    message = result.get_message()
    ctx_result["message"] = message

    summary = result.get_summary()
    ctx_result["summary"] = summary

    data = result.get_data()

    if not data:
        return ctx_result

    data = data[0]

    if not data:
        return ctx_result

    ctx_result["data"] = data

    return ctx_result


def hash_view(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue
            results.append(ctx_result)
    # print context
    return "hash_view.html"
