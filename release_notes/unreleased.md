**Unreleased**

* Verify App Control TLS certificates by default.
* Existing assets retain their saved **Verify server certificate** setting after upgrade; review and enable it where appropriate.
* Contain downloaded files in anonymous vault staging and use safe display names.
* Validate computer identifiers before constructing App Control API paths.
* Escape file hash values rendered in the action widget.
* Reject foreign and policy-scoped file rules, and enforce connector-owned report-only bans before reporting success.
* Require approval for endpoint, policy, file-enumeration, and vault-writing actions previously classified as read-only.
* Remove App Control CLI passwords from system-information and computer-update results.
