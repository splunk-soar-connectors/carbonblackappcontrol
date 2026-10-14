from soar_sdk.action_results import PermissiveActionOutput

from .app import app
from .helper import hash_type


@app.view_handler(template="hash_view.html")
def hash_view(outputs: list[PermissiveActionOutput]) -> dict:
    """Prepare hash action outputs for the legacy hash summary widget."""
    results = []
    for output in outputs:
        values = output.model_dump(by_alias=True, exclude_none=True)
        file_hash = values.get("view_hash", "")
        results.append(
            {
                "hash": file_hash,
                "hash_type": hash_type(file_hash) or "hash",
                "message": values.get("view_message", ""),
            }
        )
    return {"results": results}
