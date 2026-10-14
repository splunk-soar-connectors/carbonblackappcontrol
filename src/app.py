from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory


class Asset(BaseAsset):
    base_url: str = AssetField(required=True, description="Device URL, e.g. https://mycb.enterprise.com", category=FieldCategory.CONNECTIVITY)
    api_token: str = AssetField(required=True, description="API Token", sensitive=True, category=FieldCategory.CONNECTIVITY)
    verify_server_cert: bool = AssetField(default=False, description="Verify server certificate", category=FieldCategory.CONNECTIVITY)


app = App(
    name="Carbon Black App Control",
    app_type="endpoint",
    logo="logo_carbonblack.svg",
    logo_dark="logo_carbonblack_dark.svg",
    product_vendor="Carbon Black",
    product_name="Carbon Black App Control",
    publisher="Splunk",
    appid="9b814caf-a3a2-4e28-8418-04b445d658ad",
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Validate the API token by querying the file catalog."""
    from .helper import make_request

    make_request(asset, "/filecatalog", params={"limit": -1})


test_connectivity.meta.description = 'Validate the API Token by attempting to connect to the Device URL. This action runs a quick query on the device to check the connection and token'
test_connectivity.meta.verbose = 'This action requires the following permission: <ul><li>View files</li></ul>'

from . import actions  # noqa: E402, F401


if __name__ == "__main__":
    app.cli()
