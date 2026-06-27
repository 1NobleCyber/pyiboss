from pyiboss.assets import get_iboss_asset, get_iboss_asset_count

def test_assets(iboss_client):
    # Get asset counts
    counts = get_iboss_asset_count(iboss_client)
    assert counts is not None
    
    # Get up to 5 assets
    assets = get_iboss_asset(iboss_client, limit=5)
    assert isinstance(assets, list)
    assert len(assets) <= 5
