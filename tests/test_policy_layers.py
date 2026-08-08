import time
from pyiboss.policy_layers import (
    get_iboss_policy_layer,
    get_iboss_policy_layer_url,
    add_iboss_policy_layer_url,
    remove_iboss_policy_layer_url
)

def test_policy_layers(iboss_client):
    layers = get_iboss_policy_layer(iboss_client)
    assert isinstance(layers, list)
    
    # Try to find a layer we can modify (type 0 or 1)
    target_layer = None
    for layer in layers:
        if layer.get("categoryType") in (0, 1):
            target_layer = layer
            break
            
    if not target_layer:
        print("No valid Block/Allow policy layer found to test.")
        return
        
    layer_id = target_layer["customCategoryId"]
    test_url = f"test-layer-{int(time.time())}.com"
    
    # Add URL
    add_resp = add_iboss_policy_layer_url(
        iboss_client,
        url=test_url,
        layer_id=layer_id,
        note="Pytest Policy Layer Test"
    )
    assert add_resp is not None
    
    time.sleep(1)
    
    # Get URLs and verify
    urls = get_iboss_policy_layer_url(iboss_client, layer_id=layer_id)
    assert isinstance(urls, list)
    found = any(u.get("url") == test_url for u in urls)
    assert found, f"URL {test_url} was not found after insertion."
    
    # Dry run remove
    dry_run_res = remove_iboss_policy_layer_url(
        iboss_client,
        url=test_url,
        layer_id=layer_id,
        dry_run=True
    )
    assert isinstance(dry_run_res, list)
    assert len(dry_run_res) > 0
    
    # Actual remove
    remove_res = remove_iboss_policy_layer_url(
        iboss_client,
        url=test_url,
        layer_id=layer_id
    )
    assert isinstance(remove_res, list)
    assert len(remove_res) > 0
    
    time.sleep(1)
    
    # Verify removal
    urls_after = get_iboss_policy_layer_url(iboss_client, layer_id=layer_id)
    found_after = any(u.get("url") == test_url for u in urls_after)
    assert not found_after, f"URL {test_url} was still found after deletion."
