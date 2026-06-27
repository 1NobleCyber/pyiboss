import time
from pyiboss.blocklist import (
    get_iboss_block_list,
    add_iboss_block_list,
    remove_iboss_block_list
)

def test_blocklist_crud(iboss_client):
    test_domain = f"test-block-{int(time.time())}.com"
    
    # 1. Add to blocklist
    add_resp = add_iboss_block_list(
        iboss_client, 
        url=test_domain, 
        note="PyTest Integration Test",
        direction=2
    )
    assert add_resp is not None
    
    # Wait briefly for propagation
    time.sleep(1)
    
    # 2. Get blocklist and find the domain
    block_list = get_iboss_block_list(iboss_client, domain_filter=test_domain)
    assert isinstance(block_list, list)
    
    found = False
    for item in block_list:
        if item.get("url") == test_domain:
            found = True
            break
            
    assert found, f"Domain {test_domain} was not found in the block list after adding."
    
    # 3. Remove from blocklist
    remove_resp = remove_iboss_block_list(
        iboss_client,
        url=test_domain,
        direction=2
    )
    assert remove_resp is not None
    
    # 4. Verify removal
    time.sleep(1)
    block_list_after = get_iboss_block_list(iboss_client, domain_filter=test_domain)
    for item in block_list_after:
        assert item.get("url") != test_domain
