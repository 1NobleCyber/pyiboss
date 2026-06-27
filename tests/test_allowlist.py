import time
from pyiboss.allowlist import (
    get_iboss_allow_list,
    get_iboss_allow_list_setting,
    add_iboss_allow_list,
    remove_iboss_allow_list
)

def test_allowlist_crud(iboss_client):
    test_domain = f"test-allow-{int(time.time())}.com"
    
    # 1. Add to allowlist
    add_resp = add_iboss_allow_list(
        iboss_client, 
        url=test_domain, 
        note="PyTest Integration Test",
        direction=2
    )
    assert add_resp is not None
    
    # Wait briefly for propagation
    time.sleep(1)
    
    # 2. Get allowlist and find the domain
    allow_list = get_iboss_allow_list(iboss_client, domain_filter=test_domain)
    assert isinstance(allow_list, list)
    
    found = False
    for item in allow_list:
        if item.get("url") == test_domain:
            found = True
            break
            
    assert found, f"Domain {test_domain} was not found in the allow list after adding."
    
    # 3. Get allowlist settings
    settings = get_iboss_allow_list_setting(iboss_client)
    assert isinstance(settings, dict)
    
    # 4. Remove from allowlist
    remove_resp = remove_iboss_allow_list(
        iboss_client,
        url=test_domain,
        direction=2
    )
    assert remove_resp is not None
    
    # 5. Verify removal
    time.sleep(1)
    allow_list_after = get_iboss_allow_list(iboss_client, domain_filter=test_domain)
    for item in allow_list_after:
        assert item.get("url") != test_domain
