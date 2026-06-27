from pyiboss.urls import get_iboss_url_lookup, submit_iboss_url_recategorization

def test_urls(iboss_client):
    test_url = "example.com"
    
    lookup = get_iboss_url_lookup(iboss_client, test_url)
    assert lookup is not None
    assert "categories" in lookup
    
    # submit_iboss_url_recategorization actually submits a real request
    # We might not want to spam their system, but we'll run it once to verify the payload works.
    resp = submit_iboss_url_recategorization(iboss_client, test_url, "PyTest Verification")
    assert resp is not None
