def test_client_connection(iboss_client):
    assert iboss_client.auth_token is not None
    assert "Gateway" in iboss_client.domains
    assert "Reporting" in iboss_client.domains
    assert iboss_client.gateway_version is not None
