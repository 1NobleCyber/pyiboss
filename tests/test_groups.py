from pyiboss.groups import get_iboss_group

def test_groups(iboss_client):
    groups = get_iboss_group(iboss_client, maximum_items_to_return=5)
    assert isinstance(groups, list)
    if groups:
        assert "GroupName" in groups[0]
        assert "GroupId" in groups[0]
