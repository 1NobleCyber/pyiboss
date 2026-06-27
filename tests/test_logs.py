import os
from pyiboss.logs import get_iboss_log_table, get_iboss_log_icon, get_iboss_log_entry

def test_logs(iboss_client, tmp_path):
    # 1. Log Tables
    tables = get_iboss_log_table(iboss_client)
    assert isinstance(tables, list)
    
    # 2. Log Icon
    out_file = tmp_path / "icon.png"
    icon_info = get_iboss_log_icon(iboss_client, domain="google.com", out_file=str(out_file))
    assert icon_info is not None
    assert icon_info["Domain"] == "google.com"
    assert "Bytes" in icon_info
    assert os.path.exists(out_file)
    
    # 3. Log Entry
    # Just query last hour for 5 items
    entries = get_iboss_log_entry(iboss_client, limit=5)
    assert isinstance(entries, list)
    if entries:
        assert "parsedLogTime" in entries[0]
