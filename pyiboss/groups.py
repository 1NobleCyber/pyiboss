import logging
from typing import Optional, List, Dict, Any
from urllib.parse import quote

from pyiboss.client import IBossClient

logger = logging.getLogger(__name__)

def get_iboss_group(
    client: IBossClient,
    search_filter: Optional[str] = None,
    maximum_items_to_return: int = 1000,
    current_row_number: int = 1,
    default_group_id: int = -1
) -> List[Dict[str, Any]]:
    """
    Retrieves a list of iBoss Groups.
    """
    uri = "/ibreports/web/log/group"
    
    if search_filter:
        uri += f"/{quote(search_filter)}"
        
    query_params = (
        f"maximumItemsToReturn={maximum_items_to_return}"
        f"&currentRowNumber={current_row_number}"
        f"&defaultGroupId={default_group_id}"
    )
    
    full_uri = f"{uri}?{query_params}"
    
    response = client.invoke_request(full_uri, service="Reporting", method="GET")
    
    results = []
    if response and isinstance(response, list):
        for item in response:
            results.append({
                "GroupName": item.get("filteringGroupName"),
                "GroupId": item.get("reportingGroup"),
                "DecryptedGroupName": item.get("decryptedGroupName"),
                "_raw": item
            })
            
    return results
