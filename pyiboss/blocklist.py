from typing import Optional, List, Dict, Any
from urllib.parse import quote
import logging

from pyiboss.client import IBossClient

logger = logging.getLogger(__name__)

def get_iboss_block_list(
    client: IBossClient,
    policy_id: int = 1,
    get_all: bool = False,
    current_row: int = 0,
    max_items: int = 20,
    domain_filter: str = ""
) -> List[Dict[str, Any]]:
    """
    Retrieves the 'Block List' controls from the iBoss Gateway.
    """
    base_uri = f"/json/controls/blockList?currentPolicyBeingEdited={policy_id}&domainFilter={quote(domain_filter)}"
    
    if get_all:
        logger.debug("Mode: ALL. Querying metadata to determine total count...")
        meta_uri = f"{base_uri}&currentRow=0&maxItems=1"
        meta_response = client.invoke_request(meta_uri, service="Gateway", method="GET")
        
        total_count = meta_response.get("count") or meta_response.get("total")
        if not total_count:
            logger.warning("Could not determine total count from API. Returning default page.")
            total_count = 20
            
        req_row = 0
        req_max = total_count
    else:
        req_row = current_row
        req_max = max_items
        
    final_uri = f"{base_uri}&currentRow={req_row}&maxItems={req_max}"
    response = client.invoke_request(final_uri, service="Gateway", method="GET")
    
    return response.get("entries", [])


def add_iboss_block_list(
    client: IBossClient,
    url: str,
    note: str = "",
    policy_id: int = 1,
    global_flag: int = 0,
    is_regex: int = 0,
    direction: int = 2,
    priority: int = 0,
    start_port: Optional[int] = None,
    end_port: Optional[int] = None,
    url_field_type: int = 0
) -> Dict[str, Any]:
    """
    Adds a URL to the iBoss Block List.
    """
    uri = f"/json/controls/blockList?currentPolicyBeingEdited={policy_id}"
    
    payload = {
        "global": global_flag,
        "isRegex": is_regex,
        "direction": direction,
        "priority": priority,
        "currentPolicyBeingEdited": policy_id,
        "startPort": start_port,
        "endPort": end_port,
        "urlFieldType": url_field_type,
        "url": url,
        "note": note
    }
    
    return client.invoke_request(uri, service="Gateway", method="PUT", body=payload)

def remove_iboss_block_list(
    client: IBossClient,
    url: str,
    direction: int,
    policy_id: int = 1,
    start_port: Optional[int] = None,
    end_port: Optional[int] = None
) -> Any:
    """
    Removes a URL from the iBoss Block List.
    """
    if start_port is None:
        start_port = 0
    if end_port is None:
        end_port = 0
        
    uri = f"/json/controls/blockList?currentPolicyBeingEdited={policy_id}"
    
    payload = {
        "currentPolicyBeingEdited": policy_id,
        "startPort": start_port,
        "endPort": end_port,
        "direction": direction,
        "url": url
    }
    
    response = client.invoke_request(uri, service="Gateway", method="DELETE", body=payload)
    
    if isinstance(response, dict):
        response["url"] = url
        
    return response
