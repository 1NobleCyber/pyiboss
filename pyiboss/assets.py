import base64
import json
import logging
from typing import Optional, List, Dict, Any

from pyiboss.client import IBossClient

logger = logging.getLogger(__name__)

def _decode_b64_json(data: str) -> Any:
    try:
        decoded = base64.b64decode(data).decode('utf-8')
        return json.loads(decoded)
    except Exception:
        return data

def get_iboss_asset(
    client: IBossClient,
    limit: int = 25,
    ascending: bool = False,
    infected: str = "All",
    missing: str = "All",
    current_row_number: int = 1
) -> List[Dict[str, Any]]:
    """
    Retrieves a list of Zero Trust assets from iBoss.
    """
    status_map = {
        "All": "-1",
        "Yes": "1",
        "No": "0"
    }
    
    asset_missing_val = status_map.get(missing, "-1")
    infected_val = status_map.get(infected, "-1")
    order_ascending = "true" if ascending else "false"
    
    max_batch_size = 1000
    total_retrieved = 0
    current_row = current_row_number
    
    results = []
    
    while total_retrieved < limit:
        calc_batch_size = limit - total_retrieved
        batch_limit = min(calc_batch_size, max_batch_size)
        
        if batch_limit <= 0:
            break
            
        uri = (
            f"/ibreports/web/zerotrust/cloudConnectorAssets"
            f"?assetMissing={asset_missing_val}"
            f"&currentRowNumber={current_row}"
            f"&infected={infected_val}"
            f"&maxItemsToReturn={batch_limit}"
            f"&orderAscending={order_ascending}"
        )
        
        response = client.invoke_request(uri, service="Reporting", method="GET")
        
        if not response:
            break
            
        if not isinstance(response, list):
            response = [response]
            
        count_returned = len(response)
        
        for item in response:
            # Decode registrationInfo
            reg_info_str = item.get("registrationInfo")
            if reg_info_str and isinstance(reg_info_str, str):
                reg_info = _decode_b64_json(reg_info_str)
                item["registrationInfo"] = reg_info
                
                # Decode nested agentPostureString
                if isinstance(reg_info, dict) and "agentPostureString" in reg_info:
                    posture_str = reg_info["agentPostureString"]
                    if posture_str and isinstance(posture_str, str):
                        raw_posture_array = _decode_b64_json(posture_str)
                        if isinstance(raw_posture_array, list):
                            posture_object = {}
                            for p_item in raw_posture_array:
                                if isinstance(p_item, dict) and "Type" in p_item:
                                    key = p_item.pop("Type")
                                    # If only one property left, unwrap it if it's Checks/Domains
                                    if len(p_item) == 1:
                                        posture_object[key] = list(p_item.values())[0]
                                    else:
                                        posture_object[key] = p_item
                            reg_info["agentPostureString"] = posture_object
            results.append(item)
            
        total_retrieved += count_returned
        current_row += count_returned
        
        if count_returned == 0:
            break
            
    return results

def get_iboss_asset_count(client: IBossClient) -> Dict[str, Any]:
    """
    Retrieves a count of Zero Trust assets from iBoss.
    """
    uri = "/ibreports/web/zerotrust/assets/counts"
    return client.invoke_request(uri, service="Reporting", method="GET")
