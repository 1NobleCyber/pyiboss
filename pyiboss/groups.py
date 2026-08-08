import logging
from typing import Optional, List, Dict, Any
from urllib.parse import quote

from pyiboss.client import IBossClient

logger = logging.getLogger(__name__)

def get_iboss_group(
    client: IBossClient,
    policy_name: Optional[str] = None,
    policy_id: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves a list of Groups (Policies) from the iBoss Gateway.
    """
    uri = "/json/groupNav/groups"
    
    response = client.invoke_request(uri, service="Gateway", method="GET")
    
    # Extract entries array safely
    entries = []
    if response:
        if isinstance(response, dict) and "entries" in response:
            entries = response["entries"]
        elif isinstance(response, list):
            entries = response
            
    if policy_name:
        return [e for e in entries if e.get("name") == policy_name]
    elif policy_id is not None:
        return [e for e in entries if e.get("number") == policy_id]
        
    return entries


def resolve_policy_id(client: IBossClient, policy_name: Optional[str], policy_id: Optional[int]) -> int:
    """
    Helper function to resolve the policy_id. It ensures that PolicyName and PolicyId 
    are mutually exclusive, and resolves PolicyName to an ID if provided.
    """
    if policy_name and policy_id is not None:
        raise ValueError("Cannot specify both policy_name and policy_id. They are mutually exclusive.")
        
    if not policy_name and policy_id is None:
        return 1
        
    if policy_name:
        groups = get_iboss_group(client, policy_name=policy_name)
        if not groups:
            raise ValueError(f"Could not find a Group with the exact name '{policy_name}'.")
        if len(groups) > 1:
            raise ValueError(f"Found multiple Groups with the exact name '{policy_name}'. Please use policy_id instead.")
        return groups[0].get("number")
        
    return policy_id
