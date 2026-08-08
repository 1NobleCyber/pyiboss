from typing import Optional, List, Dict, Any
from urllib.parse import quote
import logging

from pyiboss.client import IBossClient

logger = logging.getLogger(__name__)

def get_iboss_policy_layer(
    client: IBossClient,
    current_row: int = 0,
    domain_filter: str = "",
    excluded_group_filter: str = "",
    group_filter: str = "",
    ip_exclusion_filter: str = "",
    ip_inclusion_filter: str = "",
    max_items: Optional[int] = None,
    policy_name_filter: str = "",
    notes_filter: str = "",
    port_filter: str = "",
    type_id: Optional[int] = None,
    type_name_filter: str = "All",
    username_filter: str = "",
    exact_match: bool = False
) -> List[Dict[str, Any]]:
    """
    Retrieves a list of iBoss Policy Layers.
    """
    if type_id is not None:
        resolved_type = type_id
    else:
        type_mapping = {
            "All": -1,
            "Block List": 0,
            "Allow List": 1,
            "Category-Based": 3,
            "Microsoft Tenant Restrictions": 5
        }
        resolved_type = type_mapping.get(type_name_filter, -1)
        
    query_params = {
        "currentRow": current_row,
        "domainFilter": quote(domain_filter),
        "groupExcludeNameFilter": quote(excluded_group_filter),
        "groupNameFilter": quote(group_filter),
        "ipExclusionFilter": quote(ip_exclusion_filter),
        "ipInclusionFilter": quote(ip_inclusion_filter),
        "nameFilter": quote(policy_name_filter),
        "notesFilter": quote(notes_filter),
        "portFilter": quote(port_filter),
        "usernameFilter": quote(username_filter),
        "typeFilter": resolved_type
    }
    
    if max_items is not None:
        query_params["maxItems"] = max_items
        
    qs = "&".join([f"{k}={v}" for k, v in query_params.items()])
    uri = f"/json/controls/policyLayers/all?{qs}"
    
    response = client.invoke_request(uri, service="Gateway", method="GET")
    
    entries = []
    if response:
        if isinstance(response, dict) and "entries" in response:
            entries = response["entries"]
        elif isinstance(response, list):
            entries = response
            
    if exact_match:
        if policy_name_filter:
            entries = [e for e in entries if e.get("customCategoryName") == policy_name_filter]
        if group_filter:
            entries = [e for e in entries if e.get("dynamicGroups") == group_filter]
        if excluded_group_filter:
            entries = [e for e in entries if e.get("dynamicExcludedGroups") == excluded_group_filter]
        if username_filter:
            entries = [e for e in entries if e.get("dynamicUsernames") == username_filter]
        if ip_inclusion_filter:
            entries = [e for e in entries if e.get("dynamicRanges") == ip_inclusion_filter]
        if ip_exclusion_filter:
            entries = [e for e in entries if e.get("dynamicRangesExclusion") == ip_exclusion_filter]
            
    return entries

def _resolve_layer_id(client: IBossClient, name: Optional[str], layer_id: Optional[int]) -> Dict[str, Any]:
    """
    Internal helper to validate and resolve Policy Layer ID and fetch its properties.
    """
    if name and layer_id is not None:
        raise ValueError("Cannot specify both name and layer_id. They are mutually exclusive.")
    if not name and layer_id is None:
        raise ValueError("Must specify either name or layer_id.")
        
    if name:
        layers = get_iboss_policy_layer(client, policy_name_filter=name, exact_match=True)
        if not layers:
            raise ValueError(f"Could not find a Policy Layer with the exact name '{name}'.")
        if len(layers) > 1:
            raise ValueError(f"Found multiple Policy Layers with the exact name '{name}'. Please use layer_id instead.")
        return layers[0]
    else:
        layers = get_iboss_policy_layer(client)
        layer = next((L for L in layers if L.get("customCategoryId") == layer_id), None)
        if not layer:
            raise ValueError(f"Could not find a Policy Layer with the ID '{layer_id}'.")
        return layer

def get_iboss_policy_layer_url(
    client: IBossClient,
    layer_id: Optional[int] = None,
    name: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves a list of URLs associated with an iBoss Policy Layer.
    """
    layer = _resolve_layer_id(client, name, layer_id)
    cat_type = layer.get("categoryType")
    
    if cat_type not in (0, 1):
        raise ValueError(f"The Policy Layer must be an Allow List (Type 1) or Block List (Type 0). Specified layer has type '{cat_type}'.")
        
    resolved_id = layer["customCategoryId"]
    uri = f"/json/controls/policyLayers/urls?customCategoryId={resolved_id}"
    
    response = client.invoke_request(uri, service="Gateway", method="GET")
    
    if response:
        if isinstance(response, dict) and "entries" in response:
            return response["entries"]
        elif isinstance(response, list):
            return response
    return []

def add_iboss_policy_layer_url(
    client: IBossClient,
    url: str,
    layer_id: Optional[int] = None,
    name: Optional[str] = None,
    priority: str = "",
    direction: int = 2,
    start_port: str = "",
    end_port: str = "",
    is_regex: int = 0,
    apply_keyword_and_safe_search: int = 0,
    timed_url: int = 0,
    note: str = "",
    do_dlp_scan: int = 1,
    do_malware_scan: int = 1,
    do_file_checks: int = 1,
    override_zero_trust: int = 0,
    ssl_bypass: int = 0,
    url_field_type: int = 0
) -> Dict[str, Any]:
    """
    Adds a new URL to an iBoss Policy Layer.
    """
    layer = _resolve_layer_id(client, name, layer_id)
    cat_type = layer.get("categoryType")
    
    if cat_type not in (0, 1):
        raise ValueError(f"The Policy Layer must be an Allow List (Type 1) or Block List (Type 0). Specified layer has type '{cat_type}'.")
        
    resolved_id = layer["customCategoryId"]
    
    body = {
        "url": url,
        "priority": priority,
        "direction": direction,
        "startPort": start_port,
        "endPort": end_port,
        "isRegex": is_regex,
        "applyKeywordAndSafeSearch": apply_keyword_and_safe_search,
        "timedUrl": timed_url,
        "note": note,
        "doDlpScan": do_dlp_scan,
        "doMalwareScan": do_malware_scan,
        "doFileChecks": do_file_checks,
        "overrideZeroTrust": override_zero_trust,
        "sslBypass": ssl_bypass,
        "urlFieldType": url_field_type,
        "customCategoryNumber": resolved_id,
        "customCategoryId": resolved_id
    }
    
    uri = "/json/controls/policyLayers/urls"
    return client.invoke_request(uri, service="Gateway", method="PUT", body=body)

def remove_iboss_policy_layer_url(
    client: IBossClient,
    url: str,
    layer_id: Optional[int] = None,
    name: Optional[str] = None,
    priority: Optional[str] = None,
    direction: Optional[int] = None,
    start_port: Optional[str] = None,
    end_port: Optional[str] = None,
    is_regex: Optional[int] = None,
    apply_keyword_and_safe_search: Optional[int] = None,
    timed_url: Optional[int] = None,
    note: Optional[str] = None,
    do_dlp_scan: Optional[int] = None,
    do_malware_scan: Optional[int] = None,
    do_file_checks: Optional[int] = None,
    override_zero_trust: Optional[int] = None,
    ssl_bypass: Optional[int] = None,
    url_field_type: Optional[int] = None,
    dry_run: bool = False
) -> List[Any]:
    """
    Removes a URL from an iBoss Policy Layer.
    """
    layer = _resolve_layer_id(client, name, layer_id)
    cat_type = layer.get("categoryType")
    
    if cat_type not in (0, 1):
        raise ValueError(f"The Policy Layer must be an Allow List (Type 1) or Block List (Type 0). Specified layer has type '{cat_type}'.")
        
    resolved_id = layer["customCategoryId"]
    
    all_urls = get_iboss_policy_layer_url(client, layer_id=resolved_id)
    matched_urls = [e for e in all_urls if e.get("url") == url]
    
    if not matched_urls:
        logger.warning(f"Could not find the URL '{url}' in the specified Policy Layer.")
        return []
        
    # Optional Filters
    if priority is not None: matched_urls = [e for e in matched_urls if str(e.get("priority")) == str(priority)]
    if direction is not None: matched_urls = [e for e in matched_urls if e.get("direction") == direction]
    if start_port is not None: matched_urls = [e for e in matched_urls if str(e.get("startPort")) == str(start_port)]
    if end_port is not None: matched_urls = [e for e in matched_urls if str(e.get("endPort")) == str(end_port)]
    if is_regex is not None: matched_urls = [e for e in matched_urls if e.get("isRegex") == is_regex]
    if apply_keyword_and_safe_search is not None: matched_urls = [e for e in matched_urls if e.get("applyKeywordAndSafeSearch") == apply_keyword_and_safe_search]
    if note is not None: matched_urls = [e for e in matched_urls if e.get("note") == note]
    if do_dlp_scan is not None: matched_urls = [e for e in matched_urls if e.get("doDlpScan") == do_dlp_scan]
    if do_malware_scan is not None: matched_urls = [e for e in matched_urls if e.get("doMalwareScan") == do_malware_scan]
    if do_file_checks is not None: matched_urls = [e for e in matched_urls if e.get("doFileChecks") == do_file_checks]
    if override_zero_trust is not None: matched_urls = [e for e in matched_urls if e.get("overrideZeroTrust") == override_zero_trust]
    if ssl_bypass is not None: matched_urls = [e for e in matched_urls if e.get("sslBypass") == ssl_bypass]
    if url_field_type is not None: matched_urls = [e for e in matched_urls if e.get("urlFieldType") == url_field_type]
    
    if timed_url is not None:
        matched_urls = [e for e in matched_urls if e.get("isTimedUrl") == timed_url or e.get("timedUrlExpiresInMinutes") == timed_url]
        
    if not matched_urls:
        logger.warning(f"The URL '{url}' was found, but did not match the other specific filter criteria.")
        return []
        
    if dry_run:
        return matched_urls
        
    results = []
    
    for target in matched_urls:
        query_params = {
            "applyKeywordAndSafeSearch": target.get("applyKeywordAndSafeSearch", ""),
            "customCategoryId": resolved_id,
            "direction": target.get("direction", ""),
            "doDlpScan": target.get("doDlpScan", ""),
            "doFileChecks": target.get("doFileChecks", ""),
            "doMalwareScan": target.get("doMalwareScan", ""),
            "endPort": target.get("endPort", ""),
            "global": target.get("global", ""),
            "isRegex": target.get("isRegex", ""),
            "isTimedUrl": target.get("isTimedUrl", ""),
            "note": target.get("note", ""),
            "overrideZeroTrust": target.get("overrideZeroTrust", ""),
            "priority": target.get("priority", ""),
            "resourceId": target.get("resourceId", ""),
            "sslBypass": target.get("sslBypass", ""),
            "startPort": target.get("startPort", ""),
            "timedUrlExpiresInMinutes": target.get("timedUrlExpiresInMinutes", ""),
            "type": target.get("type", ""),
            "url": target.get("url", ""),
            "urlFieldType": target.get("urlFieldType", ""),
            "weight": target.get("weight", "")
        }
        
        # Build query string
        qs = "&".join([f"{k}={quote(str(v))}" for k, v in sorted(query_params.items())])
        uri = f"/json/controls/policyLayers/urls?{qs}"
        
        try:
            client.invoke_request(uri, service="Gateway", method="DELETE")
            logger.debug(f"Successfully deleted '{target.get('url')}'.")
            results.append(target)
        except Exception as e:
            logger.error(f"Failed to delete URL '{target.get('url')}': {e}")
            
    return results
