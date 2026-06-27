import logging
from typing import Dict, Any

from pyiboss.client import IBossClient

logger = logging.getLogger(__name__)

def get_iboss_url_lookup(client: IBossClient, url: str) -> Dict[str, Any]:
    """
    Checks the categorization and reputation of a URL.
    """
    uri = "/json/controls/urlLookup"
    payload = {"url": url}
    
    return client.invoke_request(uri, service="Gateway", method="POST", body=payload)

def submit_iboss_url_recategorization(client: IBossClient, url: str, note: str) -> Any:
    """
    Submits a URL for recategorization.
    """
    lookup = get_iboss_url_lookup(client, url)
    
    cat_string = lookup.get("categories")
    if not cat_string:
        raise ValueError(f"Could not retrieve 'categories' bitmask for {url}. Recategorization requires this data.")
        
    cat_array = [int(char) for char in cat_string]
    
    submit_payload = {
        "url": url,
        "categories": cat_array,
        "note": note
    }
    
    uri = "/json/controls/urlLookup/recatSite"
    return client.invoke_request(uri, service="Gateway", method="POST", body=submit_payload)
