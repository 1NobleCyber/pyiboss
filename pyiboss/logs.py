import hashlib
import time
import struct
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

from pyiboss.client import IBossClient

logger = logging.getLogger(__name__)


def get_iboss_log_table(client: IBossClient, log_family: str = "url") -> List[Dict[str, Any]]:
    """
    Retrieves the list of available log tables (archives) from the iBoss Reporting Service.
    """
    if log_family not in ["url", "ips"]:
        raise ValueError(f"Invalid log_family: {log_family}")
        
    uri = f"/ibreports/web/log/{log_family}/archives?includeAllRecord=true&includeLogReports=true"
    response = client.invoke_request(uri, service="Reporting", method="GET")
    
    return response if isinstance(response, list) else []

def get_iboss_log_icon(client: IBossClient, domain: str, out_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieves the icon (favicon/logo) for a domain from iBoss.
    """
    uri = f"/ibreports/web/lookup/domain/logo?domain={quote(domain)}"
    
    # We need the raw bytes
    response = client.invoke_request(uri, service="Reporting", method="GET", raw_response=True)
    bytes_data = response.content
    
    if not bytes_data:
        raise ValueError("Icon retrieved but content is empty.")
        
    hex_head = bytes_data[:8].hex().upper()
    file_type = "Unknown"
    
    if hex_head.startswith("89504E47"):
        file_type = "PNG"
    elif hex_head.startswith("00000100"):
        file_type = "ICO"
    elif hex_head.startswith("3C3F786D") or hex_head.startswith("3C737667"):
        file_type = "SVG"
        
    sha256_hash = hashlib.sha256(bytes_data).hexdigest().upper()
    dimensions = "Unknown"
    
    try:
        if file_type == "PNG" and len(bytes_data) >= 24:
            w = struct.unpack(">I", bytes_data[16:20])[0]
            h = struct.unpack(">I", bytes_data[20:24])[0]
            dimensions = f"{w} x {h}"
        elif file_type == "ICO" and len(bytes_data) >= 8:
            w = bytes_data[6]
            h = bytes_data[7]
            if w == 0: w = 256
            if h == 0: h = 256
            dimensions = f"{w} x {h}"
    except Exception as e:
        logger.debug(f"Failed to parse dimensions: {e}")
        
    if out_file:
        with open(out_file, 'wb') as f:
            f.write(bytes_data)
            
    return {
        "Domain": domain,
        "Size": len(bytes_data),
        "FileType": file_type,
        "Dimensions": dimensions,
        "SHA256": sha256_hash,
        "Bytes": bytes_data
    }


def get_iboss_log_entry(
    client: IBossClient,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    url_filter: Optional[str] = None,
    user_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    device_name: Optional[str] = None,
    group_name: Optional[str] = None,
    category_name: Optional[str] = None,
    action: str = "All",
    ascending: bool = False,
    limit: int = 100,
    log_type: str = "url_log_entry",
    event_log_type: str = "All",
    locale: str = "en_US",
    zero_trust_policy_name: Optional[str] = None,
    client_application: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves log entries from the iBoss Cloud Reporting Service.
    """
    if not end_time:
        end_time = datetime.now(timezone.utc)
        
    end_epoch = int(end_time.timestamp() * 1000)
    
    log_family = log_type.split('_')[0]
    if log_family not in ["url", "ips"]:
        log_family = "url"
        
    all_tables = get_iboss_log_table(client, log_family)
    
    if start_time:
        start_epoch = int(start_time.timestamp() * 1000)
    else:
        matching_table = None
        for tbl in all_tables:
            tbl_display = tbl.get("displayString", "")
            # Basic suffix strip: remove _MMDDYYYY
            tbl_type = "_".join(tbl_display.split("_")[:-1]) if "_" in tbl_display else tbl_display
            
            if tbl_type != log_type and tbl_display.replace(tbl_display[-9:], "") != log_type:
                # If exact split isn't perfect, just check if it starts with log_type
                if not tbl_display.startswith(log_type):
                    continue
            
            t_start = tbl.get("startDate", 0)
            t_end = tbl.get("endDate")
            if not t_end:
                t_end = int(time.time() * 1000)
                
            if t_start <= end_epoch <= t_end:
                matching_table = tbl
                break
                
        if matching_table:
            start_epoch = matching_table.get("startDate", 0)
        else:
            start_epoch = end_epoch - 3600000
            
    target_tables = []
    for tbl in all_tables:
        tbl_display = tbl.get("displayString", "")
        # Naive matching of type
        if not tbl_display.startswith(log_type):
            continue
            
        t_end = tbl.get("endDate") or int(time.time() * 1000)
        t_start = tbl.get("startDate", 0)
        
        if start_epoch <= t_end and end_epoch > t_start:
            target_tables.append(tbl)
            
    if not target_tables:
        logger.warning(f"No log tables found for LogType '{log_type}' in the specified time range.")
        return []
        
    type_settings = {
        'All': {'statusRecordType': '-1', 'auditRecord': '-1', 'noiseFilter': '-1', 'isProxyError': '-1', 'callout': '-1', 'statusRecord': '-1'},
        'Access': {'statusRecordType': '0', 'auditRecord': '-1', 'noiseFilter': '-1', 'isProxyError': '-1', 'callout': '-1', 'statusRecord': '-1'},
        'UserActivity': {'statusRecordType': '1', 'auditRecord': '-1', 'noiseFilter': '-1', 'isProxyError': '-1', 'callout': '-1', 'statusRecord': '-1'},
        'ConnectionError': {'statusRecordType': '-1', 'auditRecord': '-1', 'noiseFilter': '-1', 'isProxyError': '1', 'callout': '-1', 'statusRecord': '-1'},
        'Search': {'statusRecordType': '2', 'auditRecord': '-1', 'noiseFilter': '-1', 'isProxyError': '-1', 'callout': '-1', 'statusRecord': '-1'},
        'ZTNA': {'statusRecordType': '-1', 'auditRecord': '-1', 'noiseFilter': '-1', 'isProxyError': '-1', 'callout': '-1', 'statusRecord': '2'},
        'SDWAN': {'statusRecordType': '-1', 'auditRecord': '-1', 'noiseFilter': '-1', 'isProxyError': '-1', 'callout': '1', 'statusRecord': '-1'},
        'DNS': {'statusRecordType': '-1', 'auditRecord': '-1', 'noiseFilter': '2', 'isProxyError': '-1', 'callout': '-1', 'statusRecord': '-1'},
        'ConnectorRegistration': {'statusRecordType': '-1', 'auditRecord': '-1', 'noiseFilter': '3', 'isProxyError': '-1', 'callout': '-1', 'statusRecord': '-1'},
        'ZTNAPeerRegistration': {'statusRecordType': '-1', 'auditRecord': '-1', 'noiseFilter': '4', 'isProxyError': '-1', 'callout': '-1', 'statusRecord': '-1'},
        'SoftOverride': {'statusRecordType': '3', 'auditRecord': '-1', 'noiseFilter': '-1', 'isProxyError': '-1', 'callout': '-1', 'statusRecord': '-1'},
        'Audit': {'statusRecordType': '-1', 'auditRecord': '0', 'noiseFilter': '-1', 'isProxyError': '-1', 'callout': '-1', 'statusRecord': '-1'}
    }.get(event_log_type, {})
    
    action_map = {
        'All': '',
        'Allowed': 'Allowed',
        'Blocked': 'Blocked',
        'RBIRedirect': 'RBI+Redirect',
        'SoftBlocked': 'Soft-blocked',
        'ConnectRequest': 'Connect+Request'
    }
    
    action_val = action_map.get(action, "")
    
    base_params = {
        "action": action_val,
        "addTag": "true",
        "auditRecord": type_settings.get('auditRecord', '-1'),
        "callout": type_settings.get('callout', '-1'),
        "caseInsensitive": "false",
        "categoryId": "1000000",
        "currentLogEntryId": "-1",
        "currentLogTable": "",
        "currentRowNumber": "1",
        "email": "",
        "endTimeMillies": str(end_epoch),
        "externalSearchEnabled": "false",
        "generatorId": "-1",
        "includeAllRecord": "true",
        "includeLogReports": "true",
        "isAdvancedSearch": "true",
        "isProxyError": type_settings.get('isProxyError', '-1'),
        "locale": locale,
        "localizeLogTime": "true",
        "logReductionType": "0",
        "maxItemsToReturn": str(limit),
        "mitm": "-1",
        "noiseFilter": type_settings.get('noiseFilter', '-1'),
        "orderAscending": "true" if ascending else "false",
        "priority": "-1",
        "proxyErrorWildcard": "true",
        "reportingGroup": "-1",
        "scrollForward": "true",
        "searchRiskType": "-1",
        "sortByCriteria": "SORT_BY_ID",
        "startTimeMillies": str(start_epoch),
        "statusRecord": type_settings.get('statusRecord', '-1'),
        "statusRecordType": type_settings.get('statusRecordType', '-1'),
        "swgGateway": "all",
        "tlsVersion": "",
        "url": "",
        "urlFilter": "",
        "wildCard": "false"
    }
    
    if url_filter: base_params['urlFilter'] = url_filter
    if user_name: base_params['username'] = user_name
    if source_ip: base_params['sourceIp'] = source_ip
    if destination_ip: base_params['destinationIp'] = destination_ip
    if zero_trust_policy_name: base_params['zeroTrustPolicyName'] = zero_trust_policy_name
    if client_application: base_params['applicationName'] = client_application
    if device_name: base_params['machineName'] = device_name
    if group_name: base_params['groupName'] = group_name.replace(' ', '+')
    
    if category_name:
        cat = next((c for c in client.web_categories if c.get("defaultText") == category_name), None)
        if cat:
            base_params['categoryId'] = str(cat["id"])
            
    all_results = []
    
    for tbl in target_tables:
        params = base_params.copy()
        params['tableName'] = tbl.get("tableName", "")
        
        # custom query string builder to match PS exact output
        query_parts = []
        for k, v in params.items():
            encoded = quote(v)
            # relax encoding
            encoded = encoded.replace('%21', '!').replace('%40', '@').replace('%24', '$').replace('%2A', '*')
            encoded = encoded.replace('%28', '(').replace('%29', ')').replace('%2C', ',').replace('%3B', ';').replace('%3A', ':')
            query_parts.append(f"{k}={encoded}")
            
        qs = "&".join(query_parts)
        uri = f"/ibreports/web/log/url/entries?{qs}"
        
        try:
            result = client.invoke_request(uri, service="Reporting", method="GET")
            if isinstance(result, list):
                for item in result:
                    log_time = item.get("logTime")
                    if log_time is not None:
                        try:
                            # Convert logTime to datetime object
                            dt = datetime.fromtimestamp(log_time / 1000.0)
                            item["parsedLogTime"] = dt
                        except Exception:
                            pass
                all_results.extend(result)
        except Exception as e:
            logger.warning(f"Failed to query table {tbl.get('tableName')}: {e}")
            
    return all_results
