import base64
import logging
from typing import Optional, Dict, Any
import requests

logger = logging.getLogger(__name__)

class IBossAPIError(Exception):
    pass

class IBossAuthError(IBossAPIError):
    pass

class IBossClient:
    """
    Client for interacting with iBoss Secure Cloud Gateways.
    """
    
    def __init__(self, username: str, password: str, totp: Optional[str] = None):
        self.username = username
        self.password = password
        self.totp = totp
        
        # Session state
        self.auth_token = None
        self.cookies = {}
        self.xsrf_token = None
        
        # Base URLs mapped by service type
        self.domains = {
            "Authentication": "https://accounts.iboss.com",
            "Core": "https://api.ibosscloud.com"
        }
        
        self.context = {}
        self.gateway_version = None
        self.cloud_nodes = []
        self.web_categories = []
        
        # A shared requests session to manage connections
        self.session = requests.Session()
        
    def connect(self):
        """
        Connects to the iBoss Cloud Gateway and captures Session/XSRF tokens.
        Equivalent to Connect-iBoss.
        """
        logger.info("Connecting to iBoss...")
        
        # --- STEP 1: LOGIN (Get Token & Cookies) ---
        login_uri = "/ibossauth/web/tokens?ignoreAuthModule=true"
        if self.totp:
            login_uri += f"&totpCode={self.totp}"
            
        full_login_url = f"{self.domains['Authentication']}{login_uri}"
        
        plain_auth = f"{self.username}:{self.password}"
        basic_auth = base64.b64encode(plain_auth.encode('iso-8859-1')).decode('utf-8')
        
        headers = {
            "Authorization": f"Basic {basic_auth}",
            "User-Agent": "ibossAPI",
            "Accept": "application/json"
        }
        
        response = self.session.get(full_login_url, headers=headers)
        
        if response.status_code >= 400:
            if "MULTIFACTOR_CREDENTIALS_REQUIRED" in response.text:
                raise IBossAuthError("Login Failed: Multi-Factor Authentication is required. Provide a TOTP code.")
            raise IBossAuthError(f"Login failed (Status {response.status_code}): {response.text}")
            
        # Parse Token
        token_obj = response.json()
        raw_token = token_obj.get("token") or token_obj
        self.auth_token = f"Token {raw_token}"
        
        # Parse Cookies and XSRF Token
        for cookie in self.session.cookies:
            self.cookies[cookie.name] = cookie.value
            if cookie.name == 'XSRF-TOKEN':
                self.xsrf_token = cookie.value
                
        # --- STEP 2: GET ACCOUNT CONTEXT ---
        self.context = self.invoke_request("/ibcloud/web/users/mySettings", service="Core")
        
        context_obj = self.context[0] if isinstance(self.context, list) and self.context else (self.context if isinstance(self.context, dict) else {})
        acc_id = context_obj.get("accountSettingsId") or context_obj.get("id")
        
        # --- STEP 3: GET CLOUD NODES ---
        self.cloud_nodes = self.invoke_request(f"/ibcloud/web/cloudNodes?accountSettingsId={acc_id}", service="Core")
        
        primary_node = next((node for node in self.cloud_nodes if node.get("primaryNode") == 1), None)
        if not primary_node:
            primary_node = next((node for node in self.cloud_nodes if node.get("masterAdminInterfaceDns")), None)
            
        if primary_node and primary_node.get("masterAdminInterfaceDns"):
            gateway_dns = primary_node["masterAdminInterfaceDns"]
            self.gateway_version = primary_node.get("currentFirmwareVersion")
            swg_url = primary_node.get("publicUrl")
            self.domains["Gateway"] = f"https://{gateway_dns}"
        else:
            raise IBossAPIError("Could not identify a Primary Gateway DNS.")
            
        # Reporting Node
        reporting_node = next((node for node in self.cloud_nodes 
                             if node.get("productFamily") == "reports" or node.get("description") == "Reporter"), None)
                             
        if reporting_node:
            reporting_dns = reporting_node["masterAdminInterfaceDns"]
            self.domains["Reporting"] = f"https://{reporting_dns}"
        else:
            self.domains["Reporting"] = f"https://{gateway_dns}"
            
        # --- STEP 4: FETCH WEB CATEGORIES ---
        if swg_url:
            cat_uri = f"{swg_url}common/lookup/mainWebCategories.json?tcm={self.gateway_version}"
            cat_headers = {
                "Authorization": self.auth_token,
                "User-Agent": "ibossAPI",
                "Content-Type": "application/json;charset=UTF-8"
            }
            if self.xsrf_token:
                cat_headers["X-XSRF-TOKEN"] = self.xsrf_token
                
            try:
                # Use standard requests directly here since we are calling publicUrl not relative to base
                cat_resp = self.session.get(cat_uri, headers=cat_headers)
                cat_resp.raise_for_status()
                categories = cat_resp.json()
                self.web_categories = [{"id": c.get("id"), "defaultText": c.get("defaultText")} for c in categories]
            except Exception as e:
                logger.warning(f"Failed to fetch Web Categories: {e}")
                
        logger.info(f"Connected to iBoss Cloud Gateway! Primary Node: {gateway_dns}")

    def invoke_request(self, uri: str, service: str, method: str = "GET", 
                       body: Optional[Any] = None, extra_headers: Optional[Dict[str, str]] = None,
                       raw_response: bool = False) -> Any:
        """
        Internal helper to execute iBoss API calls.
        Equivalent to Invoke-iBossRequest.
        """
        if service not in ["Authentication", "Core", "Gateway", "Reporting"]:
            raise ValueError(f"Invalid service: {service}")
            
        if service not in self.domains:
            raise IBossAPIError(f"Cannot find base URL for '{service}'. You must run connect() first.")
            
        base_url = self.domains[service]
        clean_uri = uri.lstrip('/')
        full_uri = f"{base_url}/{clean_uri}"
        
        headers = {
            "User-Agent": "ibossAPI",
            "Authorization": self.auth_token,
            "Content-Type": "application/json;charset=UTF-8"
        }
        
        if self.xsrf_token:
            headers["X-XSRF-TOKEN"] = self.xsrf_token
            
        if extra_headers:
            headers.update(extra_headers)
            
        kwargs = {
            "method": method,
            "url": full_uri,
            "headers": headers,
            "cookies": self.cookies
        }
        
        if body is not None:
            kwargs["json"] = body
            
        response = self.session.request(**kwargs)
        
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            try:
                error_body = response.text
                logger.error(f"API Call Failed. Error Body: {error_body}")
            except Exception:
                pass
            raise IBossAPIError(f"API Call Failed: {e}") from e
            
        if raw_response:
            return response
            
        # Handle cases where response might be empty
        if not response.content:
            return None
            
        try:
            return response.json()
        except ValueError:
            return response.text
