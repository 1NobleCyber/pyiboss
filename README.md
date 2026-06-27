# pyiboss

**pyiboss** is a Python package designed to facilitate authentication and seamless interactions with the **iBoss Cloud Gateway REST API**. It allows administrators and security teams to automate gateway management, URL classification, allow/block lists, asset tracking, and log retrieval.

## Features

- **Authentication Handling**: Easily authenticate and manage API session tokens with `IBossClient` (supports Multi-Factor Authentication/TOTP).
- **List Management**: Programmatically add, retrieve, or remove domains and IPs from your Allow/Block lists.
- **Log and Report Management**: Fetch log entries and log tables to analyze traffic and threats dynamically.
- **Asset Discovery**: Query and retrieve counts and details of devices (assets) connected to your iBoss environment.
- **URL Classification**: Check category mappings and submit recategorization requests natively.

## Installation

Currently, this module can be installed locally from the repository.

```bash
# Clone the repository
git clone https://github.com/1NobleCyber/pyiboss.git

# Navigate to the project directory
cd pyiboss

# Install dependencies (requests)
pip install -r requirements.txt # (or pip install requests)
```

## Getting Started

First, you'll need to authenticate to your iBoss instance using the `IBossClient`.

```python
from pyiboss.client import IBossClient

# Connect to iBoss (Standard Auth)
client = IBossClient("username@domain.com", "YourPassword")
client.connect()

# Connect to iBoss (With MFA / TOTP)
client_mfa = IBossClient("username@domain.com", "YourPassword", totp="123456")
client_mfa.connect()
```

## Usage Examples

### Retrieve Current Assets
```python
from pyiboss.assets import get_iboss_asset

# Get a list of the latest 10 assets
assets = get_iboss_asset(client, limit=10)
print(assets)
```

### Manage Allow/Block Lists
```python
from pyiboss.blocklist import add_iboss_block_list, get_iboss_block_list

# Add a domain to the block list
add_iboss_block_list(client, url="malicious-site.com")

# View the current block list
block_list = get_iboss_block_list(client)
print(block_list)
```

### Perform URL Lookups
```python
from pyiboss.urls import get_iboss_url_lookup

# Check the category of a specific URL
lookup = get_iboss_url_lookup(client, url="example.com")
print(lookup)
```

### Fetch Log Entries
```python
from pyiboss.logs import get_iboss_log_entry

# Retrieve recent traffic logs
logs = get_iboss_log_entry(client, limit=50)
print(logs)
```

## Available Modules

| Module | Features |
|---|---|
| `client` | `IBossClient` for connection management and authenticated REST API requests. |
| `assets` | Retrieve asset details and asset counts from the Zero Trust gateway. |
| `allowlist` | Add, get, and remove domains from the Allow List. |
| `blocklist` | Add, get, and remove domains from the Block List. |
| `logs` | Retrieve log entries, tables, and domain icons with full filtering and parsing. |
| `groups` | Retrieve iBoss group configurations. |
| `urls` | Lookup URL categorization and submit URLs for recategorization. |

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

## License

This project is licensed under the [Unlicense](LICENSE) - see the LICENSE file for details.
