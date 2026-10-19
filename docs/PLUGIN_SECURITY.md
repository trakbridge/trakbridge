# Plugin Security and Management

## Overview

TrakBridge implements a secure plugin system that allows administrators to add new GPS tracking plugins without modifying core application code, while maintaining security against arbitrary code execution.

## Security Architecture

### Built-in Security Features

1. **Module Whitelist**: Only pre-approved plugin modules can be loaded
2. **Path Validation**: Prevents path traversal attacks (no `../` allowed)
3. **Namespace Restriction**: All plugins must be under the `plugins.` namespace
4. **Character Filtering**: Only alphanumeric, dots, and underscores allowed in module names
5. **Configuration-based**: Plugin approval is done through configuration files, not code

### Default Allowed Plugins

The following plugins are built-in and always allowed:
- `plugins.garmin_plugin`
- `plugins.spot_plugin`
- `plugins.traccar_plugin`
- `plugins.deepstate_plugin`

## Adding New Plugins Securely

### Method 1: Configuration File (Recommended)

Add new plugins to `config/settings/plugins.yaml`:

```yaml
allowed_plugin_modules:
  - plugins.custom_gps_plugin
  - plugins.enterprise_tracker
  - plugins.third_party.special_tracker
```

### Method 2: Admin CLI Tool

Use the management script for temporary additions:

```bash
# List currently allowed modules
python scripts/manage_plugins.py list

# Add a new plugin module (temporary - until restart)
python scripts/manage_plugins.py add plugins.my_custom_plugin

# Reload configuration from files
python scripts/manage_plugins.py reload
```

### Method 3: Programmatic API

For administrative interfaces:

```python
from plugins.plugin_manager import get_plugin_manager

manager = get_plugin_manager()

# Add a module (temporary)
success = manager.add_allowed_plugin_module('plugins.new_plugin')

# Get current allowed modules
allowed = manager.get_allowed_plugin_modules()

# Reload from config files
manager.reload_plugin_config()
```

## Plugin Development Guidelines

### Security Requirements

1. **Namespace**: All plugins must be in the `plugins.` namespace
2. **Inheritance**: Must inherit from `BaseGPSPlugin`
3. **Validation**: Implement proper input validation
4. **No System Calls**: Avoid shell commands or system calls
5. **Safe Dependencies**: Only use approved third-party libraries

### Example Plugin Structure

```python
# plugins/my_custom_plugin.py
from plugins.base_plugin import BaseGPSPlugin, PluginConfigField

class MyCustomPlugin(BaseGPSPlugin):
    PLUGIN_NAME = "my_custom"
    
    @classmethod
    def get_plugin_name(cls) -> str:
        return cls.PLUGIN_NAME
    
    # ... implement required methods
```

## Configuration File Locations

The system checks these locations in order:

1. `config/settings/plugins.yaml` (recommended)
2. `/etc/trakbridge/plugins.yaml` (system-wide)
3. `~/.trakbridge/plugins.yaml` (user-specific)
4. `plugins.yaml` (current directory)

## Security Considerations

### What This Prevents

- **Arbitrary Code Execution**: Only whitelisted modules can be loaded
- **Path Traversal**: Cannot load modules outside the plugins namespace
- **Injection Attacks**: Module names are strictly validated
- **Privilege Escalation**: Plugins run with same permissions as main app

### What Administrators Must Ensure

- **Trust**: Only add plugins from trusted sources
- **Review**: Review plugin code before adding to whitelist
- **Updates**: Keep plugin dependencies updated
- **Monitoring**: Monitor logs for unauthorized loading attempts

### Security Logging

The system logs:
- Successful plugin module additions
- Rejected unsafe module names
- Unauthorized loading attempts
- Configuration reload events

Example log entries:
```
INFO: Added allowed plugin module from config: plugins.custom_tracker
WARNING: Rejected unsafe plugin module name: ../../../etc/passwd
WARNING: Attempted to load unauthorized plugin module: malicious.plugin
```

## Troubleshooting

### Plugin Not Loading

1. Check if module is in allowed list: `python scripts/manage_plugins.py list`
2. Verify module name follows security requirements
3. Check application logs for security warnings
4. Ensure YAML configuration is valid

### Permission Denied

1. Verify file permissions on config files
2. Check that PyYAML is installed for config file parsing
3. Ensure plugin file is readable by application user

### Development Mode

For development, you can temporarily add modules programmatically, but they won't persist across restarts. Use configuration files for permanent additions.

## Custom CoT Attributes Security (v1.1.0+)

### XML Injection Prevention

TrakBridge v1.1.0+ allows plugins to add custom XML elements and attributes to CoT messages via the `custom_cot_attrib` field. This feature includes comprehensive security protections:

#### XML Name Validation

All element and attribute names are validated using a strict regex pattern to prevent XML injection attacks:

**Validation Pattern**: `^[a-zA-Z_][\w\-\.]*$`

**Rules**:
- Must start with letter (a-z, A-Z) or underscore (_)
- Can contain letters, digits, hyphens (-), periods (.), underscores (_)
- Cannot contain spaces, special characters, or XML metacharacters
- Cannot start with numbers

**Examples**:

```python
# ✓ VALID element names
"custom_element"     # Letters and underscore
"milsym"            # Letters only
"element-2"         # Letters, hyphen, digit
"__group"           # Underscores and letters
"data.field"        # Letters, period

# ✗ INVALID element names (rejected with warning)
"123invalid"        # Starts with number
"element name"      # Contains space
"element<script>"   # Contains XML metacharacters
"../../../etc"      # Path traversal attempt
"element&attr"      # Contains ampersand
```

#### Protected Element System

Critical CoT elements cannot be overridden by plugin custom attributes to maintain CoT integrity and prevent security issues:

**Event-level protected attributes**:
- `version`, `uid`, `type`, `time`, `start`, `stale`, `how`

**Detail-level protected elements**:
- `contact`, `uid`, `precisionlocation`, `__group`, `status`, `track`

Attempts to override protected elements are:
1. Logged as warnings with the element name
2. Silently ignored (not applied to XML)
3. Tracked in security audit logs

**Example**:

```python
# This custom attribute will be REJECTED
"custom_cot_attrib": {
    "detail": {
        "contact": {"_text": "Malicious override"},  # REJECTED - protected
        "custom_field": {"_text": "Allowed"}          # ALLOWED - not protected
    }
}
```

#### Attack Scenarios Prevented

1. **XML Injection**: Invalid characters and metacharacters rejected
2. **XSS via CoT**: Special characters in element names blocked
3. **CoT Structure Tampering**: Protected elements cannot be modified
4. **Path Traversal**: Directory traversal patterns rejected in names
5. **Code Injection**: No executable code can be injected via element names

#### Security Logging

The system logs all custom CoT attribute security events:

```
WARNING: Invalid XML element name rejected: 123invalid
WARNING: Skipping protected detail element: contact
WARNING: Skipping protected event attribute: uid
INFO: Applied custom CoT attributes for uid TRACK-001
```

### Input Validation Best Practices

When implementing plugins that use custom CoT attributes:

#### 1. Validate External Data

```python
# ✓ GOOD - Validate before using in custom attributes
def transform_data(self, raw_data):
    symbol_code = raw_data.get("symbol")

    # Validate format before using
    if symbol_code and len(symbol_code) == 15:
        location["custom_cot_attrib"] = {
            "detail": {
                "__milsym": {"_text": symbol_code}
            }
        }
```

#### 2. Sanitize User Input

```python
# ✓ GOOD - Sanitize user-provided values
import re

def sanitize_callsign(callsign: str) -> str:
    """Remove potentially dangerous characters"""
    return re.sub(r'[^\w\-\.]', '', callsign)

location["custom_cot_attrib"] = {
    "detail": {
        "custom_callsign": {
            "_text": sanitize_callsign(raw_callsign)
        }
    }
}
```

#### 3. Use Safe Defaults

```python
# ✓ GOOD - Provide safe defaults for missing data
access_level = raw_data.get("access", "Unclassified")  # Safe default

location["custom_cot_attrib"] = {
    "event": {
        "_attributes": {
            "access": access_level
        }
    }
}
```

#### 4. Avoid Dynamic Element Names

```python
# ✗ BAD - User-controlled element names
user_field_name = raw_data.get("field_name")  # Dangerous!
location["custom_cot_attrib"] = {
    "detail": {
        user_field_name: {"_text": "value"}  # XML injection risk
    }
}

# ✓ GOOD - Fixed element names only
location["custom_cot_attrib"] = {
    "detail": {
        "custom_field": {  # Safe - hardcoded name
            "_text": raw_data.get("field_value", "")
        }
    }
}
```

### CoT Integrity Protection

The custom CoT attributes system is designed to extend CoT messages safely without compromising message integrity:

1. **Core Structure Preserved**: Essential CoT elements (point, event metadata, timing) cannot be modified
2. **Team Member Protection**: Team member-specific elements (__group, contact) are protected when team mode is enabled
3. **Validation Layers**: Multiple validation layers ensure malformed XML cannot be generated
4. **Graceful Degradation**: Invalid custom attributes are dropped with warnings, but message generation continues
5. **Audit Trail**: All custom attribute applications are logged for security review

### Monitoring and Auditing

**Monitor these logs for potential security issues**:

```bash
# Check for rejected XML names
grep "Invalid XML element name" /var/log/trakbridge/app.log

# Check for protected element override attempts
grep "Skipping protected" /var/log/trakbridge/app.log

# Review custom attribute usage
grep "Applied custom CoT attributes" /var/log/trakbridge/app.log
```

**Security Indicators**:
- Frequent "Invalid XML element name" warnings → Possible injection attempts
- Repeated protected element overrides → Misconfigured or malicious plugin
- High volume of custom attribute applications → Review plugin behavior

## Best Practices

1. **Minimal Permissions**: Only add plugins you actually need
2. **Regular Audits**: Periodically review allowed plugin list
3. **Version Control**: Keep plugin configurations in version control
4. **Testing**: Test new plugins in development before production
5. **Documentation**: Document why each plugin was added
6. **Backup**: Backup working configurations before changes
7. **Custom CoT Review**: Audit plugins using custom_cot_attrib for proper validation
8. **Security Monitoring**: Regularly review logs for XML injection attempts

---

## Plugin Signing (V1/V2)

TrakBridge verifies an Ed25519 signature on every plugin it loads.
The signing key belongs to the TrakBridge Project — the same key that
signs licence tokens. Third-party developers can build and share
plugins, but signed distribution goes through Emfour.

### Load-time behaviour

| Source | Signed | Unsigned |
| --- | --- | --- |
| ZIP upload via admin UI (any tier) | Installed cleanly | Community-tier: installed with an "unverified" banner. Pro/enterprise: **refused** |
| Package directory in `external_plugins/` | Loaded cleanly | Community-tier: **refused** unless `allow_community_sideload` is on. Pro/enterprise: **always refused** |
| Loose `.py` file in `external_plugins/` | Loaded cleanly | **Refused** unless `allow_community_sideload` is on. Never permitted for pro/enterprise (loose files carry no tier declaration) |

### Enabling unsigned community-tier sideload

Edit `config/settings/plugins.yaml`:

```yaml
plugin_settings:
  # ... existing keys ...
  allow_community_sideload: true
```

Then restart. Every unsigned load will emit a `WARNING` log line
naming the file. This flag never permits unsigned pro or enterprise
plugins — those must be shipped as signed packages.

Recommendation: leave `allow_community_sideload: false` in production.
Use it only in development or in CI-controlled deployments where
every file in `external_plugins/` is guaranteed to be trusted.

### Where signatures come from

TrakBridge distributions of premium plugins are signed by the
TrakBridge Project's offline signing key. The verifier's public
half is embedded in `services/license_service.py`.

Community-tier plugins produced by third-party developers are not
signed today — they either install as unverified ZIPs (banner in
the admin UI) or require `allow_community_sideload: true` for
loose sideload. First-class tooling for third-party developers to
sign their own plugins is a future item on the roadmap.

### What signing protects against

- Filesystem-write attackers dropping a `.py` file to gain RCE at
  next restart.
- Compromised distribution channels swapping a valid plugin ZIP for
  a malicious one.
- Accidental drift where a modified plugin loads in production
  without anyone noticing.

### What signing does NOT protect against

- Bugs or bad behaviour in signed plugins. Signing proves origin,
  not quality. Review plugin code you don't own.
