# Network Intelligence System - Smart Network-Based Persistence

## Overview

The Network Intelligence System provides smart, network-aware tracking of vulnerabilities and credentials discovered by Ragnar. It automatically manages the lifecycle of findings based on WiFi network context, maintaining active vs resolved states for intelligent persistence.

## Key Features

### 🌐 Network-Aware Tracking
- **WiFi Network Context**: Tracks findings per WiFi network (SSID-based)
- **Automatic State Management**: Active findings on current network, resolved when network changes
- **Network Profiles**: Maintains statistics and history per network

### 🔄 Smart State Transitions
- **Active State**: Findings detected on current network
- **Resolved State**: Findings no longer detected or from previous networks
- **Auto-Resolution**: Findings automatically resolve after timeout if not re-confirmed
- **Manual Resolution**: API endpoints for manual state management

### 📊 Dual View Architecture
- **Dashboard View**: Shows only active findings for current network
- **NetKB View**: Shows all findings (active + resolved) across all networks
- **Real-time Sync**: WebSocket updates when findings change

## Architecture

### Core Components

1. **NetworkIntelligence Class** (`network_intelligence.py`)
   - Main intelligence engine
   - Manages network context and finding lifecycle
   - Provides APIs for adding, confirming, and resolving findings

2. **WebApp Integration** (`webapp_modern.py`)
   - Network-aware API endpoints
   - Dashboard/NetKB view differentiation
   - Real-time WebSocket updates

3. **Data Storage** (`data/intelligence/`)
   - JSON-based persistent storage
   - Network profiles and finding history
   - Separated active/resolved states

### Network Identification

```python
def create_network_id(self, ssid: str) -> str:
    """Create a stable network identifier from SSID"""
    network_hash = hashlib.md5(ssid.encode()).hexdigest()[:8]
    return f"net_{network_hash}"
```

Networks are identified by hashing the SSID to create stable, privacy-preserving identifiers.

## API Endpoints

### Core Network Intelligence

- `GET /api/network-intelligence` - Complete intelligence summary
- `GET /api/vulnerabilities` - Network-aware vulnerability data  
- `GET /api/credentials` - Network-aware credential data

### Finding Management

- `POST /api/network-intelligence/add-vulnerability` - Add new vulnerability
- `POST /api/network-intelligence/add-credential` - Add new credential

### Request/Response Examples

#### Add Vulnerability
```json
POST /api/network-intelligence/add-vulnerability
{
    "host": "192.168.1.100",
    "port": 22,
    "service": "ssh",
    "vulnerability": "Weak Authentication",
    "severity": "high",
    "details": {
        "cve": "CVE-2023-1234",
        "description": "SSH allows weak authentication"
    }
}
```

#### Add Credential
```json
POST /api/network-intelligence/add-credential
{
    "host": "192.168.1.100", 
    "service": "ssh",
    "username": "admin",
    "password": "password123",
    "protocol": "ssh",
    "details": {
        "method": "brute_force",
        "attempts": 5
    }
}
```

## Data Structures

### Vulnerability Finding
```json
{
    "id": "vuln_abc123def456",
    "host": "192.168.1.100",
    "port": 22,
    "service": "ssh", 
    "vulnerability": "Weak Authentication",
    "severity": "high",
    "details": {...},
    "discovered": "2024-01-15T10:30:00Z",
    "network_id": "net_abc12345",
    "status": "active",
    "confirmation_count": 3,
    "last_confirmed": "2024-01-15T10:30:00Z"
}
```

### Credential Finding
```json
{
    "id": "cred_def456ghi789",
    "host": "192.168.1.100",
    "service": "ssh",
    "username": "admin", 
    "password": "password123",
    "protocol": "ssh",
    "details": {...},
    "discovered": "2024-01-15T10:30:00Z",
    "network_id": "net_abc12345",
    "status": "active",
    "confirmation_count": 2,
    "last_confirmed": "2024-01-15T10:30:00Z"
}
```

### Network Profile
```json
{
    "net_abc12345": {
        "first_seen": "2024-01-15T09:00:00Z",
        "last_seen": "2024-01-15T10:30:00Z",
        "connection_count": 5,
        "total_vulnerabilities": 10,
        "total_credentials": 8,
        "active_vulnerabilities": 3,
        "active_credentials": 2
    }
}
```

## Configuration

### Default Settings (`shared_config.json`)
```json
{
    "network_intelligence_enabled": true,
    "network_resolution_timeout": 3600,
    "network_confirmation_scans": 3,
    "network_change_grace": 300,
    "network_auto_resolution": true
}
```

### Configuration Parameters

- **`network_intelligence_enabled`**: Enable/disable the intelligence system
- **`network_resolution_timeout`**: Seconds before auto-resolving unconfirmed findings (default: 1 hour)
- **`network_confirmation_scans`**: Number of confirmations needed to keep finding active
- **`network_change_grace`**: Grace period after network change before resolution (5 minutes)
- **`network_auto_resolution`**: Enable automatic resolution based on network presence

## File Structure

```
data/
└── intelligence/
    ├── network_profiles.json     # Network statistics and history
    ├── active_findings.json      # Current active findings
    └── resolved_findings.json    # Historical resolved findings
```

## Integration Guide

### 1. Action Module Integration

Action modules can report findings using the network intelligence API:

```python
# Example from an action module
def report_vulnerability(host, port, service, vuln_desc):
    if hasattr(shared_data, 'network_intelligence') and shared_data.network_intelligence:
        vuln_id = shared_data.network_intelligence.add_vulnerability(
            host=host,
            port=port, 
            service=service,
            vulnerability=vuln_desc,
            severity="medium"
        )
        logger.info(f"Reported vulnerability: {vuln_id}")
```

### 2. WebApp Dashboard Integration

The dashboard automatically shows network-aware data:

```javascript
// Dashboard gets current network findings
fetch('/api/vulnerabilities')
    .then(response => response.json())
    .then(data => {
        console.log(`Current network: ${data.network_context.current_network}`);
        console.log(`Active vulnerabilities: ${data.network_context.count}`);
        // Display only current network findings
    });
```

### 3. NetKB Integration

NetKB shows comprehensive historical view:

```javascript
// NetKB gets all findings across networks
fetch('/api/network-intelligence')
    .then(response => response.json())
    .then(data => {
        const netkb = data.netkb_findings;
        console.log(`Total vulnerabilities: ${netkb.counts.total_vulnerabilities}`);
        console.log(`Active: ${netkb.counts.active_vulnerabilities}`);
        console.log(`Resolved: ${netkb.counts.resolved_vulnerabilities}`);
    });
```

## Workflow Examples

### Network Change Scenario

1. **Home Network** (net_abc12345)
   - Dashboard shows: 3 vulnerabilities, 2 credentials
   - NetKB shows: Same as dashboard (first network)

2. **Move to Office Network** (net_def67890)
   - Home findings marked for resolution
   - Dashboard shows: 0 findings (new network)
   - NetKB shows: 3 vulnerabilities, 2 credentials (pending resolution)

3. **Office Network Scanning**
   - New findings discovered: 1 vulnerability, 1 credential
   - Dashboard shows: 1 vulnerability, 1 credential
   - NetKB shows: 4 vulnerabilities, 3 credentials (mixed states)

4. **After Resolution Timeout**
   - Home findings auto-resolved (not confirmed on office network)
   - Dashboard shows: 1 vulnerability, 1 credential (office only)
   - NetKB shows: 4 vulnerabilities, 3 credentials (office active, home resolved)

### Manual Resolution

```python
# Manually resolve a finding
shared_data.network_intelligence.resolve_finding(
    finding_id="vuln_abc123def456",
    reason="manually_verified_fixed"
)
```

## Benefits

### 🎯 Smart Contextual Awareness
- **Current Focus**: Dashboard shows only what's relevant to current network
- **Historical Intelligence**: NetKB maintains comprehensive knowledge base
- **Automatic Lifecycle**: Findings resolve when no longer relevant

### 🔄 Efficient Resource Management
- **Avoid Noise**: Old findings don't clutter current view
- **Persistent Knowledge**: Historical data maintained for forensics
- **Smart Confirmation**: Multiple confirmations required for persistence

### 🚀 Enhanced Workflow
- **Real-time Updates**: WebSocket integration for immediate feedback
- **API-Driven**: Easy integration with existing action modules
- **Configurable**: Timeout and confirmation thresholds adjustable

## Testing

Run the demonstration script to see the system in action:

```bash
python3 demo_network_intelligence.py
```

This will:
- Initialize the intelligence system
- Add sample vulnerabilities and credentials
- Show dashboard vs NetKB views
- Demonstrate network context awareness
- Save sample data for inspection

## Future Enhancements

### Planned Features
- **Geographic Context**: Location-aware intelligence
- **Threat Intelligence Integration**: CVE database correlation
- **Machine Learning**: Pattern recognition for findings
- **Export/Import**: Intelligence data sharing between Ragnar instances

### Advanced Scenarios
- **Multi-Interface Support**: Handling multiple network connections
- **VPN Detection**: Different handling for VPN vs direct connections
- **Network Fingerprinting**: Enhanced network identification beyond SSID

## Troubleshooting

### Common Issues

1. **Network Intelligence Not Loading**
   ```python
   # Check if properly initialized
   if hasattr(shared_data, 'network_intelligence'):
       print("Network intelligence available")
   else:
       print("Network intelligence not initialized")
   ```

2. **Findings Not Persisting**
   - Check `network_intelligence_enabled` configuration
   - Verify intelligence directory permissions
   - Review logs for JSON serialization errors

3. **Network ID Changes**
   - SSID changes cause new network IDs
   - Hidden networks may cause fallback to "default_network"
   - Check WiFi manager integration

### Debug Information

```python
# Get comprehensive debug info
summary = shared_data.network_intelligence.get_network_summary()
print(f"Current network: {summary['current_network']}")
print(f"Total networks: {summary['total_networks']}")
print(f"Active findings: {summary['global_totals']}")
```

The Network Intelligence System provides a sophisticated, network-aware approach to vulnerability and credential management, enabling Ragnar to maintain contextual awareness while preserving valuable historical intelligence.