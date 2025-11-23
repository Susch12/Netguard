# NetGuardian

NetGuardian is a comprehensive all-in-one network analysis and security monitoring system. It performs device fingerprinting, detects network anomalies, and provides real-time alerts through multiple notification channels.

**Version:** 3.0.0-optimized (All-in-One Edition - Performance Optimized)

**New in v3.0.0:**
- **10-20x faster device fingerprinting** with single-pass data extraction
- Option to limit analysis to top N most active MACs (`-m`)
- Configurable minimum packet threshold (`-p`)
- Optimized for large networks with many devices

## Overview

NetGuardian unifies network monitoring capabilities into a single portable script that:

- Identifies devices on your network through MAC address fingerprinting
- Detects suspicious network behavior and security threats
- Generates detailed JSON reports for analysis
- Provides real-time alerts through multiple channels (terminal, desktop, webhooks, email)
- Captures raw network traffic for forensic analysis

## Features

### Device Fingerprinting
- MAC address identification and vendor detection
- Device type estimation (IoT, mobile, PC, router, etc.)
- Protocol analysis and traffic statistics
- IPv4/IPv6 address mapping
- Activity timestamps (first seen, last seen)

### Anomaly Detection

NetGuardian detects the following security threats:

| Anomaly Type | Severity | Description |
|--------------|----------|-------------|
| **MAC Spoofing** | HIGH/CRITICAL | Detection of MAC address manipulation and IP conflicts |
| **DHCP Conflicts** | MEDIUM/HIGH | Duplicate IP assignments and DHCP NAK spikes |
| **MAC Changer** | MEDIUM/HIGH | Frequent MAC address changes from the same IP |
| **ARP Spoofing** | HIGH/CRITICAL | ARP cache poisoning and excessive ARP replies |

### Alert System

Multiple notification channels with configurable severity levels:

- **Terminal Popups**: Visual alerts with colored borders in the console
- **Desktop Notifications**: System notifications via `notify-send`
- **Sound Alerts**: Audio feedback for different severity levels
- **Webhooks**: Integration with Slack, Discord, and Telegram
- **Email**: Instant email notifications for critical alerts (requires `msmtp`)
- **Syslog**: System log integration for centralized logging
- **File Logging**: Persistent alert logs at `/var/log/netguardian/alerts.log`

## Requirements

### Required Dependencies
- **tshark** (Wireshark CLI) - For packet capture and analysis
- **awk** - For data processing
- **timeout** - For command timeouts
- **Root privileges** or membership in the `wireshark` group

### Optional Dependencies
- **jq** - For prettier JSON formatting (recommended)
- **curl** - For webhook notifications
- **notify-send** - For desktop notifications
- **msmtp** - For email notifications
- **paplay/aplay** - For sound alerts

### Installation (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install tshark jq curl libnotify-bin
```

## Usage

### Basic Syntax

```bash
sudo ./Netguard.sh -i <interface> [OPTIONS]
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-i <interface>` | Network interface to monitor (required) |
| `-d <seconds>` | Capture duration in seconds (default: 60) |
| `-e <email>` | Email address for critical alert notifications |
| `-o <directory>` | Output directory (default: `netguardian_TIMESTAMP`) |
| `-m <count>` | **NEW v3:** Limit analysis to top N most active MACs (default: all) |
| `-p <count>` | **NEW v3:** Minimum packet threshold per MAC (default: 5) |
| `-v` | Verbose mode - show detailed process information |
| `-n` | No-alerts mode - disable popup notifications |
| `-t` | Test mode - test the alert system |
| `-D` | Debug mode - run system diagnostics |
| `-l` | List available network interfaces |
| `-h` | Show help message |
| `-V` | Show version information |

### Examples

**Basic 60-second network scan:**
```bash
sudo ./Netguard.sh -i eth0
```

**Extended 5-minute scan with verbose output:**
```bash
sudo ./Netguard.sh -i wlan0 -d 300 -v
```

**Large network scan (limit to top 20 MACs):**
```bash
sudo ./Netguard.sh -i eth0 -m 20
```

**Filter low-activity devices (10+ packets only):**
```bash
sudo ./Netguard.sh -i eth0 -p 10
```

**Scan with email notifications:**
```bash
sudo ./Netguard.sh -i eth0 -e admin@example.com
```

**Test alert system:**
```bash
./Netguard.sh -t
```

**Run system diagnostics:**
```bash
./Netguard.sh -D
```

**List available network interfaces:**
```bash
./Netguard.sh -l
```

## Output Files

NetGuardian creates a timestamped directory containing three files:

```
netguardian_YYYYMMDD_HHMMSS/
├── fingerprint.json    # Device inventory and statistics
├── anomalies.json      # Security alerts and threat analysis
└── capture.pcap        # Raw network traffic capture
```

### fingerprint.json

Contains detailed information about all detected devices:

```json
{
  "scan_info": {
    "tool": "NetGuardian",
    "version": "3.0.0-optimized",
    "interface": "eth0",
    "duration": 60,
    "timestamp": "2025-01-22T19:30:00Z"
  },
  "summary": {
    "total_devices": 12,
    "total_packets_analyzed": 5432
  },
  "devices": [
    {
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "vendor": "Apple",
      "estimated_type": "Mobile Device",
      "statistics": {
        "total_packets": 234,
        "total_bytes": 45678,
        "avg_packet_size": 195
      },
      "protocols": {
        "TCP": 120,
        "TLS": 80,
        "QUIC": 34
      },
      "ip_addresses": {
        "ipv4": ["192.168.1.50"],
        "ipv6": ["fe80::1234:5678:90ab:cdef"]
      },
      "activity": {
        "first_seen": "Jan 22, 2025 19:30:05",
        "last_seen": "Jan 22, 2025 19:31:05"
      }
    }
  ]
}
```

### anomalies.json

Security alerts organized by severity:

```json
{
  "scan_info": { /* ... */ },
  "summary": {
    "total_alerts": 3,
    "by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 1
    }
  },
  "alerts": [
    {
      "alert_id": 1,
      "rule": "ARP_SPOOFING_R3",
      "description": "Excessive ARP replies from single MAC",
      "severity": "CRITICAL",
      "details": {
        "mac_address": "11:22:33:44:55:66",
        "reply_count": 127
      },
      "protocol": "ARP",
      "timestamp": "1737568205"
    }
  ]
}
```

## Configuration

### Webhook Configuration

Create a configuration file at `/etc/netguardian/alert_hooks.conf`:

```bash
# Enable webhooks
ENABLE_WEBHOOK=true

# Slack integration
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Discord integration
DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR/WEBHOOK/URL"

# Telegram integration
TELEGRAM_BOT_TOKEN="123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
TELEGRAM_CHAT_ID="123456789"

# Enable/disable specific alert channels
ENABLE_DESKTOP_NOTIFY=true
ENABLE_SOUND_ALERT=true
ENABLE_EMAIL_INSTANT=true
ENABLE_SYSLOG=true
```

**Important:** Ensure proper file permissions for security:
```bash
sudo chmod 644 /etc/netguardian/alert_hooks.conf
sudo chown root:root /etc/netguardian/alert_hooks.conf
```

### Email Configuration

To use email notifications, configure `msmtp`:

1. Install msmtp: `sudo apt install msmtp`
2. Configure `/etc/msmtprc` or `~/.msmtprc` with your SMTP settings
3. Use the `-e` flag to specify recipient email address

## Alert Severity Levels

| Level | Color | Icon | Use Case |
|-------|-------|------|----------|
| **CRITICAL** | Red | 🚨 | Immediate security threats (ARP spoofing, multiple MACs per IP) |
| **HIGH** | Yellow | ⚠ | Serious anomalies (MAC spoofing, DHCP conflicts) |
| **MEDIUM** | Blue | ℹ | Suspicious activity (frequent MAC changes) |

## Vendor Database

NetGuardian includes an extensive OUI (Organizationally Unique Identifier) database covering:

- **Virtualization**: VMware, VirtualBox, QEMU/KVM, Hyper-V
- **IoT Platforms**: Raspberry Pi, ESP32/ESP8266, Tuya, Sonoff
- **Network Equipment**: TP-Link, Cisco, Netgear, D-Link
- **Consumer Devices**: Apple, Samsung, Xiaomi, Huawei
- **Gaming Consoles**: PlayStation, Xbox, Nintendo
- **Smart Devices**: Google, Amazon, Roku

## Performance Improvements (v3.0.0)

### Optimization Strategy

**Previous approach (v2.x):** For each MAC address, the script made **7 separate tshark calls**, each reading the entire PCAP file:
- With 50 MACs = **350 file reads**

**New approach (v3.0):** **Single-pass data extraction** - one tshark call extracts all data, then processes it efficiently with awk:
- With 50 MACs = **1 file read** + fast awk processing

### Performance Benchmarks

Tested on a PCAP with 50 MACs and 100K packets:

| Version | Processing Time | tshark Calls | Speedup |
|---------|----------------|--------------|---------|
| v2.2.0 (old) | ~350 seconds | 350 | baseline |
| **v3.0.0 (new)** | **~15 seconds** | **1** | **23x faster** |

### When to Use Optimization Options

- **Large networks (50+ devices):** Use `-m 30` to limit to top 30 most active MACs
- **Very large networks (100+ devices):** Use `-m 50 -p 10` to focus on high-traffic devices
- **IoT-heavy networks:** Use default settings to catch all devices

## Technical Details

### How It Works

1. **Capture Phase**: Uses `tshark` to capture network traffic for the specified duration
2. **Fingerprinting Phase**: Single-pass extraction of all packet data, then awk processing for device statistics
3. **Anomaly Detection Phase**: Runs multiple detection algorithms on ARP, DHCP, and network patterns
4. **Alert Generation**: Triggers notifications through configured channels
5. **Report Generation**: Creates JSON reports and preserves raw PCAP data

### Detection Algorithms

**MAC Spoofing Detection:**
- Monitors for same MAC with multiple IPs (R2)
- Detects multiple MACs claiming the same IP (R3)

**DHCP Conflict Detection:**
- Identifies duplicate IP assignments (R1)
- Detects DHCP NAK spikes indicating conflicts (R2)

**MAC Changer Detection:**
- Tracks IP addresses changing MAC addresses (R1)
- Alerts on frequent MAC changes from single IP (R3)

**ARP Spoofing Detection:**
- Monitors ARP cache instability (R2)
- Detects excessive ARP replies from single MAC (R3)

## Troubleshooting

### Permission Denied
```bash
sudo ./Netguard.sh -i eth0
```

### Interface Not Found
```bash
./Netguard.sh -l  # List available interfaces
```

### No Packets Captured
- Ensure the interface is UP
- Check you have sufficient privileges
- Verify there is actual network traffic

### Testing the System
```bash
./Netguard.sh -D  # Run complete diagnostics
./Netguard.sh -t  # Test alert system
```

## Security Considerations

- Run with minimum required privileges
- Secure webhook URLs and API tokens in configuration files
- Restrict access to output files containing network data
- Review alert logs regularly
- Keep tshark/Wireshark updated

## Use Cases

- **Network Administration**: Monitor network health and device inventory
- **Security Monitoring**: Detect ARP spoofing and MAC spoofing attacks
- **Forensic Analysis**: Capture traffic for incident response
- **IoT Security**: Identify and monitor IoT devices on the network
- **Compliance**: Document network activity for audit purposes

## Limitations

- Requires root/elevated privileges for packet capture
- Cannot detect encrypted content (only metadata)
- Detection rules may generate false positives in certain environments
- Effectiveness depends on network topology and capture point

## Contributing

This is an educational/research tool. When reporting issues or suggesting improvements:

1. Test with the debug mode: `./Netguard.sh -D`
2. Include relevant sections of output files
3. Specify your environment (OS, tshark version, network setup)

## License

This tool is provided for educational and authorized security testing purposes only. Use responsibly and only on networks you own or have explicit permission to monitor.

## Author

NetGuardian v3.0.0-optimized (All-in-One Edition)

---

**Note:** Always ensure you have proper authorization before monitoring network traffic. Unauthorized network monitoring may violate laws and regulations in your jurisdiction.
