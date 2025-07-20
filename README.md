# WiFi Security Test Tool

**ВНИМАНИЕ: Этот инструмент предназначен ИСКЛЮЧИТЕЛЬНО для тестирования собственных сетей!**  
**WARNING: This tool is intended EXCLUSIVELY for testing your own networks!**

## Overview

WiFi Security Test Tool is a comprehensive WiFi security testing suite designed specifically for macOS. It provides modern, ethical WiFi security testing capabilities with full compliance to macOS system restrictions and security policies.

### Key Features

- **Modern macOS Compatibility**: Uses current macOS tools (wdutil, networksetup) instead of deprecated utilities
- **Automatic Dependency Management**: Installs and manages required tools via Homebrew
- **SIP-Aware Operations**: Handles System Integrity Protection restrictions gracefully
- **Multi-Method Password Cracking**: Supports both aircrack-ng and hashcat with GPU acceleration
- **Intelligent Fallback Systems**: Automatically switches to alternative methods when primary methods fail
- **Comprehensive Error Handling**: Robust error recovery and user guidance
- **Performance Optimization**: Optimized for large wordlists and long-running operations
- **Ethical Usage Enforcement**: Built-in legal compliance and usage logging

## Legal Notice

⚠️ **IMPORTANT LEGAL DISCLAIMER** ⚠️

This tool is designed for:
- Testing your own WiFi networks
- Educational purposes in controlled environments
- Authorized penetration testing with explicit permission
- Security research in compliance with local laws

**Unauthorized use of this tool against networks you do not own is illegal and unethical.**

By using this tool, you agree to:
- Only test networks you own or have explicit written permission to test
- Comply with all applicable local, state, and federal laws
- Take full responsibility for your actions
- Use the tool ethically and responsibly

## System Requirements

### Supported Systems
- macOS 10.15 (Catalina) or later
- Intel or Apple Silicon Macs
- Administrator privileges for some operations

### Required Tools (Auto-installed)
- Homebrew (package manager)
- aircrack-ng (WiFi security testing)
- hashcat (password cracking with GPU support)

### Optional Tools
- Wireshark (packet analysis)
- External WiFi adapter (for monitor mode if built-in adapter restricted)

## Installation

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mirvald-space/wifi-audit-macos.git
   cd wifi-audit-macos
   ```

2. **Run the application:**
   ```bash
   python3 wifi_security_tester/main.py
   ```

3. **Follow the setup wizard:**
   - Accept legal terms and conditions
   - Allow automatic dependency installation
   - Configure WiFi interfaces

### Manual Installation

If you prefer to install dependencies manually:

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install required tools
brew install aircrack-ng hashcat

# Run the application
python3 wifi_security_tester/main.py
```

## Usage Guide

### Main Menu Options

1. **Check Dependencies** - Verify and install required tools
2. **Scan Networks** - Discover available WiFi networks
3. **Interface Management** - Configure WiFi interfaces
4. **Packet Capture** - Capture handshake packets
5. **Password Cracking** - Test password strength
6. **Wordlist Management** - Create and manage password dictionaries
7. **Security Settings** - Check SIP status and permissions

### Basic Workflow

#### 1. Initial Setup
```bash
# Start the application
python3 wifi_security_tester/main.py

# Check and install dependencies
Select option 1: "Check Dependencies"
```

#### 2. Network Discovery
```bash
# Scan for available networks
Select option 2: "Scan Networks"

# Review discovered networks
# Note target network details (SSID, BSSID, Channel)
```

#### 3. Interface Configuration
```bash
# Configure WiFi interface
Select option 3: "Interface Management"

# Check interface capabilities
# Enable monitor mode if supported
```

#### 4. Packet Capture
```bash
# Capture handshake packets
Select option 4: "Packet Capture"

# Select target network
# Wait for handshake capture
# Verify capture quality
```

#### 5. Password Testing
```bash
# Create or select wordlist
Select option 6: "Wordlist Management"

# Start password cracking
Select option 5: "Password Cracking"

# Monitor progress and results
```

### Advanced Usage

#### Custom Wordlist Creation

```python
# Create built-in wordlist
from components.wordlist_manager import WordlistManager

wm = WordlistManager()
passwords = wm.generate_builtin_wordlist('common')
wm.create_custom_wordlist('my_wordlist', passwords)
```

#### Performance Optimization

```python
# Optimize for large wordlists
from core.performance_optimizer import get_performance_optimizer

optimizer = get_performance_optimizer()
config = optimizer.optimize_for_operation('large_wordlist_crack', {
    'wordlist_size': 10000000
})
```

#### Error Handling

```python
# Handle errors with automatic recovery
from core.error_handler import handle_error

try:
    # Your operation here
    pass
except Exception as e:
    result = handle_error(e, context={'operation': 'network_scan'})
    if result['recovery_successful']:
        # Continue with fallback method
        pass
```

## Configuration

### Environment Variables

```bash
# Set custom wordlist directory
export WIFI_TESTER_WORDLISTS_DIR="/path/to/wordlists"

# Set custom results directory
export WIFI_TESTER_RESULTS_DIR="/path/to/results"

# Enable debug logging
export WIFI_TESTER_DEBUG=1
```

### Configuration Files

The tool creates configuration files in `.kiro/` directory:
- `settings/config.json` - Main configuration
- `logs/` - Application logs
- `wordlists/` - Custom wordlists
- `results/` - Test results

## Troubleshooting

### Common Issues

#### SIP Restrictions
```
Error: Operation blocked by System Integrity Protection
Solution: 
1. Use external WiFi adapter
2. Disable SIP temporarily (not recommended)
3. Use alternative methods that don't require SIP bypass
```

#### Permission Denied
```
Error: Permission denied for interface operations
Solution: Run with sudo privileges
sudo python3 wifi_security_tester/main.py
```

#### Missing Dependencies
```
Error: aircrack-ng not found
Solution: Use automatic dependency installation
Select option 1 in main menu
```

#### Interface Not Found
```
Error: No WiFi interfaces detected
Solution: 
1. Check WiFi is enabled in System Preferences
2. Try external WiFi adapter
3. Restart WiFi service: sudo ifconfig en0 down && sudo ifconfig en0 up
```

### Performance Issues

#### Large Wordlist Processing
- Use wordlist optimization features
- Enable memory-mapped file access
- Split large wordlists for parallel processing
- Monitor system resources

#### Slow Cracking Speed
- Use GPU acceleration with hashcat
- Optimize wordlist (remove duplicates)
- Use SSD storage for better I/O
- Close unnecessary applications

### Recovery Procedures

#### Interface Stuck in Monitor Mode
```bash
# Automatic recovery
Select "Interface Management" → "Restore managed mode"

# Manual recovery
sudo ifconfig en0 down
sudo ifconfig en0 up
```

#### Hanging Processes
```bash
# Kill hanging processes
pkill -f "airodump-ng|hashcat|aircrack-ng"

# Or use built-in recovery
The tool automatically detects and recovers from hanging processes
```

## API Reference

### Core Components

#### WordlistManager
```python
from components.wordlist_manager import WordlistManager

wm = WordlistManager()

# Generate built-in wordlist
passwords = wm.generate_builtin_wordlist('common')

# Create custom wordlist
success, path = wm.create_custom_wordlist('test', ['password123'])

# Import external wordlist
success, message, count = wm.import_wordlist('/path/to/wordlist.txt')
```

#### NetworkScanner
```python
from components.network_scanner import NetworkScanner

scanner = NetworkScanner()

# Scan networks
networks = scanner.scan_networks()

# Get network details
details = scanner.get_network_details('target_ssid')
```

#### PasswordCracker
```python
from components.password_cracker import PasswordCracker

cracker = PasswordCracker()

# Start cracking job
job = cracker.crack_with_aircrack('capture.cap', 'wordlist.txt')

# Monitor progress
progress = cracker.get_job_progress(job.job_id)
```

### Error Handling

#### Custom Error Types
```python
from core.exceptions import *

# System errors
SIPRestrictionError
InterfaceNotFoundError
PermissionDeniedError

# Tool errors
DependencyMissingError
ExecutionFailedError

# Network errors
CaptureFailedError
NoHandshakeError
```

#### Recovery Strategies
```python
from core.error_handler import RecoveryStrategy

# Available strategies
RecoveryStrategy.RETRY
RecoveryStrategy.FALLBACK
RecoveryStrategy.DEGRADE
RecoveryStrategy.USER_INTERVENTION
RecoveryStrategy.ABORT
```

## Performance Optimization

### Memory Management
- Automatic garbage collection for large operations
- Memory-mapped file access for huge wordlists
- Configurable memory limits and thresholds

### Process Optimization
- Optimal thread count calculation
- Process priority adjustment
- Resource usage monitoring

### Caching
- Network scan result caching
- Wordlist preprocessing cache
- LRU cache eviction policy

## Security Features

### Ethical Usage Enforcement
- Mandatory legal agreement acceptance
- Comprehensive operation logging
- Suspicious activity detection
- Usage audit trails

### System Security
- Minimal privilege requirements
- Secure temporary file handling
- Automatic cleanup procedures
- SIP compliance checking

## Development

### Project Structure
```
wifi_security_tester/
├── main.py                 # Application entry point
├── components/             # Core components
│   ├── dependency_manager.py
│   ├── interface_manager.py
│   ├── network_scanner.py
│   ├── capture_engine.py
│   ├── password_cracker.py
│   ├── wordlist_manager.py
│   └── security_manager.py
├── core/                   # Core systems
│   ├── menu_system.py
│   ├── logger.py
│   ├── error_handler.py
│   ├── recovery_manager.py
│   ├── performance_optimizer.py
│   └── exceptions.py
├── utils/                  # Utilities
│   └── common.py
└── tests/                  # Test files
```

### Testing
```bash
# Run unit tests
python3 -m pytest wifi_security_tester/tests/

# Run integration tests
python3 wifi_security_tester/test_integration_comprehensive.py

# Run specific component tests
python3 wifi_security_tester/test_wordlist_manager.py
```

### Contributing
1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit pull request

## Author

**Author:** @mirvaId  
**Contact:** Telegram [@mirvaId](https://t.me/mirvaId)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

Copyright (c) 2025 @mirvaId

## Disclaimer

The authors and contributors of this tool are not responsible for any misuse or damage caused by this software. Users are solely responsible for ensuring their use of this tool complies with applicable laws and regulations.

## Support

For support, issues, or feature requests:
1. Check the troubleshooting section
2. Contact the author via Telegram [@mirvaId](https://t.me/mirvaId)
3. Create a new issue with detailed information
4. Include system information and error logs

## Changelog

### Version 1.0.0
- Initial release
- Complete macOS compatibility
- Automatic dependency management
- Multi-method password cracking
- Comprehensive error handling
- Performance optimization
- Ethical usage enforcement

---

**Remember: Use this tool responsibly and only on networks you own or have explicit permission to test.**