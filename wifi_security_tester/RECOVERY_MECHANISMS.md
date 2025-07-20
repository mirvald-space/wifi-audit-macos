# Recovery and Fallback Mechanisms

This document describes the comprehensive recovery and fallback mechanisms implemented in the WiFi Security Tester to address requirements 1.4, 2.4, and 3.4.

## Overview

The recovery system consists of three main components:

1. **Recovery Coordinator** - Orchestrates comprehensive recovery workflows
2. **Recovery Manager** - Implements automatic fallback methods and system state recovery
3. **Fallback Mechanisms** - Provides specific fallback implementations for critical operations
4. **User Guidance System** - Provides clear instructions for manual error resolution

## Requirement Implementation

### Requirement 1.4: Homebrew Installation Fallback

**Requirement**: "IF Homebrew не установлен THEN система SHALL предложить установку Homebrew"

**Implementation**:
- **Automatic Detection**: System checks if Homebrew is installed using `shutil.which('brew')`
- **Automatic Installation**: Attempts to install Homebrew using the official installation script
- **Manual Guidance**: If automatic installation fails, provides step-by-step manual installation instructions
- **Alternative Methods**: Suggests alternative package managers if Homebrew installation is not possible

**Code Location**: `core/fallback_mechanisms.py` - `homebrew_installation_fallback()`

**Fallback Chain**:
1. Check if Homebrew is already installed
2. Attempt automatic installation via official script
3. Provide manual installation guidance with detailed steps
4. Suggest alternative package managers

### Requirement 2.4: Network Scanning Fallback

**Requirement**: "IF wdutil недоступен THEN система SHALL предложить альтернативные методы сканирования"

**Implementation**:
- **Primary Method**: Uses `wdutil` for modern network scanning
- **Fallback Methods**: Automatically tries alternative scanning methods in priority order
- **Manual Guidance**: Provides comprehensive manual scanning instructions when all methods fail

**Code Location**: `core/fallback_mechanisms.py` - `network_scanning_fallback()`

**Fallback Chain**:
1. `wdutil scan` (primary method)
2. `system_profiler SPAirPortDataType` (fallback 1)
3. `networksetup -listpreferredwirelessnetworks` (fallback 2)
4. Legacy `airport -s` utility (fallback 3)
5. Manual scanning guidance (final fallback)

### Requirement 3.4: Monitor Mode Fallback

**Requirement**: "IF интерфейс не поддерживает режим мониторинга THEN система SHALL предупредить пользователя и предложить альтернативы"

**Implementation**:
- **Capability Detection**: Automatically checks if interface supports monitor mode
- **Alternative Methods**: Tries different approaches to enable monitor mode
- **Comprehensive Alternatives**: Provides detailed alternatives when monitor mode is not supported

**Code Location**: `core/fallback_mechanisms.py` - `monitor_mode_fallback()`

**Fallback Chain**:
1. Check monitor mode support capability
2. Try `networksetup` method
3. Try `ifconfig` method
4. Try legacy `airport` utility method
5. Provide comprehensive alternatives:
   - External WiFi adapters with specific model recommendations
   - Passive scanning methods
   - Alternative capture methods
   - Virtual machine setup guidance

## System State Recovery

### Automatic State Saving
- System automatically saves state before critical operations
- Includes interface states, network configuration, running processes, and temporary files
- Maintains history of up to 10 previous states

### State Restoration
- Can restore system to any previous saved state
- Automatically restores interfaces to managed mode
- Cleans up temporary files and hanging processes
- Provides rollback capability for failed operations

### Code Location
- `core/recovery_manager.py` - `save_system_state()`, `restore_system_state()`

## User Guidance System

### Guidance Levels
- **Basic**: Simple, easy-to-follow instructions
- **Detailed**: Comprehensive guidance with multiple solutions
- **Expert**: Technical details and advanced troubleshooting

### Error-Specific Guidance
- **SIP Restrictions**: External adapter recommendations, SIP disable guidance
- **Dependency Issues**: Installation instructions, alternative tools
- **Monitor Mode**: Hardware recommendations, alternative methods
- **Permission Issues**: Privilege escalation guidance

### Code Location
- `core/user_guidance.py` - Complete user guidance system

## Recovery Coordinator

### Comprehensive Error Handling
- Handles errors with multiple recovery strategies
- Tracks recovery operations and success rates
- Provides detailed recovery reports
- Supports concurrent recovery operations

### Recovery Strategies
- **System Recovery**: Interface reset, state restoration
- **Tool Recovery**: Dependency installation, version compatibility
- **Network Recovery**: Alternative scanning, capture methods
- **Resource Recovery**: Memory cleanup, disk space management

### Code Location
- `core/recovery_coordinator.py` - Main recovery orchestration

## Usage Examples

### Basic Error Recovery
```python
from core.recovery_coordinator import handle_error_with_recovery

# Handle error with automatic recovery
result = handle_error_with_recovery(
    error=DependencyMissingError("aircrack-ng"),
    operation="dependency_install",
    context={"tool": "aircrack-ng"}
)

if result['recovery_successful']:
    print("Recovery successful!")
else:
    print("Manual intervention required:")
    print(result['guidance_text'])
```

### Fallback Method Usage
```python
from core.fallback_mechanisms import get_fallback_mechanisms

fallback = get_fallback_mechanisms()

# Try network scanning with automatic fallback
success, networks, details = fallback.network_scanning_fallback()

if success:
    print(f"Found {len(networks)} networks using {details['method']}")
else:
    print("Manual scanning required:")
    print(details['guidance'])
```

### User Guidance
```python
from core.user_guidance import get_user_guidance_system, GuidanceLevel

guidance = get_user_guidance_system()

# Get detailed guidance for an error
error_guidance = guidance.get_guidance(
    error=MonitorModeError("en0", "Monitor mode not supported"),
    level=GuidanceLevel.DETAILED
)

print(guidance.format_guidance_text(error_guidance))
```

## Testing

### Integration Tests
- Comprehensive test suite in `test_recovery_fallback_integration.py`
- Tests all three requirements (1.4, 2.4, 3.4)
- Verifies complete recovery workflows
- Tests concurrent recovery operations

### Simple Tests
- Basic functionality tests in `test_recovery_simple.py`
- Quick verification of core mechanisms
- Suitable for continuous integration

### Running Tests
```bash
# Run comprehensive tests
python3 wifi_security_tester/test_recovery_fallback_integration.py

# Run simple tests
python3 wifi_security_tester/test_recovery_simple.py
```

## Configuration

### Recovery Settings
- Maximum recovery attempts: 3 (configurable)
- Recovery timeout: 300 seconds (5 minutes)
- Maximum concurrent recoveries: 3
- State history limit: 10 states

### Fallback Priorities
- Methods are tried in order of priority (1 = highest)
- Success rates are tracked and influence future selections
- Failed methods are temporarily deprioritized

## Monitoring and Statistics

### Recovery Statistics
- Total recovery operations
- Success rates by method
- Common error patterns
- Performance metrics

### Logging
- All recovery operations are logged
- Detailed error information preserved
- Recovery method effectiveness tracked
- User guidance interactions logged

## Best Practices

### For Developers
1. Always use recovery coordinator for error handling
2. Implement specific recovery methods for new error types
3. Provide meaningful context information
4. Test recovery mechanisms thoroughly

### For Users
1. Follow user guidance instructions carefully
2. Consider hardware recommendations for best results
3. Keep system dependencies up to date
4. Report persistent issues for improvement

## Future Enhancements

### Planned Improvements
- Machine learning for recovery method selection
- Cloud-based guidance updates
- Hardware compatibility database
- Automated system optimization

### Extensibility
- Plugin system for custom recovery methods
- User-defined fallback chains
- Custom guidance templates
- Integration with external monitoring systems

## Troubleshooting

### Common Issues
1. **Recovery loops**: Implement circuit breakers and maximum attempt limits
2. **Resource exhaustion**: Monitor system resources during recovery
3. **Permission issues**: Provide clear privilege escalation guidance
4. **Network timeouts**: Implement appropriate timeout handling

### Debug Mode
Enable detailed logging by setting log level to DEBUG:
```python
import logging
logging.getLogger('recovery_coordinator').setLevel(logging.DEBUG)
```

## Conclusion

The recovery and fallback mechanisms provide comprehensive error handling and automatic recovery capabilities that fully address requirements 1.4, 2.4, and 3.4. The system is designed to be robust, user-friendly, and extensible, ensuring reliable operation even when primary methods fail.